"""Replicate signed Grove display notes and voluntary member departures."""
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import grove
from .peer import quarantine
from .peer.credentials import NODE_ID, node_id
from .peer.policy import require_pair
from .peer.protocol import PeerError, decode_json, parse_b64, wire_b64
from .state import audit


METHOD = 'grove.metadata.page'
NOTE = 'node-note'
DEPARTURE = 'member-departure'
PAGE_SIZE = 16
MAX_REVISION = 2**53 - 1
NODE_TYPES = {'generic', 'pc', 'laptop', 'workstation', 'server', 'nas', 'edge', 'vm'}
NODE_ICONS = {'auto', 'monitor', 'laptop', 'workstation', 'server', 'hard-drive', 'cpu', 'layers', 'cloud', 'smartphone'}


def appearance(data):
    node_type, icon = data.get('node_type', 'generic'), data.get('icon', 'auto')
    if not isinstance(node_type, str) or node_type not in NODE_TYPES or not isinstance(icon, str) or icon not in NODE_ICONS:
        raise PeerError('INVALID_REQUEST', 'Choose a supported node type and icon')
    return {'node_type': node_type, 'icon': icon}


def saved_appearance(envelope):
    # The envelope was verified before entering the metadata table. Optional
    # display fields fit the existing signed record and backup format.
    data = decode_json(parse_b64(json.loads(envelope)['record'], 2048))
    return appearance(data)


def realm_id(db):
    record = db.execute("SELECT id FROM grove_realm WHERE frozen=''").fetchone()
    return record['id'] if record else None


def enabled(db, node):
    return db.execute('SELECT 1 FROM grove_member WHERE node_id=? AND enabled=1', (node,)).fetchone() is not None


def text(value):
    if not isinstance(value, str) or len(value) > 80 or value != value.strip() or value and not value.isprintable():
        raise PeerError('INVALID_REQUEST', 'A node note must contain at most 80 printable characters')
    return value


def verify(document, kind):
    try:
        unverified = decode_json(parse_b64(document['record'], 2048))
        public = parse_b64(unverified['public_key'], 32)
        author = node_id(Ed25519PublicKey.from_public_bytes(public))
        data = grove.verified(kind, document, public, 2048)
        if data['author'] != author or not isinstance(data['realm'], str):
            raise ValueError
        return data
    except (TypeError, ValueError, KeyError, PeerError) as error:
        raise PeerError('DENIED', 'Invalid signed Grove metadata') from error


def store_note(db, realm, document):
    data = verify(document, NOTE)
    required = {'realm','author','public_key','node','revision','note'}
    if (not required <= data.keys() or data.keys() - required - {'node_type', 'icon'} or data['realm'] != realm
            or not isinstance(data['node'], str) or NODE_ID.fullmatch(data['node']) is None
            or type(data['revision']) is not int or not 1 <= data['revision'] <= MAX_REVISION
            or not enabled(db, data['author']) or not enabled(db, data['node'])):
        raise PeerError('DENIED', 'The note does not belong to an active Grove member')
    note = text(data['note'])
    appearance(data)
    envelope = grove.encoded(document).decode()
    db.execute('''INSERT INTO grove_node_note VALUES (?,?,?,?,?) ON CONFLICT(node_id) DO UPDATE SET
                   revision=excluded.revision,author=excluded.author,note=excluded.note,envelope=excluded.envelope
                   WHERE (excluded.revision,excluded.author,excluded.envelope) >
                         (grove_node_note.revision,grove_node_note.author,grove_node_note.envelope)''',
               (data['node'], data['revision'], data['author'], note, envelope))


def notes(state):
    with state.connect(read_only=True) as db:
        return {row['node_id']:row['note'] for row in db.execute('''SELECT n.node_id,n.note FROM grove_node_note n
                            JOIN grove_member m ON m.node_id=n.node_id WHERE m.enabled=1''')}


def profiles(state):
    with state.connect(read_only=True) as db:
        return {row['node_id']: {'note': row['note'], **saved_appearance(row['envelope'])}
                for row in db.execute('''SELECT n.node_id,n.note,n.envelope FROM grove_node_note n
                           JOIN grove_member m ON m.node_id=n.node_id WHERE m.enabled=1''')}


def save_note(state, actor, node, value):
    result = save_profile(state, actor, node, value)
    return {'note': result['note']}


def save_profile(state, actor, node, value, *, node_type=None, icon=None):
    note = text(value.strip())
    local, public = state.identity()
    with state.connect(write=True) as db:
        realm = realm_id(db)
        if realm is None or not enabled(db, local) or not enabled(db, node):
            raise PeerError('NOT_FOUND', 'The node is not an active member of this Grove')
        old = db.execute('SELECT revision,envelope FROM grove_node_note WHERE node_id=?', (node,)).fetchone()
        settings = saved_appearance(old['envelope']) if old else appearance({})
        if node_type is not None:
            settings['node_type'] = node_type
        if icon is not None:
            settings['icon'] = icon
        settings = appearance(settings)
        revision = (old['revision'] if old else 0) + 1
        extra = settings if node_type is not None or icon is not None or settings != appearance({}) else {}
        document = grove.signed(NOTE, {'realm':realm,'author':local,'public_key':wire_b64(public),
                                      'node':node,'revision':revision,'note':note, **extra}, state.signing_key())
        store_note(db, realm, document)
        event = 'grove.node_profile_changed' if node_type is not None or icon is not None else 'grove.node_note_changed'
        audit(db, actor.operation_actor, actor.address, event, node)
    return {'note':note, **settings}


def departure(state):
    local, public = state.identity()
    with state.connect(read_only=True) as db:
        realm = realm_id(db)
        if realm is None or not db.execute('SELECT 1 FROM grove_member_admission WHERE node_id=?', (local,)).fetchone():
            raise PeerError('DENIED', 'Only an admitted member can sign its departure')
    return grove.signed(DEPARTURE, {'realm':realm,'author':local,'public_key':wire_b64(public)}, state.signing_key())


def store_departure(db, realm, document):
    data = verify(document, DEPARTURE)
    if (data.keys() != {'realm','author','public_key'} or data['realm'] != realm
            or not db.execute('SELECT 1 FROM grove_member_admission WHERE node_id=?', (data['author'],)).fetchone()):
        raise PeerError('DENIED', 'The departure does not belong to an admitted Grove member')
    node = data['author']
    if db.execute('INSERT OR IGNORE INTO grove_member_departure VALUES (?,?)',
                  (node, grove.encoded(document).decode())).rowcount:
        db.execute('UPDATE grove_member SET enabled=0 WHERE node_id=?', (node,))
        db.execute('DELETE FROM grove_node_note WHERE node_id=? OR author=?', (node,node))
        db.execute('DELETE FROM peer WHERE node_id=?', (node,))
        audit(db, 'grove', 'member-departure', 'grove.member_departed', node)
    return node


def apply_departure(state, document):
    with state.connect(write=True) as db:
        return store_departure(db, realm_id(db), document)


def current_realm(state):
    with state.connect(read_only=True) as db:
        return realm_id(db)


def page(state, pair, params):
    if (params.keys() != {'realm','after'} or not isinstance(params['after'], str)
            or params['after'] and NODE_ID.fullmatch(params['after']) is None):
        raise PeerError('INVALID_REQUEST', 'Invalid Grove metadata cursor')
    with state.connect(read_only=True) as db:
        db.execute('BEGIN')
        require_pair(db, pair)
        if (pair.legacy or quarantine.contains(db, pair.node_id) or not enabled(db, pair.node_id)
                or realm_id(db) != params['realm']):
            raise PeerError('DENIED', 'Grove metadata requires a current member')
        records = db.execute('''SELECT node_id,envelope,kind FROM (
                        SELECT node_id,envelope,'note' AS kind FROM grove_node_note UNION ALL
                        SELECT node_id,envelope,'departure' AS kind FROM grove_member_departure)
                        WHERE node_id>? ORDER BY node_id LIMIT ?''', (params['after'], PAGE_SIZE+1)).fetchall()
    return {'records':[[row['kind'],json.loads(row['envelope'])] for row in records[:PAGE_SIZE]],
            'next':records[PAGE_SIZE-1]['node_id'] if len(records)>PAGE_SIZE else ''}


def merge(state, realm, records):
    if not isinstance(records,list) or len(records)>PAGE_SIZE:
        raise PeerError('PROTOCOL', 'Invalid Grove metadata page')
    with state.connect(write=True) as db:
        if realm != realm_id(db):
            return
        for record in records:
            if not isinstance(record,list) or len(record)!=2 or record[0] not in ('note','departure'):
                continue
            try:
                handler = store_note if record[0] == 'note' else store_departure
                handler(db, realm, record[1])
            except PeerError:
                continue
