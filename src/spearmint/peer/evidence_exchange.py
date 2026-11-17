"""Share selected policy conflict reports with authenticated Grove members."""

from dataclasses import dataclass
import json
import re
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..state import State, audit
from . import evidence
from .credentials import NODE_ID
from .grove_endpoints import trusted_members
from .mesh_policy import configured_trust
from .pairing import Pair
from .policy import require_pair
from .policy_records import encoded, positive, root_id
from .protocol import PeerError, matches


LIST = 'security.evidence.list'
PART = 'security.evidence.part'
PROOF_ID = re.compile(r'mpe1-[0-9a-f]{64}')
PAGE = 20
TTL = 7 * 86400
MAX_REPORTS = 64
MAX_PER_OBSERVER = 16
HEADER = {'version', 'mesh_id', 'observer_public_key', 'observation'}
WIRE_SCOPE = {'realm_id', 'root_key_id'}


@dataclass(frozen=True)
class Scope:
    realm_id: str
    mesh_id: str
    root_key: bytes

    @property
    def public(self) -> Ed25519PublicKey:
        return Ed25519PublicKey.from_public_bytes(self.root_key)

    @property
    def root_key_id(self) -> str:
        return root_id(self.public)

    def wire(self) -> dict:
        return {'realm_id': self.realm_id, 'root_key_id': self.root_key_id}


def current_scope(db, pair: Pair | None = None) -> Scope:
    anchor = configured_trust(db)
    local = db.execute('SELECT node_id FROM node WHERE singleton=1').fetchone()
    trust = trusted_members(db, local[0]) if local is not None else None
    if pair is not None:
        require_pair(db, pair)
        if pair.legacy or trust is None or pair.node_id not in trust.origins:
            raise PeerError('DENIED', 'An active Grove member is required')
    if anchor is None or trust is None or pair is not None and pair.mesh_id != anchor['mesh_id']:
        raise PeerError('UNAVAILABLE', 'Configure the Grove and its Mesh policy root before exchanging reports')
    return Scope(trust.realm_id, anchor['mesh_id'], anchor['root_key'])


def shares(db, scope: Scope, now: int) -> dict[int, int]:
    return dict(db.execute('''
        SELECT term, expires_at FROM mesh_evidence_share
        WHERE mesh_id=? AND realm_id=? AND root_key_id=? AND expires_at>?
    ''', (scope.mesh_id, scope.realm_id, scope.root_key_id, now)))


def local_shares(state: State) -> dict[int, int] | None:
    with state.connect() as db:
        db.execute('BEGIN')
        try:
            scope = current_scope(db)
        except PeerError:
            return None
        return shares(db, scope, int(time.time()))


def authorize_peer(state: State, pair: Pair) -> Scope:
    with state.connect() as db:
        db.execute('BEGIN')
        return current_scope(db, pair)


def require_wire_scope(scope: Scope, params: dict) -> None:
    if any(params[key] != value for key, value in scope.wire().items()):
        raise PeerError('DENIED', 'Evidence exchange requires matching Grove and policy root')


def set_share(state: State, term: int, enabled: bool, actor: str, source: str) -> dict:
    if not positive(term):
        raise PeerError('INVALID_REQUEST', 'Invalid policy term')
    if not enabled:
        with state.connect(write=True) as db:
            row = db.execute('''
                DELETE FROM mesh_evidence_share WHERE term=? AND mesh_id=(SELECT mesh_id FROM mesh_profile)
                RETURNING term
            ''', (term,)).fetchone()
            if row is not None:
                audit(db, actor, source, 'mesh.evidence.unshared', str(term))
        return {'shared_until': None}
    with state.connect() as db:
        db.execute('BEGIN')
        scope = current_scope(db)
    evidence.export_report(state, term, scope.public)
    expires = int(time.time()) + TTL
    with state.connect(write=True) as db:
        if current_scope(db) != scope:
            raise PeerError('CONFLICT', 'Grove trust changed while sharing the report')
        db.execute('''
            INSERT INTO mesh_evidence_share VALUES (?,?,?,?,?)
            ON CONFLICT(mesh_id,term) DO UPDATE SET realm_id=excluded.realm_id,
                root_key_id=excluded.root_key_id,expires_at=excluded.expires_at
        ''', (scope.mesh_id, term, scope.realm_id, scope.root_key_id, expires))
        audit(db, actor, source, 'mesh.evidence.shared', str(term))
    return {'shared_until': expires}


def page(state: State, pair: Pair, params: dict) -> dict:
    if params.keys() != WIRE_SCOPE | {'before'} or params['before'] is not None and not positive(params['before']):
        raise PeerError('INVALID_REQUEST', 'Invalid evidence list cursor')
    before = params['before']
    with state.connect() as db:
        db.execute('BEGIN')
        scope = current_scope(db, pair)
        require_wire_scope(scope, params)
        rows = db.execute('''
            SELECT c.term, c.recorded_at, s.expires_at AS shared_until
            FROM mesh_policy_conflict c JOIN mesh_evidence_share s USING(mesh_id,term)
            WHERE c.mesh_id=? AND s.realm_id=? AND s.root_key_id=? AND s.expires_at>?
                AND (? IS NULL OR c.term<?)
            ORDER BY c.term DESC LIMIT ?
        ''', (scope.mesh_id, scope.realm_id, scope.root_key_id, int(time.time()), before, before, PAGE + 1)).fetchall()
    return {'reports': [dict(row) for row in rows[:PAGE]],
            'next_before': rows[PAGE - 1]['term'] if len(rows) > PAGE else None}


def part(state: State, pair: Pair, params: dict) -> dict:
    if (params.keys() != WIRE_SCOPE | {'term', 'index'} or not positive(params['term'])
            or type(params['index']) is not int or params['index'] not in (0, 1)):
        raise PeerError('INVALID_REQUEST', 'Invalid evidence report part')
    term, index = params['term'], params['index']
    with state.connect() as db:
        db.execute('BEGIN')
        scope = current_scope(db, pair)
        require_wire_scope(scope, params)
        if term not in shares(db, scope, int(time.time())):
            raise PeerError('NOT_FOUND', 'This report is not shared with the Grove')
    document = evidence.export_report(state, term, scope.public)
    with state.connect() as db:
        db.execute('BEGIN')
        if current_scope(db, pair) != scope or term not in shares(db, scope, int(time.time())):
            raise PeerError('NOT_FOUND', 'This report is no longer shared with the Grove')
    result = {'statement': document['statements'][index]}
    if index == 0:
        result.update({key: document[key] for key in HEADER})
    return result


def check_page(result: dict) -> dict:
    if (result.keys() != {'reports', 'next_before'} or not isinstance(result['reports'], list)
            or len(result['reports']) > PAGE or result['next_before'] is not None and not positive(result['next_before'])
            or any(not isinstance(row, dict) or row.keys() != {'term', 'recorded_at', 'shared_until'}
                   or not all(positive(value) for value in row.values()) for row in result['reports'])):
        raise PeerError('PROTOCOL', 'Invalid shared evidence list')
    terms = [row['term'] for row in result['reports']]
    if terms != sorted(set(terms), reverse=True) or (result['next_before'] is not None
            and (len(terms) != PAGE or result['next_before'] != terms[-1])):
        raise PeerError('PROTOCOL', 'Invalid shared evidence list ordering')
    return result


def assemble(first: dict, second: dict) -> dict:
    if first.keys() != HEADER | {'statement'} or second.keys() != {'statement'}:
        raise PeerError('PROTOCOL', 'Invalid evidence report parts')
    return {**{key: first[key] for key in HEADER}, 'statements': [first['statement'], second['statement']]}


def receive(state: State, pair: Pair, scope: Scope, term: int, document: dict, actor: str) -> dict:
    raw = encoded(document)
    if len(raw) > evidence.LIMIT:
        raise PeerError('LIMIT', 'Evidence report exceeds its size limit')
    try:
        report = evidence.verify_report(document, scope.public, scope.mesh_id, pair.node_id)
        if report['statements'][0]['term'] != term:
            raise ValueError('Report differs from the requested term')
    except (ValueError, InvalidSignature) as exc:
        raise PeerError('DENIED', 'The report does not verify under the current Grove trust') from exc
    now = int(time.time())
    proof = report['proof_id']
    with state.connect(write=True) as db:
        if current_scope(db, pair) != scope:
            raise PeerError('CONFLICT', 'Grove trust changed while verifying the report')
        db.execute('DELETE FROM mesh_evidence_inbox WHERE received_at<=?', (now - TTL,))
        inserted = db.execute('''
            INSERT INTO mesh_evidence_inbox VALUES (?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(observer,proof_id) DO NOTHING RETURNING proof_id
        ''', (pair.node_id, proof, scope.realm_id, scope.mesh_id, scope.root_key_id, term, report['kind'],
              report['recorded_at'], now, raw.decode())).fetchone()
        if inserted is not None:
            db.execute('''
                DELETE FROM mesh_evidence_inbox WHERE rowid IN (
                    SELECT rowid FROM mesh_evidence_inbox WHERE observer=?
                    ORDER BY received_at DESC,rowid DESC LIMIT -1 OFFSET ?
                )
            ''', (pair.node_id, MAX_PER_OBSERVER))
            db.execute('''
                DELETE FROM mesh_evidence_inbox WHERE rowid IN (
                    SELECT rowid FROM mesh_evidence_inbox ORDER BY received_at DESC,rowid DESC LIMIT -1 OFFSET ?
                )
            ''', (MAX_REPORTS,))
            audit(db, actor, pair.node_id, 'mesh.evidence.received', proof)
    return {'proof_id': proof, 'observer': pair.node_id, 'stored': inserted is not None}


def inbox(state: State) -> list[dict]:
    with state.connect() as db:
        return [dict(row) for row in db.execute('''
            SELECT observer,proof_id,realm_id,mesh_id,root_key_id,term,kind,recorded_at,received_at
            FROM mesh_evidence_inbox WHERE received_at>? ORDER BY received_at DESC,rowid DESC
        ''', (int(time.time()) - TTL,))]


def received_report(state: State, observer: str, proof: str) -> dict:
    if not matches(NODE_ID, observer) or not matches(PROOF_ID, proof):
        raise PeerError('INVALID_REQUEST', 'Invalid evidence report identifier')
    with state.connect() as db:
        row = db.execute('SELECT document FROM mesh_evidence_inbox WHERE observer=? AND proof_id=? AND received_at>?',
                         (observer, proof, int(time.time()) - TTL)).fetchone()
    if row is None:
        raise PeerError('NOT_FOUND', 'No report with this identifier is retained')
    return json.loads(row[0])
