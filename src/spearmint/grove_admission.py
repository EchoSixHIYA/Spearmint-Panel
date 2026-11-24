"""Approve an already authenticated Mesh node as a Grove login member."""
import json
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import auth, grove, grove_continuity, grove_login, grove_voters
from .peer.credentials import NODE_ID, node_id
from .peer import quarantine
from .peer.pairing import configured
from .peer.policy import require_pair
from .peer.protocol import PeerError, decode_json, parse_b64, wire_b64
from .state import State, audit


BALLOT = 'grove.members.admit.ballot'
APPLY = 'grove.members.admit.apply'
JOIN = 'grove.members.admit.join'
GET = 'grove.members.admit.get'
KIND = 'member-admission'
MAX_ADMISSIONS = 64
MAX_ORIGIN_LENGTH = 270
INVITATION_PREFIX = 'grove4.'
INVITATION_LIMIT = 8192


def invitation_code(state: State) -> str:
    with state.connect(read_only=True) as db:
        db.execute('BEGIN')
        current = grove_continuity.read_anchor(db)
        if current is None or grove_login.usable_replica(db, int(time.time())) is None:
            raise PeerError('GROVE_QUORUM_UNAVAILABLE', 'The current Grove member authorization has expired or is unavailable')
        _, anchor = current
        realm = grove.realm_data(db.execute('SELECT * FROM grove_realm').fetchone())
        members = anchor['voters']
    return INVITATION_PREFIX + wire_b64(grove.encoded({'realm': realm, 'members': members}))


def read_invitation(code: str) -> tuple[dict, list[str]]:
    try:
        if not code.startswith(INVITATION_PREFIX) or len(code) > INVITATION_LIMIT:
            raise ValueError
        data = decode_json(parse_b64(code[len(INVITATION_PREFIX):], INVITATION_LIMIT))
        members = data['members']
        if (data.keys() != {'realm', 'members'} or not isinstance(members, list) or not 2 <= len(members) <= 64
                or any(not isinstance(node, str) or NODE_ID.fullmatch(node) is None for node in members)
                or len(set(members)) != len(members)):
            raise ValueError
        return grove.invitation(data['realm']), members
    except (KeyError, TypeError, ValueError, PeerError) as error:
        raise PeerError('INVALID_REQUEST', 'Invalid Grove quorum invitation') from error


def validate_ballot(document: dict, anchor: dict, digest: str) -> tuple[str, str, str]:
    try:
        raw = json.loads(parse_b64(document['record'], 2048))
        public = parse_b64(raw['public_key'], 32)
        voter = node_id(Ed25519PublicKey.from_public_bytes(public))
        ballot = grove.verified(KIND, document, public, 2048)
        anchor = grove_voters.verification(anchor, [document])
        ballot = grove_voters.unstamp(ballot)
        subject, origin = ballot['node_id'], grove.origin(ballot['origin'])
        if (voter not in anchor['voters'] or NODE_ID.fullmatch(subject) is None or subject in anchor['voters'] or len(origin) > MAX_ORIGIN_LENGTH
                or ballot != {'anchor': digest, 'node_id': subject, 'origin': origin, 'public_key': raw['public_key']}):
            raise ValueError
    except (ValueError, TypeError, KeyError, PeerError) as error:
        raise PeerError('DENIED', 'Invalid Grove membership approval') from error
    return voter, subject, origin


def validate_certificate(certificate: list, anchor: dict, digest: str) -> tuple[str, str]:
    anchor = grove_voters.verification(anchor, certificate, certificate=certificate)
    if not isinstance(certificate, list) or not len(anchor['voters']) // 2 < len(certificate) <= len(anchor['voters']):
        raise PeerError('DENIED', 'Grove admission requires approval from a majority of identity members')
    ballots = [validate_ballot(ballot, anchor, digest) for ballot in certificate]
    subjects = {(subject, origin) for _, subject, origin in ballots}
    if len(subjects) != 1 or len({voter for voter, _, _ in ballots}) != len(ballots):
        raise PeerError('DENIED', 'Grove membership approvals refer to different nodes or origins')
    return subjects.pop()


def eligible(db, subject: str, origin: str) -> None:
    if db.execute('SELECT 1 FROM grove_realm WHERE issuer_node=?', (subject,)).fetchone():
        raise PeerError('CONFLICT', 'The Grove identity issuer is already registered')
    _check_member(db, subject, origin)


def _check_member(db, subject: str, origin: str) -> None:
    if db.execute('SELECT 1 FROM grove_member_departure WHERE node_id=?', (subject,)).fetchone():
        raise PeerError('DENIED', 'This node has left the Grove')
    current = db.execute('SELECT origin,enabled FROM grove_member WHERE node_id=?', (subject,)).fetchone()
    if current is not None and (not current['enabled'] or current['origin'] != origin):
        raise PeerError('CONFLICT', 'This node already has a different Grove membership')
    if db.execute('SELECT 1 FROM grove_member WHERE origin=? AND node_id!=? AND enabled=1', (origin, subject)).fetchone():
        raise PeerError('CONFLICT', 'This HTTPS origin already belongs to another Grove member')
    if (db.execute('SELECT count(*) FROM grove_member_admission').fetchone()[0] >= MAX_ADMISSIONS
            and not db.execute('SELECT 1 FROM grove_member_admission WHERE node_id=?', (subject,)).fetchone()):
        raise PeerError('LIMIT', 'Grove admission limit reached')


def admit(db, certificate: list, anchor: dict, envelope: dict, source: str) -> bool:
    subject, origin = validate_certificate(certificate, anchor, grove_continuity.anchor_digest(envelope))
    _check_member(db, subject, origin)
    if not db.execute('SELECT 1 FROM grove_member_admission WHERE node_id=?', (subject,)).fetchone():
        grove_voters.require_unlocked(db)
    inserted = db.execute('INSERT OR IGNORE INTO grove_member_admission VALUES (?,?,?)',
                          (subject, origin, json.dumps(certificate))).rowcount
    if inserted:
        db.execute('INSERT OR IGNORE INTO grove_member VALUES (?,?,1)', (subject, origin))
        audit(db, 'grove', source, 'grove.member_admitted', subject)
    return bool(inserted)


def approve(state: State, actor: auth.Actor, subject: str, origin: str, *, before_mesh: bool = False) -> tuple[dict, list[str]]:
    origin = grove.origin(origin)
    if len(origin) > MAX_ORIGIN_LENGTH:
        raise PeerError('INVALID_REQUEST', 'The HTTPS origin is too long')
    with state.connect(write=True) as db:
        now = int(time.time())
        session = auth.active_session(db, actor.token_hash, now)
        if session is None or session['id'] != actor.account_id or not session['grove_replica'] or session['role'] != 'node_admin':
            raise PeerError('DENIED', 'Sign in directly as a Grove administrator to approve a member')
        if session['mfa_at'] is None or not now - auth.RECENT_FACTOR_SECONDS < session['mfa_at'] <= now:
            raise auth.SessionReauthenticationRequired
        current = grove_continuity.read_anchor(db)
        if current is None or state.identity()[0] not in current[1]['voters']:
            raise PeerError('DENIED', 'Only a Grove identity voter can approve new members')
        envelope, anchor = current
        if not before_mesh:
            pair = configured(db, subject)
            if pair is None or pair.legacy:
                raise PeerError('CONFLICT', 'Set up the target Mesh identity before approving the node')
            require_pair(db, pair)
        ballot = record_ballot(db, state, subject, origin, envelope, anchor, actor.operation_actor, actor.address)
        return ballot, anchor['voters']


def record_ballot(db, state, subject, origin, envelope, anchor, actor, source):
    grove_voters.require_unlocked(db)
    from . import grove_availability
    grove_availability.require_current(db)
    eligible(db, subject, origin)
    prior = db.execute('SELECT node_id,origin,ballot FROM grove_member_admission_vote WHERE node_id=? OR origin=?',
                       (subject, origin)).fetchall()
    digest = grove_continuity.anchor_digest(envelope)
    if prior:
        if len(prior) != 1 or (prior[0]['node_id'], prior[0]['origin']) != (subject, origin):
            raise PeerError('CONFLICT', 'This member has already approved a different node or HTTPS origin')
        ballot = json.loads(prior[0]['ballot'])
        validate_ballot(ballot, anchor, digest)
        raw = json.loads(parse_b64(ballot['record'], 2048))
        if raw.get('configuration') == grove_voters.stamp(anchor).get('configuration'):
            return ballot
        db.execute('DELETE FROM grove_member_admission_vote WHERE node_id=?', (subject,))
    key = state.signing_key()
    ballot = grove.signed(KIND, {'anchor': digest, 'node_id': subject, 'origin': origin,
                                'public_key': wire_b64(key.public_key().public_bytes_raw()), **grove_voters.stamp(anchor)}, key)
    validate_ballot(ballot, anchor, digest)
    db.execute('INSERT INTO grove_member_admission_vote VALUES (?,?,?)', (subject, origin, json.dumps(ballot)))
    audit(db, actor, source, 'grove.member_admission_approved', subject)
    return ballot


def baseline_origin(db, subject):
    realm = db.execute('SELECT public_key,manifest FROM grove_realm').fetchone()
    if realm is None or not realm['manifest']:
        return None
    directory = grove.verified('directory', json.loads(realm['manifest']), realm['public_key'])
    return next((member['origin'] for member in directory['members']
                 if member['enabled'] and member['node_id'] == subject), None)


def existing_member_ballot(state, subject):
    with state.connect(write=True) as db:
        current = grove_continuity.read_anchor(db)
        origin = baseline_origin(db, subject)
        if (current is None or origin is None or state.identity()[0] not in current[1]['voters']
                or grove_login.usable_replica(db, int(time.time())) is None or quarantine.contains(db, subject)):
            raise PeerError('DENIED', 'Only a current Grove voter can approve an existing member')
        pair = configured(db, subject)
        if pair is None or pair.legacy:
            raise PeerError('CONFLICT', 'A certified Mesh pairing is required')
        require_pair(db, pair)
        return record_ballot(db, state, subject, origin, *current, 'admin', 'local')


def apply_existing_member(state, certificate):
    with state.connect(write=True) as db:
        current = grove_continuity.read_anchor(db)
        if current is None or state.identity()[0] not in current[1]['voters']:
            raise PeerError('DENIED', 'Only a Grove voter can record this approval')
        envelope, anchor = current
        node, origin = validate_certificate(certificate, anchor, grove_continuity.anchor_digest(envelope))
        if baseline_origin(db, node) != origin:
            raise PeerError('DENIED', 'The approvals do not match an existing Grove member')
        admit(db, certificate, anchor, envelope, 'local')
        return node


def read_ballot(db, requester: str, subject: str) -> dict:
    current = grove_continuity.read_anchor(db)
    if current is None or requester not in current[1]['voters']:
        raise PeerError('DENIED', 'A Grove voter is required to read membership approvals')
    row = db.execute('SELECT ballot FROM grove_member_admission_vote WHERE node_id=?', (subject,)).fetchone()
    if row is None:
        raise PeerError('NOT_FOUND', 'Member approval has not been recorded')
    return json.loads(row['ballot'])


def collect(state: State, proposal: dict, replies: list[dict]) -> tuple[dict, list[dict]]:
    with state.connect(write=True) as db:
        current = grove_continuity.read_anchor(db)
        if current is None:
            raise PeerError('CONFLICT', 'The Grove identity authorization changed')
        envelope, anchor = current
        digest = grove_continuity.anchor_digest(envelope)
        own, subject, origin = validate_ballot(proposal, anchor, digest)
        approvals = {own: proposal}
        for reply in replies:
            try:
                voter, node, address = validate_ballot(reply, anchor, digest)
            except PeerError:
                continue
            if (node, address) == (subject, origin):
                approvals[voter] = reply
        required = len(anchor['voters']) // 2 + 1
        result = {'approved': len(approvals), 'required': required, 'applied': len(approvals) >= required}
        if not result['applied']:
            return result, []
        certificate = [approvals[voter] for voter in sorted(approvals)[:required]]
        admit(db, certificate, anchor, envelope, 'local')
        return result, certificate


def synchronize(state: State, certificate: list, source: str, authorize) -> bool:
    with state.connect(write=True) as db:
        authorize(db)
        current = grove_continuity.read_anchor(db)
        if current is None or source not in current[1]['voters']:
            raise PeerError('DENIED', 'A Grove voter is required to distribute admission certificates')
        envelope, anchor = current
        return admit(db, certificate, anchor, envelope, source)


def join_bundle(state: State, db, subject: str) -> dict:
    current = grove_continuity.read_anchor(db)
    row = db.execute('SELECT certificate FROM grove_member_admission WHERE node_id=?', (subject,)).fetchone()
    realm = db.execute('SELECT * FROM grove_realm').fetchone()
    if (current is None or row is None or realm is None or not grove_continuity.admitted(db, current[1], subject)
            or state.identity()[0] not in current[1]['voters']):
        raise PeerError('NOT_FOUND', 'This node has no Grove membership approval')
    envelope, anchor = current
    certificate = json.loads(row['certificate'])
    if validate_certificate(certificate, anchor, grove_continuity.anchor_digest(envelope))[0] != subject:
        raise PeerError('DENIED', 'Grove admission does not match the requesting node')
    return {'realm': grove.realm_data(realm), 'certificate': certificate,
            'snapshot': grove_continuity.snapshot(state, db, realm['id'], subject)}


def read_certificate(db, requester: str, subject: str) -> dict:
    current = grove_continuity.read_anchor(db)
    if current is None or not grove_continuity.admitted(db, current[1], requester):
        raise PeerError('DENIED', 'A Grove member is required to read admission certificates')
    row = db.execute('SELECT certificate FROM grove_member_admission WHERE node_id=?', (subject,)).fetchone()
    if row is None:
        raise PeerError('NOT_FOUND', 'Grove admission certificate is unavailable')
    return {'certificate': json.loads(row['certificate'])}


def require_unjoined_admin(db, actor: auth.Actor) -> None:
    grove.require_recent(db, actor)
    if db.execute('SELECT 1 FROM grove_realm').fetchone():
        raise PeerError('CONFLICT', 'This panel already belongs to a Grove')


def join(state: State, actor: auth.Actor | None, origin: str, bundle: dict, source: str, authorize,
         *, seed_certificate=None) -> dict:
    if not isinstance(bundle, dict) or bundle.keys() != {'realm', 'certificate', 'snapshot'}:
        raise PeerError('PROTOCOL', 'Invalid Grove admission response')
    realm_data = grove.invitation(bundle['realm'])
    snapshot = bundle['snapshot']
    if not isinstance(snapshot, dict) or snapshot.keys() != {'authorization', 'manifest', 'records'}:
        raise PeerError('PROTOCOL', 'Invalid Grove admission snapshot')
    document, governance = grove_continuity.split_document(snapshot['authorization'])
    recovered = isinstance(document, dict) and document.keys() == {'authorization', 'votes'}
    envelope = document['authorization'] if recovered else document
    local = state.identity()[0]
    with state.lock('maintenance.lock'), state.connect(write=True) as db:
        authorize(db)
        if actor is not None:
            require_unjoined_admin(db, actor)
        elif seed_certificate is None or db.execute('SELECT 1 FROM grove_realm').fetchone():
            raise PeerError('DENIED', 'SSH enrollment requires an unjoined node and its admission certificate')
        realm = realm_data | {'public_key': parse_b64(realm_data['public_key'], 32)}
        directory = grove.directory_data(snapshot['manifest'], realm_data, allow_expired=True)
        anchor = grove_continuity.snapshot_authorization(realm, directory, envelope, 'login-recovery' if recovered else 'login-continuity')
        base = anchor
        anchor = grove_voters.history_anchor(anchor, governance)
        if recovered:
            grove_continuity.verify_recovery_votes(envelope, anchor, document['votes'])
            if int(time.time()) < directory['issued_at'] + grove_login.STANDBY_TTL:
                raise PeerError('CONFLICT', 'The original Grove authorization has not expired')
        if source not in anchor['voters'] or validate_certificate(bundle['certificate'], anchor,
            grove_continuity.anchor_digest(envelope)) != (local, origin):
            raise PeerError('DENIED', 'Grove admission does not match this panel or its HTTPS origin')
        if actor is None and validate_certificate(seed_certificate, anchor, grove_continuity.anchor_digest(envelope)) != (local, origin):
            raise PeerError('DENIED', 'SSH enrollment certificate does not match this panel')
        db.execute('''INSERT INTO grove_realm(singleton,id,name,public_key,issuer_node,issuer_origin,is_issuer,sequence,manifest)
                      VALUES (1,?,?,?,?,?,0,?,?)''', (realm['id'], realm['name'], realm['public_key'], realm['issuer_node'],
                                                    realm['issuer_origin'], anchor['sequence'], json.dumps(snapshot['manifest'])))
        db.executemany('INSERT INTO grove_member VALUES (?,?,?)',
                       ((member['node_id'], member['origin'], member['enabled']) for member in directory['members']))
        admit(db, bundle['certificate'], anchor, envelope, source)
        grove_login.import_snapshot(state, db, directory, snapshot['records'], anchor['verifiers_sha256'])
        db.execute('INSERT INTO grove_login_continuity(singleton,sequence,anchor,recovery_proof) VALUES (1,?,?,?)',
                   (anchor['sequence'], json.dumps(envelope), json.dumps(document['votes']) if recovered else None))
        grove_voters.install_history(db, base, governance, source)
    return realm_data
