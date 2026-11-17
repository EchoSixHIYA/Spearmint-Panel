"""Apply Grove role changes approved by a majority of the identity members."""
import json
import re
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import auth, grove, grove_revocation
from .peer.credentials import node_id
from .peer.protocol import PeerError, parse_b64, wire_b64
from .state import State, audit


BALLOT_METHOD = 'grove.login.roles.ballot'
APPLY_METHOD = 'grove.login.roles.apply'
GET_METHOD = 'grove.login.roles.get'
KIND = 'login-role'
ADMIN = 'node_admin'
OPERATOR = 'remote_operator'
USER_ID = re.compile(r'usr1-[a-f0-9]{32}')


def recovery_admin(users: list[dict]) -> str | None:
    admins = sorted(user['id'] for user in users if user['enabled'] and user['role'] == ADMIN)
    return admins[0] if admins else None


def subject_profile(users: list[dict], subject: str) -> dict:
    profile = next((user for user in users if user['enabled'] and user['id'] == subject), None)
    owner = recovery_admin(users)
    if owner is None or profile is None or subject == owner:
        raise PeerError('DENIED', 'The Grove recovery administrator keeps its original role')
    return profile


def expected_role(profile: dict, generation: int) -> str:
    if generation % 2 == 0:
        return profile['role']
    return OPERATOR if profile['role'] == ADMIN else ADMIN


def approve(state: State, actor: auth.Actor, subject: str, role: str) -> tuple[dict, list[str]]:
    with state.connect(write=True) as db:
        now = int(time.time())
        session = auth.active_session(db, actor.token_hash, now)
        if (session is None or session['id'] != actor.account_id or not session['grove_replica'] or session['role'] != ADMIN):
            raise PeerError('DENIED', 'Sign in directly with a Grove administrator account')
        if session['mfa_at'] is None or not now - auth.RECENT_FACTOR_SECONDS < session['mfa_at'] <= now:
            raise auth.SessionReauthenticationRequired
        digest, anchor, users = grove_revocation.current_context(db)
        if state.identity()[0] not in anchor['voters']:
            raise PeerError('DENIED', 'Use a Grove identity voter to approve role changes')
        profile = subject_profile(users, subject)
        if db.execute('SELECT 1 FROM grove_login_revocation WHERE user_id=?', (subject,)).fetchone():
            raise PeerError('DENIED', 'This Grove account is suspended')
        current = db.execute('SELECT generation FROM grove_login_role WHERE user_id=?', (subject,)).fetchone()
        generation = (current['generation'] if current else 0) + 1
        if role != expected_role(profile, generation) or role == ADMIN and not profile['require_mfa']:
            raise PeerError('CONFLICT', 'Choose a different role. Grove administrators require MFA')
        key = state.signing_key()
        payload = {'anchor': digest, 'user_id': subject, 'generation': generation, 'role': role,
                   'public_key': wire_b64(key.public_key().public_bytes_raw())}
        vote = grove.signed(KIND, payload, key)
        db.execute('''INSERT INTO grove_login_role_vote VALUES (?,?,?) ON CONFLICT(user_id) DO UPDATE SET
                      generation=excluded.generation,ballot=excluded.ballot''', (subject, generation, json.dumps(vote)))
        audit(db, actor.operation_actor, actor.address, 'grove.role_approved', subject, reason=role)
        return vote, anchor['voters']


def read_vote(db, requester: str, subject: str) -> dict:
    grove_revocation.current_context(db, requester)
    vote = db.execute('''SELECT v.ballot FROM grove_login_role_vote v LEFT JOIN grove_login_role r ON r.user_id=v.user_id
                         WHERE v.user_id=? AND (r.generation IS NULL OR v.generation>=r.generation)''', (subject,)).fetchone()
    if vote is None:
        raise PeerError('NOT_FOUND', 'Grove role approval is not recorded on this member')
    return json.loads(vote['ballot'])


def read_certificate(db, requester: str, subject: str) -> dict:
    from . import grove_continuity
    current = grove_continuity.read_anchor(db)
    if current is None or not grove_continuity.admitted(db, current[1], requester):
        raise PeerError('DENIED', 'A Grove member is required to read role changes')
    row = db.execute('SELECT certificate FROM grove_login_role WHERE user_id=?', (subject,)).fetchone()
    if row is None:
        raise PeerError('NOT_FOUND', 'Grove role certificate is not stored on this member')
    return {'certificate': json.loads(row['certificate'])}


def validate(vote: dict, digest: str, anchor: dict, users: list[dict]) -> tuple[str, str, int, str]:
    try:
        raw = json.loads(parse_b64(vote['record'], 1024))
        public = parse_b64(raw['public_key'], 32)
        voter = node_id(Ed25519PublicKey.from_public_bytes(public))
        data = grove.verified(KIND, vote, public, 1024)
        subject, generation, role = data['user_id'], data['generation'], data['role']
        profile = subject_profile(users, subject)
        if (voter not in anchor['voters'] or data.keys() != {'anchor', 'user_id', 'generation', 'role', 'public_key'}
                or data['anchor'] != digest or type(generation) is not int or not 0 < generation < 2**63
                or role != expected_role(profile, generation) or role == ADMIN and not profile['require_mfa']):
            raise ValueError
    except (KeyError, ValueError, TypeError, PeerError) as error:
        raise PeerError('DENIED', 'Invalid Grove role approval') from error
    return voter, subject, generation, role


def install(db, certificate: list[dict], digest: str, anchor: dict, users: list[dict], source: str) -> bool:
    if not isinstance(certificate, list) or not len(anchor['voters']) // 2 < len(certificate) <= len(anchor['voters']):
        raise PeerError('DENIED', 'A majority of Grove members must approve this role')
    ballots = [validate(vote, digest, anchor, users) for vote in certificate]
    approvals = {voter for voter, _, _, _ in ballots}
    proposals = {ballot[1:] for ballot in ballots}
    if len(approvals) != len(ballots) or len(proposals) != 1:
        raise PeerError('DENIED', 'Grove role approvals refer to different changes')
    subject, generation, role = proposals.pop()
    changed = db.execute('''INSERT INTO grove_login_role VALUES (?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET
                            generation=excluded.generation,role=excluded.role,certificate=excluded.certificate
                            WHERE excluded.generation>grove_login_role.generation''',
                         (subject, generation, role, json.dumps(certificate))).rowcount
    if changed:
        db.execute('DELETE FROM session WHERE account_id IN (SELECT account_id FROM grove_account WHERE user_id=?)', (subject,))
        audit(db, 'grove', source, 'grove.role_changed', subject, reason=role)
    return bool(changed)


def apply(state: State, certificates: list, source: str, authorize=None) -> int:
    if not isinstance(certificates, list) or len(certificates) > 64:
        raise PeerError('INVALID_REQUEST', 'Invalid Grove role certificate list')
    with state.connect(write=True) as db:
        if authorize is not None:
            authorize(db)
        digest, anchor, users = grove_revocation.current_context(db, source)
        return sum(install(db, certificate, digest, anchor, users, source) for certificate in certificates)


def collect(state: State, proposal: dict, replies: list[dict]) -> tuple[dict, list[dict]]:
    with state.connect(write=True) as db:
        digest, anchor, users = grove_revocation.current_context(db)
        own, subject, generation, role = validate(proposal, digest, anchor, users)
        current = db.execute('SELECT generation FROM grove_login_role WHERE user_id=?', (subject,)).fetchone()
        if current and current['generation'] > generation:
            raise PeerError('CONFLICT', 'A newer Grove role change is already active')
        ballots = {own: proposal}
        for reply in replies:
            try:
                voter, *change = validate(reply, digest, anchor, users)
            except PeerError:
                continue
            if tuple(change) == (subject, generation, role):
                ballots[voter] = reply
        required = len(anchor['voters']) // 2 + 1
        result = {'approved': len(ballots), 'required': required}
        if len(ballots) < required:
            return result | {'applied': False}, []
        certificate = [ballots[node] for node in sorted(ballots)[:required]]
        install(db, certificate, digest, anchor, users, 'local')
        return result | {'applied': True}, certificate
