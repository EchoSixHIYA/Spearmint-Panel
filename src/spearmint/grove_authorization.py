"""Grove administrative delegations signed by a user-operated key.

Each user's public key must be approved at the local consoles of a majority of
the current voters. Neither a Grove password nor a node key can enroll a
delegate over RPC. A signed delegation explicitly lets its source panel act
within the selected scope until it expires.
"""
from contextlib import suppress
from hashlib import sha256
import json
from secrets import token_hex
from threading import Lock
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import auth, grove, grove_accounts, grove_continuity, grove_voters
from .peer.credentials import NODE_ID
from .peer.protocol import PeerError, parse_b64, wire_b64
from .platforms import secure_private
from .state import audit

KINDS = {'services', 'terminal', 'deployment', 'seed', 'accounts', 'voters', 'updates', 'identity', 'join', 'self', 'signin'}
KEY_VOTE = 'administrator-key'
GRANT = 'administrator-delegation'
LIFETIME = 300
SEED_RELAY = 'grove-seed-session-relay'
SEED_DURATION = 15 * 60
SERVICE_CONTROL = 'service-control'
SERVICE_SIGNIN = [SERVICE_CONTROL, 'signin']
ADMIN_SIGNIN = sorted((KINDS - {'join'}) | {SERVICE_CONTROL})
ACCOUNT_SIGNIN = ['self', 'signin']
SERVICE_WORKSPACE = {'detail', 'group-run'}
LIMIT = 32 * 1024
ERROR = 'GROVE_USER_AUTHORIZATION_REQUIRED'
MESSAGE = '请使用 Grove 登录设备重新登录。'
_grants = {}
_lock = Lock()


def http_scope(path):
    parts = path.removeprefix('/api/v1/').split('/')
    if parts[:2] == ['grove', 'sync-directory'] or parts[:1] == ['peers'] and parts[2:] == ['workspace', 'host']:
        return None
    if parts[0] == 'grove':
        section = parts[1] if len(parts) > 1 else None
        return {'updates': 'updates', 'seed-wizard': 'seed', 'seed-targets': 'seed', 'voters': 'voters',
                'accounts': 'accounts'}.get(section, 'identity')
    if parts[0] == 'services' and len(parts) == 3 and parts[2] == 'actions':
        return SERVICE_CONTROL
    if parts[0] == 'peers' and len(parts) > 2:
        if (parts[2] == 'services' and len(parts) == 5 and parts[4] == 'actions'
                or parts[2] == 'workspace' and len(parts) == 4 and parts[3] in SERVICE_WORKSPACE):
            return SERVICE_CONTROL
        return {'terminal': 'terminal', 'service-deployment': 'deployment',
                'service-deployment-upload': 'deployment'}.get(parts[2], 'services')
    return 'services'


def context(db):
    current = grove_continuity.read_anchor(db)
    if current is None:
        raise PeerError(ERROR, '此节点尚未同步 Grove 投票授权。')
    envelope, anchor = current
    return {'anchor': grove_continuity.anchor_digest(envelope),
            'configuration': grove_voters.current_id(anchor)}, anchor


def key_vote(state, username: str, public_key: str):
    """Local console ceremony, never invoked by panel HTTP or Mesh handlers."""
    from .peer.grove_service_admin import admin_revision

    if len(parse_b64(public_key, 32)) != 32:
        raise ValueError('Invalid Ed25519 public key')
    with state.connect(write=True) as db:
        location, anchor = context(db)
        if state.identity()[0] not in anchor['voters']:
            raise PeerError('DENIED', '此节点没有 Grove 投票资格。')
        account = grove_accounts.record_for(db, username)
        user = account['profile'] if account else grove_accounts.legacy_profile(db, username)
        if user is None:
            raise PeerError('NOT_FOUND', '找不到已同步的 Grove 账号。')
        identity = admin_revision(db, anchor['realm_id'], user['id'], require_admin=False)
        audit(db, identity[1], 'local-console', 'grove.user_key_approved', sha256(parse_b64(public_key, 32)).hexdigest())
    key = state.signing_key()
    return grove.signed(KEY_VOTE, {**location, 'identity': identity, 'key': public_key,
                                  'public_key': wire_b64(key.public_key().public_bytes_raw())}, key)


def challenge(db, owner, node, identity, scopes, *, executor=None, joining=None):
    location, _ = context(db)
    now = int(time.time())
    if scopes in (ADMIN_SIGNIN, ACCOUNT_SIGNIN):
        login_session = {'session_until': now + auth.SESSION_SECONDS}
    else:
        login_session = {'service_until': now + auth.SESSION_SECONDS} if scopes == SERVICE_SIGNIN else {}
    return {**location, 'identity': identity, 'source': node, **login_session,
            'session': session_binding(owner), 'scopes': scopes, 'seed_executor': executor, 'joining': joining, 'issued_at': now,
            'expires_at': now + LIFETIME, 'nonce': token_hex(16)}


def valid_join(value):
    try:
        return (isinstance(value, dict) and set(value) == {'node_id', 'origin'}
                and isinstance(value['node_id'], str) and NODE_ID.fullmatch(value['node_id']) is not None
                and grove.origin(value['origin']) == value['origin'])
    except (ValueError, TypeError, PeerError):
        return False


def session_binding(actor) -> str:
    return sha256(b'spearmint-admin-session-v1\0' + actor.token_hash).hexdigest()


def unsigned(document):
    return json.loads(parse_b64(document['record'], 4096))


def revision(payload):
    from .peer.grove_service_admin import parse_identity
    try:
        return parse_identity(unsigned(payload['grant'])['identity'])
    except (ValueError, TypeError, KeyError) as error:
        raise PeerError(ERROR, MESSAGE) from error


def for_seed_executor(state, proof, executor, job):
    grant = unsigned(proof['grant'])
    if 'session_until' not in grant:
        return proof
    now = int(time.time())
    binding = {'source': grant['source'], 'executor': executor, 'job': job,
               'proof': sha256(grove.encoded(proof)).hexdigest(), 'issued_at': now,
               'expires_at': min(grant['session_until'], now + SEED_DURATION)}
    return {**proof, 'seed_relay': grove.signed(SEED_RELAY, binding, state.signing_key())}


def seed_executor(proof, executor, job) -> bool:
    if relay := proof.get('seed_relay'):
        binding = unsigned(relay)
        return (binding['executor'], binding['job']) == (executor, job)
    return unsigned(proof['grant'])['seed_executor'] == executor


def verify_seed_relay(db, payload, grant, scope, now):
    from .peer.credentials import RANDOM_ID, certificate
    from .peer.grove_endpoints import trusted_members
    from .peer.pairing import configured
    from .peer.policy import credentials_current, require_pair
    from .peer.quarantine import contains

    if scope not in {'seed', 'voters'} or 'session_until' not in grant:
        raise ValueError
    local = db.execute('SELECT node_id,public_key FROM node WHERE singleton=1').fetchone()
    trust = trusted_members(db, local['node_id'], operational=True, transport=True)
    source = grant['source']
    if trust is None or source not in trust.origins:
        raise ValueError
    if source == local['node_id']:
        public_key = local['public_key']
    else:
        pair = configured(db, source)
        if pair is None or pair.legacy or not credentials_current(pair) or contains(db, source):
            raise ValueError
        require_pair(db, pair)
        public_key = certificate(pair.remote_pem).public_key().public_bytes_raw()
    binding = grove.verified(SEED_RELAY, payload['seed_relay'], public_key, 2048)
    issued, expires = binding['issued_at'], binding['expires_at']
    if (set(binding) != {'source', 'executor', 'job', 'proof', 'issued_at', 'expires_at'}
            or binding['source'] != source or binding['executor'] not in trust.origins
            or not RANDOM_ID.fullmatch(binding['job'])
            or type(issued) is not int or type(expires) is not int
            or not 0 < expires - issued <= SEED_DURATION
            or expires > grant['session_until'] or not issued - grove.CLOCK_SKEW <= now < expires
            or binding['proof'] != sha256(grove.encoded({k: payload[k] for k in ('grant', 'approvals')})).hexdigest()):
        raise ValueError
    return binding['executor']


def verify(db, payload, source, scope, *, owner=None, at=None, delegated=False):
    """Validate a device signature for the specified source and permission."""
    from .peer.grove_service_admin import admin_revision, parse_identity

    try:
        if not isinstance(payload, dict) or payload.keys() not in ({'grant', 'approvals'}, {'grant', 'approvals', 'seed_relay'}):
            raise ValueError
        location, anchor = context(db)
        grant = unsigned(payload['grant'])
        identity = parse_identity(grant['identity'])
        scopes = grant['scopes']
        now = int(time.time()) if at is None else at
        issued, expires = grant['issued_at'], grant['expires_at']
        fields = {*location, 'identity', 'source', 'session', 'scopes', 'seed_executor', 'joining', 'issued_at', 'expires_at', 'nonce'}
        if type(issued) is not int or type(expires) is not int or not 0 < expires - issued <= LIFETIME:
            raise ValueError
        effective_expiry = expires
        if 'session_until' in grant:
            fields.add('session_until')
            until = grant['session_until']
            if (scopes not in (ADMIN_SIGNIN, ACCOUNT_SIGNIN) or type(until) is not int
                    or until != issued + auth.SESSION_SECONDS
                    or grant['seed_executor'] is not None or grant['joining'] is not None):
                raise ValueError
            if scope != 'signin':
                effective_expiry = until
        elif 'service_until' in grant:
            fields.add('service_until')
            until = grant['service_until']
            if (scopes != SERVICE_SIGNIN or type(until) is not int or until != issued + auth.SESSION_SECONDS
                    or grant['seed_executor'] is not None or grant['joining'] is not None):
                raise ValueError
            if scope == SERVICE_CONTROL:
                effective_expiry = until
        elif not isinstance(scopes, list) or scopes != sorted(set(scopes)) or not scopes or not set(scopes) <= KINDS:
            raise ValueError
        accepted_scope = 'services' if scope == SERVICE_CONTROL and not timed_session(grant) else scope
        executor = verify_seed_relay(db, payload, grant, scope, now) if 'seed_relay' in payload else grant['seed_executor']
        if (set(grant) != fields
                or any(grant[key] != value for key, value in location.items())
                or ('join' in scopes) != (grant['joining'] is not None)
                or grant['joining'] is not None and not valid_join(grant['joining'])
                or accepted_scope not in scopes or not NODE_ID.fullmatch(grant['source'])
                or grant['seed_executor'] is not None and not NODE_ID.fullmatch(grant['seed_executor'])
                or source != grant['source'] and not (delegated and scope in {'seed', 'voters'} and source == executor)
                or not issued - grove.CLOCK_SKEW <= now < effective_expiry
                or owner is not None and grant['session'] != session_binding(owner)
                or not isinstance(grant['session'], str) or len(grant['session']) != 64
                or not isinstance(grant['nonce'], str) or len(grant['nonce']) != 32):
            raise ValueError
        if identity != admin_revision(db, anchor['realm_id'], identity[1], require_admin=any(item not in {'self', 'signin'} for item in scopes)):
            raise PeerError(ERROR, '账号权限已变化，请重新登录。')
        approvals = payload['approvals']
        if pinned_key := grove_accounts.device_key(db, identity[1]):
            grove.verified(GRANT, payload['grant'], parse_b64(pinned_key, 32), 4096)
            return identity
        if not isinstance(approvals, list) or not len(anchor['voters']) // 2 < len(approvals) <= len(anchor['voters']):
            raise ValueError
        seen = set()
        signing_key = None
        for approval in approvals:
            voter, record = grove_voters.verified_node(KEY_VOTE, approval)
            key = record['key']
            if (record != {**location, 'identity': identity, 'key': key, 'public_key': record['public_key']}
                    or voter not in anchor['voters'] or voter in seen
                    or signing_key is not None and key != signing_key):
                raise ValueError
            seen.add(voter)
            signing_key = key
        grove.verified(GRANT, payload['grant'], parse_b64(signing_key, 32), 4096)
        return identity
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        raise PeerError(ERROR, MESSAGE) from error


def issue(private_key: Ed25519PrivateKey, challenge: dict, approvals: list[dict]) -> dict:
    return {'grant': grove.signed(GRANT, challenge, private_key), 'approvals': approvals}


def enrollment(state, actor, payload, *, required_scope=None):
    from .peer.outbound import actor_account

    try:
        grant = unsigned(payload['grant'])
        if timed_session(grant):
            raise ValueError
        scope = required_scope if required_scope is not None else grant['scopes'][0]
    except (KeyError, ValueError, TypeError, IndexError) as error:
        raise PeerError(ERROR, MESSAGE) from error
    with state.connect(read_only=True) as db:
        db.execute('BEGIN')
        session = actor_account(db, actor)
        identity = verify(db, payload, state.identity()[0], scope, owner=actor)
        if identity[1] != session['grove_user']:
            raise PeerError(ERROR, MESSAGE)
    expires = grant['expires_at']
    with _lock:
        now = int(time.time())
        for key, (_, until) in tuple(_grants.items()):
            if until <= now:
                del _grants[key]
        _grants[(state.directory, actor.token_hash)] = (payload, expires)
    return {'expires_at': expires, 'scopes': grant['scopes']}


def self_proof(state, actor):
    with state.connect(read_only=True) as db:
        db.execute('BEGIN')
        session = auth.active_session(db, actor.token_hash, int(time.time()))
        proof, identity = session_grant(db, state, actor, state.identity()[0], 'self')
        if session is None or not session['grove_replica'] or identity[1] != session['grove_user']:
            raise PeerError(ERROR, MESSAGE)
    return proof


def has_service_session(proof) -> bool:
    return 'service_until' in unsigned(proof['grant'])


def timed_session(grant) -> bool:
    return 'service_until' in grant or 'session_until' in grant


def session_grant(db, state, actor, source, scope):
    try:
        proof = service_session(state, actor)
        identity = verify(db, proof, source, scope, owner=actor)
    except PeerError as error:
        if error.code != ERROR:
            raise
        proof = enrolled(state, actor)
        identity = verify(db, proof, source, scope, owner=actor)
    return proof, identity


def service_session_path(state, owner):
    return state.directory / 'grove-service-sessions' / (session_binding(owner) + '.json')


def remember_service_session(state, owner, proof, now):
    from .update_worker import write_record

    path = service_session_path(state, owner)
    path.parent.mkdir(mode=0o700, exist_ok=True)
    secure_private(path.parent, 0o700)
    write_record(path, proof)
    for expired in path.parent.glob('*.json'):
        with suppress(OSError):
            if expired != path and expired.stat().st_mtime <= now - auth.SESSION_SECONDS:
                expired.unlink(missing_ok=True)


def forget_service_session(state, owner):
    with suppress(OSError):
        service_session_path(state, owner).unlink(missing_ok=True)


def service_session(state, owner):
    from .update_worker import read_record

    try:
        data = read_record(service_session_path(state, owner))
        if data is not None:
            return data
    except (OSError, ValueError):
        pass
    raise PeerError(ERROR, MESSAGE)


def enrolled(state, actor):
    with _lock:
        data = _grants.get((state.directory, actor.token_hash))
    if data and data[1] > int(time.time()):
        return data[0]
    raise PeerError(ERROR, MESSAGE)
