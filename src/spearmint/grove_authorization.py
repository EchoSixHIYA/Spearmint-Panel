"""Grove administrative delegations signed by a user-operated key.

Each user's public key must be approved at the local consoles of a majority of
the current voters. Neither a Grove password nor a node key can enroll a
delegate over RPC. A signed delegation explicitly lets its source panel act
within the selected scope until it expires.
"""
from hashlib import sha256
import json
from secrets import token_hex
from threading import Lock
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import auth, grove, grove_accounts, grove_continuity, grove_voters
from .peer.credentials import NODE_ID
from .peer.protocol import PeerError, parse_b64, wire_b64
from .state import audit

KINDS = {'services', 'terminal', 'deployment', 'seed', 'accounts', 'voters', 'updates', 'identity', 'join', 'self', 'signin'}
KEY_VOTE = 'administrator-key'
GRANT = 'administrator-delegation'
LIFETIME = 300
LIMIT = 32 * 1024
ERROR = 'GROVE_USER_AUTHORIZATION_REQUIRED'
MESSAGE = '请先在「身份与安全」授权当前面板执行此项 Grove 管理操作。'
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
    if parts[0] == 'peers' and len(parts) > 2:
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
    return {**location, 'identity': identity, 'source': node,
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


def verify(db, payload, source, scope, *, owner=None, at=None, delegated=False):
    """Validate an independently signed, short-lived grant for a specific source."""
    from .peer.grove_service_admin import admin_revision, parse_identity

    try:
        if not isinstance(payload, dict) or payload.keys() != {'grant', 'approvals'}:
            raise ValueError
        location, anchor = context(db)
        grant = unsigned(payload['grant'])
        identity = parse_identity(grant['identity'])
        scopes = grant['scopes']
        now = int(time.time()) if at is None else at
        issued, expires = grant['issued_at'], grant['expires_at']
        if (set(grant) != {*location, 'identity', 'source', 'session', 'scopes', 'seed_executor', 'joining', 'issued_at', 'expires_at', 'nonce'}
                or any(grant[key] != value for key, value in location.items())
                or not isinstance(scopes, list) or scopes != sorted(set(scopes)) or not scopes or not set(scopes) <= KINDS
                or ('join' in scopes) != (grant['joining'] is not None)
                or grant['joining'] is not None and not valid_join(grant['joining'])
                or scope not in scopes or not NODE_ID.fullmatch(grant['source'])
                or grant['seed_executor'] is not None and not NODE_ID.fullmatch(grant['seed_executor'])
                or source != grant['source'] and not (delegated and scope in {'seed', 'voters'} and source == grant['seed_executor'])
                or type(issued) is not int or type(expires) is not int or not 0 < expires - issued <= LIFETIME
                or not issued - grove.CLOCK_SKEW <= now < expires
                or owner is not None and grant['session'] != session_binding(owner)
                or not isinstance(grant['session'], str) or len(grant['session']) != 64
                or not isinstance(grant['nonce'], str) or len(grant['nonce']) != 32):
            raise ValueError
        if identity != admin_revision(db, anchor['realm_id'], identity[1], require_admin=any(item not in {'self', 'signin'} for item in scopes)):
            raise PeerError(ERROR, '管理员权限已变化，请重新授权当前面板。')
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


def enrollment(state, actor, payload):
    from .peer.outbound import actor_account

    try:
        grant = unsigned(payload['grant'])
        scope = grant['scopes'][0]
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
    proof = enrolled(state, actor)
    with state.connect(read_only=True) as db:
        db.execute('BEGIN')
        session = auth.active_session(db, actor.token_hash, int(time.time()))
        identity = verify(db, proof, state.identity()[0], 'self', owner=actor)
        if session is None or not session['grove_replica'] or identity[1] != session['grove_user']:
            raise PeerError(ERROR, MESSAGE)
    return proof


def enrolled(state, actor):
    with _lock:
        data = _grants.get((state.directory, actor.token_hash))
    if data and data[1] > int(time.time()):
        return data[0]
    raise PeerError(ERROR, MESSAGE)
