"""Discover a Grove verifier and confirm a pending browser join."""
from ipaddress import ip_address
import re
import time
from urllib.parse import urlsplit

from . import auth, grove
from .config import Config
from .peer import quarantine
from .peer.pairing import Pair
from .peer.policy import require_pair
from .peer.protocol import PeerError, decode_json, parse_b64, wire_b64
from .state import State, audit


METHOD = 'grove.members.web_join'
INVITATION_METHOD = 'grove.members.web_invitation'
INVITATION_PREFIX = 'grove3.'
INVITATION_TTL = 86400
INVITATION_LIMIT = 8192


def browser_origin(value: str) -> bool:
    host = urlsplit(grove.origin(value)).hostname.rstrip('.')
    try:
        address = ip_address(host)
    except ValueError:
        return host != 'localhost' and not host.endswith('.localhost')
    address = getattr(address, 'ipv4_mapped', None) or address
    return not (address.is_loopback or address.is_unspecified or address.is_multicast)


def require_verification_peer(db, config: Config, pair: Pair) -> None:
    if pair.legacy or pair.node_id not in config.grove_login_replicas:
        raise PeerError('DENIED', 'This member is not enrolled for Grove login verification')
    require_pair(db, pair)
    if quarantine.contains(db, pair.node_id):
        raise PeerError('DENIED', 'This member is locally quarantined')


def invitation(state: State, config: Config, realm_id: str, pair: Pair | None = None) -> dict:
    now = int(time.time())
    with state.connect() as db:
        row = db.execute('SELECT * FROM grove_realm WHERE id=?', (realm_id,)).fetchone()
        if not row or grove.issuer_replaced(db):
            raise PeerError('OFFLINE', 'Grove browser invitations are unavailable')
        if pair is not None:
            require_verification_peer(db, config, pair)
            if not db.execute('SELECT 1 FROM grove_member WHERE node_id=? AND enabled=1', (pair.node_id,)).fetchone():
                raise PeerError('DENIED', 'This member is not active')
        key = grove.issuer_key(state, row)
        eligible = config.grove_login_replicas | {row['issuer_node']}
        origins = list(dict.fromkeys(
            member['origin'] for member in db.execute('SELECT * FROM grove_member WHERE enabled=1 ORDER BY node_id')
            if member['node_id'] in eligible and len(member['origin']) <= 384 and browser_origin(member['origin'])
        ))[:8]
        if not origins:
            raise PeerError('OFFLINE', 'This Grove has no browser-accessible verification origin')
        return grove.signed('browser-invitation', {'realm': grove.realm_data(row), 'origins': origins,
                            'issued_at': now, 'expires_at': now + INVITATION_TTL}, key)


def read_invitation(code: str, local_origin: str) -> dict:
    try:
        if not code.startswith(INVITATION_PREFIX) or len(code) > INVITATION_LIMIT:
            raise ValueError
        envelope = decode_json(parse_b64(code[len(INVITATION_PREFIX):], INVITATION_LIMIT))
        unsigned = decode_json(parse_b64(envelope['record'], 4608))
        realm = grove.invitation(unsigned['realm'])
        data = grove.verified('browser-invitation', envelope, parse_b64(realm['public_key'], 32), 4608)
        origins = data['origins']
        if (data.keys() != {'realm', 'origins', 'issued_at', 'expires_at'}
                or type(data['issued_at']) is not int or type(data['expires_at']) is not int
                or not isinstance(origins, list) or not 0 < len(origins) <= 8
                or any(not isinstance(item, str) or len(item) > 512 or not browser_origin(item) for item in origins)
                or len(set(origins)) != len(origins)):
            raise ValueError
    except (ValueError, TypeError, KeyError, PeerError) as error:
        raise PeerError('INVALID_REQUEST', 'Invalid Grove browser invitation') from error
    if not grove.valid_time_window(data['issued_at'], data['expires_at'], int(time.time()), INVITATION_TTL):
        raise PeerError('GROVE_INVITATION_EXPIRED', 'The Grove invitation expired')
    return {'realm': realm, 'origins': [item for item in origins if item != local_origin]}


def invitation_code(envelope: dict, local_origin: str) -> str:
    code = INVITATION_PREFIX + wire_b64(grove.encoded(envelope))
    read_invitation(code, local_origin)
    return code


def invitation_reply(state: State, config: Config, pair: Pair, params: dict) -> dict:
    if (params.keys() != {'realm_id'} or not isinstance(params['realm_id'], str)
            or re.fullmatch(r'grv1-[a-f0-9]{32}', params['realm_id']) is None):
        raise PeerError('INVALID_REQUEST', 'Expected the current Grove ID')
    return invitation(state, config, params['realm_id'], pair)


def verification(state: State, config: Config, raw: str, actor: auth.Actor) -> tuple[dict, dict, dict]:
    data = grove.request_data(raw)
    if data.get('verification_origin') != config.origin:
        raise PeerError('DENIED', 'Open the Grove member selected for this request')
    now = int(time.time())
    with state.connect() as db:
        realm = db.execute('SELECT * FROM grove_realm').fetchone()
        if realm is None or realm['id'] != data['realm_id']:
            raise PeerError('DENIED', 'The request belongs to another Grove')
        member = db.execute('SELECT m.origin,m.enabled FROM grove_member m JOIN node n ON n.node_id=m.node_id').fetchone()
        if (realm['is_issuer'] or realm['frozen'] or realm['issuer_paused'] or grove.issuer_replaced(db)
                or not member or not member['enabled'] or member['origin'] != config.origin):
            raise PeerError('OFFLINE', 'This member cannot verify a browser join')
        current = auth.active_session(db, actor.token_hash, now)
        if not current or current['id'] != actor.account_id or not current['grove_replica']:
            raise auth.SessionReauthenticationRequired
        if current['role'] != 'node_admin':
            raise PeerError('DENIED', 'A Grove administrator must confirm the join')
        stamp = db.execute('''SELECT s.created_at,ga.identity_epoch FROM session s
                              JOIN grove_account ga ON ga.account_id=s.account_id
                              WHERE s.token_hash=?''', (actor.token_hash,)).fetchone()
        mfa_at = current['mfa_at']
        timestamp = mfa_at if mfa_at is not None else stamp['created_at']
        if not now - auth.RECENT_FACTOR_SECONDS < timestamp <= now:
            raise auth.SessionReauthenticationRequired
        proof_request = {'request': raw, 'user_id': current['grove_user'], 'epoch': stamp['identity_epoch'],
                         'authenticated_at': stamp['created_at'], 'mfa_at': mfa_at}
        return grove.realm_data(realm), data, proof_request


def inspect(state: State, config: Config, raw: str, actor: auth.Actor) -> dict:
    realm, data, _ = verification(state, config, raw, actor)
    return {'kind': 'join', 'node_id': data['node_id'], 'origin': data['origin'], 'grove': realm['name'],
            'username': actor.display_name or actor.username, 'role': actor.role}


def reply(state: State, config: Config, pair: Pair, params: dict) -> dict:
    if (params.keys() != {'request', 'user_id', 'epoch', 'authenticated_at', 'mfa_at'}
            or not isinstance(params['request'], str) or not isinstance(params['user_id'], str)
            or type(params['epoch']) is not int or type(params['authenticated_at']) is not int
            or (params['mfa_at'] is not None and type(params['mfa_at']) is not int)):
        raise PeerError('INVALID_REQUEST', 'Expected a verified Grove administrator and a browser join request')
    now = int(time.time())
    data = grove.request_data(params['request'])
    mfa_at = params['mfa_at']
    if ('verification_origin' not in data
            or not now - auth.RECENT_FACTOR_SECONDS < params['authenticated_at'] <= now + grove.CLOCK_SKEW
            or (mfa_at is not None and not now - auth.RECENT_FACTOR_SECONDS < mfa_at <= now + grove.CLOCK_SKEW)):
        raise PeerError('DENIED', 'Grove administrator verification has expired')
    with state.connect(write=True) as db:
        require_verification_peer(db, config, pair)
        realm = db.execute('SELECT * FROM grove_realm').fetchone()
        member = db.execute('SELECT * FROM grove_member WHERE node_id=?', (pair.node_id,)).fetchone()
        if (realm is None or realm['id'] != data['realm_id'] or grove.issuer_replaced(db)
                or not member or not member['enabled'] or member['origin'] != data['verification_origin']):
            raise PeerError('DENIED', 'This member cannot verify a join for this Grove')
        profile = next((user for user in grove.public_users(db, realm['id']) if user['id'] == params['user_id']), None)
        if (not profile or not profile['enabled'] or profile['role'] != 'node_admin'
                or profile['epoch'] != params['epoch'] or (profile['require_mfa'] and mfa_at is None)):
            raise PeerError('DENIED', 'The Grove administrator identity changed. Sign in again after directory sync')
        grove.register_member(db, data)
        redirect = grove.browser_proof(state, db, realm, data, profile, mfa_at, now)
        audit(db, profile['id'], pair.node_id, 'grove.member_approved', data['node_id'], reason='MEMBER_WEB_VERIFIED')
        return {'redirect_url': redirect}
