"""Discover a Grove verifier and confirm a pending browser join."""
from ipaddress import ip_address
import re
import time
from urllib.parse import urlsplit

from . import grove
from .config import Config
from .peer import quarantine
from .peer.pairing import Pair
from .peer.policy import require_pair
from .peer.protocol import PeerError, decode_json, parse_b64, wire_b64
from .state import State


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
        origins = [row['issuer_origin']] if browser_origin(row['issuer_origin']) else []
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
    return {'realm': realm, 'origins': [realm['issuer_origin']] if realm['issuer_origin'] != local_origin
            and realm['issuer_origin'] in origins else []}


def invitation_code(envelope: dict, local_origin: str) -> str:
    code = INVITATION_PREFIX + wire_b64(grove.encoded(envelope))
    read_invitation(code, local_origin)
    return code


def invitation_reply(state: State, config: Config, pair: Pair, params: dict) -> dict:
    if (params.keys() != {'realm_id'} or not isinstance(params['realm_id'], str)
            or re.fullmatch(r'grv1-[a-f0-9]{32}', params['realm_id']) is None):
        raise PeerError('INVALID_REQUEST', 'Expected the current Grove ID')
    return invitation(state, config, params['realm_id'], pair)
