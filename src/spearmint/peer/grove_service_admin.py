"""Authorize service setup using a Grove account and the authenticated Mesh source."""

from dataclasses import dataclass
from hashlib import sha256
import json
import re
import time

from .. import auth, grove
from . import quarantine
from .grove_endpoints import trusted_members
from .outbound import account_admin
from .pairing import Pair, configured
from .policy import credentials_current, require_pair
from .protocol import PeerError


OPERATION_KEY = re.compile(r'grove-admin:([1-9][0-9]*):([a-f0-9]{64}):([a-f0-9]{32})')
GROVE_REQUEST = "request_key GLOB 'grove-admin:*' AND substr(request_key,-32)=?"


def require_member(db, local_id: str, pair: Pair):
    require_pair(db, pair)
    members = trusted_members(db, local_id)
    if (pair.legacy or not credentials_current(pair) or quarantine.contains(db, pair.node_id)
            or members is None or pair.node_id not in members.origins):
        raise PeerError('DENIED', 'Service setup requires an active Grove Mesh peer')
    return members


def admin_revision(db, member_realm: str, user_id: str) -> list:
    realm = db.execute('SELECT * FROM grove_realm WHERE id=?', (member_realm,)).fetchone()
    if realm is None:
        raise PeerError('DENIED', 'The Grove identity directory is unavailable')
    if realm['is_issuer']:
        users = grove.public_users(db, member_realm)
    else:
        try:
            users = grove.verified('directory', json.loads(realm['manifest']), realm['public_key'])['users']
        except (KeyError, TypeError, ValueError) as error:
            raise PeerError('DENIED', 'The Grove identity directory is unavailable') from error
    user = next((entry for entry in users if entry['id'] == user_id and entry['enabled']), None)
    role = db.execute('SELECT role,generation FROM grove_login_role WHERE user_id=?', (user_id,)).fetchone()
    revoked = db.execute('SELECT 1 FROM grove_login_revocation WHERE user_id=?', (user_id,)).fetchone()
    if user is None or revoked or (role['role'] if role else user['role']) != 'node_admin':
        raise PeerError('DENIED', 'Grove administrator required')
    password = db.execute('SELECT generation FROM grove_login_password WHERE user_id=?', (user_id,)).fetchone()
    return [member_realm, user_id, user['epoch'], role['generation'] if role else 0,
            password['generation'] if password else 0]


def source_identity(state, local_id: str, pair: Pair | None, actor: auth.Actor) -> list:
    with state.connect() as db:
        db.execute('BEGIN')
        members = require_member(db, local_id, pair) if pair else trusted_members(db, local_id)
        if members is None:
            raise PeerError('OFFLINE', 'This panel is waiting for a current Grove directory')
        session = account_admin(db, actor)
        user = session['grove_user']
        if user is None and db.execute('SELECT 1 FROM grove_realm WHERE is_issuer=1').fetchone():
            user = grove.user_id(members.realm_id, actor.account_id)
        if user is None or session['mfa_at'] is None or session['mfa_at'] > int(time.time()):
            raise PeerError('DENIED', 'Sign in with a verified Grove administrator account')
        return admin_revision(db, members.realm_id, user)


def parse_identity(identity) -> list:
    if (not isinstance(identity, list) or len(identity) != 5
            or not all(isinstance(value, str) and 1 <= len(value) <= 64 for value in identity[:2])
            or any(type(value) is not int or not 0 <= value < 2**63 for value in identity[2:])):
        raise PeerError('INVALID_REQUEST', 'Invalid Grove account identity')
    return identity


def require_admin_identity(db, local_id: str, pair: Pair | None, identity) -> list:
    identity = parse_identity(identity)
    members = require_member(db, local_id, pair) if pair else trusted_members(db, local_id)
    if members is None:
        raise PeerError('OFFLINE', 'This panel is waiting for a current Grove directory')
    if identity != admin_revision(db, members.realm_id, identity[1]):
        raise PeerError('CONFLICT', 'Grove account permissions changed. Retry after the identity directory synchronizes')
    return identity


@dataclass(frozen=True)
class GroveServiceAdmin:
    local_id: str
    peer: Pair
    identity: list

    @classmethod
    def from_wire(cls, local_id: str, peer: Pair, identity) -> "GroveServiceAdmin":
        return cls(local_id, peer, parse_identity(identity))

    @property
    def operation_actor(self) -> str:
        return self.identity[1]

    @property
    def address(self) -> str:
        return self.peer.node_id

    def require(self, db) -> None:
        require_admin_identity(db, self.local_id, self.peer, self.identity)

    def operation_key(self, version: int, request_id: str) -> str:
        return f'grove-admin:{version}:{operation_revision(self.peer, self.identity)}:{request_id}'


def operation_revision(peer: Pair, identity: list) -> str:
    return sha256(grove.encoded([peer.mesh_id, peer.write_epoch, *identity])).hexdigest()


def operation_origin(db, operation, local_id: str) -> bool:
    parsed = OPERATION_KEY.fullmatch(operation['request_key'])
    peer = configured(db, operation['source'])
    if parsed is None or peer is None:
        return False
    try:
        trust = require_member(db, local_id, peer)
        identity = admin_revision(db, trust.realm_id, operation['actor'])
    except PeerError:
        return False
    return parsed[2] == operation_revision(peer, identity)
