"""Authorize service setup using a Grove account and the authenticated Mesh source."""

from dataclasses import dataclass
from hashlib import sha256
import json
import re
import time

from .. import auth, grove, grove_authorization
from . import quarantine
from .grove_endpoints import trusted_members
from .outbound import account_admin
from .pairing import Pair, configured
from .policy import credentials_current, require_pair
from .protocol import PeerError


OPERATION_KEY = re.compile(r'grove-user-admin:([1-9][0-9]*):([a-f0-9]{64}):([a-f0-9]{32})')
GROVE_REQUEST = "request_key GLOB 'grove-user-admin:*' AND substr(request_key,-32)=?"


def require_member(db, local_id: str, pair: Pair, *, transport: bool = False):
    require_pair(db, pair)
    members = trusted_members(db, local_id, operational=True, transport=transport)
    if (pair.legacy or not credentials_current(pair) or quarantine.contains(db, pair.node_id)
            or members is None or pair.node_id not in members.origins):
        error = PeerError('DENIED', 'Service setup requires an active Grove Mesh peer')
        from .. import grove_availability
        error.diagnostic_context = {'pair_legacy': pair.legacy, 'credentials_current': credentials_current(pair),
            'quarantined': quarantine.contains(db, pair.node_id), 'members_available': members is not None,
            'source_is_member': members is not None and pair.node_id in members.origins,
            'access_at_rejection': grove_availability.status(db)}
        raise error
    return members


def admin_revision(db, member_realm: str, user_id: str, *, require_admin=True) -> list:
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
    from .. import grove_accounts
    users = grove_accounts.profile_overlay(db, users)
    user = next((entry for entry in users if entry['id'] == user_id and entry['enabled']), None)
    role = db.execute('SELECT role,generation FROM grove_login_role WHERE user_id=?', (user_id,)).fetchone()
    revoked = db.execute('SELECT 1 FROM grove_login_revocation WHERE user_id=?', (user_id,)).fetchone()
    if user is None or revoked or (require_admin and (role['role'] if role else user['role']) != 'node_admin'):
        raise PeerError('DENIED', 'Grove administrator required')
    password = db.execute('SELECT generation FROM grove_login_password WHERE user_id=?', (user_id,)).fetchone()
    revision = grove_accounts.credential_version(db, user_id)
    return [member_realm, user_id, user['epoch'], role['generation'] if role else 0,
            revision if revision is not None else password['generation'] if password else 0]


def source_identity(state, local_id: str, pair: Pair | None, actor: auth.Actor) -> list:
    with state.connect() as db:
        db.execute('BEGIN')
        members = require_member(db, local_id, pair) if pair else trusted_members(db, local_id, operational=True)
        if members is None:
            raise PeerError('OFFLINE', 'This panel is waiting for a current Grove directory')
        session = account_admin(db, actor)
        user = session['grove_user']
        if user is None and db.execute('SELECT 1 FROM grove_realm WHERE is_issuer=1').fetchone():
            user = grove.user_id(members.realm_id, actor.account_id)
        if user is None or session['mfa_at'] is None or session['mfa_at'] > int(time.time()):
            error = PeerError('DENIED', 'Sign in with a verified Grove administrator account')
            error.diagnostic_context = {'grove_user_present': user is not None, 'mfa_present': session['mfa_at'] is not None,
                'mfa_in_future': session['mfa_at'] is not None and session['mfa_at'] > int(time.time())}
            raise error
        return admin_revision(db, members.realm_id, user)


def parse_identity(identity) -> list:
    if (not isinstance(identity, list) or len(identity) != 5
            or not all(isinstance(value, str) and 1 <= len(value) <= 64 for value in identity[:2])
            or any(type(value) is not int or not 0 <= value < 2**63 for value in identity[2:])):
        raise PeerError('INVALID_REQUEST', 'Invalid Grove account identity')
    return identity


def require_admin_identity(db, local_id: str, pair: Pair | None, identity, scope: str, *, delegated=False) -> list:
    members = require_member(db, local_id, pair) if pair else trusted_members(db, local_id, operational=True)
    if members is None:
        raise PeerError('OFFLINE', 'This panel is waiting for a current Grove directory')
    if pair is not None or isinstance(identity, dict):
        return grove_authorization.verify(db, identity, pair.node_id if pair else local_id, scope, delegated=delegated)
    identity = parse_identity(identity)
    if identity != admin_revision(db, members.realm_id, identity[1]):
        raise PeerError('CONFLICT', 'Grove account permissions changed. Retry after the identity directory synchronizes')
    return identity


def source_grant(state, local_id, pair, actor, scope):
    identity = source_identity(state, local_id, pair, actor)
    with state.connect(read_only=True) as db:
        db.execute('BEGIN')
        account_admin(db, actor)
        proof, verified = grove_authorization.session_grant(db, state, actor, local_id, scope)
        if verified != identity:
            raise PeerError(grove_authorization.ERROR, grove_authorization.MESSAGE)
    return proof


@dataclass(frozen=True)
class GroveServiceAdmin:
    local_id: str
    peer: Pair
    identity: list
    authorization: dict
    scope: str

    @classmethod
    def from_wire(cls, local_id: str, peer: Pair, proof, scope: str) -> "GroveServiceAdmin":
        return cls(local_id, peer, grove_authorization.revision(proof), proof, scope)

    @property
    def operation_actor(self) -> str:
        return self.identity[1]

    @property
    def address(self) -> str:
        return self.peer.node_id

    def require(self, db) -> None:
        require_admin_identity(db, self.local_id, self.peer, self.authorization, self.scope)

    def require_current_identity(self, db) -> None:
        members = require_member(db, self.local_id, self.peer, transport=True)
        if self.identity != admin_revision(db, members.realm_id, self.identity[1]):
            raise PeerError('DENIED', 'Grove account permissions changed')

    def operation_key(self, version: int, request_id: str) -> str:
        return f'grove-user-admin:{version}:{operation_revision(self.peer, self.identity)}:{request_id}'


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
