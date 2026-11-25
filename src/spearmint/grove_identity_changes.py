"""Collect automatic majority approval before committing Grove identity changes."""
from hashlib import sha256
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import grove, grove_availability, grove_revocation, grove_voters
from .peer.credentials import node_id
from .peer.protocol import PeerError, parse_b64, wire_b64


METHOD = 'grove.identity.change.approve.v1'
KIND = 'identity-change-approval'


def envelope(document):
    if not isinstance(document, dict) or document.keys() - {'record', 'signature', 'approvals'}:
        raise PeerError('INVALID_REQUEST', 'Invalid Grove identity change')
    return {field: document[field] for field in ('record', 'signature')}


def document_digest(document):
    return sha256(grove.encoded(envelope(document))).hexdigest()


def validate_change(kind, document, digest, anchor, users):
    bare = envelope(document)
    if kind == 'password':
        from . import grove_password
        return grove_password.data_for(bare, digest, anchor, users)
    if kind == 'revocation':
        return {'user_id': grove_revocation.validate_document(bare, digest, anchor, users)}
    if kind == 'role':
        from . import grove_roles
        _, subject, generation, role = grove_roles.validate(bare, digest, anchor, users)
        return {'user_id': subject, 'generation': generation, 'role': role}
    raise PeerError('INVALID_REQUEST', 'Unknown Grove identity change')


def ballot(state, kind, document, actor: str, requester: str | None = None):
    with state.connect(read_only=True) as db:
        db.execute('BEGIN')
        grove_availability.require_current(db)
        grove_voters.require_unlocked(db)
        digest, anchor, users = grove_revocation.current_context(db, requester)
        local = state.identity()[0]
        if local not in anchor['voters']:
            raise PeerError('DENIED', 'A Grove identity voter is required')
        record = validate_change(kind, document, digest, anchor, users)
        profile = next((user for user in users if user['id'] == actor and user['enabled']), None)
        if profile is None or db.execute('SELECT 1 FROM grove_login_revocation WHERE user_id=?', (actor,)).fetchone():
            raise PeerError('DENIED', 'An active Grove account is required')
        role = db.execute('SELECT role FROM grove_login_role WHERE user_id=?', (actor,)).fetchone()
        if kind == 'password':
            from . import grove_accounts
            if grove_accounts.credential_version(db, actor) is not None:
                raise PeerError('CONFLICT', '请使用支持新版 Grove 账号管理的面板修改密码。')
            current = db.execute('SELECT generation FROM grove_login_password WHERE user_id=?', (actor,)).fetchone()
            if record['user_id'] != actor or record['generation'] != (current['generation'] if current else 0) + 1:
                raise PeerError('CONFLICT', 'The Grove password revision changed')
        elif (role['role'] if role else profile['role']) != 'node_admin':
            raise PeerError('DENIED', 'A Grove administrator is required')
        if kind == 'revocation':
            target_role = db.execute('SELECT role FROM grove_login_role WHERE user_id=?', (record['user_id'],)).fetchone()
            if target_role is not None and target_role['role'] == 'node_admin':
                raise PeerError('CONFLICT', 'The target is now a Grove administrator; synchronize its role first')
        raw = json.loads(parse_b64(document['record'], 2048))
        author = node_id(Ed25519PublicKey.from_public_bytes(parse_b64(raw['public_key'], 32)))
        if author != (requester or local):
            raise PeerError('DENIED', 'The change must come from its authoring voter')
        key = state.signing_key()
        if kind == 'role':
            from . import grove_roles
            current = db.execute('SELECT generation FROM grove_login_role WHERE user_id=?', (record['user_id'],)).fetchone()
            if record['generation'] != (current['generation'] if current else 0) + 1:
                raise PeerError('CONFLICT', 'The Grove role revision changed')
            return grove.signed(grove_roles.KIND, {'anchor': digest, **record,
                'public_key': wire_b64(key.public_key().public_bytes_raw()), **grove_voters.stamp(anchor)}, key)
        return grove.signed(KIND, {'anchor': digest, 'kind': kind, 'document': document_digest(document),
            'actor': actor, 'public_key': wire_b64(key.public_key().public_bytes_raw()), **grove_voters.stamp(anchor)}, key)


def verify(kind, document, digest, anchor, users):
    anchor = grove_voters.verification(anchor, [envelope(document)], certificate=document)
    validate_change(kind, document, digest, anchor, users)
    approvals = document.get('approvals')
    if not isinstance(approvals, list) or not len(anchor['voters']) // 2 < len(approvals) <= len(anchor['voters']):
        raise PeerError('GROVE_QUORUM_REQUIRED', '身份变更尚未取得 Grove 多数成员确认。')
    voters, actors = set(), set()
    for approval in approvals:
        raw = json.loads(parse_b64(approval['record'], 1024))
        public = parse_b64(raw['public_key'], 32)
        voter = node_id(Ed25519PublicKey.from_public_bytes(public))
        data = grove.verified(KIND, approval, public, 1024)
        if data.get('configuration') != json.loads(parse_b64(document['record'], 2048)).get('configuration'):
            raise PeerError('CONFLICT', 'Grove identity confirmations use different voter configurations')
        data = grove_voters.unstamp(data)
        if (voter not in anchor['voters'] or data != {'anchor': digest, 'kind': kind,
                'document': document_digest(document), 'actor': data.get('actor'), 'public_key': raw['public_key']}):
            raise PeerError('DENIED', 'The Grove identity approval does not match this change')
        voters.add(voter)
        actors.add(data['actor'])
    if len(voters) <= len(anchor['voters']) // 2 or len(actors) != 1:
        raise PeerError('GROVE_QUORUM_REQUIRED', '身份变更尚未取得 Grove 多数成员确认。')


def certify(state, kind, document, approvals):
    certified = envelope(document) | {'approvals': approvals}
    with state.connect(read_only=True) as db:
        grove_availability.require_current(db)
        grove_voters.require_unlocked(db)
        digest, anchor, users = grove_revocation.current_context(db)
        verify(kind, certified, digest, anchor, users)
    return certified
