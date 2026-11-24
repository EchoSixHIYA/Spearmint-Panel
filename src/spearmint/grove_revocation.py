"""Replicate irreversible account suspensions after Grove identity handoff."""
from collections.abc import Callable
import json
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import auth, grove, grove_continuity, grove_voters
from .peer.credentials import node_id
from .peer.protocol import PeerError, parse_b64, wire_b64
from .state import State, audit


APPLY = 'grove.login.revocations.apply'
KIND = 'login-revocation'


def current_context(db, requester: str | None = None) -> tuple[str, dict, list[dict]]:
    current = grove_continuity.read_anchor(db)
    if current is None:
        raise PeerError('CONFLICT', 'This member has no permanent Grove identity authorization')
    envelope, anchor = current
    if requester is not None and requester not in anchor['voters']:
        raise PeerError('DENIED', 'This operation requires a Grove identity member')
    realm = db.execute('SELECT manifest,public_key FROM grove_realm').fetchone()
    users = grove.verified('directory', json.loads(realm['manifest']), realm['public_key'])['users']
    return grove_continuity.anchor_digest(envelope), anchor, users


def validate_document(document: dict, digest: str, anchor: dict, users: list[dict]) -> str:
    from .grove_identity_changes import envelope
    document = envelope(document)
    try:
        raw = json.loads(parse_b64(document['record'], 1024))
        public = parse_b64(raw['public_key'], 32)
        voter = node_id(Ed25519PublicKey.from_public_bytes(public))
        record = grove.verified(KIND, document, public, 1024)
        anchor = grove_voters.verification(anchor, [document])
        record = grove_voters.unstamp(record)
        subject = record['user_id']
        if (voter not in anchor['voters'] or record != {'anchor': digest, 'user_id': subject,
                                                        'public_key': raw['public_key']}
                or not any(user['id'] == subject and user['enabled'] and user['role'] == 'remote_operator' for user in users)):
            raise ValueError
    except (KeyError, ValueError, TypeError, PeerError) as error:
        raise PeerError('DENIED', 'Invalid Grove operator revocation') from error
    return subject


def store(db, document: dict, digest: str, subject: str, actor: str, source: str) -> bool:
    if not db.execute('SELECT 1 FROM grove_login_revocation WHERE user_id=?', (subject,)).fetchone():
        grove_voters.require_unlocked(db)
    inserted = db.execute('INSERT OR IGNORE INTO grove_login_revocation VALUES (?,?,?)',
                          (subject, digest, json.dumps(document))).rowcount
    if inserted:
        db.execute('DELETE FROM session WHERE account_id IN (SELECT account_id FROM grove_account WHERE user_id=?)', (subject,))
        audit(db, actor, source, 'grove.operator_revoked', subject)
    return bool(inserted)


def issue(state: State, actor: auth.Actor, user_id: str) -> tuple[dict, list[str]]:
    with state.connect(write=True) as db:
        from . import grove_availability
        grove_availability.require_current(db)
        grove_voters.require_unlocked(db)
        now = int(time.time())
        session = auth.active_session(db, actor.token_hash, now)
        if (session is None or session['id'] != actor.account_id or session['grove_user'] is None
                or not session['grove_replica'] or session['role'] != 'node_admin'):
            raise PeerError('DENIED', 'Sign in with a Grove administrator account to revoke an operator')
        digest, anchor, users = current_context(db)
        if state.identity()[0] not in anchor['voters']:
            raise PeerError('DENIED', 'Use a Grove identity voter to suspend an operator')
        if db.execute("SELECT 1 FROM grove_login_role WHERE user_id=? AND role='node_admin'", (user_id,)).fetchone():
            raise PeerError('DENIED', 'A Grove administrator cannot be suspended as an operator')
        existing = db.execute('SELECT document FROM grove_login_revocation WHERE user_id=? AND anchor_digest=?',
                              (user_id, digest)).fetchone()
        if existing:
            return json.loads(existing['document']), anchor['voters']
        key = state.signing_key()
        document = grove.signed(KIND, {'anchor': digest, 'user_id': user_id,
                                     'public_key': wire_b64(key.public_key().public_bytes_raw()), **grove_voters.stamp(anchor)}, key)
        subject = validate_document(document, digest, anchor, users)
        return document, anchor['voters']


def apply(state: State, documents: list[dict], source: str, authorize: Callable | None = None) -> int:
    if not isinstance(documents, list) or len(documents) > 64:
        raise PeerError('INVALID_REQUEST', 'Invalid Grove operator revocation list')
    with state.connect(write=True) as db:
        if authorize is not None:
            authorize(db)
        digest, anchor, users = current_context(db, source)
        from .grove_identity_changes import verify
        for document in documents:
            verify('revocation', document, digest, anchor, users)
        return sum(store(db, document, digest, validate_document(document, digest, anchor, users), 'peer', source)
                   for document in documents)
