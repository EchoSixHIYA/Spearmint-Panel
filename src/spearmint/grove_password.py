"""Keep a Grove member's password change bound to its account and identity snapshot."""
from collections.abc import Callable
from hashlib import sha256
import json
import time

from argon2.exceptions import VerificationError
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import auth, factors, grove, grove_login, grove_revocation, grove_voters
from .peer.credentials import node_id
from .peer.protocol import PeerError, parse_b64, wire_b64
from .state import State, audit


APPLY = 'grove.login.password.apply'
KIND = 'login-password'


def verifier_for_session(db, actor: auth.Actor, now: int):
    from . import grove_availability
    grove_availability.require_current(db)
    grove_voters.require_unlocked(db)
    session = auth.active_session(db, actor.token_hash, now)
    if session is None or not session['grove_replica'] or session['id'] != actor.account_id:
        raise PeerError('DENIED', 'Sign in directly with the Grove account to change its password')
    if db.execute('SELECT 1 FROM grove_login_continuity').fetchone() is None:
        raise PeerError('CONFLICT', 'This Grove has not handed off its original identity role')
    if state_voter_missing(db):
        raise PeerError('DENIED', 'Use a Grove identity voter to change the password')
    record = db.execute('''SELECT v.*,p.generation,p.change_digest,p.document FROM grove_login_verifier v
                           LEFT JOIN grove_login_password p ON p.user_id=v.user_id WHERE v.user_id=?''',
                        (session['grove_user'],)).fetchone()
    if record is None:
        raise PeerError('DENIED', 'This Grove account has no active password')
    return session, record


def state_voter_missing(db):
    from . import grove_continuity
    current = grove_continuity.read_anchor(db)
    return current is None or db.execute('SELECT node_id FROM node').fetchone()[0] not in current[1]['voters']


def available(state: State, actor: auth.Actor) -> bool:
    with state.connect(read_only=True) as db:
        db.execute('BEGIN')
        try:
            verifier_for_session(db, actor, int(time.time()))
        except PeerError:
            return False
        return True


def data_for(document: dict, digest: str, anchor: dict, users: list[dict]) -> dict:
    from .grove_identity_changes import envelope
    document = envelope(document)
    try:
        raw = json.loads(parse_b64(document['record'], 2048))
        public = parse_b64(raw['public_key'], 32)
        record = grove.verified(KIND, document, public, 2048)
        anchor = grove_voters.verification(anchor, [document])
        record = grove_voters.unstamp(record)
        if (node_id(Ed25519PublicKey.from_public_bytes(public)) not in anchor['voters']
                or record.keys() != {'anchor', 'user_id', 'generation', 'password_hash', 'public_key'}
                or record['anchor'] != digest or type(record['generation']) is not int
                or not 1 <= record['generation'] < 2**63 - 1
                or not any(user['id'] == record['user_id'] and user['enabled'] for user in users)):
            raise ValueError
        grove_login.verify_password_hash(record['password_hash'])
    except (KeyError, ValueError, TypeError, VerificationError, PeerError) as error:
        raise PeerError('DENIED', 'Invalid Grove password change') from error
    return record


def store(state: State, db, document: dict, record: dict, actor: str, source: str) -> bool:
    user_id = record['user_id']
    change_digest = sha256(parse_b64(document['record'], 2048) + parse_b64(document['signature'], 64)).hexdigest()
    previous = db.execute('SELECT generation,change_digest FROM grove_login_password WHERE user_id=?', (user_id,)).fetchone()
    if previous and (record['generation'], change_digest) <= (previous['generation'], previous['change_digest']):
        return False
    grove_voters.require_unlocked(db)
    sealed = factors.seal(state, user_id, json.dumps(document))
    db.execute('''INSERT INTO grove_login_password VALUES (?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET
                  anchor_digest=excluded.anchor_digest,generation=excluded.generation,
                  change_digest=excluded.change_digest,document=excluded.document''',
               (user_id, record['anchor'], record['generation'], change_digest, sealed))
    db.execute('DELETE FROM session WHERE account_id IN (SELECT account_id FROM grove_account WHERE user_id=?)', (user_id,))
    audit(db, actor, source, 'grove.password_changed', user_id)
    return True


def issue(state: State, actor: auth.Actor, current_password: str, new_password: str) -> tuple[dict, list[str]]:
    now = int(time.time())
    with auth.authentication_attempt(state, actor.address, now, username=actor.display_name) as (db, _):
        session, verifier = verifier_for_session(db, actor, now)
        if session['mfa_at'] is not None and session['mfa_at'] <= now - auth.RECENT_FACTOR_SECONDS:
            raise auth.SessionReauthenticationRequired
    if not auth.PASSWORD_SLOTS.acquire(blocking=False):
        raise auth.LoginLimited(1)
    try:
        if verifier['document'] is None:
            password_hash, _ = json.loads(factors.unseal(state, verifier['user_id'], verifier['verifier']))
        else:
            password_hash = grove_login.password_verifier(state, verifier['user_id'], verifier['document'])
        if not auth.PASSWORD.verify(password_hash, current_password):
            raise PeerError('DENIED', 'The current Grove password is incorrect')
        replacement = auth.PASSWORD.hash(new_password)
    except VerificationError as error:
        raise PeerError('DENIED', 'The current Grove password is incorrect') from error
    finally:
        auth.PASSWORD_SLOTS.release()
    with state.connect(write=True) as db:
        now = int(time.time())
        current, checked = verifier_for_session(db, actor, now)
        if checked != verifier or current['mfa_at'] != session['mfa_at']:
            raise PeerError('CONFLICT', 'The Grove password or session changed during verification')
        if current['mfa_at'] is not None and current['mfa_at'] <= now - auth.RECENT_FACTOR_SECONDS:
            raise auth.SessionReauthenticationRequired
        digest, anchor, _ = grove_revocation.current_context(db)
        if state.identity()[0] not in anchor['voters']:
            raise PeerError('DENIED', 'Use a Grove identity voter to change the password')
        key = state.signing_key()
        record = {'anchor': digest, 'user_id': verifier['user_id'], 'generation': (verifier['generation'] or 0) + 1,
                  'password_hash': replacement, 'public_key': wire_b64(key.public_key().public_bytes_raw()), **grove_voters.stamp(anchor)}
        document = grove.signed(KIND, record, key)
        return document, anchor['voters']


def apply(state: State, documents: list[dict], source: str, authorize: Callable | None = None) -> int:
    if not isinstance(documents, list) or len(documents) > 64:
        raise PeerError('INVALID_REQUEST', 'Invalid Grove password change list')
    with state.connect(write=True) as db:
        if authorize is not None:
            authorize(db)
        digest, anchor, users = grove_revocation.current_context(db, source)
        from .grove_identity_changes import verify
        for document in documents:
            verify('password', document, digest, anchor, users)
        return sum(store(state, db, document, data_for(document, digest, anchor, users), 'peer', source)
                   for document in documents)
