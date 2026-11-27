"""Authenticate a Grove user using a one-use challenge and a device-held key."""
from hashlib import sha256
import json
from secrets import token_urlsafe
from threading import Lock
import time
from types import SimpleNamespace

from . import auth, factors, grove, grove_accounts, grove_authorization, grove_login
from .peer.grove_service_admin import admin_revision
from .peer.protocol import PeerError
from .state import audit


CHALLENGE_LIMIT = 128
BROWSER_HANDOFF_SECONDS = 60
_pending = {}
_handoffs = {}
_lock = Lock()


def profile_for(db, username):
    record = grove_accounts.record_for(db, username)
    return record['profile'] if record is not None else grove_accounts.legacy_profile(db, username)


def challenge(state, username, address, *, service_controls=False, session_authorization=False):
    now = int(time.time())
    with auth.authentication_attempt(state, address, now, username=username) as (db, _):
        if grove_login.usable_replica(db, now, operational=True) is None:
            raise PeerError('OFFLINE', '此面板尚未同步 Grove 账号目录。')
        _, anchor = grove_authorization.context(db)
        profile = profile_for(db, username)
        if profile is None or not profile['enabled']:
            raise PeerError('DENIED', 'Grove 账号暂不可用。')
        identity = admin_revision(db, anchor['realm_id'], profile['id'], require_admin=False)
        changed_role = db.execute('SELECT role FROM grove_login_role WHERE user_id=?', (profile['id'],)).fetchone()
        effective_role = changed_role['role'] if changed_role else profile['role']
        if session_authorization:
            scopes = grove_authorization.ADMIN_SIGNIN if effective_role == 'node_admin' else grove_authorization.ACCOUNT_SIGNIN
        else:
            scopes = grove_authorization.SERVICE_SIGNIN if service_controls and effective_role == 'node_admin' else ['signin']
        token = token_urlsafe(32)
        subject = SimpleNamespace(token_hash=auth.digest(token))
        value = grove_authorization.challenge(db, subject, state.identity()[0], identity, scopes)
    with _lock:
        for key, (current, _) in tuple(_pending.items()):
            if current['expires_at'] <= now:
                del _pending[key]
        if len(_pending) >= CHALLENGE_LIMIT:
            raise PeerError('BUSY', '请稍后再申请登录验证。')
        _pending[(state.directory, value['nonce'])] = (value, token)
    return value


def finish(state, proof, address):
    try:
        if not isinstance(proof, dict):
            raise ValueError
        rolling_update = proof.get('rolling_update')
        proof = {key: value for key, value in proof.items() if key != 'rolling_update'}
        grant = grove_authorization.unsigned(proof['grant'])
        expected_update = grove_authorization.rolling_update_challenge(grant)
        if rolling_update is not None and (
                expected_update is None or grove_authorization.unsigned(rolling_update['grant']) != expected_update):
            raise ValueError
        nonce = grant['nonce']
        with _lock:
            pending = _pending.get((state.directory, nonce))
        if pending is None or pending[0] != grant:
            raise ValueError
    except (KeyError, TypeError, ValueError) as error:
        raise PeerError('DENIED', '登录请求已过期，请重新生成。') from error

    now = int(time.time())
    with auth.authentication_attempt(state, address, now) as (db, _):
        if grove_login.usable_replica(db, now, operational=True) is None:
            raise PeerError('OFFLINE', '此面板尚未同步 Grove 账号目录。')
        realm_id, user_id, epoch, _, _ = grove_authorization.verify(db, proof, state.identity()[0], 'signin')
        if rolling_update is not None:
            grove_authorization.verify(db, rolling_update, state.identity()[0], 'updates')
        with _lock:
            if _pending.pop((state.directory, nonce), None) != pending:
                raise PeerError('DENIED', '此登录请求已经使用。')
        realm = db.execute('SELECT manifest,public_key FROM grove_realm WHERE id=?', (realm_id,)).fetchone()
        base = grove.verified('directory', json.loads(realm['manifest']), realm['public_key'])['users']
        profile = next(profile for profile in grove_accounts.profile_overlay(db, base) if profile['id'] == user_id)
        changed_role = db.execute('SELECT role FROM grove_login_role WHERE user_id=?', (user_id,)).fetchone()
        role = changed_role['role'] if changed_role else profile['role']
        linked = db.execute('SELECT account_id,valid_until FROM grove_account WHERE user_id=?', (user_id,)).fetchone()
        account_id = linked['account_id'] if linked else 'acctg-' + sha256((realm_id + '\0' + user_id).encode()).hexdigest()[:32]
        if linked is None:
            db.execute('''INSERT INTO panel_account(id,username,password_hash,role,operation_actor,require_mfa)
                          VALUES (?,?,?,?,?,1)''', (account_id, '@' + user_id, 'grove-only', role, account_id))
        else:
            if linked['valid_until'] != -1:
                factors.revoke_account_sessions(db, account_id)
            db.execute('UPDATE panel_account SET role=?,enabled=1,require_mfa=1 WHERE id=?', (role, account_id))
        db.execute('''INSERT INTO grove_account VALUES (?,?,?,?,?) ON CONFLICT(account_id) DO UPDATE SET
                      display_name=excluded.display_name,identity_epoch=excluded.identity_epoch,valid_until=-1''',
                   (account_id, user_id, profile['name'], epoch, -1))
        audit(db, account_id, address, 'grove.device_login', user_id)
        username = db.execute('SELECT username FROM panel_account WHERE id=?', (account_id,)).fetchone()[0]
        account = auth.account_for(db, username)
        service_session = grove_authorization.timed_session(grant)
        session = auth.issue_session(db, account, address, now, mfa_at=now, method='grove-device', grove_replica=True,
                                     token=pending[1], created_at=grant['issued_at'] if service_session else None)
        if service_session:
            owner = SimpleNamespace(token_hash=auth.digest(session[0]))
            grove_authorization.remember_service_session(state, owner, proof, now, rolling_update=rolling_update)
        return session


def browser_handoff(state, proof, address):
    session = finish(state, proof, address)
    now = int(time.time())
    ticket = token_urlsafe(32)
    with _lock:
        for key, (_, _, expires) in tuple(_handoffs.items()):
            if expires <= now:
                del _handoffs[key]
        if len(_handoffs) >= CHALLENGE_LIMIT:
            _handoffs.pop(next(iter(_handoffs)))
        _handoffs[(state.directory, auth.digest(ticket))] = (session, address, now + BROWSER_HANDOFF_SECONDS)
    return ticket


def finish_browser_handoff(state, ticket, address):
    with _lock:
        key = (state.directory, auth.digest(ticket))
        pending = _handoffs.get(key)
        if pending is None or pending[1] != address or pending[2] <= int(time.time()):
            raise PeerError('DENIED', '登录链接已过期，请从登录设备重新打开。')
        del _handoffs[key]
    return pending[0]


def current_session(db, row):
    try:
        profile = profile_for(db, row['display_name'])
        if profile is None or not profile['enabled'] or profile['id'] != row['grove_user'] or profile['epoch'] != row['identity_epoch']:
            return False
        changed_role = db.execute('SELECT role FROM grove_login_role WHERE user_id=?', (profile['id'],)).fetchone()
        return row['role'] == (changed_role['role'] if changed_role else profile['role'])
    except (TypeError, KeyError, ValueError, PeerError):
        return False
