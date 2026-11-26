"""Quorum-certified account credentials layered over the retired issuer snapshot."""

from hashlib import sha256
from hmac import compare_digest
import json
import re
from secrets import token_bytes
import time

from argon2.exceptions import VerificationError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import BaseModel, ConfigDict, Field

from . import auth, factors, grove, grove_availability, grove_continuity, grove_login, grove_voters
from .accounts import USERNAME
from .peer.protocol import PeerError, parse_b64, wire_b64
from .state import StateError, audit


METHOD = 'grove.accounts.v1'
PREPARED = 'grove-account-prepared-v2'
ACCEPTED = 'grove-account-accepted-v2'
EMPTY = '0' * 64
MAX_ACCOUNTS = 128
USERNAME_PATTERN = r'^[a-z0-9][a-z0-9._-]{0,63}$'
DIGEST_PATTERN = r'^[a-f0-9]{64}$'
CODE_PATTERN = r'^[A-Za-z0-9_-]{43}$'
INVITE_AGE = 24 * 60 * 60
RESET_AGE = 30 * 60


class Change(BaseModel):
    model_config = ConfigDict(strict=True, extra='forbid')
    username: str = Field(pattern=USERNAME_PATTERN)
    action: str = Field(pattern=r'^(create|invite|register|assist|reset|recovery-code|bind-device)$')
    request_id: str = Field(pattern=r'^[a-f0-9]{32}$')
    issued: int = Field(gt=0, lt=2**53)
    role: str | None = Field(default=None, pattern=r'^(node_admin|remote_operator)$')
    recovery_hash: str | None = Field(default=None, pattern=DIGEST_PATTERN)
    ticket_hash: str | None = Field(default=None, pattern=DIGEST_PATTERN)
    device_key: str | None = Field(default=None, pattern=r'^[A-Za-z0-9_-]{43}$')


def storage(db):
    return grove_voters.local_state(db).get('account_book', {'records': {}, 'ballots': {}})


def save(db, book):
    data = grove_voters.local_state(db)
    data['account_book'] = book
    grove_voters.save_local_state(db, data)


def record_for(db, username):
    return storage(db)['records'].get(username)


def profile_overlay(db, users):
    merged = {item['id']: item for item in users}
    for entry in storage(db)['records'].values():
        profile = entry['profile']
        merged[profile['id']] = profile
    return sorted(merged.values(), key=lambda item: (item['name'], item['id']))


def credential_version(db, user_id):
    for entry in storage(db)['records'].values():
        if entry['profile']['id'] == user_id and (entry['owns_password'] or entry.get('device_key')):
            return 2**40 + entry['credential_revision']
    return None


def device_key(db, user_id):
    return next((entry.get('device_key') for entry in storage(db)['records'].values() if entry['profile']['id'] == user_id), None)


def versions(db):
    return {name: entry['revision'] for name, entry in storage(db)['records'].items()}


def public_versions(db):
    return {name: entry['revision'] for name, entry in storage(db)['records'].items()
            if entry.get('public_only') or not entry['owns_password']}


def version_digest(db):
    return grove_voters.digest(public_versions(db))


EMPTY_VERSION = grove_voters.digest({})


def checkpoint_proofs(db):
    return [entry['digest'] for entry in storage(db)['records'].values()]


def require_no_accepted_changes(db):
    _, anchor = context(db)
    configuration = grove_voters.stamp(anchor).get('configuration')
    if any('accepted' in entry and entry['slot'].get('configuration') == configuration
           for entry in storage(db)['ballots'].values()):
        raise PeerError('CONFLICT', '有账号变更正在确认，请先同步账号目录。')


def projected_ids(db):
    return {entry['profile']['id'] for entry in storage(db)['records'].values() if entry['profile'].get('account_directory')}


def context(db):
    current = grove_continuity.read_anchor(db)
    if current is None:
        raise PeerError('CONFLICT', '此节点尚未取得 Grove 多数成员授权。')
    envelope, anchor = current
    return grove_continuity.anchor_digest(envelope), anchor


def available(db):
    return db.execute(
        'SELECT 1 FROM grove_login_continuity c JOIN grove_realm r ON c.sequence=r.sequence '
        "WHERE r.is_issuer=0 AND r.frozen='' AND r.issuer_paused=0"
    ).fetchone() is not None


def vault(state):
    # The dedicated key follows the backed-up node identity, independent of locally enrolled factors.
    derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'spearmint-grove-accounts-v1')
    return AESGCM(derived.derive(state.signing_key().private_bytes_raw()))


def seal(state, name, value):
    nonce = token_bytes(12)
    return wire_b64(nonce + vault(state).encrypt(nonce, grove.encoded(value), name.encode('ascii')))


def decrypt(state, name, value):
    sealed = parse_b64(value, 64 * 1024)
    try:
        return json.loads(vault(state).decrypt(sealed[:12], sealed[12:], name.encode('ascii')))
    except InvalidTag as error:
        raise StateError('The Grove account record is damaged') from error


def merge_checkpoint(saved, checkpoint):
    for name, entry in checkpoint['records'].items():
        old = saved['records'].get(name)
        if old and old['revision'] == entry['revision'] and old['digest'] != entry['digest']:
            raise StateError('Backup conflicts with a confirmed Grove account revision')
        if old is None or old['revision'] < entry['revision']:
            saved['records'][name] = entry
    for name, entry in checkpoint['ballots'].items():
        old = saved['ballots'].get(name)
        if old is None or old['term'] < entry['term']:
            saved['ballots'][name] = entry
    for name, entry in saved['records'].items():
        ballot = saved['ballots'].get(name)
        if ballot and ballot['slot']['revision'] <= entry['revision']:
            saved['ballots'].pop(name)
    return saved


def certificate(state, db, username):
    entry = record_for(db, username)
    return decrypt(state, username, entry['certificate']) if entry else None


def data_for(state, db, username):
    saved = certificate(state, db, username)
    return saved['proposal']['account'] if saved else None


def login_password(state, db, username):
    entry = record_for(db, username)
    if entry and entry['owns_password']:
        if local := entry.get('legacy_material'):
            return decrypt(state, username, local)['password_hash']
        return data_for(state, db, username)['password_hash']
    return None


def hash_code(value):
    return sha256(value.encode('ascii')).hexdigest()


def legacy_profile(db, name):
    realm = db.execute('SELECT manifest,public_key FROM grove_realm').fetchone()
    users = grove.verified('directory', json.loads(realm['manifest']), realm['public_key'])['users']
    return next((user for user in users if user['name'].lower() == name), None)


def effective_password(state, db, name, user_id):
    password = login_password(state, db, name)
    if password:
        return password
    changed = db.execute('SELECT document FROM grove_login_password WHERE user_id=?', (user_id,)).fetchone()
    if changed:
        return grove_login.password_verifier(state, user_id, changed[0])
    row = db.execute('SELECT verifier FROM grove_login_verifier WHERE user_id=?', (user_id,)).fetchone()
    return json.loads(factors.unseal(state, user_id, row[0]))[0] if row else None


def verify_password(state, db, profile, proof):
    old = effective_password(state, db, profile['name'], profile['id'])
    supplied = proof.get('current_password')
    if not isinstance(supplied, str) or not 1 <= len(supplied) <= 256 or not old:
        raise PeerError('DENIED', '请核对现有 Grove 密码。')
    if not auth.PASSWORD_SLOTS.acquire(blocking=False):
        raise PeerError('BUSY', '请稍后再试。')
    try:
        if not auth.PASSWORD.verify(old, supplied):
            raise PeerError('DENIED', '请核对现有 Grove 密码。')
    except VerificationError as error:
        raise PeerError('DENIED', '请核对现有 Grove 密码。') from error
    finally:
        auth.PASSWORD_SLOTS.release()


def proposal(state, db, change, proof, verify_authorization):
    raw = Change.model_validate(change)
    name, operation = raw.username, raw.action
    now = int(time.time())
    if abs(now - raw.issued) > 90:
        raise PeerError('CONFLICT', '请求已过期，请重新提交。')
    previous = record_for(db, name)
    record = data_for(state, db, name)
    legacy = legacy_profile(db, name)
    prior = record['profile'] if record else legacy
    anchor_digest, anchor = context(db)
    admin = None
    if operation in {'invite', 'create', 'assist'}:
        admin = verify_authorization(db, proof.get('identity'), 'accounts')
        if admin[0] != anchor['realm_id']:
            raise PeerError('DENIED', '需要 Grove 管理员账号。')

    if operation in {'invite', 'create'}:
        if (prior is not None and (legacy is not None or prior['enabled'])
                or prior is None and len(versions(db)) >= MAX_ACCOUNTS):
            raise PeerError('CONFLICT', '账号名已使用，或账号数量已达上限。')
        if not raw.role:
            raise PeerError('INVALID_REQUEST', '请选择账号角色。')
        profile = {'id': grove.user_id(anchor['realm_id'], 'account:' + name), 'name': name, 'role': raw.role,
                   'epoch': 1, 'enabled': operation == 'create', 'require_mfa': True, 'account_directory': True}
    else:
        if prior is None or db.execute('SELECT 1 FROM grove_login_revocation WHERE user_id=?', (prior['id'],)).fetchone():
            raise PeerError('DENIED', '账号或一次性凭据无效。')
        profile = prior.copy()
        if not profile['enabled'] and operation != 'register':
            raise PeerError('DENIED', '账号或一次性凭据无效。')

    if previous is None and len(versions(db)) >= MAX_ACCOUNTS:
        raise PeerError('CONFLICT', 'Grove 账号变更记录已达上限。')
    if operation == 'register' and not record:
        raise PeerError('DENIED', '一次性凭据无效或已经使用。')
    next_account = (record if operation not in {'invite', 'create'} else None) or {
        'profile': profile, 'password_hash': None, 'totp': None, 'recovery_hash': None,
        'ticket': None, 'credential_revision': 0,
    }
    if operation in {'invite', 'assist'}:
        if not raw.ticket_hash or (operation == 'assist' and profile['id'] == admin[1]):
            raise PeerError('DENIED', '请由另一位管理员为该账号签发重置码。')
        next_account['ticket'] = {'hash': raw.ticket_hash, 'purpose': operation,
                                  'expires': raw.issued + (INVITE_AGE if operation == 'invite' else RESET_AGE)}
    if operation in {'register', 'reset'}:
        supplied = proof.get('code', '')
        if not isinstance(supplied, str) or not re.fullmatch(CODE_PATTERN, supplied):
            raise PeerError('DENIED', '一次性凭据无效或已经使用。')
        digest = hash_code(supplied)
        ticket = next_account['ticket']
        purpose = 'invite' if operation == 'register' else 'assist'
        token_ok = bool(ticket and ticket['purpose'] == purpose and ticket['expires'] >= now and compare_digest(ticket['hash'], digest))
        recovery_ok = bool(operation == 'reset' and next_account['recovery_hash']
                           and compare_digest(next_account['recovery_hash'], digest))
        if not (token_ok or recovery_ok) or (operation == 'register' and profile['enabled']):
            raise PeerError('DENIED', '一次性凭据无效或已经使用。')
        next_account['ticket'] = None
    if operation in {'recovery-code', 'bind-device'}:
        authorization = proof.get('identity')
        identity = verify_authorization(db, authorization, 'self')
        if identity[1] != profile['id']:
            raise PeerError('DENIED', '请使用此 Grove 账号授权变更。')
        if operation == 'bind-device':
            from . import grove_authorization
            raw_key = device_key(db, profile['id']) or grove_authorization.unsigned(authorization['approvals'][0])['key']
            next_account['device_key'] = raw_key
            next_account['password_hash'] = None
            next_account['totp'] = None
            next_account['credential_revision'] += 1
    if operation in {'create', 'register', 'reset'}:
        if raw.device_key is None or len(parse_b64(raw.device_key, 32)) != 32:
            raise PeerError('INVALID_REQUEST', '请提供有效的登录设备公钥。')
        next_account['device_key'] = raw.device_key
        next_account['profile'] = {**profile, 'enabled': True}
        next_account['credential_revision'] += 1
    if operation in {'create', 'register', 'reset', 'recovery-code'}:
        if not raw.recovery_hash:
            raise PeerError('INVALID_REQUEST', '需要新的恢复凭据。')
        next_account['recovery_hash'] = raw.recovery_hash
    next_account['password_hash'] = None
    next_account['totp'] = None

    return {'anchor': anchor_digest, 'username': name, 'revision': (previous['revision'] if previous else 0) + 1,
            'previous': previous['digest'] if previous else EMPTY, 'request_id': raw.request_id, 'action': operation, 'authorization_version': 2, 'account': next_account, **grove_voters.stamp(anchor)}


def digest_of(value):
    return grove_voters.digest(value)


def slot(record):
    return {key: record[key] for key in ('anchor', 'username', 'revision', 'previous', 'configuration') if key in record}


def require_slot(db, record, digest, anchor):
    if record.get('authorization_version') != 2:
        raise PeerError('DENIED', '此账号操作缺少独立用户授权。')
    name = record['username']
    if (not isinstance(name, str) or not USERNAME.fullmatch(name) or record['anchor'] != digest
            or record.get('configuration') != grove_voters.stamp(anchor).get('configuration')):
        raise PeerError('INVALID_REQUEST', 'Grove account proposal does not match this directory')
    current = record_for(db, name)
    if (record['revision'], record['previous']) != ((current['revision'] + 1, current['digest']) if current else (1, EMPTY)):
        raise PeerError('CONFLICT', '账号记录已变化，请同步后重试。')


def validate_votes(kind, votes, anchor, expected):
    if not isinstance(votes, list) or not len(anchor['voters']) // 2 < len(votes) <= len(anchor['voters']):
        raise PeerError('GROVE_QUORUM_REQUIRED', '需要在线多数 Grove 投票节点确认。')
    seen = set()
    records = []
    for vote in votes:
        voter, data = grove_voters.verified_node(kind, vote)
        if voter not in anchor['voters'] or voter in seen or any(data.get(key) != value for key, value in expected.items()):
            raise PeerError('DENIED', '账号确认记录与本次操作不符。')
        seen.add(voter)
        records.append(data)
    return records


def prepare(state, db, change, proof, term, verify_admin):
    grove_voters.validate_term(term)
    digest, anchor = context(db)
    if state.identity()[0] not in anchor['voters']:
        raise PeerError('DENIED', '此节点不具备 Grove 账号投票权限。')
    record = proposal(state, db, change, proof, verify_admin)
    name = record['username']
    book = storage(db)
    prior = book['ballots'].get(name, {})
    if prior.get('slot') != slot(record) or prior.get('authorization_version') != 2:
        prior = {}
    if prior.get('term', []) > term:
        return {'promised': prior['term']}
    old = decrypt(state, name, prior['accepted']) if 'accepted' in prior else None
    ballot = {**prior, 'slot': slot(record), 'term': term, 'authorization_version': 2}
    book['ballots'][name] = ballot
    save(db, book)
    key = state.signing_key()
    statement = {**slot(record), 'term': term, 'candidate': digest_of(record),
                 'accepted_term': old['term'] if old else None, 'accepted': digest_of(old['proposal']) if old else None,
                 'public_key': wire_b64(key.public_key().public_bytes_raw()), **grove_voters.stamp(anchor)}
    return {'record': record, 'vote': grove.signed(PREPARED, statement, key), 'accepted': old}


def accept(state, db, record, term, prepared, requested):
    grove_voters.validate_term(term)
    digest, anchor = context(db)
    require_slot(db, record, digest, anchor)
    if state.identity()[0] not in anchor['voters']:
        raise PeerError('DENIED', '此节点不具备 Grove 账号投票权限。')
    expected = {**slot(record), 'term': term, 'candidate': requested, 'configuration': grove_voters.stamp(anchor).get('configuration')}
    statements = validate_votes(PREPARED, prepared, anchor, expected)
    accepted = [statement for statement in statements if statement['accepted_term'] is not None]
    chosen = max(accepted, key=lambda statement: statement['accepted_term'])['accepted'] if accepted else requested
    if digest_of(record) != chosen:
        raise PeerError('CONFLICT', '账号操作与已确认的提案不一致。')
    name = record['username']
    book = storage(db)
    previous = book['ballots'].get(name) or {}
    if previous.get('slot') != slot(record) or previous.get('authorization_version') != 2:
        previous = {}
    if previous.get('term', []) > term:
        raise PeerError('CONFLICT', '此账号正由另一节点处理。')
    if 'accepted' in previous:
        old = decrypt(state, name, previous['accepted'])
        if old['term'] == term and old['proposal'] != record:
            raise PeerError('CONFLICT', '此确认轮次已经接受其他账号提案。')
    book['ballots'][name] = {'slot': slot(record), 'term': term, 'authorization_version': 2, 'accepted': seal(state, name, {'term': term, 'proposal': record})}
    save(db, book)
    key = state.signing_key()
    return grove.signed(ACCEPTED, {**slot(record), 'term': term, 'proposal': chosen,
        'public_key': wire_b64(key.public_key().public_bytes_raw()), **grove_voters.stamp(anchor)}, key)


def apply(state, db, approved, source):
    record, term, votes = approved['proposal'], approved['term'], approved['votes']
    grove_voters.validate_term(term)
    digest, anchor = context(db)
    name = record['username']
    if not isinstance(name, str) or not USERNAME.fullmatch(name) or record['anchor'] != digest:
        raise PeerError('INVALID_REQUEST', '账号记录不属于当前 Grove。')
    book = storage(db)
    previous = book['records'].get(name)
    if previous and previous['revision'] >= record['revision']:
        if previous['revision'] == record['revision'] and previous['digest'] != digest_of(record):
            raise PeerError('CONFLICT', '检测到冲突的 Grove 账号记录。')
        return
    roster = grove_voters.verification(anchor, votes)
    configuration = json.loads(parse_b64(votes[0]['record'], 8192)).get('configuration')
    if record.get('configuration') != configuration:
        raise PeerError('CONFLICT', '该账号记录与确认时的投票名单不符。')
    if anchor.get('_version'):
        checkpoint = anchor['_contexts'][configuration or next(iter(anchor['_contexts']))]['proofs']
        if checkpoint is not None and digest_of(record) not in checkpoint:
            raise PeerError('CONFLICT', '该账号变更未包含在已确认的历史权限中。')
    validate_votes(ACCEPTED, votes, roster, {**slot(record), 'term': term, 'proposal': digest_of(record), 'configuration': configuration})
    account, profile = record['account'], record['account']['profile']
    if account.get('password_hash') is not None or account.get('totp') is not None:
        raise PeerError('DENIED', 'Grove 不再接收可复用的登录材料。')
    private = None if account.get('device_key') else login_password(state, db, name)
    old_credential = previous['credential_revision'] if previous else 0
    book['records'][name] = {'revision': record['revision'], 'digest': digest_of(record), 'profile': profile,
        'credential_revision': account['credential_revision'], 'owns_password': bool(private),
        'recovery_configured': bool(account['recovery_hash']), 'device_key': account.get('device_key'), 'public_only': True,
        'certificate': seal(state, name, approved)}
    if private is not None:
        book['records'][name]['legacy_material'] = seal(state, name, {'password_hash': private})
    book['ballots'].pop(name, None)
    save(db, book)
    if account.get('device_key'):
        db.execute('DELETE FROM grove_login_verifier WHERE user_id=?', (profile['id'],))
        db.execute('DELETE FROM grove_login_password WHERE user_id=?', (profile['id'],))
    else:
        project_verifier(state, db, account)
    if old_credential != account['credential_revision']:
        db.execute('DELETE FROM session WHERE account_id IN (SELECT account_id FROM grove_account WHERE user_id=?)', (profile['id'],))
    audit(db, 'grove', source, 'grove.account_changed', profile['id'], reason=record['action'])


def project_verifier(state, db, account, *, restore=False):
    profile = account['profile']
    if profile['enabled'] and account['totp']:
        factors.initialize_vault(state)
        if restore and db.execute('SELECT 1 FROM grove_login_verifier WHERE user_id=?', (profile['id'],)).fetchone():
            return
        db.execute('''INSERT INTO grove_login_verifier(user_id,username,role,epoch,verifier)
                      VALUES (?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET verifier=excluded.verifier''',
                   (profile['id'], profile['name'], profile['role'], profile['epoch'],
                    factors.seal(state, profile['id'], json.dumps([account['password_hash'], account['totp']]))))


def restore_verifiers(state, db):
    for name, entry in storage(db)['records'].items():
        if entry['profile'].get('account_directory'):
            project_verifier(state, db, data_for(state, db, name), restore=True)
