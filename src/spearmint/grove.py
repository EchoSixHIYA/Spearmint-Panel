"""Grove browser sign-in and signed public identity synchronization.

Only the explicitly trusted identity issuer holds a login signing key. Ordinary
members hold public records; Mesh transport identities cannot mint user logins.
"""
from hashlib import sha256
import json
import secrets
import ssl
import time
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, Request, build_opener, HTTPSHandler, HTTPRedirectHandler

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import auth, factors, onboarding
from .config import Config
from .peer.credentials import NODE_ID, node_id
from .peer.protocol import PeerError, decode_json, parse_b64, wire_b64
from .state import State, StateError, audit, private_path


KEY_FILE = 'grove-issuer.key'
DIRECTORY_SEEDS = 'grove-directory-seeds.json'
COOKIE = '__Host-spearmint-grove'
FLOW_TTL = 300
PROOF_TTL = 120
DIRECTORY_TTL = 300
CLOCK_SKEW = 5
MAX_DOCUMENT = 64 * 1024
METHOD = 'grove.identity.get'
REALM_FIELDS = {'version', 'id', 'name', 'public_key', 'issuer_node', 'issuer_origin'}
DIRECTORY_REQUEST_EVENTS = {
    'https': 'grove.member_directory_requested',
    'mesh': 'grove.member_directory_requested_mesh',
}


def valid_time_window(issued: int, expires: int, now: int, lifetime: int) -> bool:
    # Allow a slightly faster signing clock without extending expiry or lifetime.
    return issued <= now + CLOCK_SKEW and now < expires and issued < expires <= issued + lifetime


def origin(value: str) -> str:
    try:
        if not isinstance(value, str):
            raise ValueError
        parsed = urlsplit(value)
        host = parsed.hostname or ''
        authority = f'[{host}]' if ':' in host else host
        if parsed.port is not None and parsed.port != 443:
            authority += f':{parsed.port}'
        if (not host or not value.isascii() or value != 'https://' + authority
                or any(character.isspace() for character in authority)):
            raise ValueError
        return value
    except (ValueError, TypeError) as error:
        raise PeerError('INVALID_REQUEST', 'Use a canonical HTTPS origin') from error


def encoded(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()


def signed(kind: str, payload: dict, key: Ed25519PrivateKey) -> dict:
    raw = encoded(payload)
    if len(raw) > MAX_DOCUMENT:
        raise PeerError('BUSY', 'Grove identity directory is full')
    signature = key.sign(f'Spearmint-Grove {kind} v1\0'.encode() + sha256(raw).digest())
    return {'record': wire_b64(raw), 'signature': wire_b64(signature)}


def verified(kind: str, envelope: dict, public: bytes, limit: int = MAX_DOCUMENT) -> dict:
    try:
        if not isinstance(envelope, dict) or envelope.keys() != {'record', 'signature'}:
            raise ValueError
        raw = parse_b64(envelope['record'], limit)
        signature = parse_b64(envelope['signature'], 64)
        Ed25519PublicKey.from_public_bytes(public).verify(signature, f'Spearmint-Grove {kind} v1\0'.encode() + sha256(raw).digest())
        return decode_json(raw)
    except (ValueError, KeyError, TypeError, InvalidSignature) as error:
        raise PeerError('DENIED', 'Invalid Grove signature or record') from error


def realm_data(row) -> dict:
    return {'version': 1, 'id': row['id'], 'name': row['name'], 'public_key': wire_b64(row['public_key']),
            'issuer_node': row['issuer_node'], 'issuer_origin': row['issuer_origin']}


def invitation(value: dict) -> dict:
    import re
    try:
        if (not isinstance(value, dict) or value.keys() != REALM_FIELDS or type(value['version']) is not int
                or value['version'] != 1 or not isinstance(value['id'], str)
                or re.fullmatch(r'grv1-[a-f0-9]{32}', value['id']) is None
                or not isinstance(value['name'], str) or not 1 <= len(value['name']) <= 40
                or not value['name'].isprintable() or NODE_ID.fullmatch(value['issuer_node']) is None
                or len(parse_b64(value['public_key'], 32)) != 32):
            raise ValueError
        origin(value['issuer_origin'])
        return value
    except (ValueError, KeyError, TypeError) as error:
        raise PeerError('INVALID_REQUEST', 'Invalid Grove invitation') from error


def issuer_key(state: State, row) -> Ed25519PrivateKey:
    if not row['is_issuer'] or row['issuer_paused'] or row['frozen']:
        raise PeerError('DENIED', 'Grove identity signing is unavailable')
    path = state.directory / KEY_FILE
    try:
        private_path(path, 0o600)
        key = Ed25519PrivateKey.from_private_bytes(path.read_bytes())
        if key.public_key().public_bytes_raw() != row['public_key']:
            raise ValueError
        return key
    except (OSError, ValueError, StateError) as error:
        raise PeerError('DENIED', 'Grove identity key is unavailable') from error


def require_recent(db, actor: auth.Actor) -> None:
    now = int(time.time())
    current = auth.active_session(db, actor.token_hash, now)
    stamp = db.execute('SELECT created_at,mfa_at FROM session WHERE token_hash=?', (actor.token_hash,)).fetchone()
    if current is None or current['id'] != actor.account_id or actor.role != 'node_admin' or actor.grove:
        raise PeerError('DENIED', 'A local node administrator must approve this trust change')
    timestamp = stamp['mfa_at'] if stamp['mfa_at'] is not None else stamp['created_at']
    if not now - auth.RECENT_FACTOR_SECONDS < timestamp <= now:
        raise auth.SessionReauthenticationRequired


def create(state: State, config: Config, name: str, actor: auth.Actor) -> dict:
    name = name.strip()
    if not 1 <= len(name) <= 40 or not name.isprintable():
        raise PeerError('INVALID_REQUEST', 'Grove name must contain 1 to 40 printable characters')
    with state.lock('maintenance.lock'):
        with state.connect() as db:
            require_recent(db, actor)
            if db.execute('SELECT 1 FROM grove_realm').fetchone():
                raise PeerError('CONFLICT', 'This node already belongs to a Grove')
        path = state.directory / KEY_FILE
        key = Ed25519PrivateKey.generate()
        onboarding.write_private(path, key.private_bytes_raw())
        with state.connect(write=True) as db:
            require_recent(db, actor)
            db.execute('''INSERT INTO grove_realm
                (singleton,id,name,public_key,issuer_node,issuer_origin,is_issuer) VALUES (1,?,?,?,?,?,1)''',
                ('grv1-' + secrets.token_hex(16), name, key.public_key().public_bytes_raw(), state.identity()[0], config.origin))
            db.execute('INSERT INTO grove_member VALUES (?,?,1)', (state.identity()[0], config.origin))
            audit(db, actor.operation_actor, actor.address, 'grove.created')
            row = db.execute('SELECT * FROM grove_realm').fetchone()
            publish(state, db, row)
            return realm_data(row)


def user_id(realm: str, account: str) -> str:
    return 'usr1-' + sha256((realm + '\0' + account).encode()).hexdigest()[:32]


def public_users(db, realm: str) -> list[dict]:
    rows = db.execute('''SELECT id,username,role,enabled,auth_epoch,require_mfa FROM panel_account
                         WHERE NOT EXISTS (SELECT 1 FROM grove_account WHERE account_id=panel_account.id) ORDER BY id''').fetchall()
    return [{'id': user_id(realm, row['id']), 'name': row['username'], 'role': row['role'],
             'enabled': bool(row['enabled']), 'epoch': row['auth_epoch'], 'require_mfa': bool(row['require_mfa'])} for row in rows]


def publish(state: State, db, row=None) -> dict:
    row = row or db.execute('SELECT * FROM grove_realm').fetchone()
    if row is None:
        raise PeerError('NOT_FOUND', 'This node has no Grove')
    if not row['is_issuer']:
        if not row['manifest']:
            raise PeerError('OFFLINE', 'Grove identity directory has not synchronized yet')
        return json.loads(row['manifest'])
    key = issuer_key(state, row)
    users = public_users(db, row['id'])
    members = [dict(member) for member in db.execute('SELECT * FROM grove_member ORDER BY node_id')]
    if len(users) > 64 or len(members) > 64:
        raise PeerError('BUSY', 'Grove supports up to 64 identities and members')
    now = int(time.time())
    if row['manifest']:
        old = verified('directory', json.loads(row['manifest']), row['public_key'])
        if old['users'] == users and old['members'] == members and old['expires_at'] > now + 120:
            return json.loads(row['manifest'])
    payload = {'version': 1, 'realm': realm_data(row), 'sequence': row['sequence'] + 1,
               'issued_at': now, 'expires_at': now + DIRECTORY_TTL, 'users': users, 'members': members}
    envelope = signed('directory', payload, key)
    db.execute('UPDATE grove_realm SET sequence=?,manifest=?', (payload['sequence'], json.dumps(envelope)))
    return envelope


def describe(state: State, *, private: bool = False) -> dict:
    with state.connect(write=private) as db:
        row = db.execute('SELECT * FROM grove_realm').fetchone()
        if row is None:
            return {'configured': False}
        result = {'configured': True, 'realm': realm_data(row), 'local_issuer': bool(row['is_issuer']),
                  'frozen': row['frozen'], 'issuer_paused': bool(row['issuer_paused'])}
        continuity = db.execute('SELECT sequence,lease_until,anchor,recovery_proof FROM grove_login_continuity').fetchone()
        if continuity and continuity['sequence'] == row['sequence']:
            result['issuer_retired'] = True
        if private:
            result['members'] = [dict(member) for member in db.execute('SELECT * FROM grove_member ORDER BY node_id')]
            if row['is_issuer']:
                requests = {event: {} for event in DIRECTORY_REQUEST_EVENTS.values()}
                for item in db.execute(
                    """SELECT event, target, MIN(recorded_at) AS recorded_at FROM audit
                       WHERE event IN (?, ?) AND reason=?
                         AND target IN (SELECT node_id FROM grove_member WHERE enabled=1) GROUP BY event, target""",
                    (*DIRECTORY_REQUEST_EVENTS.values(), row['id']),
                ):
                    requests[item['event']][item['target']] = item['recorded_at']
                result['directory_requested_at'] = requests[DIRECTORY_REQUEST_EVENTS['https']]
                result['directory_mesh_requested_at'] = requests[DIRECTORY_REQUEST_EVENTS['mesh']]
            try:
                if row['frozen'] or row['issuer_paused']:
                    # Recovery may retain a signed directory while preventing new publication.
                    envelope = json.loads(row['manifest']) if row['manifest'] else None
                else:
                    envelope = publish(state, db, row)
                if envelope is not None:
                    directory = verified('directory', envelope, row['public_key'])
                    if not row['is_issuer'] and (lease := member_directory_lease(db, row['sequence'])) is not None:
                        directory['expires_at'] = lease['lease_until']
                    if result.get('issuer_retired') and not row['is_issuer']:
                        directory['members'] = members_after_handoff(db, directory['members'])
                        kind = 'login-continuity' if continuity['recovery_proof'] is None else 'login-recovery'
                        anchor = verified(kind, json.loads(continuity['anchor']), row['public_key'])
                        local = db.execute('SELECT node_id FROM node').fetchone()[0]
                        result['identity_voter'] = local in anchor['voters']
                    result.update(members=directory['members'], sequence=directory['sequence'], valid_until=directory['expires_at'])
                    if not row['frozen'] and not row['issuer_paused'] and directory['expires_at'] > int(time.time()):
                        result['member_directory'] = member_directory_version(directory)
                    if not row['issuer_paused']:
                        revoked = {item[0] for item in db.execute('SELECT user_id FROM grove_login_revocation')}
                        roles = {item['user_id']: item['role'] for item in db.execute('SELECT user_id,role FROM grove_login_role')}
                        result['users'] = [user | {'enabled': user['enabled'] and user['id'] not in revoked,
                                                  'role': roles.get(user['id'], user['role']),
                                                  'can_suspend': user['role'] == 'remote_operator' and roles.get(user['id']) != 'node_admin'}
                                           for user in directory['users']]
                        if not row['is_issuer'] and result.get('issuer_retired'):
                            if result['identity_voter']:
                                result['operator_revocation'] = 'available' if result.get('member_directory') else 'awaiting-quorum'
                            admins = [user['id'] for user in directory['users'] if user['enabled'] and user['role'] == 'node_admin']
                            if admins:
                                result['recovery_admin'] = min(admins)
                            result['role_votes'] = [item[0] for item in db.execute('''SELECT v.user_id FROM grove_login_role_vote v
                                LEFT JOIN grove_login_role r ON v.user_id=r.user_id WHERE v.generation>coalesce(r.generation,0) ORDER BY v.user_id''')]
            except (PeerError, ValueError):
                pass
        return result


def start(state: State, config: Config, kind: str, address: str, *, realm: dict | None = None,
          setup_token: str | None = None, actor: auth.Actor | None = None,
          local_browser: bool = False, verification_origin: str | None = None,
          directory_origins: list[str] | None = None) -> tuple[str, str]:
    if kind not in {'login', 'join'}:
        raise PeerError('INVALID_REQUEST', 'Invalid sign-in purpose')
    if verification_origin is not None:
        verification_origin = origin(verification_origin)
        if kind != 'join' or verification_origin == config.origin:
            raise PeerError('INVALID_REQUEST', 'Select the HTTPS panel of an existing Grove member')
    now = int(time.time())
    setup_hash = None
    with state.lock('onboarding.lock'):
        with auth.authentication_attempt(state, address, now) as (db, _):
            current = db.execute('SELECT * FROM grove_realm').fetchone()
            if kind == 'login':
                if current is None or current['is_issuer'] or current['frozen'] not in {'', 'restore'}:
                    raise PeerError('DENIED', 'Grove login is unavailable on this node')
                if issuer_replaced(db):
                    raise PeerError('DENIED', 'Use this panel to sign in with the Grove account')
                realm = realm_data(current)
            else:
                if current is not None:
                    raise PeerError('CONFLICT', 'This node already belongs to a Grove')
                realm = invitation(realm)
                if setup_token is not None or (actor is None and local_browser):
                    record = onboarding.owner_record(state, db, setup_token, now, local_browser=local_browser)
                    if record is None:
                        raise PeerError('DENIED', 'A valid node-owner setup code is required')
                    setup_hash = auth.digest(record['token'] if setup_token is not None else 'local-browser:' + record['token'])
                elif actor:
                    require_recent(db, actor)
                else:
                    raise PeerError('DENIED', 'Node owner confirmation is required')
            browser = secrets.token_urlsafe(32)
            nonce = secrets.token_urlsafe(32)
            db.execute('DELETE FROM grove_login_flow WHERE expires_at<=?', (now,))
            if db.execute('SELECT count(*) FROM grove_login_flow').fetchone()[0] >= 500:
                raise PeerError('BUSY', 'Too many pending Grove sign-ins')
            flow_realm = {'realm': realm, 'directory_origins': directory_origins} if directory_origins else realm
            db.execute('INSERT INTO grove_login_flow VALUES (?,?,?,?,?,?)',
                       (nonce, auth.digest(browser), now + FLOW_TTL, kind, json.dumps(flow_realm), setup_hash))
        payload = {'version': 1, 'realm_id': realm['id'], 'kind': kind, 'node_id': state.identity()[0],
                   'public_key': wire_b64(state.identity()[1]), 'origin': config.origin, 'nonce': nonce,
                   'issued_at': now, 'expires_at': now + FLOW_TTL}
        if verification_origin is not None and verification_origin != realm['issuer_origin']:
            payload['verification_origin'] = verification_origin
        request = signed('request', payload, state.signing_key())
        return (verification_origin or realm['issuer_origin']) + '/#/grove-authorize/' + wire_b64(encoded(request)), browser


def request_data(raw: str) -> dict:
    try:
        envelope = decode_json(parse_b64(raw, 8192))
        unsafe = decode_json(parse_b64(envelope['record'], 4096))
        public = parse_b64(unsafe['public_key'], 32)
        data = verified('request', envelope, public, 4096)
        expected = {'version', 'realm_id', 'kind', 'node_id', 'public_key', 'origin', 'nonce', 'issued_at', 'expires_at'}
        if 'verification_origin' in data:
            if data.get('kind') != 'join' or origin(data['verification_origin']) == data.get('origin'):
                raise ValueError
            expected.add('verification_origin')
        now = int(time.time())
        if (data.keys() != expected or data['version'] != 1 or data['kind'] not in {'login', 'join', 'directory'}
                or data['node_id'] != node_id(Ed25519PublicKey.from_public_bytes(public))
                or not isinstance(data['nonce'], str) or onboarding.TOKEN.fullmatch(data['nonce']) is None
                or type(data['issued_at']) is not int or type(data['expires_at']) is not int
                or not valid_time_window(data['issued_at'], data['expires_at'], now, FLOW_TTL)):
            raise ValueError
        origin(data['origin'])
        return data
    except (ValueError, KeyError, TypeError) as error:
        raise PeerError('INVALID_REQUEST', 'Invalid or expired Grove request') from error


def inspect(state: State, raw: str, actor: auth.Actor) -> dict:
    data = request_data(raw)
    if data['kind'] not in {'login', 'join'} or 'verification_origin' in data:
        raise PeerError('INVALID_REQUEST', 'Not a browser sign-in request')
    with state.connect() as db:
        realm = db.execute('SELECT * FROM grove_realm').fetchone()
        if realm is None or data['realm_id'] != realm['id']:
            raise PeerError('DENIED', 'The request belongs to another Grove')
        issuer_key(state, realm)
        if auth.active_session(db, actor.token_hash, int(time.time())) is None:
            raise PeerError('SESSION_REQUIRED', 'Sign in again')
        member = db.execute('SELECT * FROM grove_member WHERE node_id=?', (data['node_id'],)).fetchone()
        if data['kind'] == 'join':
            require_recent(db, actor)
            if member and not member['enabled']:
                raise PeerError('DENIED', 'This member has been revoked')
        elif not member or not member['enabled'] or member['origin'] != data['origin']:
            raise PeerError('DENIED', 'This node is not an approved Grove member')
        return {'kind': data['kind'], 'node_id': data['node_id'], 'origin': data['origin'], 'grove': realm['name'],
                'username': actor.username, 'role': actor.role}


def approve(state: State, raw: str, actor: auth.Actor) -> str:
    inspect(state, raw, actor)
    data = request_data(raw)
    now = int(time.time())
    with state.connect(write=True) as db:
        realm = db.execute('SELECT * FROM grove_realm').fetchone()
        current = auth.active_session(db, actor.token_hash, now)
        if current is None or current['id'] != actor.account_id or actor.grove:
            raise PeerError('DENIED', 'A local Grove identity is required')
        if data['kind'] == 'join':
            require_recent(db, actor)
            register_member(db, data)
        else:
            member = db.execute('SELECT * FROM grove_member WHERE node_id=?', (data['node_id'],)).fetchone()
            if member is None or not member['enabled'] or member['origin'] != data['origin']:
                raise PeerError('DENIED', 'Member is unavailable')
        account = auth.account_for(db, actor.username)
        stamp = db.execute('SELECT mfa_at FROM session WHERE token_hash=?', (actor.token_hash,)).fetchone()
        profile = next(user for user in public_users(db, realm['id']) if user['id'] == user_id(realm['id'], account['id']))
        redirect = browser_proof(state, db, realm, data, profile, stamp['mfa_at'], now)
        audit(db, actor.operation_actor, actor.address, 'grove.member_approved' if data['kind'] == 'join' else 'grove.login_approved', data['node_id'])
    return redirect


def register_member(db, data: dict) -> None:
    prior = db.execute('SELECT * FROM grove_member WHERE node_id=?', (data['node_id'],)).fetchone()
    if prior and (not prior['enabled'] or prior['origin'] != data['origin']):
        raise PeerError('DENIED', 'Member origin or revocation does not match')
    db.execute('INSERT OR IGNORE INTO grove_member VALUES (?,?,1)', (data['node_id'], data['origin']))


def browser_proof(state: State, db, realm, data: dict, profile: dict, mfa_at: int | None, now: int) -> str:
    key = issuer_key(state, realm)
    directory = verified('directory', publish(state, db, realm), realm['public_key'])
    payload = {'version': 1, 'realm': realm_data(realm), 'kind': data['kind'], 'node_id': data['node_id'],
               'origin': data['origin'], 'nonce': data['nonce'], 'user': profile, 'mfa_at': mfa_at,
               'issued_at': now, 'expires_at': now + PROOF_TTL, 'valid_until': now + DIRECTORY_TTL,
               'sequence': directory['sequence']}
    proof = signed('login', payload, key)
    return data['origin'] + '/#/grove-return/' + wire_b64(encoded(proof))


def profile_valid(user: dict) -> bool:
    import re
    from .accounts import USERNAME
    return (isinstance(user, dict) and user.keys() == {'id', 'name', 'role', 'enabled', 'epoch', 'require_mfa'}
            and isinstance(user['id'], str) and re.fullmatch(r'usr1-[a-f0-9]{32}', user['id']) is not None
            and isinstance(user['name'], str) and USERNAME.fullmatch(user['name']) is not None
            and user['role'] in {'node_admin', 'remote_operator'} and type(user['enabled']) is bool
            and type(user['epoch']) is int and 0 < user['epoch'] < 2**63 and type(user['require_mfa']) is bool)


def finish(state: State, config: Config, raw: str, browser: str, address: str) -> tuple[tuple[str, str], bool]:
    try:
        envelope = decode_json(parse_b64(raw, 8192))
        unsafe = decode_json(parse_b64(envelope['record'], 4096))
        nonce = unsafe['nonce']
        if not isinstance(nonce, str) or onboarding.TOKEN.fullmatch(nonce) is None or onboarding.TOKEN.fullmatch(browser) is None:
            raise ValueError
        with state.connect() as db:
            flow = db.execute('SELECT * FROM grove_login_flow WHERE nonce=?', (nonce,)).fetchone()
        now = int(time.time())
        if flow is None or flow['expires_at'] <= now or not secrets.compare_digest(flow['browser_hash'], auth.digest(browser)):
            raise ValueError
        saved = json.loads(flow['realm'])
        if not isinstance(saved, dict):
            raise ValueError
        realm = invitation(saved.get('realm', saved))
        seeds = saved.get('directory_origins', [])
        proof = verified('login', envelope, parse_b64(realm['public_key'], 32), 4096)
        fields = {'version', 'realm', 'kind', 'node_id', 'origin', 'nonce', 'user', 'mfa_at',
                  'issued_at', 'expires_at', 'valid_until', 'sequence'}
        if (proof.keys() != fields or type(proof['version']) is not int or proof['version'] != 1
                or proof['realm'] != realm or proof['kind'] != flow['kind'] or proof['node_id'] != state.identity()[0]
                or proof['origin'] != config.origin or proof['nonce'] != nonce or not profile_valid(proof['user'])
                or not proof['user']['enabled'] or flow['kind'] == 'join' and proof['user']['role'] != 'node_admin'
                or any(type(proof[key]) is not int for key in ('issued_at', 'expires_at', 'valid_until', 'sequence'))
                or not valid_time_window(proof['issued_at'], proof['expires_at'], now, PROOF_TTL)
                or not proof['expires_at'] <= proof['valid_until'] <= proof['issued_at'] + DIRECTORY_TTL
                or not 0 < proof['sequence'] < 2**63
                or proof['mfa_at'] is not None and (type(proof['mfa_at']) is not int or not 0 < proof['mfa_at'] <= now + CLOCK_SKEW)
                or proof['user']['require_mfa'] and proof['mfa_at'] is None):
            raise ValueError
    except (ValueError, TypeError, KeyError) as error:
        raise PeerError('DENIED', 'Grove sign-in proof is invalid, expired or belongs to another browser') from error
    # This credential is never disclosed and cannot be used for a local login.
    if not auth.PASSWORD_SLOTS.acquire(blocking=False):
        raise auth.LoginLimited(1)
    try:
        placeholder = auth.PASSWORD.hash(secrets.token_urlsafe(48))
    finally:
        auth.PASSWORD_SLOTS.release()
    cleanup = False
    with state.lock('onboarding.lock'):
        record = onboarding.read_record(state) if flow['setup_hash'] else None
        with state.connect(write=True) as db:
            current_flow = db.execute('SELECT * FROM grove_login_flow WHERE nonce=?', (nonce,)).fetchone()
            if current_flow is None or current_flow['expires_at'] <= int(time.time()):
                raise PeerError('EXPIRED', 'Grove sign-in was already consumed or expired')
            current = db.execute('SELECT * FROM grove_realm').fetchone()
            if current is None:
                if flow['kind'] != 'join':
                    raise PeerError('DENIED', 'The Grove trust configuration changed')
                db.execute('''INSERT INTO grove_realm
                    (singleton,id,name,public_key,issuer_node,issuer_origin,is_issuer,sequence) VALUES (1,?,?,?,?,?,0,?)''',
                    (realm['id'], realm['name'], parse_b64(realm['public_key'], 32), realm['issuer_node'], realm['issuer_origin'],
                     proof['sequence']))
            elif realm_data(current) != realm or current['is_issuer'] or current['frozen'] not in {'', 'restore'}:
                raise PeerError('DENIED', 'Grove trust is unavailable or changed')
            elif proof['sequence'] < current['sequence']:
                raise PeerError('DENIED', 'Grove sign-in uses an older identity version')
            elif issuer_replaced(db):
                raise PeerError('DENIED', 'The original Grove signing role has retired')
            user = proof['user']
            linked = db.execute('SELECT * FROM grove_account WHERE user_id=?', (user['id'],)).fetchone()
            if linked and user['epoch'] < linked['identity_epoch']:
                raise PeerError('DENIED', 'Grove credential version is older than the current identity')
            if flow['setup_hash']:
                account = onboarding.pending_account(db, record) if record else None
                owner_confirmed = account is not None and (
                    secrets.compare_digest(auth.digest('local-browser:' + record['token']), flow['setup_hash'])
                    or (record['expires_at'] > now and secrets.compare_digest(auth.digest(record['token']), flow['setup_hash'])))
                if not owner_confirmed:
                    raise PeerError('DENIED', 'Initial node ownership confirmation expired')
                account_id = account['id']
                db.execute('UPDATE panel_account SET password_hash=? WHERE id=?', (placeholder, account_id))
                cleanup = True
            elif linked:
                account_id = linked['account_id']
            else:
                account_id = 'acctg-' + sha256((realm['id'] + '\0' + user['id']).encode()).hexdigest()[:32]
                local_name = '@' + user['id']
                db.execute('''INSERT INTO panel_account (id,username,password_hash,role,operation_actor)
                              VALUES (?,?,?,?,?)''', (account_id, local_name, placeholder, user['role'], account_id))
            account = db.execute('SELECT * FROM panel_account WHERE id=?', (account_id,)).fetchone()
            if (not linked or linked['identity_epoch'] != user['epoch'] or account['role'] != user['role'] or not account['enabled']):
                factors.revoke_account_sessions(db, account_id)
            db.execute('UPDATE panel_account SET role=?,enabled=1,require_mfa=? WHERE id=?',
                       (user['role'], int(user['require_mfa']), account_id))
            db.execute('''INSERT INTO grove_account VALUES (?,?,?,?,?) ON CONFLICT(account_id) DO UPDATE SET
                        user_id=excluded.user_id,display_name=excluded.display_name,
                        identity_epoch=excluded.identity_epoch,valid_until=excluded.valid_until''',
                       (account_id, user['id'], user['name'], user['epoch'], proof['valid_until']))
            db.execute('INSERT INTO grove_member VALUES (?,?,1) ON CONFLICT(node_id) DO UPDATE SET origin=excluded.origin,enabled=1',
                       (state.identity()[0], config.origin))
            db.execute('INSERT OR IGNORE INTO grove_member VALUES (?,?,1)', (realm['issuer_node'], realm['issuer_origin']))
            db.execute("UPDATE grove_realm SET frozen='' WHERE frozen='restore'")
            db.execute('DELETE FROM grove_login_flow WHERE nonce=?', (nonce,))
            account = auth.account_for(db, account['username'])
            result = auth.issue_session(db, account, address, now, mfa_at=proof['mfa_at'], method='grove')
            audit(db, account['operation_actor'], address, 'grove.login', user['id'])
        if flow['kind'] == 'join' and seeds:
            try:
                onboarding.write_private(state.directory / DIRECTORY_SEEDS, encoded({'realm': realm, 'origins': seeds}))
            except (OSError, StateError):
                pass
        if cleanup:
            try:
                onboarding.clear_handoff(state)
            except (OSError, StateError):
                pass
    return result, flow['kind'] == 'join'


def directory_data(envelope: dict, realm: dict, *, allow_expired: bool = False) -> dict:
    data = verified('directory', envelope, parse_b64(realm['public_key'], 32))
    now = int(time.time())
    try:
        if (data.keys() != {'version', 'realm', 'sequence', 'issued_at', 'expires_at', 'users', 'members'}
                or data['version'] != 1 or data['realm'] != realm
                or any(type(data[key]) is not int for key in ('sequence', 'issued_at', 'expires_at'))
                or not 0 < data['sequence'] < 2**63 or data['issued_at'] > now + CLOCK_SKEW
                or not valid_time_window(data['issued_at'], data['expires_at'],
                                         min(now, data['issued_at']) if allow_expired else now, DIRECTORY_TTL)
                or not isinstance(data['users'], list) or len(data['users']) > 64
                or not isinstance(data['members'], list) or len(data['members']) > 64
                or not all(profile_valid(user) for user in data['users'])
                or len({user['id'] for user in data['users']}) != len(data['users'])):
            raise ValueError
        nodes = set()
        for member in data['members']:
            if (not isinstance(member, dict) or member.keys() != {'node_id', 'origin', 'enabled'}
                    or NODE_ID.fullmatch(member['node_id']) is None or member['node_id'] in nodes
                    or type(member['enabled']) is not int or member['enabled'] not in (0, 1)):
                raise ValueError
            origin(member['origin']); nodes.add(member['node_id'])
        return data
    except (ValueError, KeyError, TypeError) as error:
        raise PeerError('PROTOCOL', 'Invalid Grove identity directory') from error


def member_directory_version(directory: dict) -> dict:
    members = sorted((item['node_id'], item['origin'], item['enabled']) for item in directory['members'])
    return {'sequence': str(directory['sequence']), 'members_sha256': sha256(encoded({'members': members})).hexdigest(),
            'valid_until': directory['expires_at']}


def members_after_handoff(db, members: list[dict]) -> list[dict]:
    combined = {member['node_id']: member for member in members}
    for row in db.execute('SELECT node_id,origin,1 AS enabled FROM grove_member_admission ORDER BY node_id'):
        combined.setdefault(row['node_id'], dict(row))
    for row in db.execute('SELECT node_id FROM grove_member_departure'):
        combined.pop(row['node_id'], None)
    return list(combined.values())


def cached_member_directory_version(state: State, realm_id: str) -> dict | None:
    with state.connect(read_only=True) as db:
        db.execute('BEGIN')
        row = db.execute('SELECT * FROM grove_realm WHERE id=?', (realm_id,)).fetchone()
        lease = member_directory_lease(db, row['sequence']) if row is not None else None
        return signed_member_directory_version(row, lease, db)


def member_directory_lease(db, sequence: int):
    retired = db.execute('SELECT sequence,lease_until FROM grove_login_continuity').fetchone()
    if retired is not None:
        return retired
    return db.execute('''SELECT sequence,standby_lease_until AS lease_until FROM grove_login_replica
                          WHERE sequence=? AND standby_lease_until>issued_at+? AND standby_lease_until>?''',
                      (sequence, DIRECTORY_TTL, int(time.time()))).fetchone()


def issuer_replaced(db) -> bool:
    return db.execute('SELECT 1 FROM grove_login_continuity UNION ALL SELECT 1 FROM grove_login_recovery_vote LIMIT 1').fetchone() is not None


def signed_member_directory_version(row, lease=None, db=None) -> dict | None:
    if row is None or row['frozen'] or row['issuer_paused'] or not row['manifest']:
        return None
    try:
        if lease is not None:
            if lease['sequence'] != row['sequence'] or lease['lease_until'] <= int(time.time()):
                return None
            directory = verified('directory', json.loads(row['manifest']), row['public_key'])
            directory['expires_at'] = lease['lease_until']
            if db is not None:
                directory['members'] = members_after_handoff(db, directory['members'])
            return member_directory_version(directory)
        return member_directory_version(directory_data(json.loads(row['manifest']), realm_data(row)))
    except (PeerError, ValueError):
        return None


def apply_directory(state: State, envelope: dict) -> str:
    with state.connect() as db:
        realm = db.execute('SELECT * FROM grove_realm').fetchone()
    if realm is None or realm['is_issuer']:
        raise PeerError('DENIED', 'No remote Grove directory is configured')
    data = directory_data(envelope, realm_data(realm))
    result = 'applied'
    with state.connect(write=True) as db:
        current = db.execute('SELECT * FROM grove_realm').fetchone()
        if current is None or realm_data(current) != realm_data(realm):
            raise PeerError('CONFLICT', 'Grove trust changed while synchronizing')
        if issuer_replaced(db):
            raise PeerError('DENIED', 'The original Grove signing role has retired')
        if data['sequence'] < current['sequence']:
            return 'older'
        if data['sequence'] == current['sequence'] and current['manifest']:
            old = json.loads(current['manifest'])
            if old['record'] != envelope['record']:
                db.execute("UPDATE grove_realm SET frozen='conflict'")
                audit(db, 'system', realm['issuer_node'], 'grove.directory_conflict')
                return 'conflict'
            result = 'unchanged'
        users = {user['id']: user for user in data['users']}
        for linked in db.execute('SELECT ga.*,a.role,a.enabled,a.require_mfa FROM grove_account ga JOIN panel_account a ON a.id=ga.account_id').fetchall():
            user = users.get(linked['user_id'])
            enabled = user is not None and user['enabled']
            if user and user['epoch'] < linked['identity_epoch']:
                db.execute("UPDATE grove_realm SET frozen='credential-rollback'")
                audit(db, 'system', realm['issuer_node'], 'grove.credential_rollback', linked['user_id'])
                return 'conflict'
            changed = (linked['enabled'] != enabled or enabled and (user['epoch'] != linked['identity_epoch']
                       or user['role'] != linked['role'] or int(user['require_mfa']) != linked['require_mfa']))
            if changed:
                factors.revoke_account_sessions(db, linked['account_id'])
            if enabled:
                db.execute('UPDATE panel_account SET enabled=1,role=?,require_mfa=? WHERE id=?',
                           (user['role'], int(user['require_mfa']), linked['account_id']))
                db.execute('UPDATE grove_account SET display_name=?,identity_epoch=?,valid_until=? WHERE account_id=?',
                           (user['name'], user['epoch'], data['expires_at'], linked['account_id']))
            else:
                db.execute('UPDATE panel_account SET enabled=0 WHERE id=?', (linked['account_id'],))
        db.execute('DELETE FROM grove_member')
        for member in data['members']:
            db.execute('INSERT INTO grove_member VALUES (?,?,?)', (member['node_id'], member['origin'], member['enabled']))
        db.execute('UPDATE grove_realm SET sequence=?,manifest=?', (data['sequence'], json.dumps(envelope)))
    return result


def record_directory_request(db, realm, member_id: str, *, transport: str) -> None:
    event = DIRECTORY_REQUEST_EVENTS[transport]
    if realm['is_issuer'] and db.execute(
        'SELECT 1 FROM audit WHERE event=? AND target=? AND reason=? LIMIT 1', (event, member_id, realm['id']),
    ).fetchone() is None:
        audit(db, 'system', member_id, event, member_id, reason=realm['id'])


def directory_reply(state: State, raw: str) -> dict:
    data = request_data(raw)
    if data['kind'] != 'directory':
        raise PeerError('INVALID_REQUEST', 'Not a directory request')
    with state.connect(write=True) as db:
        realm = db.execute('SELECT * FROM grove_realm').fetchone()
        member = db.execute('SELECT * FROM grove_member WHERE node_id=?', (data['node_id'],)).fetchone()
        if (realm is None or realm['id'] != data['realm_id'] or not member or not member['enabled']
                or member['origin'] != data['origin']):
            raise PeerError('DENIED', 'Not an active Grove member')
        envelope = publish(state, db, realm)
        record_directory_request(db, realm, data['node_id'], transport='https')
        return envelope


def directory_seeds(state: State, realm: dict) -> list[str]:
    path = state.directory / DIRECTORY_SEEDS
    try:
        private_path(path, 0o600)
        if path.stat().st_size > 8192:
            return []
        cache = decode_json(path.read_bytes())
        if cache['realm'] != realm or not isinstance(cache['origins'], list):
            return []
        return [origin(candidate) for candidate in cache['origins'][:8]]
    except (OSError, StateError, KeyError, ValueError, TypeError, PeerError):
        return []


def sync_http(state: State, config: Config) -> str:
    return pull_http(state, config)[0]


def pull_http(state: State, config: Config, *, extra_origins: tuple[str, ...] = ()) -> tuple[str, str | None]:
    with state.connect() as db:
        realm = db.execute('SELECT * FROM grove_realm').fetchone()
    if realm is None:
        return 'not-configured', None
    if realm['is_issuer']:
        with state.connect(write=True) as db:
            publish(state, db)
        return 'issuer', None
    identity = realm_data(realm)
    issuer = identity['issuer_origin']
    members = directory_seeds(state, identity)
    if realm['manifest']:
        try:
            directory = directory_data(json.loads(realm['manifest']), identity, allow_expired=True)
            members = [member['origin'] for member in directory['members'] if member['enabled']]
        except (PeerError, ValueError):
            pass
    candidates = [origin(candidate) for candidate in extra_origins]
    if onboarding.loopback_host(urlsplit(issuer).hostname):
        candidates.extend(candidate for candidate in members if candidate != issuer)
        candidates.append(issuer)
    else:
        candidates.extend([issuer, *members])
    targets = [candidate for candidate in dict.fromkeys(candidates) if candidate != config.origin][:8]
    now = int(time.time())
    payload = {'version': 1, 'realm_id': realm['id'], 'kind': 'directory', 'node_id': state.identity()[0],
               'public_key': wire_b64(state.identity()[1]), 'origin': config.origin,
               'nonce': secrets.token_urlsafe(32), 'issued_at': now, 'expires_at': now + 30}
    raw = wire_b64(encoded(signed('request', payload, state.signing_key())))
    context = directory_tls_context(config)
    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context), NoRedirect())
    last_error = None
    for target in targets:
        request = Request(target + '/api/v1/auth/grove/directory',
                          data=encoded({'request': raw}), headers={'Content-Type': 'application/json'}, method='POST')
        try:
            with opener.open(request, timeout=3) as response:
                body = response.read(MAX_DOCUMENT + 1)
            if len(body) > MAX_DOCUMENT:
                raise PeerError('PROTOCOL', 'Grove directory response is too large')
            status = apply_directory(state, decode_json(body))
            if status != 'older':
                return status, 'issuer-https' if target == issuer else 'member-https'
        except (PeerError, ValueError, OSError) as error:
            last_error = error
    if last_error is not None:
        raise last_error
    return 'unavailable', None


def directory_tls_context(config: Config) -> ssl.SSLContext:
    return ssl.create_default_context(cafile=str(config.grove_ca) if config.grove_ca is not None else None)


def set_member(state: State, actor: auth.Actor, member: str, enabled: bool) -> None:
    with state.connect(write=True) as db:
        require_recent(db, actor)
        realm = db.execute('SELECT * FROM grove_realm').fetchone()
        if realm is None or not realm['is_issuer'] or member == realm['issuer_node']:
            raise PeerError('DENIED', 'Only the identity node can manage other members')
        if db.execute('UPDATE grove_member SET enabled=? WHERE node_id=?', (int(enabled), member)).rowcount != 1:
            raise PeerError('NOT_FOUND', 'Unknown Grove member')
        audit(db, actor.operation_actor, actor.address, 'grove.member_enabled' if enabled else 'grove.member_disabled', member)
        publish(state, db)


def detach(state: State, expected: str) -> None:
    """Local owner recovery; caller stops the panel and saves a verified backup."""
    with state.connect(write=True) as db:
        realm = db.execute('SELECT * FROM grove_realm').fetchone()
        if realm is None or realm['id'] != expected:
            raise StateError('The confirmed Grove ID does not match')
        for row in db.execute('SELECT account_id FROM grove_account').fetchall():
            factors.revoke_account_sessions(db, row['account_id'])
            db.execute('UPDATE panel_account SET enabled=0 WHERE id=?', (row['account_id'],))
        db.execute('DELETE FROM grove_login_flow')
        db.execute('DELETE FROM grove_login_verifier')
        db.execute('DELETE FROM grove_login_replica')
        db.execute('DELETE FROM grove_login_continuity')
        db.execute('DELETE FROM grove_login_recovery_vote')
        db.execute('DELETE FROM grove_login_revocation')
        db.execute('DELETE FROM grove_login_password')
        db.execute('DELETE FROM grove_login_role')
        db.execute('DELETE FROM grove_login_role_vote')
        db.execute('DELETE FROM grove_member_admission')
        db.execute('DELETE FROM grove_member_admission_vote')
        db.execute('DELETE FROM grove_member_departure')
        db.execute('DELETE FROM grove_node_note')
        db.execute('DELETE FROM grove_account')
        db.execute('DELETE FROM grove_member')
        db.execute('DELETE FROM grove_realm')
        audit(db, 'admin', 'local', 'grove.detached', expected, reason='LOCAL_OWNER_RECOVERY')
