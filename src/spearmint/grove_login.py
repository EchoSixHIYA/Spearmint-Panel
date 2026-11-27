"""Verify Grove accounts at an explicitly enrolled member panel."""
from collections.abc import Callable
from contextlib import contextmanager
from hashlib import sha256
import json
import re
import secrets
from sqlite3 import Connection
import time

from argon2 import extract_parameters
from argon2.exceptions import VerificationError

from . import auth, factors, grove
from .peer.protocol import PeerError, parse_b64
from .state import State, audit


METHOD = 'grove.login.verifiers'
STANDBY_METHOD = 'grove.login.verifiers.v2'
RECOVERY_METHOD = 'grove.login.verifiers.v3'
VERIFIER_TTL = grove.DIRECTORY_TTL
STANDBY_TTL = 15 * 60


def export_verifiers(state: State, recipient: str, realm_id: str, authorize: Callable[[Connection], None],
                     standby_members: frozenset[str] | None = None, recovery_members: frozenset[str] | None = None,
                     *, standby_voters: frozenset[str] = frozenset()) -> dict:
    with state.connect(write=True) as db:
        authorize(db)
        realm = db.execute('SELECT * FROM grove_realm').fetchone()
        member = db.execute('SELECT enabled FROM grove_member WHERE node_id=?', (recipient,)).fetchone()
        if realm is None or realm['id'] != realm_id or member is None or not member['enabled']:
            raise PeerError('DENIED', 'Grove login verifier recipient is not active')
        key = grove.issuer_key(state, realm)
        directory = grove.verified('directory', grove.publish(state, db, realm), realm['public_key'])
        records = verifier_records(state, db, directory)
        content_digest = verifier_digest(records)
        verifiers = grove.signed('login-verifiers', {'realm_id': realm_id, 'recipient': recipient,
                                'sequence': directory['sequence'], 'issued_at': directory['issued_at'],
                                'expires_at': directory['issued_at'] + VERIFIER_TTL, 'records': [],
                                'profiles_only': True, 'verifiers_sha256': content_digest}, key)
        if standby_members is None:
            return verifiers
        voters = active_non_issuer_members(directory)
        authorization = {'realm_id': realm_id, 'sequence': directory['sequence'], 'directory_sha256': snapshot_digest(directory),
                         'verifiers_sha256': content_digest, 'voters': voters}
        standby = None
        recovery = None
        complete = len(voters) >= 2 and len(records) == sum(user['enabled'] for user in directory['users'])
        active = frozenset(voters)
        selected = standby_voters or standby_members
        standby_allowed = selected <= (active & standby_members) if standby_voters else selected == active
        if complete and standby_allowed and len(selected) >= 2 and recipient in selected:
            standby = grove.signed('login-standby', authorization | {'voters': sorted(selected),
                                   'not_after': directory['issued_at'] + STANDBY_TTL}, key)
        if complete and recovery_members is not None and frozenset(voters) == recovery_members:
            recovery = grove.signed('login-recovery', authorization, key)
        bundle = {'verifiers': verifiers, 'standby': standby}
        if recovery_members is not None:
            bundle['recovery'] = recovery
        return bundle


def active_non_issuer_members(directory: dict) -> list[str]:
    issuer = directory['realm']['issuer_node']
    return sorted(member['node_id'] for member in directory['members'] if member['enabled'] and member['node_id'] != issuer)


def snapshot_digest(directory: dict) -> str:
    return sha256(grove.encoded(directory)).hexdigest()


def verifier_records(state: State, db: Connection, directory: dict) -> list[dict]:
    rows = db.execute('''SELECT a.*, t.secret FROM panel_account a LEFT JOIN panel_totp t ON t.account_id=a.id
                         WHERE a.enabled=1 AND NOT EXISTS (SELECT 1 FROM grove_account WHERE account_id=a.id)
                         ORDER BY a.id''')
    profiles = {row['id']: row for row in directory['users']}
    return [{'profile': profiles[grove.user_id(directory['realm']['id'], row['id'])], 'password_hash': row['password_hash'],
             'totp': factors.unseal(state, row['id'], row['secret']) if row['require_mfa'] else None}
            for row in rows if not row['require_mfa'] or row['secret'] is not None]


def verifier_digest(records: list[dict]) -> str:
    return sha256(grove.encoded({'records': records})).hexdigest()


def verify_record(record: dict) -> None:
    if not isinstance(record, dict) or set(record) != {'profile', 'password_hash', 'totp'}:
        raise ValueError('Unexpected verifier fields')
    user, password_hash, totp = record['profile'], record['password_hash'], record['totp']
    if (not grove.profile_valid(user) or not user['enabled'] or user['require_mfa'] != (totp is not None)
            or totp is not None and (not isinstance(totp, str) or re.fullmatch(r'[A-Z2-7]{32}', totp) is None)):
        raise ValueError('Invalid verifier record')
    verify_password_hash(password_hash)


def verify_password_hash(password_hash: str) -> None:
    if not isinstance(password_hash, str) or len(password_hash) > 128:
        raise ValueError('Invalid password verifier')
    params = extract_parameters(password_hash)
    if (params.type != auth.PASSWORD.type or params.version != 19 or params.time_cost != auth.PASSWORD.time_cost
            or params.memory_cost != auth.PASSWORD.memory_cost or params.parallelism != auth.PASSWORD.parallelism
            or params.hash_len != auth.PASSWORD.hash_len or params.salt_len != auth.PASSWORD.salt_len):
        raise ValueError('Unsupported password verifier parameters')


def import_snapshot(state: State, db, directory: dict, records: list[dict], digest: str) -> None:
    profiles = {user['id']: user for user in directory['users'] if user['enabled']}
    if not isinstance(records, list) or len(records) != len(profiles) or verifier_digest(records) != digest:
        raise PeerError('DENIED', 'Grove verifier data does not match the recovery authorization')
    seen = set()
    try:
        for record in records:
            verify_record(record)
            profile = record['profile']
            if profile['id'] in seen or profile != profiles.get(profile['id']):
                raise ValueError
            seen.add(profile['id'])
    except (ValueError, TypeError, KeyError, VerificationError) as error:
        raise PeerError('DENIED', 'Invalid Grove recovery verifier data') from error
    factors.initialize_vault(state)
    store_records(state, db, records, seen)
    import_public_snapshot(db, directory, digest)


def import_public_snapshot(db, directory, digest):
    db.execute('''INSERT INTO grove_login_replica(singleton,sequence,issued_at,expires_at,payload_digest,content_digest)
                  VALUES (1,?,?,?,?,?) ON CONFLICT(singleton) DO UPDATE SET sequence=excluded.sequence,
                  issued_at=excluded.issued_at,expires_at=0,payload_digest=excluded.payload_digest,
                  content_digest=excluded.content_digest,standby=NULL,recovery=NULL,standby_lease_until=0''',
               (directory['sequence'], directory['issued_at'], 0, digest, digest))


def store_records(state: State, db, records: list[dict], seen: set[str]) -> None:
    from . import grove_accounts

    for record in records:
        profile = record['profile']
        sealed = factors.seal(state, profile['id'], json.dumps([record['password_hash'], record['totp']], ensure_ascii=True))
        db.execute('''INSERT INTO grove_login_verifier(user_id,username,role,epoch,verifier) VALUES (?,?,?,?,?)
                      ON CONFLICT(user_id) DO UPDATE SET username=excluded.username,role=excluded.role,
                      last_step=CASE WHEN excluded.epoch=grove_login_verifier.epoch THEN grove_login_verifier.last_step ELSE -1 END,
                      epoch=excluded.epoch,verifier=excluded.verifier''',
                   (profile['id'], profile['name'], profile['role'], profile['epoch'], sealed))
    db.execute('DELETE FROM grove_login_verifier WHERE user_id NOT IN (SELECT value FROM json_each(?))', (json.dumps(sorted(seen | grove_accounts.projected_ids(db))),))
    grove_accounts.restore_verifiers(state, db)


def apply_verifiers(state: State, envelope: dict, standby: dict | None = None, recovery: dict | None = None) -> str:
    local_id = state.verify()
    with state.lock('maintenance.lock'), state.connect(write=True) as db:
        realm = db.execute('SELECT * FROM grove_realm').fetchone()
        member = db.execute('SELECT enabled FROM grove_member WHERE node_id=?', (local_id,)).fetchone()
        if realm is None or realm['is_issuer'] or realm['frozen'] or not member or not member['enabled'] or not realm['manifest']:
            raise PeerError('DENIED', 'Grove member login is unavailable')
        if grove.issuer_replaced(db):
            raise PeerError('DENIED', 'The original Grove signing role has retired')
        data = grove.verified('login-verifiers', envelope, realm['public_key'])
        directory = grove.directory_data(json.loads(realm['manifest']), grove.realm_data(realm))
        try:
            if (not isinstance(data, dict) or set(data) != {'realm_id', 'recipient', 'sequence', 'issued_at', 'expires_at', 'records',
                        'profiles_only', 'verifiers_sha256'}
                    or data['realm_id'] != realm['id'] or data['recipient'] != local_id
                    or type(data['sequence']) is not int or data['sequence'] != realm['sequence']
                    or type(data['issued_at']) is not int or data['issued_at'] != directory['issued_at']
                    or type(data['expires_at']) is not int
                    or data['expires_at'] != directory['issued_at'] + VERIFIER_TTL
                    or data['profiles_only'] is not True or data['records'] != []
                    or not isinstance(data['verifiers_sha256'], str) or not re.fullmatch(r'[a-f0-9]{64}', data['verifiers_sha256'])):
                raise ValueError('Verifier snapshot does not match the current directory')
        except (KeyError, TypeError, ValueError, VerificationError) as error:
            raise PeerError('PROTOCOL', 'Invalid Grove login verifier snapshot') from error

        digest = sha256(grove.encoded(data)).hexdigest()
        content_digest = data['verifiers_sha256']
        active = active_non_issuer_members(directory)
        expected = {'realm_id': realm['id'], 'sequence': directory['sequence'], 'directory_sha256': snapshot_digest(directory),
                    'verifiers_sha256': content_digest, 'voters': active}
        if standby is not None or recovery is not None:
            if len(expected['voters']) < 2 or local_id not in expected['voters']:
                raise PeerError('PROTOCOL', 'Incomplete Grove login snapshot')
            if standby is not None:
                selected = grove.verified('login-standby', standby, realm['public_key'])
                voters = selected.get('voters')
                if (not isinstance(voters, list) or not 2 <= len(voters) <= len(active)
                        or any(not isinstance(voter, str) or voter not in active for voter in voters)
                        or voters != sorted(set(voters)) or local_id not in voters
                        or selected != (expected | {'voters': voters, 'not_after': directory['issued_at'] + STANDBY_TTL})):
                    raise PeerError('PROTOCOL', 'Invalid Grove standby authorization')
            if recovery is not None and grove.verified('login-recovery', recovery, realm['public_key']) != expected:
                raise PeerError('PROTOCOL', 'Invalid Grove recovery authorization')
        standby_json = json.dumps(standby) if standby is not None else None
        recovery_json = json.dumps(recovery) if recovery is not None else None
        previous = db.execute('SELECT * FROM grove_login_replica').fetchone()
        if previous and previous['sequence'] == data['sequence']:
            if not secrets.compare_digest(previous['payload_digest'], digest) and previous['content_digest'] != content_digest:
                raise PeerError('CONFLICT', 'Conflicting Grove login verifier snapshots')
            if previous['content_digest'] is None or previous['standby'] != standby_json or previous['recovery'] != recovery_json:
                db.execute('''UPDATE grove_login_replica SET content_digest=?,recovery=?,
                              standby_lease_until=CASE WHEN standby IS ? THEN standby_lease_until ELSE 0 END,standby=?''',
                           (content_digest, recovery_json, standby_json, standby_json))
            return 'unchanged'
        db.execute('''INSERT INTO grove_login_replica(singleton,sequence,issued_at,expires_at,payload_digest,content_digest,standby,recovery)
                      VALUES (1,?,?,?,?,?,?,?) ON CONFLICT(singleton) DO UPDATE SET
                      sequence=excluded.sequence,issued_at=excluded.issued_at,expires_at=excluded.expires_at,
                      payload_digest=excluded.payload_digest,content_digest=excluded.content_digest,
                      standby=excluded.standby,standby_lease_until=0,recovery=excluded.recovery''',
                   (data['sequence'], data['issued_at'], data['expires_at'], digest, content_digest, standby_json, recovery_json))
        return 'applied'


def usable_replica(db, now: int, *, operational: bool = False):
    if operational:
        from . import grove_availability
        if not grove_availability.ordinary(db, now):
            return None
    return db.execute('''SELECT coalesce(c.lease_until,max(replica.expires_at,replica.standby_lease_until)) AS expires_at
                         FROM grove_login_replica replica JOIN grove_realm realm
                         ON realm.sequence=replica.sequence AND realm.is_issuer=0 AND realm.frozen=''
                         LEFT JOIN grove_login_continuity c ON c.singleton=1
                         WHERE realm.issuer_paused=0 AND (? OR coalesce(c.lease_until,max(replica.expires_at,replica.standby_lease_until))>?) AND EXISTS (
                             SELECT 1 FROM grove_member m JOIN node n ON m.node_id=n.node_id WHERE m.enabled=1
                         ) AND (c.singleton IS NULL OR c.sequence=replica.sequence)''', (operational, now)).fetchone()


def available(state: State) -> bool:
    with state.connect(read_only=True) as db:
        return usable_replica(db, int(time.time()), operational=True) is not None


def password_verifier(state: State, user_id: str, sealed: bytes) -> str:
    change = json.loads(factors.unseal(state, user_id, sealed))
    return json.loads(parse_b64(change['record'], 2048))['password_hash']


@contextmanager
def verified_password(state: State, username: str, password: str, code: str | None, address: str):
    from . import grove_accounts

    def read_verifier(db):
        if usable_replica(db, int(time.time()), operational=True) is None:
            raise PeerError('OFFLINE', 'This member has no current Grove login verifiers')
        row = db.execute('''SELECT v.*, p.change_digest, p.document AS password_change, coalesce(r.role,v.role) AS effective_role
                             FROM grove_login_verifier v LEFT JOIN grove_login_password p ON p.user_id=v.user_id
                             LEFT JOIN grove_login_role r ON r.user_id=v.user_id WHERE v.username=?
                             AND NOT EXISTS (SELECT 1 FROM grove_login_revocation r WHERE r.user_id=v.user_id)''', (username,)).fetchone()
        if row is not None and grove_accounts.device_key(db, row['user_id']) is None:
            return dict(row) | {'account_password': grove_accounts.login_password(state, db, username)}
        return None

    with auth.authentication_attempt(state, address, int(time.time()), username=username) as (db, _):
        verifier = read_verifier(db)
        comparison = auth.bootstrap_account(db)
    if not auth.PASSWORD_SLOTS.acquire(blocking=False):
        raise auth.LoginLimited(1)
    try:
        totp = None
        if verifier is not None:
            password_hash, totp = json.loads(factors.unseal(state, verifier['user_id'], verifier['verifier']))
            if verifier['account_password']:
                password_hash = verifier['account_password']
            elif verifier['password_change'] is not None:
                # The signed change is validated and sealed when the member accepts it.
                password_hash = password_verifier(state, verifier['user_id'], verifier['password_change'])
            valid = auth.PASSWORD.verify(password_hash, password)
        else:
            if comparison is not None:
                auth.PASSWORD.verify(comparison['password_hash'], password)
            valid = False
    except VerificationError:
        valid = False
    finally:
        auth.PASSWORD_SLOTS.release()

    with state.connect(write=True) as db:
        now = int(time.time())
        if not valid or verifier is None or read_verifier(db) != verifier:
            auth.auth_rejection(db, None, address, 'grove.login_rejected', 'VERIFIER_INVALID')
            yield db, None, False
            return
        if totp is not None:
            step = factors.matching_step(totp, code or '', now, verifier['last_step'])
            if step is None:
                auth.auth_rejection(db, None, address, 'grove.login_rejected', 'FACTOR_INVALID')
                yield db, None, False
                return
            db.execute('UPDATE grove_login_verifier SET last_step=? WHERE user_id=?', (step, verifier['user_id']))
        yield db, verifier, totp is not None


def login(state: State, username: str, password: str, code: str | None, address: str) -> tuple[str, str] | None:
    with verified_password(state, username, password, code, address) as (db, verifier, has_factor):
        if verifier is None:
            return None
        now = int(time.time())
        realm = db.execute('SELECT id FROM grove_realm').fetchone()
        linked = db.execute('SELECT * FROM grove_account WHERE user_id=?', (verifier['user_id'],)).fetchone()
        if linked and verifier['epoch'] < linked['identity_epoch']:
            raise PeerError('DENIED', 'Grove credential version is older than the current identity')
        account_id = linked['account_id'] if linked else 'acctg-' + sha256((realm['id'] + '\0' + verifier['user_id']).encode()).hexdigest()[:32]
        if linked is None:
            db.execute('''INSERT INTO panel_account(id, username, password_hash, role, operation_actor)
                          VALUES (?,?,?,?,?)''', (account_id, '@' + verifier['user_id'], 'grove-only', verifier['effective_role'], account_id))
        account = db.execute('SELECT * FROM panel_account WHERE id=?', (account_id,)).fetchone()
        if linked and (linked['valid_until'] == -1 or linked['identity_epoch'] != verifier['epoch'] or account['role'] != verifier['effective_role']
                       or not account['enabled'] or bool(account['require_mfa']) != has_factor):
            factors.revoke_account_sessions(db, account_id)
        db.execute('UPDATE panel_account SET enabled=1,role=?,require_mfa=? WHERE id=?',
                   (verifier['effective_role'], int(has_factor), account_id))
        db.execute('''INSERT INTO grove_account VALUES (?,?,?,?,?) ON CONFLICT(account_id) DO UPDATE SET
                      display_name=excluded.display_name,identity_epoch=excluded.identity_epoch,valid_until=0''',
                   (account_id, verifier['user_id'], username, verifier['epoch'], 0))
        db.execute('DELETE FROM login_attempt WHERE address=? AND account_key=?', (address, auth.digest(username)))
        account = auth.account_for(db, account['username'])
        audit(db, account['operation_actor'], address, 'grove.login', verifier['user_id'])
        return auth.issue_session(db, account, address, now, mfa_at=now if has_factor else None, method='grove-member', grove_replica=True)
