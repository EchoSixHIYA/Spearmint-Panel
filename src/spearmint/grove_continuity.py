"""Continue Grove login on a snapshot approved by the original issuer or its members."""
from hashlib import sha256
import json
import re
import time

from argon2.exceptions import VerificationError
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import auth, factors, grove, grove_login
from .peer.credentials import node_id
from .peer.protocol import PeerError, parse_b64, wire_b64
from .state import State, audit


METHOD = 'grove.login.continuity'
VOTE_METHOD = 'grove.login.continuity.v2'
PASSWORD_VOTE_METHOD = 'grove.login.continuity.v3'
ROLE_VOTE_METHOD = 'grove.login.continuity.v4'
MEMBERS_VOTE_METHOD = 'grove.login.continuity.v5'
ACCOUNTS_VOTE_METHOD = 'grove.login.continuity.v6'
STATUS_METHOD = 'grove.login.continuity.ready'
INSTALL_METHOD = 'grove.login.continuity.install'
DOCUMENT_METHOD = 'grove.login.continuity.get'
SNAPSHOT_METHOD = 'grove.login.continuity.snapshot'
RECOVERY_VOTE_METHOD = 'grove.login.recovery.vote'
ANCHOR_DIGEST = re.compile(r'[a-f0-9]{64}')
LEASE_SECONDS = grove.DIRECTORY_TTL
ANCHOR_FIELDS = {'realm_id', 'sequence', 'directory_sha256', 'verifiers_sha256', 'voters'}
VOTE_FIELDS = {'requester', 'nonce', 'anchor', 'issued_at', 'public_key'}
EMPTY_REVOCATIONS = sha256(grove.encoded({'users': []})).hexdigest()
EMPTY_PASSWORDS = EMPTY_REVOCATIONS
EMPTY_ROLES = EMPTY_REVOCATIONS
EMPTY_ADMISSIONS = sha256(grove.encoded({'members': []})).hexdigest()


def base_envelope(envelope):
    # Local promises/jobs are never exported as part of the public authorization.
    if isinstance(envelope, dict) and envelope.keys() == {'record', 'signature', 'voter_state'}:
        return {field: envelope[field] for field in ('record', 'signature')}
    return envelope


def issue_anchor(state: State, actor: auth.Actor, voters: frozenset[str], readiness: dict[str, dict],
                 selected: bool = False) -> tuple[dict, dict]:
    """A local issuer owner seals the current identities and retires issuing."""
    with state.connect(write=True) as db:
        grove.require_recent(db, actor)
        realm = db.execute('SELECT * FROM grove_realm').fetchone()
        if realm is None or not realm['is_issuer']:
            raise PeerError('DENIED', 'Only the original Grove identity node can retire its signing role')
        previous = db.execute('SELECT anchor FROM grove_login_continuity').fetchone()
        if previous is not None:
            envelope = base_envelope(json.loads(previous['anchor']))
            return envelope, grove.verified('login-continuity', envelope, realm['public_key'])
        if len(voters) < 2:
            raise PeerError('INVALID_REQUEST', 'At least two enrolled members are required')
        key = grove.issuer_key(state, realm)
        if not realm['manifest']:
            raise PeerError('CONFLICT', 'Synchronize the identity snapshot before retiring the issuer')
        envelope = json.loads(realm['manifest'])
        directory = grove.directory_data(envelope, grove.realm_data(realm))
        members_now = [dict(member) for member in db.execute('SELECT * FROM grove_member ORDER BY node_id')]
        if directory['members'] != members_now or directory['users'] != grove.public_users(db, realm['id']):
            raise PeerError('CONFLICT', 'Publish and synchronize the updated identity snapshot before retirement')
        eligible = frozenset(grove_login.active_non_issuer_members(directory))
        if not voters <= eligible:
            raise PeerError('CONFLICT', 'Every Grove voter must be a current enabled member')
        if not selected and voters != eligible:
            raise PeerError('CONFLICT', 'Enroll every other active Grove member before retiring the issuer')
        records = grove_login.verifier_records(state, db, directory)
        if len(records) != sum(user['enabled'] for user in directory['users']):
            raise PeerError('CONFLICT', 'An enabled Grove account lacks a usable member login factor')
        try:
            for record in records:
                grove_login.verify_record(record)
        except (ValueError, VerificationError) as error:
            raise PeerError('CONFLICT', 'An enabled Grove account lacks a usable member login factor') from error
        payload = {'realm_id': realm['id'], 'sequence': directory['sequence'],
                   'directory_sha256': grove_login.snapshot_digest(directory), 'verifiers_sha256': grove_login.verifier_digest(records),
                   'voters': sorted(voters)}
        expected = {field: payload[field] for field in ('realm_id', 'sequence', 'directory_sha256', 'verifiers_sha256')}
        if not voters <= readiness.keys() or any(readiness[node] != expected for node in voters):
            raise PeerError('CONFLICT', 'Every voter must acknowledge the same current Grove snapshot before retirement')
        anchor = grove.signed('login-continuity', payload, key)
        db.execute('INSERT INTO grove_login_continuity(singleton,sequence,anchor) VALUES (1,?,?)',
                   (payload['sequence'], json.dumps(anchor)))
        db.execute('UPDATE grove_realm SET issuer_paused=1')
        audit(db, actor.operation_actor, actor.address, 'grove.issuer_retired', realm['id'])
        return anchor, payload


def readiness(state: State, realm_id: str) -> dict:
    with state.connect(read_only=True) as db:
        db.execute('BEGIN')
        realm = db.execute('SELECT * FROM grove_realm').fetchone()
        replica = db.execute('SELECT * FROM grove_login_replica').fetchone()
        if (realm is None or realm['id'] != realm_id or realm['is_issuer'] or realm['frozen'] or realm['issuer_paused']
                or not realm['manifest'] or not replica or replica['sequence'] != realm['sequence']
                or not replica['content_digest'] or replica['expires_at'] <= int(time.time())):
            raise PeerError('DENIED', 'The member has no current Grove verifier snapshot')
        directory = grove.directory_data(json.loads(realm['manifest']), grove.realm_data(realm))
        return {'realm_id': realm_id, 'sequence': realm['sequence'], 'directory_sha256': grove_login.snapshot_digest(directory),
                'verifiers_sha256': replica['content_digest']}


def verified_anchor(db, envelope: dict, *, kind: str = 'login-continuity') -> dict:
    realm = db.execute('SELECT * FROM grove_realm').fetchone()
    replica = db.execute('SELECT * FROM grove_login_replica').fetchone()
    if (realm is None or realm['is_issuer'] or realm['frozen'] or realm['issuer_paused'] or not realm['manifest']
            or replica is None or replica['sequence'] != realm['sequence']):
        raise PeerError('DENIED', 'The member has no applicable Grove verifier snapshot')
    local = db.execute('SELECT node_id FROM node').fetchone()[0]
    directory = grove.directory_data(json.loads(realm['manifest']), grove.realm_data(realm), allow_expired=True)
    data = snapshot_authorization(realm, directory, envelope, kind)
    if (data['sequence'] != realm['sequence'] or data['verifiers_sha256'] != replica['content_digest']
            or not admitted(db, data, local)):
        raise PeerError('DENIED', 'Retirement authorization does not match this member or its identity snapshot')
    return data


def admitted(db, anchor: dict, node: str) -> bool:
    historical = any(node in context['voters'] for context in anchor.get('_contexts', {}).values())
    return historical or node in anchor.get('_base_voters', anchor['voters']) or node in anchor['voters'] or db.execute('''SELECT 1 FROM grove_member_admission a
        WHERE a.node_id=? AND NOT EXISTS (SELECT 1 FROM grove_member_departure d WHERE d.node_id=a.node_id)''',
        (node,)).fetchone() is not None


def snapshot_authorization(realm, directory: dict, envelope: dict, kind: str) -> dict:
    data = grove.verified(kind, envelope, realm['public_key'])
    members = grove_login.active_non_issuer_members(directory)
    voters = data.get('voters')
    if (not isinstance(data, dict) or data.keys() != ANCHOR_FIELDS or data['realm_id'] != realm['id']
            or type(data['sequence']) is not int or data['sequence'] != directory['sequence']
            or data['directory_sha256'] != grove_login.snapshot_digest(directory)
            or not isinstance(data['verifiers_sha256'], str) or ANCHOR_DIGEST.fullmatch(data['verifiers_sha256']) is None
            or not isinstance(voters, list) or not 2 <= len(voters) <= len(members)
            or any(not isinstance(voter, str) or voter not in members for voter in voters)
            or voters != sorted(set(voters))
            or kind == 'login-recovery' and voters != members):
        raise PeerError('DENIED', 'Retirement authorization does not match this member or its identity snapshot')
    return data


def install_anchor(state: State, envelope: dict, authorize=None) -> dict:
    with state.connect(write=True) as db:
        if authorize is not None:
            authorize(db)
        anchor = verified_anchor(db, envelope)
        previous = db.execute('SELECT anchor FROM grove_login_continuity').fetchone()
        if previous is not None:
            if base_envelope(json.loads(previous['anchor'])) != envelope:
                raise PeerError('CONFLICT', 'The installed retirement authorization differs')
            return anchor
        if db.execute('SELECT 1 FROM grove_login_recovery_vote').fetchone():
            raise PeerError('CONFLICT', 'This member has already voted to recover the Grove')
        db.execute('INSERT INTO grove_login_continuity(singleton,sequence,anchor) VALUES (1,?,?)',
                   (anchor['sequence'], json.dumps(envelope)))
        audit(db, 'admin', 'local', 'grove.continuity_enrolled', anchor['realm_id'])
        return anchor


def recovery_candidate(db) -> tuple[dict, dict] | None:
    row = db.execute('''SELECT v.recovery FROM grove_login_replica v JOIN grove_realm r
                        ON r.sequence=v.sequence AND r.is_issuer=0 AND r.frozen='' AND r.issuer_paused=0
                        WHERE v.recovery IS NOT NULL AND NOT EXISTS (SELECT 1 FROM grove_login_continuity)''').fetchone()
    if row is None:
        return None
    envelope = json.loads(row['recovery'])
    return envelope, verified_anchor(db, envelope, kind='login-recovery')


def recovery_details(db) -> dict | None:
    current = recovery_candidate(db)
    if current is None:
        return None
    envelope, anchor = current
    replica = db.execute('SELECT issued_at FROM grove_login_replica').fetchone()
    ballot = db.execute('SELECT anchor_digest FROM grove_login_recovery_vote').fetchone()
    return {'sequence': anchor['sequence'], 'voters': len(anchor['voters']), 'required': len(anchor['voters']) // 2 + 1,
            'available_at': replica['issued_at'] + grove_login.STANDBY_TTL,
            'approved': ballot is not None and ballot['anchor_digest'] == anchor_digest(envelope)}


def recovery_ballot(state: State, realm_id: str, sequence: int) -> dict:
    """The local node owner permanently approves a specific stored recovery snapshot."""
    with state.connect(write=True) as db:
        current = recovery_candidate(db)
        if current is None or current[1]['realm_id'] != realm_id or current[1]['sequence'] != sequence:
            raise PeerError('CONFLICT', 'This node has no matching Grove recovery snapshot')
        envelope, anchor = current
        issued_at = db.execute('SELECT issued_at FROM grove_login_replica').fetchone()[0]
        if int(time.time()) < issued_at + grove_login.STANDBY_TTL:
            raise PeerError('CONFLICT', 'Wait for the original snapshot and its standby window to expire')
        digest = anchor_digest(envelope)
        prior = db.execute('SELECT * FROM grove_login_recovery_vote').fetchone()
        if prior is not None:
            if digest != prior['anchor_digest']:
                raise PeerError('CONFLICT', 'This node already approved another Grove recovery snapshot')
            return json.loads(prior['ballot'])
        key = state.signing_key()
        ballot = grove.signed('login-recovery-vote', {'anchor': digest, 'public_key': wire_b64(key.public_key().public_bytes_raw())}, key)
        db.execute('INSERT INTO grove_login_recovery_vote VALUES (1,?,?)', (digest, json.dumps(ballot)))
        audit(db, 'admin', 'local', 'grove.recovery_approved', anchor['realm_id'])
        return ballot


def recovery_status(state: State) -> tuple[dict, dict, dict] | None:
    with state.connect(read_only=True) as db:
        db.execute('BEGIN')
        ballot = db.execute('SELECT * FROM grove_login_recovery_vote').fetchone()
        current = recovery_candidate(db) if ballot else None
        if current is None or ballot['anchor_digest'] != anchor_digest(current[0]):
            return None
        return current[0], current[1], json.loads(ballot['ballot'])


def recovery_reply(db, requester: str, digest: str) -> dict:
    ballot = db.execute('SELECT * FROM grove_login_recovery_vote WHERE anchor_digest=?', (digest,)).fetchone()
    if ballot is None:
        raise PeerError('NOT_FOUND', 'This member has not approved the requested Grove recovery')
    current = recovery_candidate(db)
    if current is None:
        retired = db.execute('SELECT anchor,recovery_proof FROM grove_login_continuity WHERE recovery_proof IS NOT NULL').fetchone()
        realm = db.execute("SELECT public_key FROM grove_realm WHERE frozen='' AND issuer_paused=0").fetchone()
        if retired is not None and realm is not None:
            envelope = base_envelope(json.loads(retired['anchor']))
            current = envelope, grove.verified('login-recovery', envelope, realm['public_key'])
    if current is None or anchor_digest(current[0]) != digest or requester not in current[1]['voters']:
        raise PeerError('NOT_FOUND', 'This member has not approved the requested Grove recovery')
    return json.loads(ballot['ballot'])


def validate_recovery(db, document: dict) -> dict:
    if not isinstance(document, dict) or document.keys() != {'authorization', 'votes'} or not isinstance(document['votes'], dict):
        raise PeerError('INVALID_REQUEST', 'Invalid Grove recovery certificate')
    envelope = document['authorization']
    anchor = verified_anchor(db, envelope, kind='login-recovery')
    verify_recovery_votes(envelope, anchor, document['votes'])
    return anchor


def verify_recovery_votes(envelope: dict, anchor: dict, votes: dict) -> None:
    digest = anchor_digest(envelope)
    if not isinstance(votes, dict) or not votes.keys() <= set(anchor['voters']) or len(votes) <= len(anchor['voters']) // 2:
        raise PeerError('DENIED', 'Grove recovery requires approval from a majority of members')
    for voter, ballot in votes.items():
        try:
            raw = json.loads(parse_b64(ballot['record'], 512))
            public = parse_b64(raw['public_key'], 32)
            if node_id(Ed25519PublicKey.from_public_bytes(public)) != voter:
                raise ValueError
            if grove.verified('login-recovery-vote', ballot, public, 512) != {'anchor': digest, 'public_key': raw['public_key']}:
                raise ValueError
        except (KeyError, ValueError, TypeError, PeerError) as error:
            raise PeerError('DENIED', 'Invalid Grove recovery approval') from error


def install_recovery(state: State, document: dict) -> dict:
    with state.connect(write=True) as db:
        anchor = validate_recovery(db, document)
        authorization = document['authorization']
        previous = db.execute('SELECT anchor,recovery_proof FROM grove_login_continuity').fetchone()
        if previous:
            if previous['recovery_proof'] is None or base_envelope(json.loads(previous['anchor'])) != authorization:
                raise PeerError('CONFLICT', 'A different Grove continuity authorization is installed')
            return anchor
        replica = db.execute('SELECT recovery,issued_at FROM grove_login_replica').fetchone()
        vote = db.execute('SELECT anchor_digest FROM grove_login_recovery_vote').fetchone()
        if (vote is not None and vote['anchor_digest'] != anchor_digest(authorization)
                or replica['recovery'] is None or json.loads(replica['recovery']) != authorization
                or int(time.time()) < replica['issued_at'] + grove_login.STANDBY_TTL):
            raise PeerError('CONFLICT', 'The Grove recovery authorization is not current on this member')
        db.execute('INSERT INTO grove_login_continuity(singleton,sequence,anchor,recovery_proof) VALUES (1,?,?,?)',
                   (anchor['sequence'], json.dumps(authorization), json.dumps(document['votes'])))
        audit(db, 'admin', 'local', 'grove.recovery_activated', anchor['realm_id'])
        return anchor


def install_document(state: State, document: dict) -> dict:
    document, governance = split_document(document)
    if isinstance(document, dict) and 'votes' in document:
        result = install_recovery(state, document)
    else:
        result = install_anchor(state, document)
    if governance is not None:
        from . import grove_voters
        grove_voters.apply(state, governance, 'grove-continuity')
    return result


def split_document(document):
    if isinstance(document, dict) and document.keys() == {'authorization', 'governance'}:
        return document['authorization'], document['governance']
    return document, None


def retirement_document(db, realm_id: str, recipient: str) -> dict:
    realm = db.execute('SELECT * FROM grove_realm').fetchone()
    record = db.execute('SELECT sequence,anchor,recovery_proof FROM grove_login_continuity').fetchone()
    if (realm is None or realm['id'] != realm_id or realm['frozen'] or record is None
            or record['sequence'] != realm['sequence']):
        raise PeerError('NOT_FOUND', 'No Grove retirement authorization is available')
    envelope = base_envelope(json.loads(record['anchor']))
    proof = record['recovery_proof']
    anchor = grove.verified('login-continuity' if proof is None else 'login-recovery', envelope, realm['public_key'])
    from . import grove_voters
    anchor = grove_voters.extend(db, anchor)
    if not admitted(db, anchor, recipient):
        raise PeerError('DENIED', 'This member is outside the Grove retirement authorization')
    document = envelope if proof is None else {'authorization': envelope, 'votes': json.loads(proof)}
    from . import grove_voters
    governance = grove_voters.history(db)
    return {'authorization': document, 'governance': governance} if governance else document


def snapshot(state: State, db, realm_id: str, recipient: str) -> dict:
    current = read_anchor(db)
    if current is None or state.identity()[0] not in current[1]['voters']:
        raise PeerError('NOT_FOUND', 'No installed Grove identity snapshot')
    authorization = retirement_document(db, realm_id, recipient)
    realm = db.execute('SELECT public_key,manifest FROM grove_realm').fetchone()
    manifest = json.loads(realm['manifest'])
    directory = grove.verified('directory', manifest, realm['public_key'])
    profiles = {profile['id']: profile for profile in directory['users']}
    records = []
    for row in db.execute('SELECT user_id,verifier FROM grove_login_verifier'):
        if row['user_id'] not in profiles:
            continue
        password, totp = json.loads(factors.unseal(state, row['user_id'], row['verifier']))
        records.append({'profile': profiles[row['user_id']], 'password_hash': password, 'totp': totp})
    # The issuer exports verifier records in the order of the signed user directory.
    profiles_order = {profile['id']: index for index, profile in enumerate(directory['users'])}
    records.sort(key=lambda record: profiles_order[record['profile']['id']])
    if grove_login.verifier_digest(records) != current[1]['verifiers_sha256']:
        raise PeerError('CONFLICT', 'Local Grove verifier data does not match the authorization')
    return {'authorization': authorization, 'manifest': manifest, 'records': records}


def import_snapshot(state: State, bundle: dict, source: str, origin: str, authorize, admission_certificate=None) -> None:
    from . import grove_admission

    if not isinstance(bundle, dict) or bundle.keys() != {'authorization', 'manifest', 'records'}:
        raise PeerError('PROTOCOL', 'Invalid Grove recovery snapshot')
    document, governance = split_document(bundle['authorization'])
    recovered = isinstance(document, dict) and document.keys() == {'authorization', 'votes'}
    envelope = document['authorization'] if recovered else document
    local = state.identity()[0]
    with state.lock('maintenance.lock'), state.connect(write=True) as db:
        authorize(db)
        realm = db.execute('SELECT * FROM grove_realm').fetchone()
        if realm is None or realm['is_issuer'] or realm['issuer_paused'] or realm['frozen'] not in {'', 'restore'}:
            raise PeerError('DENIED', 'This node has no recoverable Grove membership')
        directory = grove.directory_data(bundle['manifest'], grove.realm_data(realm), allow_expired=True)
        anchor = snapshot_authorization(realm, directory, envelope, 'login-recovery' if recovered else 'login-continuity')
        from . import grove_voters
        base = anchor
        anchor = grove_voters.history_anchor(anchor, governance)
        private_voter_state = grove_voters.recovery_checkpoint(db)
        baseline_match = any(member['enabled'] and member['node_id'] == local and member['origin'] == origin
                             for member in directory['members'])
        pending_admission = False
        if local in anchor['voters']:
            matches_local = baseline_match
        else:
            admission = db.execute('SELECT certificate FROM grove_member_admission WHERE node_id=?', (local,)).fetchone()
            certificate = json.loads(admission['certificate']) if admission else admission_certificate if baseline_match else None
            matches_local = certificate is not None and grove_admission.validate_certificate(certificate, anchor,
                                                                                              anchor_digest(envelope)) == (local, origin)
            pending_admission = matches_local and admission is None
        if not matches_local or source not in anchor['voters'] or anchor['sequence'] < realm['sequence']:
            raise PeerError('DENIED', 'Recovery snapshot does not match this Grove member')
        if recovered:
            verify_recovery_votes(envelope, anchor, document['votes'])
            if int(time.time()) < directory['issued_at'] + grove_login.STANDBY_TTL:
                raise PeerError('CONFLICT', 'The original Grove authorization has not expired')
        if realm['manifest'] and anchor['sequence'] == realm['sequence']:
            prior = grove.verified('directory', json.loads(realm['manifest']), realm['public_key'])
            if prior['sequence'] == realm['sequence'] and grove_login.snapshot_digest(prior) != anchor['directory_sha256']:
                raise PeerError('CONFLICT', 'Recovery conflicts with the current Grove identity version')
        installed = db.execute('SELECT anchor FROM grove_login_continuity').fetchone()
        if installed is not None and (base_envelope(json.loads(installed['anchor'])) != envelope or realm['frozen'] != 'restore'):
            raise PeerError('CONFLICT', 'This node already has a Grove continuity authorization')
        ballot = db.execute('SELECT anchor_digest FROM grove_login_recovery_vote').fetchone()
        if ballot is not None and (not recovered or ballot['anchor_digest'] != anchor_digest(envelope)):
            raise PeerError('CONFLICT', 'This member approved a different Grove recovery')
        profiles = {profile['id']: profile for profile in directory['users']}
        for linked in db.execute('SELECT user_id,identity_epoch FROM grove_account'):
            current = profiles.get(linked['user_id'])
            if current is not None and current['epoch'] < linked['identity_epoch']:
                raise PeerError('CONFLICT', 'Recovery would roll back a Grove credential version')
        grove_login.import_snapshot(state, db, directory, bundle['records'], anchor['verifiers_sha256'])
        db.execute('DELETE FROM session WHERE account_id IN (SELECT account_id FROM grove_account)')
        db.execute('DELETE FROM grove_login_flow')
        db.execute('UPDATE grove_account SET valid_until=0')
        db.execute('DELETE FROM grove_member')
        db.executemany('INSERT INTO grove_member VALUES (?,?,?)',
                       ((member['node_id'], member['origin'], member['enabled']) for member in directory['members']))
        if pending_admission:
            grove_admission.admit(db, admission_certificate, anchor, envelope, source)
        db.execute('''INSERT OR IGNORE INTO grove_member SELECT a.node_id,a.origin,
                      NOT EXISTS (SELECT 1 FROM grove_member_departure d WHERE d.node_id=a.node_id)
                      FROM grove_member_admission a''')
        db.execute('UPDATE grove_member SET enabled=0 WHERE node_id IN (SELECT node_id FROM grove_member_departure)')
        db.execute("UPDATE grove_realm SET sequence=?,manifest=?,frozen=''", (anchor['sequence'], json.dumps(bundle['manifest'])))
        db.execute('''INSERT INTO grove_login_continuity(singleton,sequence,anchor,recovery_proof) VALUES (1,?,?,?)
                      ON CONFLICT(singleton) DO UPDATE SET sequence=excluded.sequence,anchor=excluded.anchor,
                      recovery_proof=excluded.recovery_proof,lease_until=0''',
                   (anchor['sequence'], json.dumps(envelope), json.dumps(document['votes']) if recovered else None))
        grove_voters.restore_checkpoint(db, private_voter_state)
        grove_voters.install_history(db, base, governance, source)
        audit(db, 'grove', source, 'grove.snapshot_recovered', realm['id'])


def recovery_realm(state: State) -> str | None:
    with state.connect(read_only=True) as db:
        row = db.execute('''SELECT r.id FROM grove_realm r WHERE r.is_issuer=0 AND r.issuer_paused=0
                            AND r.frozen IN ('','restore') AND (r.frozen='restore'
                                OR NOT EXISTS (SELECT 1 FROM grove_login_continuity))''').fetchone()
    return row['id'] if row else None


def local_anchor(state: State):
    with state.connect(read_only=True) as db:
        db.execute('BEGIN')
        return read_anchor(db)


def read_anchor(db):
    current = db.execute('SELECT anchor,recovery_proof FROM grove_login_continuity').fetchone()
    if current is None or db.execute("SELECT 1 FROM grove_realm WHERE frozen!='' OR issuer_paused=1").fetchone():
        return None
    envelope = base_envelope(json.loads(current['anchor']))
    kind = 'login-continuity' if current['recovery_proof'] is None else 'login-recovery'
    from . import grove_voters
    return envelope, grove_voters.extend(db, verified_anchor(db, envelope, kind=kind))


def vote(state: State, requester: str, nonce: str, digest: str, known_revocations: str | None = None,
         known_passwords: str | None = None, known_roles: str | None = None, known_members: str | None = None,
         known_accounts: str | None = None) -> dict:
    with state.connect(read_only=True) as db:
        db.execute('BEGIN')
        current = read_anchor(db)
        if current is None:
            current = read_standby(db, int(time.time()))
        if current is None:
            raise PeerError('DENIED', 'Grove login continuity is disabled on this member')
        if 'not_after' not in current[1]:
            from . import grove_voters
            grove_voters.require_unlocked(db)
        envelope, anchor = current
        if state.identity()[0] not in anchor['voters'] or not admitted(db, anchor, requester) or digest != anchor_digest(envelope):
            raise PeerError('DENIED', 'The requester is outside the installed Grove continuity authorization')
        key = state.signing_key()
        payload = {'requester': requester, 'nonce': nonce, 'anchor': digest, 'issued_at': int(time.time()),
                   'public_key': wire_b64(key.public_key().public_bytes_raw())}
        from . import grove_voters
        payload.update(grove_voters.stamp(anchor))
        response = {}
        if 'not_after' not in anchor:
            revocations = revocation_digest(db, digest)
            if known_revocations is not None:
                payload['revocations'] = revocations
                response['revocations'] = []
                if known_revocations != revocations:
                    documents = db.execute('SELECT document FROM grove_login_revocation WHERE anchor_digest=? ORDER BY user_id',
                                           (digest,))
                    response['revocations'] = [json.loads(row[0]) for row in documents]
            elif revocations != EMPTY_REVOCATIONS:
                raise PeerError('CONFLICT', 'Synchronize Grove account revocations before renewing')
            passwords = password_digest(db, digest)
            if known_passwords is not None:
                payload['passwords'] = passwords
                response['passwords'] = []
                if known_passwords != passwords:
                    documents = db.execute('SELECT user_id,document FROM grove_login_password WHERE anchor_digest=? ORDER BY user_id',
                                           (digest,))
                    response['passwords'] = [json.loads(factors.unseal(state, row['user_id'], row['document'])) for row in documents]
            elif passwords != EMPTY_PASSWORDS:
                raise PeerError('CONFLICT', 'Synchronize Grove password changes before renewing')
            roles = role_versions(db)
            roles_digest = role_digest(roles)
            if known_roles is not None:
                payload['roles'] = roles_digest
                response['roles'] = roles if known_roles != roles_digest else {}
            elif roles_digest != EMPTY_ROLES:
                raise PeerError('CONFLICT', 'Synchronize Grove role changes before renewing')
            members = admission_versions(db)
            if known_members is not None:
                payload['members'] = admission_digest(members)
                response['members'] = members if known_members != payload['members'] else {}
            elif members:
                raise PeerError('CONFLICT', 'Synchronize Grove admissions before renewing')
            from . import grove_accounts
            accounts = grove_accounts.versions(db)
            if known_accounts is not None:
                payload['accounts'] = grove_accounts.digest_of(accounts)
                response['accounts'] = accounts if known_accounts != payload['accounts'] else {}
            elif accounts:
                raise PeerError('CONFLICT', 'Synchronize Grove accounts before renewing')
        ballot = grove.signed('login-continuity-vote', payload, key)
        if known_revocations is not None:
            return {'ballot': ballot, **response}
        return ballot


def anchor_digest(envelope: dict) -> str:
    return sha256(grove.encoded(base_envelope(envelope))).hexdigest()


def revocation_digest(db, digest: str) -> str:
    users = [row[0] for row in db.execute('SELECT user_id FROM grove_login_revocation WHERE anchor_digest=? ORDER BY user_id', (digest,))]
    return sha256(grove.encoded({'users': users})).hexdigest()


def password_digest(db, digest: str) -> str:
    users = [tuple(row) for row in db.execute('SELECT user_id,change_digest FROM grove_login_password WHERE anchor_digest=? ORDER BY user_id',
                                             (digest,))]
    return sha256(grove.encoded({'users': users})).hexdigest()


def role_versions(db) -> dict[str, int]:
    return {row[0]: row[1] for row in db.execute('SELECT user_id,generation FROM grove_login_role ORDER BY user_id')}


def role_digest(versions: dict[str, int]) -> str:
    return sha256(grove.encoded({'users': sorted(versions.items())})).hexdigest()


def admission_versions(db) -> dict[str, str]:
    return {row[0]: row[1] for row in db.execute('SELECT node_id,origin FROM grove_member_admission ORDER BY node_id')}


def admission_digest(members: dict[str, str]) -> str:
    return sha256(grove.encoded({'members': sorted(members.items())})).hexdigest()


def read_standby(db, now: int) -> tuple[dict, dict] | None:
    row = db.execute('''SELECT v.standby,r.public_key FROM grove_login_replica v JOIN grove_realm r
                        ON r.sequence=v.sequence AND r.is_issuer=0 AND r.frozen='' AND r.issuer_paused=0
                        WHERE v.standby IS NOT NULL AND NOT EXISTS (SELECT 1 FROM grove_login_continuity)''').fetchone()
    if row is None:
        return None
    envelope = json.loads(row['standby'])
    standby = grove.verified('login-standby', envelope, row['public_key'])
    return (envelope, standby) if standby['not_after'] > now else None


def standby_anchor(state: State) -> tuple[dict, dict] | None:
    with state.connect(read_only=True) as db:
        return read_standby(db, int(time.time()))


def renew(state: State, envelope: dict, nonce: str, votes: dict[str, dict], *, standby: bool = False) -> bool:
    local = state.identity()[0]
    now = int(time.time())
    digest = anchor_digest(envelope)
    with state.connect(write=True) as db:
        if standby:
            current = read_standby(db, now)
            if current is None or current[0] != envelope:
                return False
            anchor = current[1]
        else:
            record = db.execute('SELECT anchor,recovery_proof FROM grove_login_continuity').fetchone()
            if record is None or base_envelope(json.loads(record['anchor'])) != envelope:
                return False
            kind = 'login-continuity' if record['recovery_proof'] is None else 'login-recovery'
            from . import grove_voters
            anchor = grove_voters.extend(db, verified_anchor(db, envelope, kind=kind))
        dates = [now] if local in anchor['voters'] else []
        admissions = admission_digest(admission_versions(db)) if not standby else None
        revocations = revocation_digest(db, digest) if not standby else None
        passwords = password_digest(db, digest) if not standby else None
        roles = role_digest(role_versions(db)) if not standby else None
        from . import grove_accounts
        accounts = grove_accounts.version_digest(db) if not standby else None
        for voter in anchor['voters']:
            if voter == local or voter not in votes:
                continue
            try:
                reply = votes[voter]
                raw = json.loads(parse_b64(reply['record'], 2048))
                public = parse_b64(raw['public_key'], 32)
                if node_id(Ed25519PublicKey.from_public_bytes(public)) != voter:
                    continue
                data = grove.verified('login-continuity-vote', reply, public, 2048)
                from . import grove_voters
                if data.get('configuration') != grove_voters.stamp(anchor).get('configuration'):
                    continue
                data = grove_voters.unstamp(data)
                issued = data['issued_at']
                correct_state = data.keys() == VOTE_FIELDS if standby else (
                    data.keys() <= VOTE_FIELDS | {'revocations', 'passwords', 'roles', 'members', 'accounts'} and VOTE_FIELDS <= data.keys()
                    and data.get('revocations', EMPTY_REVOCATIONS) == revocations
                    and data.get('passwords', EMPTY_PASSWORDS) == passwords and data.get('roles', EMPTY_ROLES) == roles
                    and data.get('members', EMPTY_ADMISSIONS) == admissions
                    and data.get('accounts', grove_accounts.EMPTY_VERSION) == accounts)
                if (correct_state and data['requester'] == local
                        and data['nonce'] == nonce and data['anchor'] == digest and type(issued) is int
                        and now - 30 <= issued <= now + grove.CLOCK_SKEW):
                    dates.append(min(now, issued))
            except (ValueError, KeyError, TypeError, PeerError):
                continue
        if len(dates) <= len(anchor['voters']) // 2:
            return False
        lease = min(dates) + LEASE_SECONDS
        if standby:
            db.execute('UPDATE grove_login_replica SET standby_lease_until=?', (min(lease, anchor['not_after']),))
        else:
            db.execute('UPDATE grove_login_continuity SET lease_until=?', (lease,))
        return True
