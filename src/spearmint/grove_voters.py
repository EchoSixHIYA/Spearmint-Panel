"""Versioned Grove voter membership, jointly certified by old and new quorums.

The original identity snapshot remains the root of trust. Membership certificates
extend it without requiring the retired issuer or copying any node's signing key.
Durable prepare/accept promises let another member finish an interrupted change.
"""
from hashlib import sha256
import json
import time
import zlib
from ipaddress import ip_address
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding

from . import factors, grove
from .peer.credentials import NODE_ID, certificate, node_id, validate_ca
from .peer.protocol import PeerError, parse_b64, wire_b64
from .state import audit

METHOD = 'grove.voters.v1'
READY_KIND = 'voter-ready'
VOTE_KIND = 'voter-configuration'
MIN_VOTERS, MAX_VOTERS = 3, 7
MAX_HISTORY = 8 * 1024 * 1024
MAX_WIRE = 256 * 1024


def digest(value):
    return sha256(grove.encoded(value)).hexdigest()


def proof_digest(document):
    return digest(document)


def base_policy(state):
    from . import mesh_enrollment
    with state.connect(read_only=True) as db:
        first = db.execute('SELECT document FROM grove_voter_configuration ORDER BY version LIMIT 1').fetchone()
        if first:
            return json.loads(first[0])['bootstrap']
    path = state.directory / mesh_enrollment.POLICY_FILE
    return mesh_enrollment.read_policy(json.loads(path.read_bytes())).core


def base_id(anchor):
    return digest({'anchor': anchor, 'version': 0})


def effective(anchor, bootstrap, changes):
    """Validate a complete public chain independently of a local database."""
    from . import mesh_enrollment
    policy = mesh_enrollment.read_policy({'policy': bootstrap, 'bind_ip': None, 'trusted_proxy': False})
    if set(anchor['voters']) != policy.voters.keys() or policy.realm != anchor['realm_id']:
        raise PeerError('CONFLICT', '投票名单与 Grove 初始授权不一致。')
    previous, voters = base_id(anchor), list(anchor['voters'])
    contexts = {previous: {'voters': voters, 'proofs': None}}
    for version, cert in enumerate(changes, 1):
        proposal = cert['proposal']
        if (proposal.keys() != {'version', 'previous', 'policy', 'checkpoint', 'identity', 'target', 'ready'}
                or proposal['version'] != version or proposal['previous'] != previous):
            raise PeerError('CONFLICT', '投票名单变更链不连续。')
        new = mesh_enrollment.read_policy({'policy': proposal['policy'], 'bind_ip': None, 'trusted_proxy': False})
        changed = set(voters) ^ new.voters.keys()
        if (new.realm != policy.realm or new.mesh != policy.mesh or len(changed) != 1
                or proposal['target'] not in changed
                or not {root.public_bytes(Encoding.PEM) for root in policy.roots} <=
                       {root.public_bytes(Encoding.PEM) for root in new.roots}):
            raise PeerError('CONFLICT', '投票名单每次只能调整一个节点，并须保留已有证书信任。')
        # Existing voter entries cannot be silently replaced while adding/removing another.
        prior = {entry['node_id']: entry for entry in policy.core['voters']}
        after = {entry['node_id']: entry for entry in new.core['voters']}
        if any(prior[node] != after[node] for node in prior.keys() & after.keys()):
            raise PeerError('CONFLICT', '投票变更不能同时替换其它节点身份。')
        if proposal['target'] in after:
            verify_ready(proposal['ready'], proposal['target'], previous, proposal['checkpoint'], after[proposal['target']])
        elif proposal['ready'] is not None:
            raise PeerError('PROTOCOL', 'Invalid voter removal readiness')
        validate_votes(cert, voters, list(new.voters))
        known = proposal['checkpoint']['proofs']
        if not isinstance(known, list) or len(known) > 512 or any(not isinstance(p, str) or len(p) != 64 for p in known):
            raise PeerError('PROTOCOL', 'Invalid voter identity checkpoint')
        for context in contexts.values():
            if context['proofs'] is None:
                context['proofs'] = set(known)
        previous, voters, policy = digest(proposal), sorted(new.voters), new
        contexts[previous] = {'voters': voters, 'proofs': None}
    return anchor | {'voters': voters, '_configuration': previous, '_version': len(changes),
                     '_contexts': contexts, '_base_voters': list(anchor['voters']), '_policy': policy.core}


def rows(db):
    return [json.loads(row[0]) for row in db.execute('SELECT document FROM grove_voter_configuration ORDER BY version')]


def extend(db, anchor):
    changes = rows(db)
    if not changes:
        return anchor
    first = changes[0]
    return effective(anchor, first['bootstrap'], [row['certificate'] for row in changes])


def current_id(anchor):
    return anchor['_configuration'] if '_configuration' in anchor else base_id(anchor)


def stamp(anchor):
    return {'configuration': current_id(anchor)} if anchor.get('_version', 0) else {}


def verification(anchor, documents, *, certificate=None):
    """Choose the signing roster and retain only checkpointed historical proofs."""
    configurations = {json.loads(parse_b64(doc['record'], 8192)).get('configuration') for doc in documents}
    if len(configurations) != 1:
        raise PeerError('CONFLICT', '投票证明来自不同版本的成员名单。')
    config = configurations.pop()
    if not anchor.get('_version'):
        if config is not None:
            raise PeerError('CONFLICT', '请先同步 Grove 投票名单。')
        return anchor
    key = config or next(iter(anchor['_contexts']))
    context = anchor['_contexts'].get(key)
    if context is None:
        raise PeerError('CONFLICT', '请先同步 Grove 投票名单。')
    if context['proofs'] is not None and certificate is not None and proof_digest(certificate) not in context['proofs']:
        raise PeerError('CONFLICT', '该变更未包含在已确认的历史权限快照中。')
    return anchor | {'voters': context['voters']}


def unstamp(record):
    return {key: value for key, value in record.items() if key != 'configuration'}


def require_unlocked(db):
    latest = db.execute('SELECT coalesce(max(version),0) FROM grove_voter_configuration').fetchone()[0]
    if db.execute('SELECT 1 FROM grove_voter_ballot WHERE version=? AND proposal IS NOT NULL', (latest + 1,)).fetchone():
        raise PeerError('GROVE_CONFIGURATION_PENDING', '投票名单正在变更，身份变更将在名单确认后恢复。')


def checkpoint(state, db):
    from . import grove_continuity
    original = json.loads(db.execute('SELECT anchor FROM grove_login_continuity').fetchone()[0])
    anchor = grove_continuity.anchor_digest(original)
    proofs = []
    for table, column in (('grove_login_role', 'certificate'), ('grove_login_revocation', 'document'),
                          ('grove_member_admission', 'certificate')):
        proofs += [proof_digest(json.loads(row[0])) for row in db.execute(f'SELECT {column} FROM {table}')]
    proofs += [proof_digest(json.loads(factors.unseal(state, row['user_id'], row['document'])))
               for row in db.execute('SELECT user_id,document FROM grove_login_password')]
    return {'proofs': sorted(set(proofs)), 'revocations': grove_continuity.revocation_digest(db, anchor),
            'passwords': grove_continuity.password_digest(db, anchor),
            'roles': grove_continuity.role_digest(grove_continuity.role_versions(db)),
            'members': grove_continuity.admission_digest(grove_continuity.admission_versions(db))}


def history(db):
    changes = rows(db)
    if not changes:
        return None
    value = {'bootstrap': changes[0]['bootstrap'], 'changes': [row['certificate'] for row in changes]}
    return pack(value)


def pack(value):
    raw = grove.encoded(value)
    if len(raw) > MAX_HISTORY:
        raise PeerError('LIMIT', '投票名单变更记录超过当前传输限制。')
    encoded = wire_b64(zlib.compress(raw, 9))
    if len(encoded) > MAX_WIRE:
        raise PeerError('LIMIT', '投票名单变更记录超过当前传输限制。')
    return encoded


def unpack(value):
    compressed = parse_b64(value, MAX_WIRE)
    stream = zlib.decompressobj()
    raw = stream.decompress(compressed, MAX_HISTORY + 1)
    if len(raw) > MAX_HISTORY or stream.unconsumed_tail or not stream.eof or stream.unused_data:
        raise PeerError('PROTOCOL', 'Invalid Grove voter history')
    return json.loads(raw)


def history_anchor(anchor, encoded):
    if encoded is None:
        return anchor
    data = unpack(encoded)
    if data.keys() != {'bootstrap', 'changes'} or not isinstance(data['changes'], list):
        raise PeerError('PROTOCOL', 'Invalid Grove voter history')
    return effective(anchor, data['bootstrap'], data['changes'])


def install_history(db, anchor, encoded, source):
    if encoded is None:
        return False
    data = unpack(encoded)
    effective(anchor, data['bootstrap'], data['changes'])
    installed = rows(db)
    incoming = data['changes']
    for index, row in enumerate(installed):
        if index < len(incoming) and (row['bootstrap'] != data['bootstrap'] or row['certificate']['proposal'] != incoming[index]['proposal']):
            raise PeerError('CONFLICT', 'Grove 投票名单出现冲突，保留已确认版本。')
    if len(incoming) <= len(installed):
        refresh_mesh_roots(db)
        return False
    for version in range(len(installed) + 1, len(incoming) + 1):
        cert = incoming[version - 1]
        document = {'bootstrap': data['bootstrap'], 'certificate': cert}
        db.execute('INSERT INTO grove_voter_configuration VALUES(?,?,?)', (version, digest(cert['proposal']), json.dumps(document)))
        for entry in cert['proposal']['policy']['voters']:
            if not db.execute('SELECT 1 FROM grove_member_departure WHERE node_id=?', (entry['node_id'],)).fetchone():
                db.execute('INSERT INTO grove_member VALUES(?,?,1) ON CONFLICT(node_id) DO UPDATE SET origin=excluded.origin',
                           (entry['node_id'], entry['origin']))
        audit(db, 'grove', source, 'grove.voters_changed', cert['proposal']['target'], reason=str(version))
    db.execute('UPDATE grove_login_continuity SET lease_until=min(lease_until,?)', (int(time.time()) - 1,))
    refresh_mesh_roots(db)
    return True


def refresh_mesh_roots(db):
    from . import mesh_enrollment
    last = db.execute('SELECT document FROM grove_voter_configuration ORDER BY version DESC LIMIT 1').fetchone()
    if last:
        core = json.loads(last[0])['certificate']['proposal']['policy']
        policy = mesh_enrollment.read_policy({'policy': core, 'bind_ip': None, 'trusted_proxy': False})
        db.execute('UPDATE mesh_profile SET ca_pem=? WHERE mesh_id=? AND ca_pem!=?',
                   (policy.roots_pem(), policy.mesh, policy.roots_pem()))


def recovery_checkpoint(db):
    return {table: [dict(row) for row in db.execute('SELECT * FROM ' + table)] for table in
            ('grove_voter_configuration', 'grove_voter_ballot', 'grove_voter_job')}


def restore_checkpoint(db, checkpoint):
    """A data restore must not undo a committed configuration or durable promise."""
    from .state import StateError
    for row in checkpoint['grove_voter_configuration']:
        previous = db.execute('SELECT digest FROM grove_voter_configuration WHERE version=?', (row['version'],)).fetchone()
        if previous and previous[0] != row['digest']:
            raise StateError('Backup conflicts with the confirmed Grove voter configuration')
        db.execute('INSERT OR IGNORE INTO grove_voter_configuration VALUES(?,?,?)',
                   (row['version'], row['digest'], row['document']))
    for row in checkpoint['grove_voter_ballot']:
        previous = db.execute('SELECT * FROM grove_voter_ballot WHERE version=?', (row['version'],)).fetchone()
        if previous:
            previous = dict(zip(('version', 'promised', 'accepted_term', 'proposal'), previous))
            row = dict(row)
            row['promised'] = json.dumps(max(json.loads(row['promised']), json.loads(previous['promised'])))
            prior_term = json.loads(previous['accepted_term']) if previous['accepted_term'] else None
            term = json.loads(row['accepted_term']) if row['accepted_term'] else None
            if prior_term and (term is None or prior_term > term):
                row['accepted_term'], row['proposal'] = previous['accepted_term'], previous['proposal']
            elif prior_term and prior_term == term and previous['proposal'] != row['proposal']:
                raise StateError('Backup conflicts with an accepted Grove voter change')
        db.execute('INSERT OR REPLACE INTO grove_voter_ballot VALUES(?,?,?,?)',
                   (row['version'], row['promised'], row['accepted_term'], row['proposal']))
    for row in checkpoint['grove_voter_job']:
        db.execute('INSERT OR REPLACE INTO grove_voter_job VALUES(?,?,?,?,?,?,?)',
                   tuple(row[key] for key in ('id', 'node_id', 'desired', 'identity', 'status', 'reason', 'updated_at')))
    refresh_mesh_roots(db)


def status(state):
    from . import grove_continuity
    with state.connect(read_only=True) as db:
        current = grove_continuity.read_anchor(db)
        if current is None:
            return {'available': False, 'voters': [], 'version': 0, 'required': 0, 'jobs': []}
        anchor = current[1]
        jobs = [dict(row) for row in db.execute('SELECT id,node_id,desired,status,reason,updated_at FROM grove_voter_job ORDER BY updated_at DESC LIMIT 20')]
        return {'available': True, 'voters': anchor['voters'], 'version': anchor.get('_version', 0),
                'configuration': current_id(anchor), 'required': len(anchor['voters']) // 2 + 1, 'jobs': jobs,
                'min_voters': MIN_VOTERS, 'max_voters': MAX_VOTERS}


def verified_node(kind, envelope):
    raw = json.loads(parse_b64(envelope['record'], 48 * 1024))
    public = parse_b64(raw['public_key'], 32)
    data = grove.verified(kind, envelope, public, 48 * 1024)
    return node_id(Ed25519PublicKey.from_public_bytes(public)), data


def verify_ready(document, target, previous, snapshot, entry):
    node, data = verified_node(READY_KIND, document)
    if node != target or data != {'previous': previous, 'checkpoint': snapshot, 'entry': entry,
                                  'public_key': data['public_key']}:
        raise PeerError('CONFLICT', '新投票节点尚未完成相同的权限同步。')
    authority = certificate(entry['ca'].encode())
    validate_ca(authority)


def validate_votes(cert, old, new):
    if cert.keys() != {'proposal', 'term', 'votes'} or not isinstance(cert['votes'], list):
        raise PeerError('PROTOCOL', 'Invalid Grove voter configuration certificate')
    validate_term(cert['term'])
    accepted = set()
    for vote in cert['votes']:
        node, data = verified_node(VOTE_KIND, vote)
        expected = {'proposal': digest(cert['proposal']), 'term': cert['term'], 'public_key': data['public_key']}
        if node not in set(old) | set(new) or node in accepted or data != expected:
            raise PeerError('DENIED', 'Invalid Grove voter confirmation')
        accepted.add(node)
    if (len(accepted & set(old)) <= len(old) // 2 or len(accepted & set(new)) <= len(new) // 2
            or cert['proposal']['target'] in new and cert['proposal']['target'] not in accepted):
        raise PeerError('GROVE_QUORUM_REQUIRED', '投票名单变更需要旧名单与新名单的多数节点共同确认。')


def validate_term(term):
    if (not isinstance(term, list) or len(term) != 2 or type(term[0]) is not int or not 0 < term[0] < 2**63
            or not isinstance(term[1], str) or not NODE_ID.fullmatch(term[1])):
        raise PeerError('INVALID_REQUEST', 'Invalid voter configuration term')


def authorize(state, db, identity, pair, *, fresh=True):
    from . import grove_availability
    from .peer.grove_service_admin import admin_revision, parse_identity, require_admin_identity
    if fresh:
        grove_availability.require_current(db)
        return require_admin_identity(db, state.identity()[0], pair, identity)
    # Finishing an already requested configuration uses a live quorum instead
    # of an expiring identity lease; cached permission revisions must still match.
    identity = parse_identity(identity)
    member = pair.node_id if pair else state.identity()[0]
    if not db.execute('SELECT 1 FROM grove_member WHERE node_id=? AND enabled=1', (member,)).fetchone():
        raise PeerError('DENIED', 'An active Grove member is required')
    if pair:
        from .peer.policy import require_pair
        require_pair(db, pair)
    if identity != admin_revision(db, identity[0], identity[1]):
        raise PeerError('CONFLICT', '发起名单变更的账号权限已经变化。')
    return identity


def readiness(state, config, identity, pair=None):
    from . import grove_continuity, mesh_enrollment
    with state.connect(read_only=True) as db:
        authorize(state, db, identity, pair, fresh=False)
        current = grove_continuity.read_anchor(db)
        if current is None:
            raise PeerError('CONFLICT', '此节点尚未同步 Grove 投票配置。')
        anchor = current[1]
        profile = db.execute('SELECT * FROM mesh_profile').fetchone()
        if profile is None:
            raise PeerError('OFFLINE', '此节点尚未完成 Mesh 配对。')
        local = state.identity()[0]
        member = db.execute('SELECT origin FROM grove_member WHERE node_id=? AND enabled=1', (local,)).fetchone()
        policy = mesh_enrollment.load_policy(state)
        if member is None or policy is None:
            raise PeerError('OFFLINE', '此节点尚未完成 Grove 成员同步。')
        leaf = certificate(profile['local_pem'])
        names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        endpoints = names.get_values_for_type(x509.DNSName) or [str(ip) for ip in names.get_values_for_type(x509.IPAddress)]
        if not endpoints:
            raise PeerError('CONFLICT', '此节点的 Mesh 证书没有可用的主机标识。')
        entry = {'node_id': local, 'origin': member['origin'], 'host': endpoints[0],
                 'address': policy.bind_ip, 'port': profile['listen_port'], 'leaf': profile['local_pem'].decode(),
                 'ca': mesh_enrollment.initialize_signer(state).read_text()}
        # Prefer an advertised, reachable fixed endpoint for public voter discovery.
        if config.mesh_advertise_ip:
            entry['address'] = config.mesh_advertise_ip
        if config.mesh_advertise_port:
            entry['port'] = config.mesh_advertise_port
        if not config.mesh_advertise_ip:
            try:
                public = ip_address(urlsplit(member['origin']).hostname)
                if public.is_global:
                    entry['address'] = str(public)
            except ValueError:
                pass
        key = state.signing_key()
        return grove.signed(READY_KIND, {'previous': current_id(anchor), 'checkpoint': checkpoint(state, db),
            'entry': entry, 'public_key': wire_b64(key.public_key().public_bytes_raw())}, key)


def prepare(state, identity, previous, version, term, pair=None):
    from . import grove_continuity
    validate_term(term)
    with state.connect(write=True) as db:
        authorize(state, db, identity, pair, fresh=False)
        anchor = grove_continuity.read_anchor(db)[1]
        if (current_id(anchor) != previous or version != anchor.get('_version', 0) + 1
                or state.identity()[0] not in anchor['voters']):
            raise PeerError('CONFLICT', '投票名单已变化，请同步后重试。')
        prior = db.execute('SELECT * FROM grove_voter_ballot WHERE version=?', (version,)).fetchone()
        promised = json.loads(prior['promised']) if prior else None
        if promised and term < promised:
            return {'promised': promised, 'granted': False}
        db.execute('INSERT INTO grove_voter_ballot(version,promised) VALUES(?,?) ON CONFLICT(version) DO UPDATE SET promised=excluded.promised',
                   (version, json.dumps(term)))
        return {'granted': True, 'promised': term,
                'accepted_term': json.loads(prior['accepted_term']) if prior and prior['accepted_term'] else None,
                'proposal': json.loads(prior['proposal']) if prior and prior['proposal'] else None}


def accept(state, identity, proposal, term, bootstrap, pair=None):
    from . import grove_continuity
    validate_term(term)
    with state.connect(write=True) as db:
        authorize(state, db, identity, pair, fresh=False)
        current = grove_continuity.read_anchor(db)
        anchor = current[1]
        old = anchor['voters']
        new = [entry['node_id'] for entry in proposal['policy']['voters']]
        local = state.identity()[0]
        if bootstrap != base_policy(state):
            raise PeerError('CONFLICT', '投票变更与本机保存的 Grove 初始配置不一致。')
        if (proposal['previous'] != current_id(anchor) or proposal['version'] != anchor.get('_version', 0) + 1
                or local not in set(old) | set(new) or checkpoint(state, db) != proposal['checkpoint']):
            raise PeerError('CONFLICT', '请等待目标节点完成 Grove 权限同步后重试。')
        if proposal['identity'] != identity:
            # A recovering coordinator may finish the already accepted operation,
            # but its original requesting administrator must remain authorized.
            from .peer.grove_service_admin import admin_revision
            if proposal['identity'] != admin_revision(db, identity[0], proposal['identity'][1]):
                raise PeerError('CONFLICT', '发起名单变更的账号权限已经变化。')
        # Structural and signature validation before recording an acceptance.
        base = grove_continuity.verified_anchor(db, current[0], kind='login-recovery' if
            db.execute('SELECT recovery_proof FROM grove_login_continuity').fetchone()[0] else 'login-continuity')
        changes = [row['certificate'] for row in rows(db)]
        # The same validation is also run on the final certificate. Here validate
        # the proposed policy/readiness separately, without inventing quorum votes.
        validate_proposal(base, bootstrap, changes, proposal)
        prior = db.execute('SELECT * FROM grove_voter_ballot WHERE version=?', (proposal['version'],)).fetchone()
        if prior and term < json.loads(prior['promised']):
            raise PeerError('CONFLICT', '另一个节点正在推进此版本的投票名单。')
        if prior and prior['accepted_term'] and json.loads(prior['accepted_term']) == term and json.loads(prior['proposal']) != proposal:
            raise PeerError('CONFLICT', '同一确认轮次不能接受不同的投票名单。')
        db.execute('''INSERT INTO grove_voter_ballot VALUES(?,?,?,?) ON CONFLICT(version) DO UPDATE SET
            promised=excluded.promised,accepted_term=excluded.accepted_term,proposal=excluded.proposal''',
            (proposal['version'], json.dumps(term), json.dumps(term), json.dumps(proposal)))
        key = state.signing_key()
        return grove.signed(VOTE_KIND, {'proposal': digest(proposal), 'term': term,
            'public_key': wire_b64(key.public_key().public_bytes_raw())}, key)


def validate_proposal(base, bootstrap, changes, proposal):
    from . import mesh_enrollment
    prior = effective(base, bootstrap, changes)
    policy = mesh_enrollment.read_policy({'policy': proposal['policy'], 'bind_ip': None, 'trusted_proxy': False})
    old = prior['_policy']
    before = {entry['node_id']: entry for entry in old['voters']}
    after = {entry['node_id']: entry for entry in policy.core['voters']}
    if (proposal['previous'] != prior['_configuration'] or proposal['version'] != len(changes) + 1
            or set(before) ^ set(after) != {proposal['target']} or policy.realm != base['realm_id']
            or policy.mesh != old['mesh_id'] or any(before[n] != after[n] for n in before.keys() & after.keys())):
        raise PeerError('CONFLICT', '无效的 Grove 投票名单变更。')
    old_policy = mesh_enrollment.read_policy({'policy': old, 'bind_ip': None, 'trusted_proxy': False})
    if not {r.public_bytes(Encoding.PEM) for r in old_policy.roots} <= {r.public_bytes(Encoding.PEM) for r in policy.roots}:
        raise PeerError('CONFLICT', '名单变更须保留现有节点使用的证书信任。')
    if proposal['target'] in after:
        verify_ready(proposal['ready'], proposal['target'], prior['_configuration'], proposal['checkpoint'], after[proposal['target']])


def apply(state, encoded, source):
    from . import grove_continuity, mesh_enrollment
    with state.connect(write=True) as db:
        current = grove_continuity.read_anchor(db)
        if current is None:
            raise PeerError('CONFLICT', '此节点尚未安装 Grove 初始投票授权。')
        base = grove_continuity.verified_anchor(db, current[0], kind='login-recovery' if
            db.execute('SELECT recovery_proof FROM grove_login_continuity').fetchone()[0] else 'login-continuity')
        changed = install_history(db, base, encoded, source)
        if changed:
            policy = mesh_enrollment.read_policy({'policy': extend(db, base)['_policy'], 'bind_ip': None, 'trusted_proxy': False})
            db.execute('UPDATE mesh_profile SET ca_pem=?', (policy.roots_pem(),))
    return changed
