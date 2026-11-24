"""Issue and install Mesh credentials after a majority of authorized Grove members approve."""
from dataclasses import dataclass
from hashlib import sha256
from ipaddress import ip_address
from pathlib import Path
import sqlite3
import time
from urllib.request import HTTPSHandler, HTTPRedirectHandler, ProxyHandler, Request, build_opener

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding

from . import grove, onboarding
from .config import Config
from .peer.credentials import (
    NODE_ID, RANDOM_ID, ca_certificate, certificate, fingerprint, make_csr, node_id, sign_csr,
    validate_ca, validate_leaf, validate_mesh_leaf,
)
from .peer.grove_endpoints import trusted_members
from .peer.mesh_policy import member_allowed
from .peer import quarantine
from .peer.pairing import MAX_MEMBERS, Pair, configured, fixed_mesh_ip, members
from .peer.protocol import PeerError, decode_json, parse_b64, wire_b64
from .state import State, StateError, audit, private_path


POLICY_FILE = 'mesh-enrollment.json'
SIGNING_KEY = 'mesh-enrollment-ca.key'
SIGNING_CA = 'mesh-enrollment-ca.pem'
TTL = 300
PREFIX = '/api/v1/mesh/enrollment/'
MAX_RESPONSE = 8192
REQUEST_FIELDS = {'policy','node_id','origin','public_key','csr','issued_at','expires_at'}
POLICY_FIELDS = {'realm_id','mesh_id','legacy_ca','voters'}


@dataclass(frozen=True)
class Voter:
    node: str
    origin: str
    host: str
    address: str
    port: int
    leaf: x509.Certificate
    authority: x509.Certificate


@dataclass(frozen=True)
class Policy:
    id: str
    realm: str
    mesh: str
    roots: tuple[x509.Certificate, ...]
    voters: dict[str, Voter]
    bind_ip: str | None
    trusted_proxy: bool
    core: dict

    def roots_pem(self):
        return b''.join(root.public_bytes(Encoding.PEM) for root in self.roots)

    def majority(self):
        return len(self.voters) // 2 + 1


def load_policy(state: State) -> Policy | None:
    path = state.directory / POLICY_FILE
    try:
        private_path(path, 0o600)
    except FileNotFoundError:
        return None
    if path.stat().st_size > 32768:
        raise ValueError('Mesh enrollment policy is too large')
    settings = decode_json(path.read_bytes())
    # The on-disk bootstrap is immutable; committed membership overrides it
    # transactionally, so a crash cannot leave identity and Mesh rosters apart.
    with state.connect(read_only=True) as db:
        if db.execute("SELECT 1 FROM sqlite_master WHERE name='grove_voter_configuration'").fetchone():
            latest = db.execute('SELECT document FROM grove_voter_configuration ORDER BY version DESC LIMIT 1').fetchone()
            if latest:
                import json
                settings['policy'] = json.loads(latest[0])['certificate']['proposal']['policy']
    return read_policy(settings)


def read_policy(data: dict) -> Policy:
    if data.keys() != {'policy','bind_ip','trusted_proxy'} or type(data['trusted_proxy']) is not bool:
        raise ValueError('Invalid Mesh enrollment policy settings')
    core = data['policy']
    if (not isinstance(core, dict) or core.keys() not in (POLICY_FIELDS, POLICY_FIELDS | {'retired_ca'}) or not RANDOM_ID.fullmatch(core['mesh_id'])
            or not core['realm_id'].startswith('grv1-') or not RANDOM_ID.fullmatch(core['realm_id'][5:])
            or not isinstance(core['voters'], list) or not 3 <= len(core['voters']) <= 7):
        raise ValueError('Invalid Mesh enrollment policy')
    old_ca = certificate(core['legacy_ca'].encode())
    validate_ca(old_ca)
    retired = tuple(certificate(pem.encode()) for pem in core.get('retired_ca', []))
    for root in retired:
        validate_ca(root)
    authorities = tuple(certificate(entry['ca'].encode()) for entry in core['voters'])
    roots = (old_ca, *retired, *authorities)
    if len({fingerprint(root) for root in roots}) != len(roots):
        raise ValueError('Each Mesh authority must be unique')
    voters = {}
    for entry in core['voters']:
        if (entry.keys() != {'node_id','origin','host','address','port','leaf','ca'} or
                not NODE_ID.fullmatch(entry['node_id']) or not 1024 <= entry['port'] <= 65535):
            raise ValueError('Invalid Mesh voter')
        leaf, authority = (certificate(entry[key].encode()) for key in ('leaf','ca'))
        validate_mesh_leaf(leaf, roots, entry['node_id'], entry['host'])
        validate_ca(authority)
        voter = Voter(entry['node_id'], grove.origin(entry['origin']), entry['host'],
                      fixed_mesh_ip(entry['address']), entry['port'], leaf, authority)
        if voter.node in voters or any(other.origin == voter.origin for other in voters.values()):
            raise ValueError('Duplicate Mesh voter')
        voters[voter.node] = voter
    bind = fixed_mesh_ip(data['bind_ip']) if data['bind_ip'] else None
    return Policy(sha256(grove.encoded(core)).hexdigest(), core['realm_id'], core['mesh_id'], roots, voters, bind,
                  data['trusted_proxy'], core)


def initialize_signer(state: State) -> Path:
    with state.lock('mesh-signer.lock'):
        key_path = state.directory / SIGNING_KEY
        if key_path.exists():
            private_path(key_path, 0o600)
            key = Ed25519PrivateKey.from_private_bytes(key_path.read_bytes())
        else:
            key = Ed25519PrivateKey.generate()
            onboarding.write_private(key_path, key.private_bytes_raw())
        public_path = state.directory / SIGNING_CA
        if not public_path.exists():
            name = 'Spearmint Mesh voter ' + state.identity()[0][5:25]
            onboarding.write_private(public_path, ca_certificate(key, name=name).public_bytes(Encoding.PEM))
        return public_path


def activate_voter(state: State, policy: Policy):
    local = state.identity()[0]
    voter = policy.voters.get(local)
    if voter is None:
        return
    with state.connect(write=True) as db:
        profile = db.execute('SELECT * FROM mesh_profile').fetchone()
        realm = db.execute('SELECT id FROM grove_realm').fetchone()
        if (not profile or profile['mesh_id'] != policy.mesh or realm is None or realm['id'] != policy.realm
                or fingerprint(certificate(profile['local_pem'])) != fingerprint(voter.leaf)):
            raise PeerError('DENIED', 'Mesh enrollment policy does not match this voter')
        if profile['ca_pem'] == policy.roots_pem():
            return
        existing = x509.load_pem_x509_certificates(profile['ca_pem'])
        if not {fingerprint(root) for root in existing} <= {fingerprint(root) for root in policy.roots}:
            raise PeerError('CONFLICT', 'Mesh enrollment policy would remove a trusted authority')
        for pair in members(db).values():
            validate_mesh_leaf(certificate(pair.remote_pem), policy.roots, pair.node_id, pair.host)
        db.execute('UPDATE mesh_profile SET ca_pem=?', (policy.roots_pem(),))
        audit(db, 'admin', 'local', 'mesh.enrollment_authorities_installed', policy.mesh, reason=policy.id)


def subject_name(node: str):
    return 'node-' + node[5:25] + '.mesh.invalid'


def request_for(state: State, config: Config, policy: Policy):
    node, public = state.identity()
    key = state.signing_key()
    now = int(time.time())
    return grove.signed('mesh-enroll-request', {
        'policy': policy.id, 'node_id': node, 'origin': config.origin, 'public_key': wire_b64(public),
        'csr': wire_b64(make_csr(key, subject_name(node))), 'issued_at': now, 'expires_at': now + TTL,
    }, key)


def request_data(policy: Policy, envelope: dict):
    try:
        unsigned = decode_json(parse_b64(envelope['record'], 4096))
        data = grove.verified('mesh-enroll-request', envelope, parse_b64(unsigned['public_key'], 32), 4096)
        node = data['node_id']
        csr = x509.load_pem_x509_csr(parse_b64(data['csr'], 2048))
        if (data.keys() != REQUEST_FIELDS or data['policy'] != policy.id or node in policy.voters
                or not csr.is_signature_valid or node_id(csr.public_key()) != node
                or csr.public_key().public_bytes_raw() != parse_b64(data['public_key'], 32)
                or any(type(data[field]) is not int for field in ('issued_at','expires_at'))
                or not grove.valid_time_window(data['issued_at'], data['expires_at'], int(time.time()), TTL)):
            raise ValueError
        grove.origin(data['origin'])
        return data
    except (PeerError, KeyError, TypeError, ValueError) as error:
        raise PeerError('DENIED', 'Invalid Mesh enrollment request') from error


def check_voter(db, local: str, policy: Policy, data: dict):
    approved = trusted_members(db, local)
    if (local not in policy.voters or not approved or approved.realm_id != policy.realm
            or approved.origins.get(data['node_id']) != data['origin']
            or not member_allowed(db, policy.mesh, data['node_id'])):
        raise PeerError('DENIED', 'A current Grove approval is required for this Node ID and origin')


def vote(state: State, policy: Policy, request: dict, data: dict):
    local = state.identity()[0]
    with state.connect(read_only=True) as db:
        db.execute('BEGIN')
        check_voter(db, local, policy, data)
    return grove.signed('mesh-enroll-vote', {'policy': policy.id, 'node_id': local,
                        'request_sha256': sha256(grove.encoded(request)).hexdigest()}, state.signing_key())


def verify_votes(policy: Policy, request: dict, votes: list):
    if not isinstance(votes, list) or not policy.majority() <= len(votes) <= len(policy.voters):
        raise PeerError('DENIED', 'Mesh enrollment requires a majority of authorized voters')
    digest = sha256(grove.encoded(request)).hexdigest()
    validated = set()
    for signed in votes:
        try:
            voter = policy.voters[decode_json(parse_b64(signed['record'], 2048))['node_id']]
            approved = grove.verified('mesh-enroll-vote', signed, voter.leaf.public_key().public_bytes_raw(), 2048)
            if approved != {'policy': policy.id, 'node_id': voter.node, 'request_sha256': digest} or voter.node in validated:
                raise ValueError
            validated.add(voter.node)
        except (KeyError, TypeError, ValueError, PeerError) as error:
            raise PeerError('DENIED', 'Mesh enrollment vote does not match the request') from error


def issue(state: State, policy: Policy, data: dict):
    path = state.directory / SIGNING_KEY
    private_path(path, 0o600)
    local = state.identity()[0]
    with state.connect(read_only=True) as db:
        db.execute('BEGIN')
        check_voter(db, local, policy, data)
    key = Ed25519PrivateKey.from_private_bytes(path.read_bytes())
    leaf = sign_csr(parse_b64(data['csr'], 2048), key, policy.voters[local].authority, data['node_id'],
                    subject_name(data['node_id']))
    return leaf.public_bytes(Encoding.PEM)


def ingress_source(policy: Policy, host: str, forwarded: list[str]) -> str:
    try:
        address = ip_address(host)
        if address.is_loopback and policy.trusted_proxy and len(forwarded) == 1:
            address = ip_address(forwarded[0].rsplit(',', 1)[-1].strip())
        if address.is_loopback:
            raise ValueError
        return fixed_mesh_ip(str(address))
    except ValueError as error:
        raise PeerError('DENIED', 'The voter cannot identify the Mesh ingress address') from error


def register(state: State, policy: Policy, data: dict, pem: bytes, source: str):
    local = state.identity()[0]
    node = data['node_id']
    leaf = certificate(pem)
    validate_mesh_leaf(leaf, policy.roots[1:], node, subject_name(node))
    address = fixed_mesh_ip(source)
    with state.connect(write=True) as db:
        check_voter(db, local, policy, data)
        profile = db.execute('SELECT * FROM mesh_profile').fetchone()
        if not profile or profile['mesh_id'] != policy.mesh or profile['ca_pem'] != policy.roots_pem():
            raise PeerError('CONFLICT', 'The voter has not installed the enrollment authority bundle')
        prior = configured(db, node)
        if prior and (not prior.ingress_only or prior.fingerprint != fingerprint(leaf) or not prior.enabled):
            raise PeerError('CONFLICT', 'A different Mesh member record already exists')
        if quarantine.contains(db, node):
            raise PeerError('DENIED', 'The node is locally quarantined')
        if prior and prior.source_ip == address:
            return
        if not prior:
            if db.execute('SELECT count(*) FROM peer').fetchone()[0] >= MAX_MEMBERS:
                raise PeerError('BUSY', 'Mesh member limit reached')
            db.execute('''INSERT INTO peer (node_id,mesh_id,host,fingerprint,remote_pem,write_epoch,enabled,routed,ingress_only)
                          VALUES (?,?,?,?,?,lower(hex(randomblob(16))),1,1,1)''',
                       (node, policy.mesh, subject_name(node), fingerprint(leaf), pem))
            db.execute('INSERT INTO peer_directory(peer_id) VALUES (?)', (node,))
        db.execute('''INSERT INTO peer_neighbor (node_id,source_ip,port) VALUES (?,?,8766)
                      ON CONFLICT(node_id) DO UPDATE SET source_ip=excluded.source_ip''', (node, address))
        audit(db, 'grove-majority', address, 'mesh.enrollment_registered', node, reason=policy.id)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def contact(config: Config, voter: Voter, action: str, body: dict):
    return post(config, voter, PREFIX + action, body)


def post(config: Config, voter: Voter, path: str, body: dict):
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=grove.directory_tls_context(config)), NoRedirect())
    request = Request(voter.origin + path, data=grove.encoded(body), headers={'Content-Type': 'application/json'})
    with opener.open(request, timeout=4) as response:
        reply = response.read(MAX_RESPONSE + 1)
    if len(reply) > MAX_RESPONSE:
        raise ValueError('Mesh enrollment reply exceeds its limit')
    return decode_json(reply)


def install_local(state: State, policy: Policy, pem: bytes):
    local = state.identity()[0]
    if not policy.bind_ip:
        raise ValueError('Mesh enrollment requires the local interface address')
    bundle = policy.roots_pem()
    validate_mesh_leaf(certificate(pem), policy.roots[1:], local, subject_name(local))
    pairs = []
    for voter in policy.voters.values():
        pair = Pair(voter.node, policy.mesh, policy.bind_ip, 8766, voter.address, voter.host, voter.port,
                    fingerprint(voter.leaf), bundle, pem, voter.leaf.public_bytes(Encoding.PEM), legacy=False, routed=True)
        pair.validate(local)
        pairs.append(pair)
    with state.connect(write=True) as db:
        if db.execute('SELECT 1 FROM mesh_profile').fetchone():
            raise PeerError('CONFLICT', 'A Mesh profile already exists')
        db.execute('''INSERT INTO mesh_profile (singleton,mesh_id,bind_ip,listen_port,ca_pem,local_pem,address_generation)
                      VALUES (1,?,?,8766,?,?,lower(hex(randomblob(16))))''', (policy.mesh, policy.bind_ip, bundle, pem))
        for pair in pairs:
            db.execute('''INSERT INTO peer (node_id,mesh_id,host,fingerprint,remote_pem,write_epoch,enabled,routed)
                          VALUES (?,?,?,?,?,lower(hex(randomblob(16))),1,1)''',
                       (pair.node_id, pair.mesh_id, pair.host, pair.fingerprint, pair.remote_pem))
            db.execute('INSERT INTO peer_neighbor VALUES (?,?,?)', (pair.node_id, pair.source_ip, pair.port))
            db.execute('INSERT INTO peer_directory(peer_id) VALUES (?)', (pair.node_id,))
        audit(db, 'grove-majority', 'local', 'mesh.enrollment_installed', policy.mesh, reason=policy.id)


def enroll(state: State, config: Config, policy: Policy, *, bootstrap: bool = False):
    local = state.identity()[0]
    if local in policy.voters or not policy.bind_ip:
        return
    with state.lock('mesh-enrollment.lock'):
        with state.connect(read_only=True) as db:
            realm = db.execute('SELECT id,frozen FROM grove_realm').fetchone()
            existing = db.execute('SELECT mesh_id FROM mesh_profile').fetchone()
            previous = db.execute('SELECT * FROM mesh_enrollment_local').fetchone()
            if (realm is None and not bootstrap) or (realm is not None and (realm['id'] != policy.realm or realm['frozen'])):
                return
            if existing and (not previous or previous['policy'] != policy.id or previous['complete']):
                return
        request = request_for(state, config, policy)
        votes = []
        for voter in policy.voters.values():
            try:
                proposed = contact(config, voter, 'vote', {'request': request})['vote']
                digest = sha256(grove.encoded(request)).hexdigest()
                expected = {'policy': policy.id, 'node_id': voter.node,'request_sha256': digest}
                if grove.verified('mesh-enroll-vote', proposed, voter.leaf.public_key().public_bytes_raw(), 2048) == expected:
                    votes.append(proposed)
            except (KeyError, OSError, ValueError, PeerError):
                continue
        verify_votes(policy, request, votes)
        body = {'request': request, 'votes': votes}
        pem = previous['certificate'] if previous and previous['policy'] == policy.id else None
        if pem is None:
            for voter in policy.voters.values():
                try:
                    result = contact(config, voter, 'issue', body)
                    candidate = parse_b64(result['certificate'], 8192)
                    validate_leaf(certificate(candidate), voter.authority, local, subject_name(local))
                except (KeyError, OSError, ValueError, PeerError):
                    continue
                pem = candidate
                break
            if pem is None:
                raise PeerError('OFFLINE', 'A Mesh signing voter is unavailable')
            with state.connect(write=True) as db:
                db.execute('''INSERT INTO mesh_enrollment_local (singleton,policy,certificate) VALUES (1,?,?)
                              ON CONFLICT(singleton) DO UPDATE SET policy=excluded.policy,certificate=excluded.certificate,complete=0''',
                           (policy.id, pem))
        accepted = 0
        for voter in policy.voters.values():
            try:
                result = contact(config, voter, 'register', body | {'certificate': wire_b64(pem)})
                accepted += result.get('registered') is True
            except (KeyError, OSError, ValueError, PeerError):
                continue
        if accepted < policy.majority():
            raise PeerError('OFFLINE', 'Waiting for a majority of Mesh members to register the certificate')
        if not existing:
            install_local(state, policy, pem)
        if accepted == len(policy.voters):
            with state.connect(write=True) as db:
                db.execute('UPDATE mesh_enrollment_local SET complete=1 WHERE policy=?', (policy.id,))
