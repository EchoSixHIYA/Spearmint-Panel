"""Approve a fresh panel at a Grove quorum before opening its Mesh connection."""
from concurrent.futures import ThreadPoolExecutor
import json
import socket
import time
from urllib.parse import urlsplit

from . import auth, grove, grove_admission, grove_continuity, grove_login, grove_web_join, mesh_enrollment, onboarding
from .peer import quarantine
from .peer.mesh_policy import member_allowed
from .peer.protocol import PeerError, decode_json, parse_b64, wire_b64


PREFIX = 'grove5.'
LIMIT = 128 * 1024
API = '/api/v1/auth/grove/quorum-join/'
PENDING = 'grove-quorum-join.json'


def current_voter(db, state, policy):
    current = grove_continuity.read_anchor(db)
    if (current is None or policy is None or set(current[1]['voters']) != policy.voters.keys()
            or policy.realm != current[1]['realm_id'] or state.identity()[0] not in policy.voters
            or grove_login.usable_replica(db, int(time.time())) is None):
        raise PeerError('OFFLINE', 'This node has no current Grove quorum admission authority')
    return current


def invitation(state, policy):
    with state.connect(read_only=True) as db:
        db.execute('BEGIN')
        envelope, _ = current_voter(db, state, policy)
        realm = db.execute('SELECT * FROM grove_realm').fetchone()
        if db.execute('SELECT recovery_proof FROM grove_login_continuity').fetchone()[0] is not None:
            return None
        contents = {'realm':grove.realm_data(realm), 'anchor':envelope,
                    'manifest':json.loads(realm['manifest']), 'mesh':policy.core}
    code = PREFIX + wire_b64(grove.encoded(contents))
    if len(code) > LIMIT:
        raise PeerError('LIMIT', 'Grove invitation exceeds the panel limit')
    return code


def read_invitation(code):
    try:
        if not code.startswith(PREFIX) or len(code) > LIMIT:
            raise ValueError
        data = decode_json(parse_b64(code[len(PREFIX):], LIMIT))
        if data.keys() != {'realm', 'anchor', 'manifest', 'mesh'}:
            raise ValueError
        realm = grove.invitation(data['realm'])
        key = parse_b64(realm['public_key'], 32)
        directory = grove.directory_data(data['manifest'], realm, allow_expired=True)
        anchor = grove_continuity.snapshot_authorization(realm | {'public_key':key}, directory, data['anchor'], 'login-continuity')
        policy = mesh_enrollment.read_policy({'policy':data['mesh'], 'bind_ip':None, 'trusted_proxy':False})
        origins = {member['node_id']:member['origin'] for member in directory['members'] if member['enabled']}
        if (policy.realm != realm['id'] or policy.voters.keys() != set(anchor['voters']) or any(
            voter.origin != origins.get(voter.node) or not grove_web_join.browser_origin(voter.origin)
            for voter in policy.voters.values()
        )):
            raise ValueError
    except (KeyError, TypeError, ValueError, PeerError) as error:
        raise PeerError('INVALID_REQUEST', 'Invalid Grove quorum invitation') from error
    return realm, data['anchor'], anchor, policy


def vote(state, policy, proof, credentials, address):
    data = mesh_enrollment.request_data(policy, proof)
    with state.connect(read_only=True) as db:
        db.execute('BEGIN')
        current_voter(db, state, policy)
        if quarantine.contains(db, data['node_id']) or not member_allowed(db, policy.mesh, data['node_id']):
            raise PeerError('DENIED', 'The panel is blocked by local Mesh policy')
        grove_admission.eligible(db, data['node_id'], data['origin'])
    session = grove_login.login(state, credentials.username, credentials.password, credentials.code, address)
    if session is None:
        raise PeerError('DENIED', 'Grove administrator credentials were rejected')
    actor = auth.actor_for(state, session[0], address)
    if actor is None:
        raise PeerError('DENIED', 'Unable to confirm the Grove administrator')
    try:
        ballot, _ = grove_admission.approve(state, actor, data['node_id'], data['origin'], before_mesh=True)
        return {'ballot':ballot}
    finally:
        auth.logout(state, actor)


def commit(state, policy, proof, certificate):
    data = mesh_enrollment.request_data(policy, proof)
    with state.connect(write=True) as db:
        envelope, anchor = current_voter(db, state, policy)
        if quarantine.contains(db, data['node_id']) or not member_allowed(db, policy.mesh, data['node_id']):
            raise PeerError('DENIED', 'The panel is blocked by local Mesh policy')
        if grove_admission.validate_certificate(certificate, anchor, grove_continuity.anchor_digest(envelope)) != (
                data['node_id'], data['origin']):
            raise PeerError('DENIED', 'The approvals concern a different panel')
        grove_admission.admit(db, certificate, anchor, envelope, 'grove-join-https')
    return {'admitted':True}


def request_members(config, policy, action, body):
    def request(voter):
        try:
            return voter.node, mesh_enrollment.post(config, voter, API + action, body)
        except (OSError, ValueError, PeerError):
            return voter.node, {}

    with ThreadPoolExecutor(max_workers=len(policy.voters)) as executor:
        return dict(executor.map(request, policy.voters.values()))


def choose_bind_ip(policy):
    def usable(value):
        try:
            return mesh_enrollment.fixed_mesh_ip(value)
        except ValueError:
            return None

    for voter in policy.voters.values():
        family = socket.AF_INET6 if ':' in voter.address else socket.AF_INET
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as route:
                route.connect((voter.address, voter.port))
                if address := usable(route.getsockname()[0]):
                    return address
        except OSError:
            continue
    for result in socket.getaddrinfo(socket.gethostname(), None):
        if address := usable(result[4][0]):
            return address
    raise PeerError('OFFLINE', 'No usable local Mesh interface was detected')


def prepare(state, config, actor, code, credentials):
    realm, envelope, anchor, policy = read_invitation(code)
    digest = grove_continuity.anchor_digest(envelope)
    target = (state.identity()[0], config.origin)
    pending = state.directory / PENDING
    with state.lock('grove-quorum-join.lock'):
        with state.connect(read_only=True) as db:
            grove_admission.require_unjoined_admin(db, actor)
            if db.execute('SELECT 1 FROM mesh_profile').fetchone() and not db.execute(
                'SELECT 1 FROM mesh_enrollment_local WHERE policy=?', (policy.id,)
            ).fetchone():
                raise PeerError('CONFLICT', 'Use the existing Mesh membership to join this Grove')
        proof = mesh_enrollment.request_for(state, config, policy)
        try:
            certificate = json.loads(pending.read_bytes())['certificate']
            if grove_admission.validate_certificate(certificate, anchor, digest) != target:
                raise PeerError('CONFLICT', 'An approval is pending for a different Grove invitation')
        except FileNotFoundError:
            if credentials is None:
                raise PeerError('DENIED', 'Enter Grove administrator credentials to continue')
            replies = request_members(config, policy, 'vote', {'request':proof, 'credentials':credentials})
            certificate = []
            for node, reply in replies.items():
                try:
                    ballot = reply['ballot']
                    if grove_admission.validate_ballot(ballot, anchor, digest) == (node, *target):
                        certificate.append(ballot)
                except (KeyError, PeerError):
                    continue
            if len(certificate) < policy.majority():
                raise PeerError('GROVE_ADMISSION_PENDING', 'A majority did not verify and approve this panel')
            onboarding.write_private(pending, grove.encoded({'certificate':certificate}))
        replies = request_members(config, policy, 'commit', {'request':proof, 'certificate':certificate})
        if sum(reply.get('admitted') is True for reply in replies.values()) < policy.majority():
            raise PeerError('OFFLINE', 'Waiting for a Grove majority to record admission')
        installed = mesh_enrollment.load_policy(state)
        if installed is not None and (installed.id != policy.id or not installed.bind_ip):
            raise PeerError('CONFLICT', 'This panel already has different managed Mesh settings')
        if installed is None:
            settings = {'policy':policy.core, 'bind_ip':choose_bind_ip(policy), 'trusted_proxy':False}
            onboarding.write_private(state.directory / mesh_enrollment.POLICY_FILE, grove.encoded(settings))
            installed = mesh_enrollment.read_policy(settings)
        mesh_enrollment.enroll(state, config, installed, bootstrap=True)
    return grove_admission.INVITATION_PREFIX + wire_b64(grove.encoded({'realm':realm, 'members':anchor['voters']}))
