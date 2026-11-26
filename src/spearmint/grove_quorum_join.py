"""Approve a fresh panel at a Grove quorum before opening its Mesh connection."""
from concurrent.futures import ThreadPoolExecutor
import json
import re
from secrets import token_hex
import socket
import time
from urllib.parse import urlsplit

from . import grove, grove_admission, grove_authorization, grove_continuity, grove_login, grove_voters, grove_web_join, mesh_enrollment, onboarding
from .peer import quarantine
from .peer.mesh_policy import member_allowed
from .peer.protocol import PeerError, decode_json, parse_b64, wire_b64


PREFIX = 'grove5.'
LIMIT = 128 * 1024
API = '/api/v1/auth/grove/quorum-join/'
PENDING = 'grove-quorum-join.json'
ADMISSION_RECEIPT = 'browser-admission-receipt'


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
        if governance := grove_voters.history(db):
            contents['governance'] = governance
    code = PREFIX + wire_b64(grove.encoded(contents))
    if len(code) > LIMIT:
        raise PeerError('LIMIT', 'Grove invitation exceeds the panel limit')
    return code


def read_invitation(code):
    try:
        if not code.startswith(PREFIX) or len(code) > LIMIT:
            raise ValueError
        data = decode_json(parse_b64(code[len(PREFIX):], LIMIT))
        if data.keys() not in ({'realm', 'anchor', 'manifest', 'mesh'}, {'realm', 'anchor', 'manifest', 'mesh', 'governance'}):
            raise ValueError
        realm = grove.invitation(data['realm'])
        key = parse_b64(realm['public_key'], 32)
        directory = grove.directory_data(data['manifest'], realm, allow_expired=True)
        anchor = grove_continuity.snapshot_authorization(realm | {'public_key':key}, directory, data['anchor'], 'login-continuity')
        anchor = grove_voters.history_anchor(anchor, data.get('governance'))
        policy = mesh_enrollment.read_policy({'policy':data['mesh'], 'bind_ip':None, 'trusted_proxy':False})
        origins = {member['node_id']:member['origin'] for member in directory['members'] if member['enabled']}
        if anchor.get('_version'):
            if policy.core != anchor['_policy']:
                raise ValueError
            origins.update({entry['node_id']:entry['origin'] for entry in anchor['_policy']['voters']})
        if (policy.realm != realm['id'] or policy.voters.keys() != set(anchor['voters']) or any(
            voter.origin != origins.get(voter.node) or not grove_web_join.browser_origin(voter.origin)
            for voter in policy.voters.values()
        )):
            raise ValueError
    except (KeyError, TypeError, ValueError, PeerError) as error:
        raise PeerError('INVALID_REQUEST', 'Invalid Grove quorum invitation') from error
    return realm, data['anchor'], anchor, policy


def vote(state, policy, proof, authorization):
    data = mesh_enrollment.request_data(policy, proof)
    try:
        grant = grove_authorization.unsigned(authorization['grant'])
        subject = {'node_id': data['node_id'], 'origin': data['origin']}
        if grant['joining'] != subject:
            raise ValueError
        source = grant['source']
    except (KeyError, ValueError, TypeError) as error:
        raise PeerError(grove_authorization.ERROR, '加入授权不属于这台节点。') from error
    with state.connect(write=True) as db:
        envelope, anchor = current_voter(db, state, policy)
        if any(quarantine.contains(db, node) or not member_allowed(db, policy.mesh, node)
               for node in (data['node_id'], source)):
            raise PeerError('DENIED', 'The panel is blocked by local Mesh policy')
        if not db.execute('SELECT 1 FROM grove_member WHERE node_id=? AND enabled=1', (source,)).fetchone():
            raise PeerError('DENIED', 'The joining authorization requires an active member')
        identity = grove_authorization.verify(db, authorization, source, 'join')
        ballot = grove_admission.record_ballot(db, state, data['node_id'], data['origin'], envelope, anchor, identity[1], source)
    return {'ballot': ballot}


def commit(state, policy, proof, certificate, nonce=None):
    if nonce is not None and (not isinstance(nonce, str) or not re.fullmatch(r'[a-f0-9]{32}', nonce)):
        raise PeerError('INVALID_REQUEST', 'Invalid admission receipt nonce')
    data = mesh_enrollment.request_data(policy, proof)
    with state.connect(write=True) as db:
        envelope, anchor = current_voter(db, state, policy)
        if quarantine.contains(db, data['node_id']) or not member_allowed(db, policy.mesh, data['node_id']):
            raise PeerError('DENIED', 'The panel is blocked by local Mesh policy')
        if grove_admission.validate_certificate(certificate, anchor, grove_continuity.anchor_digest(envelope)) != (
                data['node_id'], data['origin']):
            raise PeerError('DENIED', 'The approvals concern a different panel')
        grove_admission.admit(db, certificate, anchor, envelope, 'grove-join-https')
    if nonce is None:
        return {'admitted': True}
    key = state.signing_key()
    record = receipt_fields(envelope, anchor, proof, certificate, nonce)
    record['public_key'] = wire_b64(key.public_key().public_bytes_raw())
    return {'receipt': grove.signed(ADMISSION_RECEIPT, record, key)}


def receipt_fields(envelope, anchor, proof, certificate, nonce):
    # Confirm durable admission for this request and round under the same voter roster.
    return {'anchor': grove_continuity.anchor_digest(envelope), 'configuration': grove_voters.current_id(anchor),
            'request': grove_voters.digest(proof), 'certificate': grove_voters.digest(certificate), 'nonce': nonce}


def confirmed_admissions(replies, envelope, anchor, proof, certificate, nonce):
    expected = receipt_fields(envelope, anchor, proof, certificate, nonce)
    voters = set(anchor['voters'])
    confirmed = set()
    for expected_node, reply in replies.items():
        try:
            node, data = grove_voters.verified_node(ADMISSION_RECEIPT, reply['receipt'])
            if node == expected_node and node in voters and data == {**expected, 'public_key': data['public_key']}:
                confirmed.add(node)
        except (PeerError, KeyError, ValueError, TypeError, AttributeError):
            continue
    return len(confirmed)


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


def prepare(state, config, actor, code, authorization):
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
            if authorization is None:
                raise PeerError(grove_authorization.ERROR, '粘贴管理员为此节点签名的加入授权。')
            replies = request_members(config, policy, 'vote', {'request': proof, 'authorization': authorization})
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
        nonce = token_hex(16)
        replies = request_members(config, policy, 'commit', {'request': proof, 'certificate': certificate, 'nonce': nonce})
        if confirmed_admissions(replies, envelope, anchor, proof, certificate, nonce) < policy.majority():
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
