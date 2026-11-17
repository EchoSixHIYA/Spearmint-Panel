"""Approve an SSH-installed node and let it join with its own Mesh identity."""
import json
import sys

from . import grove, grove_admission, grove_continuity, grove_quorum_join, mesh_enrollment, onboarding
from .peer import quarantine
from .peer.mesh_policy import member_allowed
from .peer.policy import require_pair
from .peer.protocol import PeerError, wire_b64
from .state import private_path


METHOD = 'grove.seed.admission'
PENDING = 'seed-admission.json'
LIMIT = grove_quorum_join.LIMIT + 32 * 1024


def handle(state, policy, pair, params, user: str | None = None, delegates=frozenset()):
    node = pair.node_id if pair else state.identity()[0]
    action = params.get('action')
    with state.connect(write=action == 'vote') as db:
        if pair:
            require_pair(db, pair)
        envelope, anchor = grove_quorum_join.current_voter(db, state, policy)
        active = db.execute('SELECT 1 FROM grove_member WHERE node_id=? AND enabled=1', (node,)).fetchone()
        if (node not in anchor['voters'] and node not in delegates or
                not active or not grove_continuity.admitted(db, anchor, node) or quarantine.contains(db, node) or
                not member_allowed(db, policy.mesh, node)):
            raise PeerError('DENIED', 'This Grove member is not authorized to sponsor an SSH deployment')
        if action == 'vote' and params.keys() == {'action', 'request', 'actor'}:
            actor = params['actor']
            if not isinstance(actor, str) or not actor.isprintable() or not 1 <= len(actor) <= 100:
                raise PeerError('INVALID_REQUEST', 'Invalid SSH deployment actor')
            data = mesh_enrollment.request_data(policy, params['request'])
            if quarantine.contains(db, data['node_id']) or not member_allowed(db, policy.mesh, data['node_id']):
                raise PeerError('DENIED', 'The target is blocked by local Mesh policy')
            ballot = grove_admission.record_ballot(db, state, data['node_id'], data['origin'], envelope, anchor,
                                                   user or actor, node)
            return {'ballot': ballot}
    if action == 'invitation' and params.keys() == {'action'}:
        code = grove_quorum_join.invitation(state, policy)
        if code is not None:
            return {'code': code}
    if action == 'commit' and params.keys() == {'action', 'request', 'certificate'}:
        return grove_quorum_join.commit(state, policy, params['request'], params['certificate'])
    raise PeerError('INVALID_REQUEST', 'Invalid SSH deployment admission request')


def pending(state):
    path = state.directory / PENDING
    try:
        private_path(path, 0o600)
        with path.open('rb') as stream:
            return json.loads(stream.read(LIMIT))
    except FileNotFoundError:
        return None


def install_policy(state, config, policy):
    installed = mesh_enrollment.load_policy(state)
    if installed is not None and (installed.id != policy.id or not installed.bind_ip):
        raise PeerError('CONFLICT', 'This node already has different Mesh settings')
    if installed is None:
        settings = {'policy': policy.core, 'bind_ip': grove_quorum_join.choose_bind_ip(policy), 'trusted_proxy': False}
        onboarding.write_private(state.directory / mesh_enrollment.POLICY_FILE, grove.encoded(settings))
        installed = mesh_enrollment.read_policy(settings)
    return mesh_enrollment.enroll(state, config, installed, bootstrap=True)


def cli(state, config, action):
    node = state.verify()
    if action == 'status':
        with state.connect(read_only=True) as db:
            row = db.execute('SELECT id FROM grove_realm').fetchone()
        return {'node_id': node, 'realm': row['id'] if row else None}
    raw = sys.stdin.buffer.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise PeerError('LIMIT', 'SSH enrollment input exceeds the limit')
    request = json.loads(raw)
    realm, envelope, anchor, policy = grove_quorum_join.read_invitation(request['invitation'])
    with state.lock('seed-admission.lock'):
        with state.connect(read_only=True) as db:
            current = db.execute('SELECT id FROM grove_realm').fetchone()
            if current:
                if current['id'] != realm['id']:
                    raise PeerError('CONFLICT', 'This node already belongs to another Grove')
                return {'node_id': node, 'realm': current['id']}
            if db.execute('SELECT 1 FROM mesh_profile').fetchone() and not db.execute(
                    'SELECT 1 FROM mesh_enrollment_local WHERE policy=?', (policy.id,)).fetchone():
                raise PeerError('CONFLICT', 'This node already has another Mesh identity')
        if action == 'request':
            return {'node_id': node, 'request': mesh_enrollment.request_for(state, config, policy)}
        certificate = request['certificate']
        if grove_admission.validate_certificate(certificate, anchor, grove_continuity.anchor_digest(envelope)) != (node, config.origin):
            raise PeerError('DENIED', 'Grove approval does not match this installed node')
        onboarding.write_private(state.directory / PENDING, grove.encoded(request))
    return {'node_id': node, 'accepted': True}


async def finish(state, config, remote, data):
    realm, envelope, anchor, policy = grove_quorum_join.read_invitation(data['invitation'])
    certificate = data['certificate']
    if grove_admission.validate_certificate(certificate, anchor, grove_continuity.anchor_digest(envelope)) != (
            state.identity()[0], config.origin):
        raise PeerError('DENIED', 'Grove approval does not match this installed node')
    with state.connect(read_only=True) as db:
        row = db.execute('SELECT id FROM grove_realm').fetchone()
    if row is None:
        remote.manager.use_system_egress = True
        await remote.work(install_policy, state, config, policy)
        code = grove_admission.INVITATION_PREFIX + wire_b64(grove.encoded({'realm':realm, 'members':anchor['voters']}))
        await remote.join_grove_from_invitation(None, code, seed_certificate=certificate)
    elif row['id'] != realm['id']:
        raise PeerError('CONFLICT', 'This node already belongs to another Grove')
    with state.lock('onboarding.lock'):
        record = onboarding.read_record(state)
        with state.connect(read_only=True) as db:
            unfinished = record and onboarding.pending_account(db, record)
        if unfinished:
            onboarding.clear_handoff(state)
    (state.directory / PENDING).unlink(missing_ok=True)
