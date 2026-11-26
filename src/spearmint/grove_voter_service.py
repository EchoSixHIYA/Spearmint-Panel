"""Automatic coordination and recovery of administrator-requested voter changes."""
import asyncio
import json
import logging
from secrets import token_hex
import time

from cryptography.hazmat.primitives.serialization import Encoding

from . import grove_continuity, grove_voters as voters, mesh_enrollment, onboarding
from .peer.grove_service_admin import source_grant
from .peer.pairing import configured
from .peer.policy import require_pair
from .peer.protocol import PeerError

logger = logging.getLogger(__name__)


class VoterService:
    def __init__(self, state, remote, config):
        self.state, self.remote, self.config = state, remote, config
        self.lock = asyncio.Lock()
        self.term = 0
        self.wake = asyncio.Event()

    def authorize_member(self, db, pair):
        if pair is None:
            return
        require_pair(db, pair)
        from .peer import quarantine
        if pair.legacy or quarantine.contains(db, pair.node_id) or not db.execute('SELECT 1 FROM grove_member WHERE node_id=? AND enabled=1', (pair.node_id,)).fetchone():
            raise PeerError('DENIED', 'Grove voter configuration requires an active member')

    def handle(self, pair, params):
        action = params.get('action')
        fields = {'history': {'action'}, 'ready': {'action', 'identity'},
                  'prepare': {'action', 'identity', 'previous', 'version', 'term'},
                  'accept': {'action', 'identity', 'proposal', 'term', 'bootstrap'},
                  'apply': {'action', 'history'}}
        allowed = fields.get(action)
        if action == 'history' and 'known' in params:
            allowed = {'action', 'known'}
        if action not in fields or params.keys() != allowed:
            raise PeerError('INVALID_REQUEST', 'Invalid Grove voter configuration request')
        with self.state.connect(read_only=True) as db:
            self.authorize_member(db, pair)
            if action == 'history':
                current = grove_continuity.read_anchor(db)
                known = {'version': current[1].get('_version', 0), 'configuration': voters.current_id(current[1])} if current else None
                return {'history': None if known is not None and params.get('known') == known else voters.history(db),
                        'bootstrap': voters.base_policy(self.state)}
        if action == 'ready':
            return {'ready': voters.readiness(self.state, self.config, params['identity'], pair)}
        if action == 'prepare':
            return voters.prepare(self.state, params['identity'], params['previous'], params['version'], params['term'], pair)
        if action == 'accept':
            return {'vote': voters.accept(self.state, params['identity'], params['proposal'], params['term'], params['bootstrap'], pair)}
        changed = voters.apply(self.state, params['history'], pair.node_id if pair else self.remote.local_id)
        if changed:
            self.remote.grove_sync_requested.set()
        return {'applied': True}

    async def rpc(self, node, params):
        if node == self.remote.local_id:
            return await self.remote.work(self.handle, None, params)
        return await self.remote.call(node, voters.METHOD, params, diagnostic=True)

    async def gather(self, nodes, params):
        async def one(node):
            try:
                return node, await self.rpc(node, params)
            except (PeerError, ValueError, OSError, TimeoutError):
                return node, None
        return dict(await asyncio.gather(*(one(node) for node in sorted(set(nodes)))))

    def install_bootstrap(self, core):
        path = self.state.directory / mesh_enrollment.POLICY_FILE
        if path.exists():
            return
        with self.state.connect(read_only=True) as db:
            current = grove_continuity.read_anchor(db)
            profile = db.execute('SELECT * FROM mesh_profile').fetchone()
            if current is None or profile is None:
                return
            anchor = current[1]
            policy = mesh_enrollment.read_policy({'policy': core, 'bind_ip': profile['bind_ip'], 'trusted_proxy': False})
            if (set(anchor.get('_base_voters', anchor['voters'])) != policy.voters.keys()
                    or policy.mesh != profile['mesh_id'] or policy.realm != anchor['realm_id']):
                raise PeerError('CONFLICT', 'Grove voter bootstrap does not match this Mesh')
            for entry in policy.core['voters']:
                member = db.execute('SELECT origin FROM grove_member WHERE node_id=? AND enabled=1', (entry['node_id'],)).fetchone()
                pair = configured(db, entry['node_id'])
                if member is None or member['origin'] != entry['origin'] or (pair and pair.fingerprint != mesh_enrollment.fingerprint(policy.voters[entry['node_id']].leaf)):
                    raise PeerError('CONFLICT', 'Grove voter bootstrap does not match the known members')
        onboarding.write_private(path, json.dumps({'policy': core, 'bind_ip': profile['bind_ip'], 'trusted_proxy': False}).encode())

    async def synchronize(self):
        with self.state.connect(read_only=True) as db:
            current = grove_continuity.read_anchor(db)
            if current is None:
                return
            nodes = [row[0] for row in db.execute('SELECT node_id FROM grove_member WHERE enabled=1')]
            known = {'version': current[1].get('_version', 0), 'configuration': voters.current_id(current[1])}
        replies = await self.gather([node for node in nodes if node != self.remote.local_id], {'action': 'history', 'known': known})
        for node, reply in replies.items():
            if reply is None:
                continue
            try:
                await self.remote.work(self.install_bootstrap, reply['bootstrap'])
                if reply['history']:
                    await self.remote.work(voters.apply, self.state, reply['history'], node)
            except (PeerError, ValueError, OSError, KeyError) as error:
                logger.debug('Grove voter history is waiting: %s', error)

    def enqueue(self, node, desired, identity, request_id=None, *, recovering=False):
        if type(desired) is not bool or not isinstance(node, str) or not voters.NODE_ID.fullmatch(node):
            raise PeerError('INVALID_REQUEST', 'Invalid Grove voter selection')
        request_id = request_id or token_hex(16)
        with self.state.connect(write=True) as db:
            revision = voters.authorize(self.state, db, identity, None, fresh=not recovering)
            if not db.execute('SELECT 1 FROM grove_member WHERE node_id=? AND enabled=1', (node,)).fetchone():
                raise PeerError('NOT_FOUND', '此节点尚未完成 Grove 入网。')
            old = voters.local_state(db)['jobs'].get(request_id)
            if old:
                if old['node_id'] != node or bool(old['desired']) != desired or json.loads(old['identity']) != identity:
                    raise PeerError('CONFLICT', '此请求已用于另一项投票名单变更。')
                return request_id
            pending = [row for row in voters.local_state(db)['jobs'].values() if row['status'] == 'pending']
            for row in pending:
                if row['node_id'] == node and bool(row['desired']) == desired and json.loads(row['identity']) == identity:
                    return row['id']
            if len(pending) >= 32:
                raise PeerError('BUSY', '已有多项投票资格调整正在等待处理，请稍后重试。')
            voters.put_job(db, {'id': request_id, 'node_id': node, 'desired': int(desired), 'identity': json.dumps(identity),
                'status': 'pending', 'reason': '正在等待同步并收集多数确认。', 'updated_at': int(time.time())})
            from .state import audit
            audit(db, revision[1], 'local', 'grove.voter_requested', node, reason='promote' if desired else 'demote')
        self.wake.set()
        return request_id

    async def request(self, actor, node, desired, request_id=None):
        identity = await self.remote.work(source_grant, self.state, self.remote.local_id, None, actor, 'voters')
        request_id = await self.remote.work(self.enqueue, node, desired, identity, request_id)
        return {'id': request_id, 'status': 'pending'}

    def outcome(self, job_id, status, reason=None):
        with self.state.connect(write=True) as db:
            row = voters.local_state(db)['jobs'].get(job_id)
            if row:
                voters.put_job(db, {**row, 'status': status, 'reason': reason, 'updated_at': int(time.time())})

    async def change(self, node, desired, identity):
        async with self.lock:
            await self.synchronize()
            current = await self.remote.work(grove_continuity.local_anchor, self.state)
            if current is None:
                raise PeerError('CONFLICT', '此 Grove 尚未启用多数成员授权。')
            envelope, anchor = current
            if (node in anchor['voters']) == desired:
                return await self.distribute_current(anchor)
            if not voters.MIN_VOTERS <= len(anchor['voters']) + (1 if desired else -1) <= voters.MAX_VOTERS:
                raise PeerError('GROVE_VOTER_LIMIT', f'投票节点数量须在 {voters.MIN_VOTERS} 至 {voters.MAX_VOTERS} 台之间。')
            with self.state.connect(read_only=True) as db:
                revision = voters.authorize(self.state, db, identity, None, fresh=False)
                history = voters.rows(db)
                bootstrap = history[0]['bootstrap'] if history else voters.base_policy(self.state)
                snapshot = voters.checkpoint(self.state, db)
                prior_ballot = voters.ballot_for(db, anchor.get('_version', 0) + 1)
            prior_counter = json.loads(prior_ballot['promised'])[0] if prior_ballot else 0
            self.term = max(self.term, prior_counter) + 1
            term = [self.term, self.remote.local_id]
            previous = voters.current_id(anchor)
            prepared = await self.gather(anchor['voters'], {'action': 'prepare', 'identity': identity,
                'previous': previous, 'version': anchor.get('_version', 0) + 1, 'term': term})
            granted = [reply for reply in prepared.values() if reply and reply.get('granted')]
            self.term = max([self.term] + [reply['promised'][0] for reply in prepared.values() if reply])
            if len(granted) <= len(anchor['voters']) // 2:
                raise PeerError('GROVE_QUORUM_REQUIRED', '正在等待现有投票成员的多数确认；请先通过群组更新升级投票节点。')
            accepted = [reply for reply in granted if reply.get('accepted_term')]
            if accepted:
                proposal = max(accepted, key=lambda reply: reply['accepted_term'])['proposal']
            else:
                ready, entry = None, None
                policy = mesh_enrollment.load_policy(self.state)
                if desired:
                    try:
                        result = await self.rpc(node, {'action': 'ready', 'identity': identity})
                    except PeerError as error:
                        raise PeerError('GROVE_VOTER_NOT_READY', '目标节点正在等待权限同步或尚未升级到支持投票变更的版本。') from error
                    ready = result['ready']
                    _, raw = voters.verified_node(voters.READY_KIND, ready)
                    entry = raw['entry']
                    voters.verify_ready(ready, node, previous, snapshot, entry)
                entries = [item for item in policy.core['voters'] if item['node_id'] != node]
                if entry:
                    entries.append(entry)
                entries.sort(key=lambda item: item['node_id'])
                active_ca = {item['ca'] for item in entries}
                retired = sorted({root.public_bytes(Encoding.PEM).decode() for root in policy.roots[1:]} - active_ca)
                core = {**policy.core, 'voters': entries, 'retired_ca': retired}
                proposal = {'version': anchor.get('_version', 0) + 1, 'previous': previous, 'policy': core,
                    'checkpoint': snapshot, 'identity': revision, 'target': node, 'ready': ready}
            new = [entry['node_id'] for entry in proposal['policy']['voters']]
            results = await self.gather(set(anchor['voters']) | set(new), {'action': 'accept', 'identity': identity,
                'proposal': proposal, 'term': term, 'bootstrap': bootstrap})
            certificate = {'proposal': proposal, 'term': term, 'votes': [r['vote'] for r in results.values() if r and 'vote' in r]}
            voters.validate_votes(certificate, anchor['voters'], new)
            chain = {'bootstrap': bootstrap, 'changes': [row['certificate'] for row in history] + [certificate]}
            encoded = voters.pack(chain)
            with self.state.connect(read_only=True) as db:
                all_nodes = [row[0] for row in db.execute('SELECT node_id FROM grove_member WHERE enabled=1')]
            applied = await self.gather(all_nodes, {'action': 'apply', 'history': encoded})
            confirmed = {node for node, reply in applied.items() if reply and reply.get('applied')}
            if (len(confirmed & set(anchor['voters'])) <= len(anchor['voters']) // 2
                    or len(confirmed & set(new)) <= len(new) // 2):
                raise PeerError('GROVE_QUORUM_REQUIRED', '投票变更已获确认，正在等待新旧多数成员保存名单。')
            self.remote.grove_sync_requested.set()
            # If recovery finished another accepted change, retain this request
            # and retry it at the next version rather than replacing that value.
            return proposal['target'] == node and (node in new) == desired

    async def distribute_current(self, anchor):
        with self.state.connect(read_only=True) as db:
            records = voters.rows(db)
            encoded = voters.history(db)
            nodes = [row[0] for row in db.execute('SELECT node_id FROM grove_member WHERE enabled=1')]
        if not records:
            return True
        results = await self.gather(nodes, {'action': 'apply', 'history': encoded})
        saved = {node for node, result in results.items() if result and result.get('applied')}
        last = records[-1]['certificate']['proposal']
        old = anchor['_contexts'][last['previous']]['voters']
        new = anchor['voters']
        return len(saved & set(old)) > len(old) // 2 and len(saved & set(new)) > len(new) // 2

    def recover_request(self):
        """Any accepting member can resume a change after its sponsor leaves."""
        with self.state.connect(read_only=True) as db:
            current = grove_continuity.read_anchor(db)
            if current is None:
                return
            row = voters.ballot_for(db, current[1].get('_version', 0) + 1)
        if row and row['proposal'] is not None:
            proposal = json.loads(row['proposal'])
            desired = proposal['target'] in {item['node_id'] for item in proposal['policy']['voters']}
            self.enqueue(proposal['target'], desired, proposal['identity'], voters.digest(proposal)[:32], recovering=True)

    async def run(self):
        while True:
            self.wake.clear()
            try:
                await self.synchronize()
                await self.remote.work(self.recover_request)
                with self.state.connect(read_only=True) as db:
                    jobs = sorted((row for row in voters.local_state(db)['jobs'].values() if row['status'] == 'pending'), key=lambda row: row['updated_at'])[:4]
                for job in jobs:
                    try:
                        completed = await self.change(job['node_id'], bool(job['desired']), json.loads(job['identity']))
                        if completed:
                            await self.remote.work(self.outcome, job['id'], 'succeeded')
                    except PeerError as error:
                        status = 'failed' if error.code in {'DENIED', 'GROVE_VOTER_LIMIT'} else 'pending'
                        await self.remote.work(self.outcome, job['id'], status, str(error))
                    except (ValueError, OSError, KeyError) as error:
                        logger.debug('Grove voter request is waiting: %s', error)
                        await self.remote.work(self.outcome, job['id'], 'pending', '正在等待 Grove 同步恢复。')
            except (PeerError, OSError, ValueError) as error:
                logger.debug('Grove voter synchronization is waiting: %s', error)
            try:
                await asyncio.wait_for(self.wake.wait(), timeout=15)
            except TimeoutError:
                pass
