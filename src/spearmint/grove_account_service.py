"""Coordinate account operations through any current Grove member."""

import asyncio
import time
from secrets import token_hex, token_urlsafe

from pydantic import ValidationError

from . import auth, grove_accounts as account, grove_authorization, grove_availability, grove_continuity, grove_voters
from .peer.grove_service_admin import require_admin_identity, source_grant
from .peer import quarantine
from .peer.policy import credentials_current, require_pair
from .peer.protocol import PeerError


class GroveAccountService:
    def __init__(self, state, remote):
        self.state = state
        self.remote = remote
        self.locks = [asyncio.Lock() for _ in range(16)]
        self.term = 0

    def dispatch(self, pair, params):
        if not isinstance(params, dict):
            raise PeerError('INVALID_REQUEST', 'Invalid Grove account request')
        operation = params.get('action')
        peer = pair.node_id if pair else self.remote.local_id
        try:
            with self.state.connect(write=operation != 'get', read_only=operation == 'get') as db:
                if operation == 'get':
                    db.execute('BEGIN')
                _, anchor = account.context(db)
                if pair:
                    require_pair(db, pair)
                    if (pair.legacy or not credentials_current(pair) or quarantine.contains(db, peer)
                            or not grove_continuity.admitted(db, anchor, peer)):
                        raise PeerError('DENIED', '此请求需要当前 Grove 成员。')
                if (operation == 'get' and set(params) == {'action', 'username'}
                        and account.USERNAME.fullmatch(params['username'])):
                    name = params['username']
                    document = account.certificate(self.state, db, name)
                    if document is not None:
                        credentials = document['proposal']['account']
                        if credentials.get('password_hash') is not None or credentials.get('totp') is not None:
                            raise PeerError('DENIED', '旧版凭据只供原节点迁移，由设备公钥替代后才会同步。')
                    return {'certificate': document}
                if operation == 'apply' and set(params) == {'action', 'certificate'}:
                    account.apply(self.state, db, params['certificate'], peer)
                    return {'applied': True}
                grove_availability.require_current(db)
                grove_voters.require_unlocked(db)
                if operation == 'prepare' and set(params) == {'action', 'change', 'proof', 'term'}:
                    if params['term'][1] != peer:
                        raise PeerError('DENIED', '账号确认轮次与成员身份不符。')
                    return account.prepare(self.state, db, params['change'], params['proof'], params['term'],
                        lambda current, identity, scope: grove_authorization.verify(current, identity, peer, scope)
                        if scope == 'self' else require_admin_identity(current, self.remote.local_id, pair, identity, 'accounts'))
                if operation == 'accept' and set(params) == {'action', 'proposal', 'term', 'prepared', 'requested'}:
                    if params['term'][1] != peer:
                        raise PeerError('DENIED', '账号确认轮次与成员身份不符。')
                    return {'vote': account.accept(self.state, db, params['proposal'], params['term'], params['prepared'], params['requested'])}
        except (ValidationError, ValueError, KeyError, TypeError, IndexError, AttributeError) as error:
            raise PeerError('INVALID_REQUEST', '账号请求格式无效。') from error
        raise PeerError('INVALID_REQUEST', 'Unknown Grove account request')

    async def call(self, node, payload):
        if node == self.remote.local_id:
            return await self.remote.work(self.dispatch, None, payload)
        return await self.remote.call(node, account.METHOD, payload, diagnostic=True)

    async def collect(self, nodes, payload):
        return await asyncio.gather(*(self.call(node, payload) for node in nodes), return_exceptions=True)

    def voters(self):
        with self.state.connect(read_only=True) as db:
            db.execute('BEGIN')
            grove_availability.require_current(db)
            grove_voters.require_unlocked(db)
            return account.context(db)[1]['voters']

    async def propose(self, change, proof):
        name = change['username']
        async with self.locks[int(account.hash_code(name)[:4], 16) % len(self.locks)]:
            for _ in range(3):
                voters = await self.remote.work(self.voters)
                self.term = max(time.time_ns(), self.term + 1)
                term = [self.term, self.remote.local_id]
                changes = await self.collect(voters, {'action': 'prepare', 'change': change, 'proof': proof, 'term': term})
                proposals = {}
                for reply in changes:
                    if isinstance(reply, dict) and 'record' in reply:
                        proposals.setdefault(account.digest_of(reply['record']), []).append(reply)
                    elif isinstance(reply, dict) and reply.get('promised'):
                        self.term = max(self.term, reply['promised'][0])
                votes = max(proposals.values(), key=len, default=[])
                if len(votes) <= len(voters) // 2:
                    for code in ('DENIED', 'CONFLICT', 'INVALID_REQUEST'):
                        errors = [reply for reply in changes if isinstance(reply, PeerError) and reply.code == code]
                        if len(errors) > len(voters) // 2:
                            raise errors[0]
                    if self.term > term[0]:
                        continue
                    raise PeerError('GROVE_QUORUM_REQUIRED', '需要在线多数 Grove 投票节点确认，请核对节点版本和连接。')

                requested = account.digest_of(votes[0]['record'])
                earlier = [reply['accepted'] for reply in votes if reply.get('accepted')]
                record = max(earlier, key=lambda item: item['term'])['proposal'] if earlier else votes[0]['record']
                confirmed = await self.collect(voters, {'action': 'accept', 'proposal': record, 'term': term,
                    'requested': requested, 'prepared': [reply['vote'] for reply in votes]})
                approvals = [reply['vote'] for reply in confirmed if isinstance(reply, dict) and 'vote' in reply]
                if len(approvals) <= len(voters) // 2:
                    raise PeerError('GROVE_QUORUM_REQUIRED', '账号变更尚未取得多数确认，请稍后重试。')
                certificate = {'proposal': record, 'term': term, 'votes': approvals}
                await self.call(self.remote.local_id, {'action': 'apply', 'certificate': certificate})
                applied = await self.collect([node for node in voters if node != self.remote.local_id],
                    {'action': 'apply', 'certificate': certificate})
                saved = int(self.remote.local_id in voters) + sum(isinstance(reply, dict) and reply.get('applied') is True for reply in applied)
                if saved <= len(voters) // 2:
                    raise PeerError('GROVE_QUORUM_REQUIRED', '账号变更正在同步到多数节点，请稍后核对结果。')
                await self.remote.request_grove_sync()
                if record['request_id'] == change['request_id']:
                    return saved
            raise PeerError('CONFLICT', '已有账号操作正在同步，请重试。')

    async def run(self, action, username, address, *, actor=None, role=None, current_password=None,
                  code=None, device_key=None):
        change = {'username': username, 'action': action, 'request_id': token_hex(16), 'issued': int(time.time())}
        proof, result = {}, {}
        if actor is not None:
            if action in {'invite', 'create', 'assist'}:
                proof['identity'] = await self.remote.work(source_grant, self.state, self.remote.local_id, None, actor, 'accounts')
            else:
                await self.remote.work(self.require_self, actor, username, action, current_password)
                proof['identity'] = await self.remote.work(grove_authorization.self_proof, self.state, actor)
        else:
            await self.remote.work(self.reserve_attempt, address, change['issued'], username)
        if role is not None:
            change['role'] = role
        if action in {'invite', 'assist'}:
            token = token_urlsafe(32)
            change['ticket_hash'] = account.hash_code(token)
            result['code'] = token
        if action in {'create', 'register', 'reset', 'recovery-code'}:
            recovery = token_urlsafe(32)
            change['recovery_hash'] = account.hash_code(recovery)
            result['recovery_code'] = recovery
        if device_key is not None:
            change['device_key'] = device_key
        if code is not None:
            proof['code'] = code
        result['confirmed'] = await self.propose(change, proof)
        return result

    def reserve_attempt(self, address, now, username):
        with auth.authentication_attempt(self.state, address, now, username=username):
            pass

    def require_self(self, actor, username, action, password):
        with self.state.connect(read_only=True) as db:
            db.execute('BEGIN')
            session = auth.active_session(db, actor.token_hash, int(time.time()))
            if not session or not session['grove_replica'] or session['display_name'] != username:
                raise PeerError('DENIED', '请使用此 Grove 账号登录。')
            if action != 'bind-device' and account.device_key(db, session['grove_user']) is None:
                account.verify_password(self.state, db, {'name': username, 'id': session['grove_user']}, {'current_password': password})
