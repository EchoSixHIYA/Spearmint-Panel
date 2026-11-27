"""Check that a user-held authorization is required at the target boundary."""
import asyncio
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel

from spearmint import auth, grove_authorization, grove_device_login, grove_quorum_join, mesh_enrollment
from spearmint.app import create_app
from spearmint.config import Config
from spearmint.peer.protocol import wire_b64
from spearmint.peer.grove_service_admin import GroveServiceAdmin
from spearmint.peer.pairing import configured, set_enabled
from spearmint.peer.services import PeerServices
from spearmint.peer.reputation import Reputation, WINDOW
from spearmint.peer.protocol import PeerError
from spearmint.request_limits import AUTH_BODY_LIMIT, RequestBodyLimit
from spearmint.state import State
from spearmint.terminal_service import SESSIONS_PER_SOURCE, TerminalService
from test_grove_voters import VoterFixture


class AuthorizationTest(unittest.TestCase):
    def test_device_verification_finishes_in_browser_with_full_session(self):
        root = Path.cwd() / 'work/tmp/codex-grove-authorization'
        root.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(dir=root) as directory:
            fixture = VoterFixture(Path(directory))
            panel = fixture.states[0]
            device = Ed25519PrivateKey.generate()
            public = wire_b64(device.public_key().public_bytes_raw())
            votes = [grove_authorization.key_vote(voter, 'admin', public) for voter in fixture.states[:2]]
            origin = 'https://localhost:18443'
            config = Config(panel.directory, origin, root / 'web', root / 'docker')
            app = create_app(config, native_loopback_setup=True)
            client = TestClient(app, base_url=origin, client=('127.0.0.1', 50001))
            headers = {'Origin': origin}
            challenge = client.post('/api/v1/auth/grove/device/challenge', headers=headers,
                                    json={'username': 'admin', 'session_authorization': True}).json()
            proof = grove_authorization.issue(device, challenge, votes)
            rolling = grove_authorization.rolling_update_challenge(challenge)
            proof['rolling_update'] = grove_authorization.issue(device, rolling, votes)
            remote = TestClient(app, base_url=origin, client=('192.0.2.10', 50002))
            self.assertEqual(remote.post('/api/v1/auth/grove/device/start-browser',
                                         headers=headers, json=proof).status_code, 403)
            remote.close()
            native = client.post('/api/v1/auth/grove/device/start-browser', headers=headers, json=proof)
            self.assertEqual(native.status_code, 200)
            self.assertNotIn('set-cookie', native.headers)
            ticket = native.json()
            endpoint = '/api/v1/auth/grove/device/finish-browser'
            self.assertEqual(client.post(endpoint, headers={'Origin': 'https://other.example'}, json=ticket).status_code, 403)
            browser = client.post(endpoint, headers=headers, json=ticket)
            self.assertEqual(browser.status_code, 200)
            self.assertEqual(browser.json()['role'], 'node_admin')
            self.assertEqual(client.post(endpoint, headers=headers, json=ticket).status_code, 403)
            token = client.cookies[auth.COOKIE]
            actor = auth.actor_for(panel, token, 'testclient')
            proof = grove_authorization.service_session(panel, actor)
            self.assertEqual(grove_authorization.unsigned(proof['grant'])['scopes'], grove_authorization.ADMIN_SIGNIN)
            self.assertIsNotNone(grove_authorization.rolling_update_proof(panel, actor, panel.identity()[0]))
            client.close()

    def test_known_member_has_only_user_approved_scopes(self):
        root = Path.cwd() / 'work/tmp/codex-grove-authorization'
        root.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(dir=root) as directory:
            fixture = VoterFixture(Path(directory))
            source, target = fixture.states[:2]
            proof = fixture.authorize(source, scopes=['terminal'])
            with target.connect(read_only=True) as db:
                target_id = target.identity()[0]
                pair = configured(db, source.identity()[0])
                actor = GroveServiceAdmin.from_wire(target_id, pair, proof, 'terminal')
                actor.require(db)
                with self.assertRaises(PeerError):
                    GroveServiceAdmin.from_wire(target_id, pair, proof, 'services').require(db)
                with self.assertRaises(PeerError):
                    GroveServiceAdmin.from_wire(target_id, pair, actor.identity, 'terminal')
                other = configured(db, fixture.states[2].identity()[0])
                with self.assertRaises(PeerError):
                    GroveServiceAdmin.from_wire(target_id, other, proof, 'terminal').require(db)
                request = grove_authorization.unsigned(proof['grant'])
                with self.assertRaises(PeerError):
                    grove_authorization.verify(db, proof, pair.node_id, 'terminal', at=request['expires_at'])


    def test_public_snapshot_can_log_in_on_a_disconnected_member(self):
        root = Path.cwd() / 'work/tmp/codex-grove-authorization'
        root.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(dir=root) as directory:
            fixture = VoterFixture(Path(directory))
            state = fixture.new
            with state.connect(read_only=True) as db:
                self.assertEqual(db.execute('SELECT count(*) FROM grove_login_verifier').fetchone()[0], 0)
            key = Ed25519PrivateKey.generate()
            public = wire_b64(key.public_key().public_bytes_raw())
            approvals = [grove_authorization.key_vote(voter, 'admin', public) for voter in fixture.states[:2]]
            fixture.expire_freshness()
            with state.connect(write=True) as db:
                db.execute('UPDATE grove_login_continuity SET lease_until=lease_until-900')
            challenge = grove_device_login.challenge(state, 'admin', 'fixture')
            proof = grove_authorization.issue(key, challenge, approvals)
            token, _ = grove_device_login.finish(state, proof, 'fixture')
            self.assertEqual(auth.actor_for(state, token, 'fixture').role, 'node_admin')
            with self.assertRaises(PeerError):
                grove_device_login.finish(state, proof, 'fixture')
            with state.connect(read_only=True) as db:
                self.assertEqual(db.execute('SELECT count(*) FROM grove_login_verifier').fetchone()[0], 0)


    def test_update_authorization_does_not_accept_an_unrelated_grant(self):
        root = Path.cwd() / 'work/tmp/codex-grove-authorization'
        root.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(dir=root) as directory:
            fixture = VoterFixture(Path(directory))
            source = fixture.states[0]
            actor = fixture.login()
            original = grove_authorization.enrolled(source, actor)
            terminal = fixture.authorize(source, actor, scopes=['terminal'])
            grove_authorization.enrollment(source, actor, original)
            with self.assertRaises(PeerError) as denied:
                grove_authorization.enrollment(source, actor, terminal, required_scope='updates')
            self.assertEqual(denied.exception.code, grove_authorization.ERROR)
            self.assertEqual(grove_authorization.enrolled(source, actor), original)

    def test_admission_confirms_a_majority_for_the_current_request(self):
        root = Path.cwd() / 'work/tmp/codex-grove-authorization'
        root.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(dir=root) as directory:
            fixture = VoterFixture(Path(directory))
            voter = fixture.states[0]
            policy = mesh_enrollment.load_policy(voter)
            target = State(Path(directory) / 'requesting-panel')
            target.initialize(lambda: fixture.password_hash)
            origin = 'https://requesting-panel.example:18443'
            proof = mesh_enrollment.request_for(target, SimpleNamespace(origin=origin), policy)
            authorization = fixture.authorize(voter, scopes=['join'],
                                              joining={'node_id': target.identity()[0], 'origin': origin})
            certificate = [grove_quorum_join.vote(state, policy, proof, authorization)['ballot']
                           for state in fixture.states[:2]]
            nonce = '1' * 32
            replies = {state.identity()[0]: grove_quorum_join.commit(state, policy, proof, certificate, nonce)
                       for state in fixture.states[:2]}
            def confirmed(attempt):
                return grove_quorum_join.confirmed_admissions(
                    replies, fixture.envelope, fixture.anchor, proof, certificate, attempt)
            self.assertEqual(confirmed(nonce), policy.majority())
            self.assertEqual(confirmed('2' * 32), 0)

    def test_terminal_reaper_closes_sessions_when_a_member_is_removed(self):
        root = Path.cwd() / 'work/tmp/codex-grove-authorization'
        root.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(dir=root) as directory:
            fixture = VoterFixture(Path(directory))
            source, target = fixture.states[:2]
            source_id = source.identity()[0]
            proof = fixture.authorize(source, scopes=['terminal'])
            with target.connect(read_only=True) as db:
                pair = configured(db, source_id)
            terminal = TerminalService(target, target.identity()[0])
            self.addCleanup(terminal.shutdown)
            def request(index):
                return terminal.dispatch(pair, {'identity': proof, 'owner': 'a' * 32, 'session': f'{index:032x}',
                                                'action': 'open', 'body': {'columns': 80, 'rows': 25}})
            with patch('spearmint.terminal_service.open_terminal',
                       side_effect=lambda *_: Mock(read=Mock(return_value=b''))) as open_backend:
                for index in range(SESSIONS_PER_SOURCE):
                    request(index)
                with self.assertRaises(PeerError) as context:
                    request(SESSIONS_PER_SOURCE)
                self.assertEqual(context.exception.code, 'BUSY')
                self.assertEqual(open_backend.call_count, SESSIONS_PER_SOURCE)
            set_enabled(target, False, node_id=source_id)
            terminal.reap()
            self.assertFalse(terminal.sessions)


    def test_package_details_require_deployment_authorization(self):
        root = Path.cwd() / 'work/tmp/codex-grove-authorization'
        root.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(dir=root) as directory:
            fixture = VoterFixture(Path(directory))
            source, target = fixture.states[:2]
            with target.connect(read_only=True) as db:
                pair = configured(db, source.identity()[0])
            service = PeerServices.__new__(PeerServices)
            service.local_id = target.identity()[0]
            service.state = target
            service.deployment_status = lambda: {'build': {'version': '0.4.0'},
                'host': {'schema': 30}, 'web': {'status': 'ready', 'package_web_sha256': 'a' * 64},
                'package_checksums_sha256': 'b' * 64}
            query = {'realm_id': fixture.realm['id']}
            self.assertEqual(service.deployment_reply(pair, query), {
                'build': {'version': '0.4.0'}, 'web': {'status': 'ready'}})
            proof = fixture.authorize(source, scopes=['deployment'])
            details = service.deployment_reply(pair, {**query, 'authorization': proof}, details=True)
            self.assertEqual(details['host']['schema'], 30)
            self.assertEqual(details['package_checksums_sha256'], 'b' * 64)


class AuthorizationReputationTest(unittest.TestCase):
    def test_authorization_failures_count_while_audits_are_sampled(self):
        clock = Mock(return_value=100.0)
        reputation = Reputation(clock)
        self.assertTrue(reputation.invalid_authorization('paired-node', 'grove.terminal.v1'))
        self.assertFalse(reputation.invalid_authorization('paired-node', 'grove.terminal.v1'))
        self.assertFalse(reputation.invalid_authorization('paired-node', 'grove.terminal.v1'))
        self.assertEqual(reputation.status('paired-node')['state'], 'suspected')
        clock.return_value += WINDOW
        self.assertTrue(reputation.invalid_authorization('paired-node', 'grove.terminal.v1'))


class BodyLimitTest(unittest.TestCase):
    def test_bound_declarative_json_and_streamed_bodies(self):
        class Input(BaseModel):
            value: str

        app = FastAPI()
        app.add_middleware(RequestBodyLimit)

        @app.post('/api/v1/session')
        async def handler(body: Input):
            return {'length': len(body.value)}

        async def status(raw, length):
            headers = [(b'content-type', b'application/json')]
            if length:
                headers += [(b'content-length', str(len(raw)).encode())]
            scope = {'type': 'http', 'method': 'POST', 'path': '/api/v1/session',
                     'query_string': b'', 'headers': headers}
            split = len(raw) // 2
            chunks = iter([{'type': 'http.request', 'body': raw[:split], 'more_body': True},
                           {'type': 'http.request', 'body': raw[split:]}])
            messages = []

            async def receive():
                return next(chunks)

            async def send(message):
                messages.append(message)

            await app(scope, receive, send)
            return messages[0]['status']

        normal = b'{"value":"ok"}'
        excessive = b'{"value":"' + b'a' * AUTH_BODY_LIMIT + b'"}'
        self.assertEqual(asyncio.run(status(normal, True)), 200)
        self.assertEqual(asyncio.run(status(excessive, True)), 413)
        self.assertEqual(asyncio.run(status(excessive, False)), 413)
