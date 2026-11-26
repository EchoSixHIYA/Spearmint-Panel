"""Check that a user-held authorization is required at the target boundary."""
import asyncio
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from pydantic import BaseModel

from spearmint import auth, grove_authorization, grove_device_login
from spearmint.peer.protocol import wire_b64
from spearmint.peer.grove_service_admin import GroveServiceAdmin
from spearmint.peer.pairing import configured
from spearmint.peer.protocol import PeerError
from spearmint.request_limits import AUTH_BODY_LIMIT, RequestBodyLimit
from test_grove_voters import VoterFixture


class AuthorizationTest(unittest.TestCase):
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
