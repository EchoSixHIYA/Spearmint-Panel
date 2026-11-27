"""Exercise management through the ordinary Grove password login endpoint."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from pyotp import TOTP

from spearmint import auth, grove_authorization, grove_password_session, grove_updates, update_release
from spearmint.app import create_app
from spearmint.config import Config
from spearmint.peer.grove_service_admin import GroveServiceAdmin, source_grant
from spearmint.peer.pairing import configured
from spearmint.peer.protocol import wire_b64
from spearmint.peer.services import PeerServices
from test_grove_voters import VoterFixture


class GrovePasswordSessionTest(unittest.TestCase):
    def test_http_login_starts_group_update_and_reuses_management_session(self):
        work = Path.cwd() / 'work/tmp/grove-password-session'
        work.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(dir=work) as tmp:
            root = Path(tmp)
            fixture = VoterFixture(root)
            panel, receiver = fixture.states[:2]
            node_id = panel.identity()[0]
            nodes = {state.identity()[0]: state for state in fixture.states}
            origin = 'https://localhost:18443'
            publisher = Ed25519PrivateKey.generate()
            release = {'sequence': 43, 'tag': 'v0.4.0-preview.43', 'version': '0.4.0', 'commit': 'a' * 40,
                       'schema': 30, 'packages': {name: {'sha256': 'b' * 64, 'size': 123}
                                                  for name in update_release.TARGETS}}
            release['signature'] = wire_b64(publisher.sign(update_release.signed_bytes(release)))
            release['packages'] = {name: {**asset, 'id': 1} for name, asset in release['packages'].items()}
            initialize = grove_updates.UpdateCoordinator.__init__

            def coordinator(instance, *args, **kwargs):
                initialize(instance, *args, **kwargs)
                instance.catalog = update_release.Release.model_validate(release)
                instance.prepare_group_archives = lambda *_: None

            async def work_in_fixture(_remote, fn, *args, rpc=False):
                return fn(*args)

            async def call_in_fixture(_remote, target_id, method, params, **kwargs):
                self.assertEqual(method, grove_password_session.METHOD)
                voter = nodes[target_id]
                with voter.connect(read_only=True) as db:
                    pair = configured(db, node_id)
                return grove_password_session.receive(voter, pair, params)

            with (patch.object(update_release, 'RELEASE_PUBLIC_KEY', publisher.public_key().public_bytes_raw()),
                  patch.object(grove_updates.UpdateCoordinator, '__init__', coordinator),
                  patch.object(PeerServices, 'work', work_in_fixture),
                  patch.object(PeerServices, 'call', call_in_fixture)):
                app = create_app(Config(panel.directory, origin, root / 'web', root / 'docker'))
                with TestClient(app, base_url=origin) as client:
                    headers = {'Origin': origin}
                    login = {'username': 'admin', 'password': fixture.password, 'code': TOTP(fixture.secret).now()}
                    response = client.post('/api/v1/auth/grove/member-login', headers=headers,
                                           json={**login, 'password': 'incorrect'})
                    self.assertEqual(response.status_code, 401)
                    response = client.post('/api/v1/auth/grove/member-login', headers=headers, json=login)
                    self.assertEqual(response.status_code, 200, response.text)
                    self.assertTrue(response.json()['grove_management_ready'])
                    headers['X-CSRF-Token'] = response.json()['csrf_token']
                    token = client.cookies.get(auth.COOKIE)
                    response = client.post('/api/v1/grove/updates', headers=headers,
                                           json={'tag': release['tag'], 'commit': release['commit']})
                    self.assertEqual(response.status_code, 202, response.text)
                    group = json.loads((panel.directory / 'grove-updates/group.json').read_bytes())
                    proof = group['identity']
                    with receiver.connect(read_only=True) as db:
                        pair = configured(db, node_id)
                        for scope in ('services', 'service-control', 'updates', 'terminal', 'deployment',
                                      'seed', 'voters', 'accounts', 'identity'):
                            GroveServiceAdmin.from_wire(receiver.identity()[0], pair, proof, scope).require(db)
                    actor = auth.actor_for(panel, token, 'testclient')
                    self.assertEqual(source_grant(panel, node_id, None, actor, 'terminal'), proof)
                    self.assertEqual(client.delete('/api/v1/session', headers=headers).status_code, 204)
                    self.assertFalse(grove_authorization.service_session_path(panel, actor).exists())
