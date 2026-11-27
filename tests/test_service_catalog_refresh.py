"""Functional catalog refresh and unchanged identity-lease renewal regressions."""
import asyncio
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pyotp import TOTP

from grove_fixture import GroveFixture
from spearmint import auth, grove_authorization, grove_availability, grove_continuity, grove_device_login, grove_identity_changes, grove_login, grove_revocation
from spearmint.catalog import register
from spearmint.peer.directory import GROVE_CATALOG_METHOD
from spearmint.peer.pairing import configured
from spearmint.peer.grove_service_admin import source_grant
from spearmint.peer.protocol import PeerError, wire_b64
from spearmint.peer.services import GROVE_SERVICE, GROVE_SERVICE_RUNTIME, PeerServices
from spearmint.peer.workspace import Workspace
from test_grove_voters import VoterFixture


class Renewal:
    renew_grove_snapshot = PeerServices.renew_grove_snapshot

    def __init__(self, fixture):
        self.state = fixture.states[0]
        self.local_id = self.state.identity()[0]
        self.remote = fixture.states[1]
        self.modes = []

    async def work(self, method, *args):
        with self.state.connect(read_only=True) as db:
            self.modes.append((getattr(method, '__name__', 'renew'), grove_availability.status(db)['mode']))
        return method(*args)

    async def call(self, node, method, params, **_):
        if node != self.remote.identity()[0]:
            raise PeerError('OFFLINE', 'Owned fixture is disconnected')
        if method != grove_continuity.ACCOUNTS_VOTE_METHOD:
            raise AssertionError('Unexpected fixture method: ' + method)
        return grove_continuity.vote(self.remote, self.local_id, params['nonce'], params['anchor'],
                                    params['revocations'], params['passwords'], params['roles'], params['members'], params['accounts'])


class Catalog:
    grove_directory = PeerServices.grove_directory

    def __init__(self, result):
        self.result = result

    async def grove_service(self, *_args, **_kwargs):
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class ServiceCatalogRefreshTest(unittest.TestCase):
    def test_local_work_congestion_keeps_an_established_directory_ready(self):
        pair = SimpleNamespace(node_id='owned')
        connection = SimpleNamespace(closed=False)
        class Congested:
            state = None
            failures = None
            ready = {'owned': connection}
            manager = SimpleNamespace(pairs={'owned': pair})
            def target_lock(self, _node):
                return asyncio.Lock()
            def connection_for(self, _node):
                return connection
            def cursor(self, _pair):
                pass
            async def work(self, *_args):
                raise PeerError('BUSY', 'Owned local worker is occupied')
        source = Congested()
        self.assertFalse(asyncio.run(PeerServices.sync_peer(source, pair, connection)))
        self.assertIs(source.ready['owned'], connection)
        connection.closed = True
        self.assertFalse(asyncio.run(PeerServices.sync_peer(source, pair, connection)))
        self.assertNotIn('owned', source.ready)

    def test_unchanged_lease_renewal_keeps_ordinary_access_online(self):
        with TemporaryDirectory() as root:
            fixture = GroveFixture(Path(root))
            coordinator = Renewal(fixture)
            self.assertTrue(asyncio.run(coordinator.renew_grove_snapshot((fixture.envelope, fixture.anchor), standby=False)))
            self.assertTrue(coordinator.modes)
            self.assertEqual({mode for _, mode in coordinator.modes}, {'online'})

    def test_actual_identity_change_is_applied_while_synchronizing_then_resumes(self):
        with TemporaryDirectory() as root:
            fixture = GroveFixture(Path(root))
            actor = fixture.login()
            document, _ = grove_revocation.issue(fixture.states[0], actor, fixture.users[1]['id'])
            ballots = [grove_identity_changes.ballot(state, 'revocation', document, fixture.users[0]['id'],
                       fixture.states[0].identity()[0] if index else None) for index, state in enumerate(fixture.states[:2])]
            certified = grove_identity_changes.certify(fixture.states[0], 'revocation', document, ballots)
            grove_revocation.apply(fixture.states[1], [certified], fixture.states[0].identity()[0])
            coordinator = Renewal(fixture)
            self.assertTrue(asyncio.run(coordinator.renew_grove_snapshot((fixture.envelope, fixture.anchor), standby=False)))
            self.assertIn(('apply', 'synchronizing'), coordinator.modes)
            with fixture.states[0].connect(read_only=True) as db:
                self.assertEqual(grove_availability.status(db)['mode'], 'online')
                self.assertEqual(db.execute('SELECT count(*) FROM grove_login_revocation').fetchone()[0], 1)

    def test_signed_in_admin_can_see_service_inventory_without_management_grant(self):
        root = Path.cwd() / 'work/tmp/service-catalog-regression'
        root.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(dir=root) as directory:
            fixture = VoterFixture(Path(directory))
            source, target = fixture.states[:2]
            source_id, target_id = source.identity()[0], target.identity()[0]
            token, _ = grove_login.login(source, 'admin', fixture.password, TOTP(fixture.secret).now(), '127.0.0.1')
            actor = auth.actor_for(source, token, '127.0.0.1')

            service = register(target, 'process', 'Existing web service', 'owned.service', {
                'runtime': 'systemd-system', 'log_path': '/private/service.log', 'command': 'echo owned',
                'service_groups': [{'id': 'a' * 32, 'name': 'Example group', 'position': 0, 'status_only': False}],
            }, managed=True)
            observed = {'status': 'running', 'source': 'process', 'checked_at': fixture.now,
                        'last_seen_at': fixture.now, 'last_status': 'running', 'stale': False, 'pid': 123}
            controller = SimpleNamespace(describe=lambda _: {'observation': observed, 'endpoint': '/private'},
                observe=lambda _: observed, service_metrics=SimpleNamespace(snapshot=lambda *_: {}))
            workspace = Workspace(target, target_id, controller, None, Path(directory) / 'docker.sock')
            recipient = SimpleNamespace(state=target, local_id=target_id, workspace=workspace, controller=controller)
            recipient.service_inventory = lambda *args, **kwargs: PeerServices.service_inventory(recipient, *args, **kwargs)

            with source.connect(read_only=True) as db:
                target_pair = configured(db, target_id)
            with target.connect(read_only=True) as db:
                source_pair = configured(db, source_id)

            class Source:
                state, local_id, adaptive = source, source_id, None
                grove_service, grove_directory = PeerServices.grove_service, PeerServices.grove_directory
                supported = True
                runtime_supported = True

                def pair_for(self, node):
                    assert node == target_id
                    return target_pair

                def directory_publication(self, node):
                    assert node == target_id
                    return (self, 1)

                async def work(self, function, *args):
                    return function(*args)

                async def call(self, method, params):
                    if method == GROVE_CATALOG_METHOD:
                        if not self.supported:
                            raise PeerError('UNSUPPORTED_METHOD', 'Owned older panel')
                        return PeerServices.grove_inventory_rpc(recipient, source_pair, params)
                    if method == GROVE_SERVICE_RUNTIME:
                        if not self.runtime_supported:
                            raise PeerError('UNSUPPORTED_METHOD', 'Owned panel still needs runtime service support')
                        return PeerServices.grove_service_rpc(recipient, source_pair, params, grove_authorization.SERVICE_CONTROL)
                    assert method == GROVE_SERVICE
                    return PeerServices.grove_service_rpc(recipient, source_pair, params)

                connection_id = 'owned-session'

            panel = Source()
            snapshot = {'node_id': target_id, 'stale': False, 'services': [],
                        'connection_id': panel.connection_id, 'directory_generation': 1}
            panel.supported = False
            old = asyncio.run(panel.grove_directory(actor, snapshot))
            self.assertFalse(old['catalog_complete'])
            self.assertTrue(old['catalog_read_only'])

            panel.supported = True
            inventory = asyncio.run(panel.grove_directory(actor, snapshot))
            self.assertTrue(inventory['catalog_complete'])
            self.assertTrue(inventory['catalog_read_only'])
            self.assertEqual(inventory['service_groups'][0]['name'], 'Example group')
            self.assertNotIn('operation', inventory['service_groups'][0])
            entry, = inventory['services']
            self.assertEqual(entry['name'], 'Existing web service')
            self.assertEqual(entry['observation']['status'], 'running')
            self.assertEqual(entry['actions'], [])
            self.assertFalse(entry['logs'])
            self.assertNotIn('pid', entry['observation'])
            self.assertNotIn('spec', entry)

            with self.assertRaises(PeerError) as denied:
                asyncio.run(panel.grove_service(target_id, actor, 'logs', {'service_id': entry['id'], 'tail': 10}))
            self.assertEqual(denied.exception.code, grove_authorization.ERROR)

            fixture.authorize(source, actor, scopes=['services'])
            signed = asyncio.run(panel.grove_directory(actor, snapshot))
            self.assertTrue(signed['catalog_complete'])
            self.assertFalse(signed['catalog_read_only'])
            self.assertIn('stop', signed['services'][0]['actions'])

            device = Ed25519PrivateKey.generate()
            public = wire_b64(device.public_key().public_bytes_raw())
            votes = [grove_authorization.key_vote(voter, 'admin', public) for voter in fixture.states[:2]]
            legacy_challenge = grove_device_login.challenge(source, 'admin', '127.0.0.1')
            self.assertEqual(legacy_challenge['scopes'], ['signin'])
            challenge = grove_device_login.challenge(source, 'admin', '127.0.0.1', service_controls=True)
            device_proof = grove_authorization.issue(device, challenge, votes)
            token, _ = grove_device_login.finish(source, device_proof, '127.0.0.1')
            actor = auth.actor_for(source, token, '127.0.0.1')
            scope = grove_authorization.SERVICE_CONTROL
            self.assertEqual(source_grant(source, source_id, target_pair, actor, scope), device_proof)

            current = asyncio.run(panel.grove_directory(actor, snapshot))
            self.assertTrue(current['catalog_controls_only'])
            self.assertFalse(current['catalog_read_only'])
            self.assertIn('restart', current['services'][0]['actions'])
            self.assertTrue(current['services'][0]['logs'])

            panel.runtime_supported = False
            legacy = asyncio.run(panel.grove_directory(actor, snapshot))
            self.assertTrue(legacy['catalog_complete'])
            self.assertTrue(legacy['catalog_read_only'])
            self.assertTrue(legacy['catalog_upgrade_required'])
            self.assertEqual(legacy['services'][0]['name'], service.name)

            detail = workspace.dispatch(source_pair, {'identity': device_proof, 'action': 'detail',
                'body': {'service_id': service.id}}, scope)
            self.assertTrue(detail['controls_only'])
            self.assertFalse(detail['can_unregister'])
            self.assertNotIn('command', detail)
            self.assertNotIn('endpoint', detail)

            with target.connect(read_only=True) as db:
                expected = challenge['identity']
                self.assertEqual(grove_authorization.verify(db, device_proof, source_id, scope,
                    at=challenge['expires_at'] + 1), expected)
                with self.assertRaises(PeerError):
                    grove_authorization.verify(db, device_proof, source_id, scope, at=challenge['service_until'])
                with self.assertRaises(PeerError):
                    grove_authorization.verify(db, device_proof, source_id, 'services')

            path = grove_authorization.service_session_path(source, actor)
            self.assertTrue(path.is_file())
            auth.logout(source, actor)
            self.assertFalse(path.is_file())
            with self.assertRaises(PeerError):
                source_grant(source, source_id, target_pair, actor, scope)

    def test_failed_catalog_is_incomplete_and_cannot_remove_visible_rows(self):
        directory = {'node_id': 'owned', 'stale': False, 'services': [], 'connection_id': 'session', 'directory_generation': 1}
        result = asyncio.run(Catalog(PeerError('ROUTE_LOST', 'Owned route changed')).grove_directory(SimpleNamespace(grove=True), directory))
        self.assertTrue(result['stale'])
        self.assertFalse(result['catalog_complete'])
        empty = asyncio.run(Catalog({'services': []}).grove_directory(SimpleNamespace(grove=True), directory))
        self.assertFalse(empty['stale'])
        self.assertTrue(empty['catalog_complete'])

    def test_grove_identity_wait_does_not_publish_an_empty_complete_catalog(self):
        directory = {'node_id': 'owned', 'stale': False, 'services': [], 'connection_id': 'session', 'directory_generation': 1}
        grove = asyncio.run(Catalog(None).grove_directory(SimpleNamespace(grove=True), directory))
        self.assertTrue(grove['stale'])
        self.assertFalse(grove['catalog_complete'])
        legacy = asyncio.run(Catalog(None).grove_directory(SimpleNamespace(grove=False), directory))
        self.assertFalse(legacy['stale'])
        self.assertTrue(legacy['catalog_complete'])


if __name__ == '__main__':
    unittest.main()
