import asyncio
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from spearmint.peer.protocol import PeerError
from spearmint.peer.services import PeerServices
from spearmint.peer_failures import PeerFailures


class PeerFailureTest(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.state = type('OwnedState', (), {'directory': Path(self.temp.name)})()
        self.log = PeerFailures(self.state, 'owned-local')

    def tearDown(self):
        self.temp.cleanup()

    def read(self):
        return json.loads(self.log.path.read_bytes())

    def test_denial_keeps_raw_reason_and_source_stage(self):
        self.log.record('owned-target', 'workspace.host', 'local_identity', PeerError('DENIED', 'Owned reason'), {'members_available': False})
        event = self.read()['events'][0]
        self.assertEqual((event['code'], event['detail'], event['stage']), ('DENIED', 'Owned reason', 'local_identity'))
        self.assertEqual(event['context'], {'members_available': False})

    def test_repeated_events_are_coalesced_and_history_is_bounded(self):
        self.log.record('owned-target', 'workspace.host', 'remote_rpc', PeerError('DENIED', 'Owned reason'))
        self.log.record('owned-target', 'workspace.host', 'remote_rpc', PeerError('DENIED', 'Owned reason'))
        self.assertEqual(len(self.log.rows), 1)
        self.assertEqual(self.log.rows[0]['count'], 2)
        for index in range(80):
            self.log.record('owned-' + str(index), 'workspace.host', 'remote_rpc', PeerError('DENIED', 'Owned reason'))
        self.assertEqual(len(self.read()['events']), 64)

    def test_disconnect_evidence_is_bounded_like_rejections(self):
        self.log.record('owned-target', 'workspace.host', 'remote_rpc', PeerError('OFFLINE', 'Owned reconnect'))
        self.assertEqual(self.read()['events'][0]['code'], 'OFFLINE')

    def test_host_timestamps_can_distinguish_successful_but_expired_sampling(self):
        self.log.host_result('owned-target', {'metrics': {'sampled_at': 100, 'valid_until': 108,
            'stale': False, 'cpu_percent': 17, 'memory': {'total': 1000}, 'private_fixture': 'excluded'}}, .25)
        value = json.loads(self.log.path.with_name('peer-hosts.json').read_bytes())
        sample = value['hosts']['owned-target']
        self.assertEqual((sample['sampled_at'], sample['valid_until'], sample['duration_ms']), (100, 108, 250))
        self.assertTrue(sample['cpu_present'] and sample['memory_present'])
        self.assertNotIn('private_fixture', json.dumps(value))

    def test_failed_diagnostic_write_does_not_replace_business_failure(self):
        with patch('spearmint.peer_failures.write_record', side_effect=OSError('Owned disk fixture')):
            self.log.record('owned-target', 'workspace.host', 'remote_rpc', PeerError('DENIED', 'Owned denial'))

    def test_guard_failure_is_recorded_before_the_workspace_handler(self):
        from fastapi.testclient import TestClient
        from spearmint.app import create_app, require_admin_write
        from spearmint.config import Config
        from spearmint.state import State
        state = State(self.state.directory / 'guard-fixture')
        state.initialize(lambda: 'owned-fixture')
        app = create_app(Config(state.directory, 'https://localhost:18443', self.state.directory / 'web', self.state.directory / 'docker.sock'))
        def waiting_guard():
            raise PeerError('GROVE_SYNCHRONIZING', 'Owned guard is synchronizing')
        app.dependency_overrides[require_admin_write] = waiting_guard
        with TestClient(app, base_url='https://localhost:18443') as client:
            response = client.post('/api/v1/peers/owned-target/workspace/host', json={})
        self.assertEqual(response.status_code, 503)
        records = json.loads((state.directory / 'diagnostics/peer-failures.json').read_bytes())
        self.assertEqual(records['events'][0]['stage'], 'http_request')
        self.assertEqual(records['events'][0]['code'], 'GROVE_SYNCHRONIZING')

    def test_rpc_capture_keeps_original_error_and_omits_request_body(self):
        recorder = self.log
        failure = PeerError('DENIED', 'Owned remote denial')

        class Remote:
            failures = recorder
            state = None

            async def call_with_connection(self, *_args, **_kwargs):
                raise failure

        with patch.object(PeerServices, 'record_failure', lambda instance, target, method, stage, error: recorder.record(target, method, stage, error)):
            with self.assertRaises(PeerError) as caught:
                asyncio.run(PeerServices.call(Remote(), 'owned-target', 'grove.workspace.v1', {'identity': 'fixture-private-identity', 'body': {'password': 'fixture-private-password'}}))
        self.assertIs(caught.exception, failure)
        raw = self.log.path.read_text()
        self.assertNotIn('fixture-private-', raw)
        self.assertEqual(self.read()['events'][0]['stage'], 'remote_rpc')


if __name__ == '__main__':
    unittest.main()
