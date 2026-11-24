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

    def test_routine_disconnects_do_not_create_a_diagnostic_file(self):
        self.log.record('owned-target', 'workspace.host', 'remote_rpc', PeerError('OFFLINE', 'Owned reconnect'))
        self.assertFalse(self.log.path.exists())

    def test_failed_diagnostic_write_does_not_replace_business_failure(self):
        with patch('spearmint.peer_failures.write_record', side_effect=OSError('Owned disk fixture')):
            self.log.record('owned-target', 'workspace.host', 'remote_rpc', PeerError('DENIED', 'Owned denial'))

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
