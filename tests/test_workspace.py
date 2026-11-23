"""Workspace metadata and lifecycle regression checks using isolated node state."""
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import time
import unittest

from spearmint import auth
from spearmint.catalog import register
from spearmint.control import Controller
from spearmint.drivers import Observation
from spearmint.peer.protocol import PeerError
from spearmint.peer.service_setup import LocalAdmin
from spearmint.peer.workspace import Workspace
from spearmint.state import State


class Driver:
    def inspect(self, service):
        return Observation('stopped')


class WorkspaceTest(unittest.TestCase):
    def setUp(self):
        temporary = Path.cwd() / 'work/tmp/ui-convergence'
        temporary.mkdir(parents=True, exist_ok=True)
        self.temporary = TemporaryDirectory(dir=temporary)
        self.root = Path(self.temporary.name)
        self.state = State(self.root / 'state')
        node = self.state.initialize(lambda: 'fixture')
        with self.state.connect(write=True) as db:
            account = auth.bootstrap_account(db)
            token, csrf = auth.issue_session(db, account, 'fixture', int(time.time()))
        self.actor = LocalAdmin(auth.Actor('admin', 'fixture', auth.digest(token), csrf, account['id'], 'admin', 'node_admin'))
        metrics = SimpleNamespace(snapshot=lambda: {'cpu_percent': 17, 'stale': False}, trend=lambda: {'points': []})
        self.workspace = Workspace(self.state, node, Controller(self.state, {'process': Driver()}), metrics, self.root / 'docker.sock')
        self.service = register(self.state, 'process', 'Workspace regression', '',
            {'argv': [sys.executable, '-c', 'print(1)'], 'cwd': str(self.root), 'stop_timeout': 3, 'command': 'echo fixture'}, managed=True)

    def tearDown(self):
        self.temporary.cleanup()

    def test_metadata_and_host_sampling(self):
        result = self.workspace.request(self.actor, 'detail', {'service_id': self.service.id})
        self.assertEqual(result['command'], 'echo fixture')
        self.assertTrue(result['can_unregister'])
        self.assertFalse(result['can_change_mode'])
        self.assertFalse(result['can_deploy'])
        self.assertIsNone(result['resources']['cpu_percent'])
        self.assertIsNone(result['resources']['gpu']['utilization_percent'])
        sample = self.workspace.request(self.actor, 'host', {'trend': True})
        self.assertEqual(sample['metrics']['cpu_percent'], 17)
        self.assertIn('trend', sample)
        self.assertNotIn('trend', self.workspace.request(self.actor, 'host', {}))

    def test_edit_retry_and_stale_version(self):
        body = {'service_id': self.service.id, 'version': 1, 'name': 'Renamed', 'endpoint': None}
        self.assertEqual(self.workspace.request(self.actor, 'edit', body)['version'], 2)
        self.assertEqual(self.workspace.request(self.actor, 'edit', body)['version'], 2)
        with self.assertRaises(PeerError) as caught:
            self.workspace.request(self.actor, 'edit', {**body, 'name': 'Another change'})
        self.assertEqual(caught.exception.code, 'CONFLICT')

    def test_stopped_foreground_can_be_unregistered_from_panel(self):
        self.assertEqual(self.workspace.request(self.actor, 'remove', {'service_id': self.service.id, 'version': 1}), {'removed': True})
        with self.assertRaises(PeerError) as caught:
            self.workspace.request(self.actor, 'detail', {'service_id': self.service.id})
        self.assertEqual(caught.exception.code, 'NOT_FOUND')


if __name__ == '__main__':
    unittest.main()
