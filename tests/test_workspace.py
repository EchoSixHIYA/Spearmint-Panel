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

    def test_service_links_round_trip_and_survive_renaming(self):
        service_id = self.service.id
        links = [
            {'label': '用户面板', 'url': 'http://nas.local:8080/#/home'},
            {'label': '管理后台', 'url': 'https://example.test/admin'},
            {'label': 'API', 'url': 'http://[fd00::1]:8000/api?v=1'},
        ]
        self.assertEqual(self.workspace.request(self.actor, 'detail', {'service_id': service_id})['access_links'], [])
        edit = {'service_id': service_id, 'version': 1, 'name': self.service.name, 'endpoint': None, 'access_links': links}
        result = self.workspace.request(self.actor, 'edit', edit)
        self.assertEqual(result['access_links'], links)
        self.assertEqual(self.workspace.request(self.actor, 'edit', edit)['version'], 2)
        renamed = self.workspace.request(self.actor, 'edit',
            {'service_id': service_id, 'version': 2, 'name': 'Renamed', 'endpoint': None})
        self.assertEqual(renamed['access_links'], links)
        with self.assertRaises(PeerError) as stale:
            self.workspace.request(self.actor, 'edit', {**edit, 'access_links': []})
        self.assertEqual(stale.exception.code, 'CONFLICT')
        self.workspace.request(self.actor, 'edit', {**edit, 'version': 3, 'name': 'Renamed', 'access_links': []})
        self.assertEqual(self.workspace.request(self.actor, 'detail', {'service_id': service_id})['access_links'], [])

    def test_service_links_require_a_complete_web_address(self):
        for url in ('nas.local/admin', 'file:///admin', 'https://'):
            with self.subTest(url=url), self.assertRaises(PeerError) as error:
                self.workspace.request(self.actor, 'edit', {'service_id': self.service.id, 'version': 1,
                    'name': self.service.name, 'endpoint': None, 'access_links': [{'label': 'Admin', 'url': url}]})
            self.assertEqual(error.exception.code, 'INVALID_REQUEST')


if __name__ == '__main__':
    unittest.main()
