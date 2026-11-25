from pathlib import Path
from tempfile import TemporaryDirectory
import time
from types import SimpleNamespace
import unittest
from uuid import uuid4

from spearmint import auth
from spearmint.catalog import get_service, list_services, register
from spearmint.control import Controller
from spearmint.drivers import Observation
from spearmint.host import HostError
from spearmint.peer.protocol import PeerError
from spearmint.peer.service_setup import LocalAdmin
from spearmint.peer.workspace import Workspace
from spearmint.service_groups import ServiceGroups
from spearmint.state import State


class Driver:
    def __init__(self):
        self.actions = []
        self.running = set()
        self.fail = None

    def inspect(self, service):
        return Observation('running' if service.id in self.running else 'stopped')

    def apply(self, service, action, before):
        self.actions.append((action, service.name))
        if service.name == self.fail:
            raise HostError('Fixture service failed')
        if action == 'start':
            self.running.add(service.id)
        else:
            self.running.discard(service.id)


class ServiceGroupTest(unittest.TestCase):
    def setUp(self):
        root = Path('work/tmp/service-groups')
        root.mkdir(parents=True, exist_ok=True)
        temporary = TemporaryDirectory(dir=root)
        self.addCleanup(temporary.cleanup)
        self.state = State(Path(temporary.name).resolve() / 'state')
        node_id = self.state.initialize(lambda: 'fixture')
        with self.state.connect(write=True) as db:
            account = auth.bootstrap_account(db)
            token, csrf = auth.issue_session(db, account, 'fixture', int(time.time()))
        self.actor = LocalAdmin(auth.Actor('admin', 'fixture', auth.digest(token), csrf, account['id'], 'admin', 'node_admin'))
        self.driver = Driver()
        self.controller = Controller(self.state, {'docker': self.driver})
        self.groups = ServiceGroups(self.state, self.controller, None)
        self.workspace = Workspace(self.state, node_id, self.controller, SimpleNamespace(), '', self.groups)
        self.members = [register(self.state, 'docker', name, str(index + 1) * 64, {'stop_timeout': 5}, managed=True)
                        for index, name in enumerate(('数据库', '前台', '共享缓存'))]
        self.payload = {'id': uuid4().hex, 'name': '诡镇奇谭', 'members': [
            {'service_id': service.id, 'status_only': index == 2} for index, service in enumerate(self.members)]}

    def request(self, action, body):
        return self.workspace.request(self.actor, action, body)

    def run_group(self, group, action):
        request = {key: group[key] for key in ('id', 'version')}
        request.update(action=action, request_id=uuid4().hex)
        self.request('group-run', request)
        self.groups.worker.join(12)
        self.assertFalse(self.groups.worker.is_alive())
        return self.request('group-run', request)

    def test_ordered_start_reverse_stop_and_observation_member(self):
        group = self.request('group-save', self.payload)
        with self.controller.running():
            self.assertEqual(self.run_group(group, 'start')['status'], 'succeeded')
            self.assertEqual(self.run_group(group, 'stop')['status'], 'succeeded')
        self.assertEqual(self.driver.actions, [('start', '数据库'), ('start', '前台'), ('stop', '前台'), ('stop', '数据库')])

    def test_failed_dependency_stops_the_sequence(self):
        group = self.request('group-save', self.payload)
        self.driver.fail = '数据库'
        with self.controller.running():
            result = self.run_group(group, 'start')
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['current_service_id'], self.members[0].id)
        self.assertEqual(self.driver.actions, [('start', '数据库')])

    def test_edit_leaves_runtime_spec_unchanged_and_shared_service_can_be_observed_twice(self):
        group = self.request('group-save', self.payload)
        shared = self.members[2]
        second = self.request('group-save', {'id': uuid4().hex, 'name': '第二个服务组',
            'members': [{'service_id': shared.id, 'status_only': True}]})
        with self.state.connect(read_only=True) as db:
            self.assertEqual(get_service(db, shared.id).runtime_spec(), shared.runtime_spec())
        self.request('group-delete', {key: group[key] for key in ('id', 'version')})
        self.assertEqual([item['id'] for item in self.groups.public(list_services(self.state))], [second['id']])
        self.assertEqual(len(list_services(self.state)), 3)

    def test_stale_group_edit_is_rejected(self):
        group = self.request('group-save', self.payload)
        self.request('group-save', {**self.payload, 'version': group['version'], 'name': '新名称'})
        with self.assertRaises(PeerError) as failure:
            self.request('group-save', {**self.payload, 'version': group['version'], 'name': '旧窗口的修改'})
        self.assertEqual(failure.exception.code, 'CONFLICT')
