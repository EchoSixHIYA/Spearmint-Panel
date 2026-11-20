"""Functional service-adoption checks; no network-security test cases."""
from pathlib import Path
from subprocess import CalledProcessError
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import json
import time
import unittest
from unittest.mock import patch

from spearmint import auth, host_service_access, seed_transport
from spearmint.catalog import Service
from spearmint.drivers import Capture, Observation, SystemUnitDriver
from spearmint.peer.protocol import PeerError
from spearmint.peer.service_setup import LocalAdmin, ServiceSetup, Takeover, Target
from spearmint.service_mode import change_mode
from spearmint.state import State


UNIT = 'illusia-crm.service'
INFO = {'Id': UNIT, 'LoadState': 'loaded', 'Transient': 'no', 'ActiveState': 'active', 'MainPID': '123'}


class HostServiceTest(unittest.TestCase):
    def setUp(self):
        root = Path.cwd() / 'work/tmp/host-service-access/tests'
        root.mkdir(parents=True, exist_ok=True)
        self.temporary = TemporaryDirectory(dir=root)
        self.state = State(Path(self.temporary.name) / 'state')
        node = self.state.initialize(lambda: 'fixture')
        with self.state.connect(write=True) as db:
            account = auth.bootstrap_account(db)
            token, csrf = auth.issue_session(db, account, 'fixture', int(time.time()))
        self.actor = LocalAdmin(auth.Actor('admin', 'fixture', auth.digest(token), csrf, account['id'], 'admin', 'node_admin'))
        self.setup = ServiceSetup(self.state, node, Path(self.temporary.name) / 'docker.sock')
        self.service = Service('a' * 32, node, 'CRM', 'process', UNIT, {'runtime': 'systemd-system', 'host_permissions': True}, True, 1)
        self.patches = [patch.object(SystemUnitDriver, 'configured_unit', return_value=INFO),
                        patch('spearmint.peer.service_setup.available_kinds', return_value=['systemd'])]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temporary.cleanup()

    def test_readable_journal_is_independent_of_sudo_and_no_new_privileges(self):
        commands = []
        def capture(argv, **kwargs):
            commands.append(argv)
            if argv[0] == '/usr/bin/pkcheck':
                return Capture(1, b'', b'host authorization required', False)
            return Capture(0, b'2026-11-20 example CRM log\n', b'', False)
        with patch.object(SystemUnitDriver, 'sudo_blocked', return_value=True), patch('spearmint.drivers.os.geteuid', return_value=1000, create=True), patch('spearmint.drivers.host_service_access.available', return_value=False), patch('spearmint.drivers.capture', side_effect=capture):
            readiness = self.setup.inspect_target(Target(kind='systemd', target=UNIT))
            self.assertFalse(readiness['ready'])
            self.assertTrue(readiness['observe_ready'])
            self.assertTrue(readiness['logs_ready'])
            self.assertEqual(readiness['control'], dict.fromkeys(('start', 'stop', 'restart'), False))
            self.assertIn('CRM log', SystemUnitDriver().logs(self.service, 10).text)
        self.assertTrue(all(argv[0] in {'/usr/bin/journalctl', '/usr/bin/pkcheck'} for argv in commands))

    def test_node_helper_makes_adoption_ready_with_no_new_privileges(self):
        calls = []
        def request(action, unit=None, **kwargs):
            calls.append((action, unit))
            return {'control': True, 'logs': True} if action == 'check' else {'text': 'example journal\n', 'truncated': False}
        with patch.object(SystemUnitDriver, 'sudo_blocked', return_value=True), patch('spearmint.drivers.host_service_access.available', return_value=True), patch('spearmint.drivers.host_service_access.request', side_effect=request):
            self.assertTrue(self.setup.inspect_target(Target(kind='systemd', target=UNIT))['ready'])
            driver = SystemUnitDriver()
            driver.apply(self.service, 'restart', Observation('running', pid=123))
            self.assertIn('example journal', driver.logs(self.service, 10).text)
        self.assertIn(('restart', UNIT), calls)
        self.assertIn(('logs', UNIT), calls)

    def test_observe_then_enable_management_preserves_registration(self):
        unavailable = {'ready': False, 'listed_actions': {}, 'listed_logs': True, 'reason': 'host_service_access_required'}
        with patch.object(SystemUnitDriver, 'delegation_status', return_value=unavailable):
            with self.assertRaises(PeerError) as failure:
                self.setup.take_over(self.actor, Takeover(kind='systemd', target=UNIT, name='CRM'))
            self.assertEqual(failure.exception.code, 'HOST_SERVICE_ACCESS')
            observed = self.setup.take_over(self.actor, Takeover(kind='systemd', target=UNIT, name='CRM', mode='observe'))['service']
            self.assertFalse(observed['managed'])
        ready = {'ready': True, 'listed_actions': dict.fromkeys(('start', 'stop', 'restart'), True), 'listed_logs': True}
        with patch.object(SystemUnitDriver, 'delegation_status', return_value=ready):
            service = change_mode(self.state, observed['id'], 'manage', actor=self.actor.actor, docker_socket=self.setup.docker_socket, version=1)
            self.assertTrue(service.managed)
            self.assertEqual(service.id, observed['id'])

    def test_legacy_exact_sudo_delegations_remain_supported(self):
        def capture(argv, **kwargs):
            return Capture(1, b'', b'access requires a delegation', False) if argv[0] in {'/usr/bin/journalctl', '/usr/bin/pkcheck'} else Capture(0, b'', b'', False)
        with patch.object(SystemUnitDriver, 'sudo_blocked', return_value=False), patch('spearmint.drivers.os.geteuid', return_value=1000, create=True), patch('spearmint.drivers.host_service_access.available', return_value=False), patch('spearmint.drivers.capture', side_effect=capture):
            result = SystemUnitDriver.delegation_status(UNIT, host_permissions=True)
            self.assertTrue(result['ready'])
            self.assertEqual(set(result['methods'].values()), {'sudo'})

    def test_embedded_worker_controls_existing_services_and_reads_logs(self):
        namespace = {'__name__': 'host_fixture'}
        exec(compile(host_service_access.WORKER, '<host-worker>', 'exec'), namespace)
        calls = []
        def capture(argv, **kwargs):
            calls.append(argv)
            if 'show' in argv:
                return {'code': 0, 'text': f'Id={UNIT}\nLoadState=loaded\nTransient=no\n', 'truncated': False}
            return {'code': 0, 'text': 'journal line\n', 'truncated': False}
        namespace['capture'] = capture
        self.assertTrue(namespace['handle']({'action': 'check', 'unit': UNIT})['control'])
        namespace['handle']({'action': 'stop', 'unit': UNIT})
        self.assertEqual(namespace['handle']({'action': 'logs', 'unit': UNIT, 'tail': 10})['text'], 'journal line\n')
        self.assertTrue(any('stop' in argv for argv in calls))
        self.assertTrue(any(argv[0] == '/usr/bin/journalctl' for argv in calls))

    def test_ssh_bootstrap_uses_password_only_on_stdin(self):
        calls = []
        secret = 'fixture-password-4Cc9'
        def answer(command, input_data=b'', **kwargs):
            if command.startswith('/usr/bin/test'):
                return b''
            calls.append((command, input_data))
            if len(calls) == 1:
                raise CalledProcessError(1, command, stderr=b'sudo: a password is required')
            return b'{"enabled":true,"uid":1000}'
        result = host_service_access.ssh_enable(SimpleNamespace(answer=answer), 'gloomyfish', secret)
        self.assertTrue(result['enabled'])
        self.assertEqual(calls[1][1], (secret + '\n').encode())
        self.assertTrue(all(secret not in command for command, _ in calls))

    def test_seed_transport_carries_host_access_requirement(self):
        with patch.object(seed_transport, '_deploy', return_value=b'SPEARMINT_SEED_STARTUP=confirmed\n') as deploy:
            seed_transport.install(Path('fixture.tar.gz'), Path(self.temporary.name), host='192.0.2.1', target='linux-arm64',
                digest='a' * 64, invitation_data=b'{}', origin='https://example.test', port=8765, windows={}, linux_host_services=True)
            self.assertIs(deploy.call_args.kwargs['linux_host_services'], True)


if __name__ == '__main__':
    unittest.main()
