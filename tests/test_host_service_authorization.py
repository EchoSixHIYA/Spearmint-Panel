"""Functional page-initiated host authorization with isolated host fixtures."""
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
import json
import time
import unittest
from unittest.mock import patch

from spearmint import auth
from spearmint.peer.protocol import PeerError
from spearmint.peer.service_setup import LocalAdmin, ServiceSetup
from spearmint.state import State


class PageHostAuthorizationTest(unittest.TestCase):
    def setUp(self):
        root = Path.cwd() / 'work/tmp/host-authorization-page/tests'
        root.mkdir(parents=True, exist_ok=True)
        self.temporary = TemporaryDirectory(dir=root)
        self.state = State(Path(self.temporary.name) / 'state')
        node = self.state.initialize(lambda: 'fixture')
        with self.state.connect(write=True) as db:
            account = auth.bootstrap_account(db)
            token, csrf = auth.issue_session(db, account, 'fixture', int(time.time()))
        self.actor = LocalAdmin(auth.Actor('admin', 'fixture', auth.digest(token), csrf, account['id'], 'admin', 'node_admin'))
        self.setup = ServiceSetup(self.state, node, Path(self.temporary.name) / 'docker.sock')
        self.enabled = False
        self.connections, self.logins, self.authorizations = [], [], []
        fixture = self

        class Connection:
            fingerprint = 'local-fixture'
            closed = False
            def __init__(self, host, port):
                self.host, self.port = host, port
                fixture.connections.append(self)
            def login(self, expected, username, secret, key):
                fixture.logins.append((username, secret, key))
                if secret == 'incorrect-fixture':
                    raise PeerError('SEED_SSH_AUTH', 'Rejected credentials')
            def system(self):
                return 'linux-amd64', '/home/host-admin'
            def close(self):
                self.closed = True

        def authorize(connection, account, password):
            self.authorizations.append((account, password))
            self.enabled = True
            return {'enabled': True}
        self.patches = [patch('spearmint.host_service_authorization.sys.platform', 'linux'),
                        patch('spearmint.host_service_authorization.seed_ssh.Connection', Connection),
                        patch('spearmint.host_service_authorization.trusted_host_key', return_value='local-fixture'),
                        patch('spearmint.host_service_authorization.host_service_access.account_name', return_value='panel-user'),
                        patch('spearmint.host_service_authorization.host_service_access.available', side_effect=lambda: self.enabled),
                        patch('spearmint.host_service_authorization.host_service_access.ssh_enable', side_effect=authorize)]
        for item in self.patches:
            item.start()

    def tearDown(self):
        self.setup.host_authorization.shutdown()
        for item in reversed(self.patches):
            item.stop()
        self.temporary.cleanup()

    def start(self, identifier='a' * 32, **options):
        return self.setup.setup(self.actor, 'host-authorize', {
            'job': identifier, 'username': 'host-admin', 'secret': 'fixture-login', **options})

    def result(self, identifier='a' * 32):
        self.setup.host_authorization.worker.join(timeout=5)
        return self.setup.setup(self.actor, 'host-authorization-status', {'job': identifier})

    def test_page_grants_panel_account_through_target_loopback(self):
        capability = self.setup.setup(self.actor, 'host-access', {})
        self.assertFalse(capability['enabled'])
        self.assertEqual(capability['account'], 'panel-user')
        self.start(port=2222)
        self.assertEqual(self.result()['status'], 'succeeded')
        self.assertEqual((self.connections[0].host, self.connections[0].port), ('127.0.0.1', 2222))
        self.assertEqual(self.authorizations, [('panel-user', 'fixture-login')])
        self.assertTrue(self.connections[0].closed)
        self.assertTrue(self.setup.setup(self.actor, 'host-access', {})['enabled'])
        with self.state.connect(read_only=True) as db:
            records = [dict(row) for row in db.execute("SELECT event,target,reason FROM audit WHERE event LIKE 'host_services.%'")]
        self.assertEqual([row['event'] for row in records], ['host_services.authorization_requested', 'host_services.authorized'])
        self.assertNotIn('fixture-login', json.dumps(records))
        self.assertNotIn('fixture-login', repr(self.setup.host_authorization.jobs))

    def test_failed_login_returns_reason_and_can_retry(self):
        self.start(secret='incorrect-fixture')
        self.assertEqual(self.result()['error'], 'HOST_SSH_AUTH')
        self.assertTrue(self.connections[0].closed)
        self.assertFalse(self.authorizations)
        self.start('b' * 32)
        self.assertEqual(self.result('b' * 32)['status'], 'succeeded')

    def test_key_login_uses_separate_sudo_password(self):
        self.start(key=True, secret='fixture-private-key', sudo_password='fixture-sudo')
        self.assertEqual(self.result()['status'], 'succeeded')
        self.assertEqual(self.logins, [('host-admin', 'fixture-private-key', True)])
        self.assertEqual(self.authorizations, [('panel-user', 'fixture-sudo')])

    def test_slow_job_returns_promptly_and_retry_does_not_repeat_install(self):
        entered, finish = Event(), Event()
        def install(*args):
            entered.set()
            finish.wait(timeout=5)
            self.enabled = True
        try:
            with patch('spearmint.host_service_authorization.host_service_access.ssh_enable', side_effect=install) as enable:
                before = time.monotonic()
                self.start()
                self.assertLess(time.monotonic() - before, .8)
                self.assertTrue(entered.wait(timeout=3))
                self.assertEqual(self.start()['job'], 'a' * 32)
                finish.set()
                self.assertEqual(self.result()['status'], 'succeeded')
                self.start()
                self.assertEqual(enable.call_count, 1)
        finally:
            finish.set()

    def test_existing_systemd_grant_does_not_hide_missing_docker_access(self):
        self.enabled = True
        docker = {'enabled': False}
        def authorize(connection, account, password, **options):
            self.assertEqual(account, 'panel-user')
            self.assertEqual(options['configured'], self.setup.docker_socket)
            docker['enabled'] = True
            return {'enabled': True}
        with patch('spearmint.host_service_authorization.docker_access.available', side_effect=lambda path: docker['enabled']), \
             patch('spearmint.host_service_authorization.docker_access.ssh_enable', side_effect=authorize) as grant:
            self.assertTrue(self.setup.setup(self.actor, 'host-access', {})['enabled'])
            self.assertFalse(self.setup.setup(self.actor, 'host-access', {'scope': 'docker'})['enabled'])
            self.start(scope='docker')
            self.assertEqual(self.result()['status'], 'succeeded')
            self.assertEqual(grant.call_count, 1)
            self.assertFalse(self.authorizations)
            self.assertTrue(self.setup.setup(self.actor, 'host-access', {'scope': 'docker'})['enabled'])
        with self.state.connect(read_only=True) as db:
            events = [row[0] for row in db.execute("SELECT event FROM audit WHERE event LIKE 'docker_access.%'")]
        self.assertEqual(events, ['docker_access.authorization_requested', 'docker_access.authorized'])

    def test_docker_scope_grants_access_even_when_systemd_is_already_authorized(self):
        self.enabled = True
        docker_enabled = False
        def authorize(*args, **kwargs):
            nonlocal docker_enabled
            docker_enabled = True
            self.assertEqual(kwargs['configured'], self.setup.docker_socket)
            return {'enabled': True}
        with patch('spearmint.host_service_authorization.docker_access.available', side_effect=lambda _: docker_enabled), \
             patch('spearmint.host_service_authorization.docker_access.ssh_enable', side_effect=authorize) as enable:
            self.assertFalse(self.setup.setup(self.actor, 'host-access', {'scope': 'docker'})['enabled'])
            self.start(scope='docker')
            self.assertEqual(self.result()['status'], 'succeeded')
            self.assertEqual(self.result()['scope'], 'docker')
            self.assertTrue(self.setup.setup(self.actor, 'host-access', {'scope': 'docker'})['enabled'])
            self.assertEqual(enable.call_count, 1)
            self.assertFalse(self.authorizations)
        with self.state.connect(read_only=True) as db:
            self.assertEqual([r[0] for r in db.execute("SELECT event FROM audit WHERE event LIKE 'docker_access.%'")],
                             ['docker_access.authorization_requested', 'docker_access.authorized'])


if __name__ == '__main__':
    unittest.main()
