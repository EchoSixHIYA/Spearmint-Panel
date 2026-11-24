"""Docker permission recovery and daemon selection; functional checks only."""
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from spearmint import docker_access, host, host_service_access


class DockerAccessTest(unittest.TestCase):
    def test_authorized_channel_is_used_immediately_by_existing_panel(self):
        upstream = Path('/var/run/docker.sock')
        proxy = Path('/run/spearmint-docker-1000.sock')
        socket_stat = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660)
        with patch.object(host, 'WINDOWS', False), patch.object(host.shutil, 'which', return_value='/usr/bin/docker'), \
             patch.object(docker_access, 'endpoint', return_value=upstream), \
             patch.object(Path, 'lstat', return_value=socket_stat), patch.object(Path, 'is_absolute', return_value=True), \
             patch.object(host.os, 'access', side_effect=lambda path, mode: path == proxy):
            with patch.object(docker_access, 'proxy_for', return_value=None), self.assertRaises(host.DockerAccessError) as caught:
                host.docker_command(upstream)
            self.assertEqual(caught.exception.code, 'DOCKER_PERMISSION')
            with patch.object(docker_access, 'proxy_for', return_value=proxy):
                command, environment = host.docker_command(upstream)
            self.assertEqual(command, ['/usr/bin/docker', '--host', 'unix://' + str(proxy)])
            self.assertNotIn('DOCKER_HOST', environment)

    def test_rootless_access_is_not_redirected_to_another_daemon(self):
        with patch.object(docker_access.sys, 'platform', 'linux'), patch.object(docker_access.os, 'getuid', return_value=1000, create=True):
            rootless = Path('/run/user/1000/docker.sock')
            with patch.object(Path, 'lstat', return_value=SimpleNamespace(st_mode=stat.S_IFSOCK)):
                self.assertEqual(docker_access.endpoint(rootless), rootless)
            with patch.object(Path, 'lstat', side_effect=PermissionError):
                self.assertEqual(docker_access.endpoint(rootless), rootless)
            with patch.object(Path, 'lstat', side_effect=FileNotFoundError):
                self.assertEqual(docker_access.endpoint(rootless), Path('/var/run/docker.sock'))

    def test_root_ssh_authorization_does_not_require_sudo(self):
        commands = []
        def answer(command, **options):
            commands.append(command)
            return b'' if command.startswith('/usr/bin/test') else b'{"enabled":true}'
        result = host_service_access.ssh_bootstrap(SimpleNamespace(answer=answer, linux_root=True, linux_user=None), 'print("fixture")')
        self.assertTrue(result['enabled'])
        self.assertFalse(any('/usr/bin/sudo' in command for command in commands))

    def test_optional_seed_authorization_can_skip_unavailable_docker(self):
        with patch('spearmint.host_service_access.ssh_bootstrap', return_value={'enabled': False, 'reason': 'docker-unavailable'}):
            result = docker_access.ssh_enable(None, 'panel-user', optional=True)
        self.assertFalse(result['enabled'])
        for optional in (True, False):
            compile(docker_access.bootstrap_source('panel-user', Path('/var/run/docker.sock'), optional=optional), '<docker-installer>', 'exec')


if __name__ == '__main__':
    unittest.main()
