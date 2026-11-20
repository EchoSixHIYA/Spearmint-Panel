"""Deployment lifecycle checks using isolated workloads and a simulated Docker engine."""
from dataclasses import replace
from io import BytesIO
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import time
import sys
import unittest
from unittest.mock import patch
from uuid import uuid4
import zipfile

from spearmint import auth
from spearmint.catalog import get_service, list_services
from spearmint.control import Controller
from spearmint.drivers import Observation
from spearmint.host import HostError
from spearmint.peer.protocol import PeerError, wire_b64
from spearmint.peer.service_setup import LocalAdmin
from spearmint.service_artifacts import docker_arguments
from spearmint.service_deployment import ServiceDeployments
from spearmint.native_process import process_driver
from spearmint.state import State


class Driver:
    def __init__(self):
        self.states = {}
        self.actions = []

    def inspect(self, service):
        return Observation(self.states.get(service.target, 'stopped'))

    def apply(self, service, action, before):
        self.actions.append((service.target, action))
        if action == 'start' and 'exit 42' in service.spec.get('command', ''):
            self.states[service.target] = 'failed'
            raise HostError('example startup exited with 42')
        self.states[service.target] = 'running' if action == 'start' else 'stopped'


class DeploymentTest(unittest.TestCase):
    def setUp(self):
        temporary = Path.cwd() / 'work/tmp/service-deployment/tests'
        temporary.mkdir(parents=True, exist_ok=True)
        self.temp = TemporaryDirectory(dir=temporary)
        self.root = Path(self.temp.name)
        self.state = State(self.root / 'state')
        self.node = self.state.initialize(lambda: 'deployment fixture')
        with self.state.connect(write=True) as db:
            account = auth.bootstrap_account(db)
            token, csrf = auth.issue_session(db, account, 'fixture', int(time.time()))
        self.actor = LocalAdmin(auth.Actor('admin', 'fixture', auth.digest(token), csrf, account['id'], 'admin', 'node_admin'))
        self.driver = Driver()
        self.controller = Controller(self.state, {'process': self.driver, 'docker': self.driver})
        self.manager = ServiceDeployments(self.state, self.node, self.controller, self.root / 'docker.sock')
        self.created = []
        self.names = {}
        self.removed = []

    def tearDown(self):
        self.manager.shutdown()
        self.temp.cleanup()

    def archive(self, version):
        data = BytesIO()
        with zipfile.ZipFile(data, 'w') as archive:
            archive.writestr('my app/app.py', f'print("{version}")\n')
        return data.getvalue()

    def begin(self, kind='package', command='python app.py', service=None, data=None):
        data = self.archive('v1') if data is None and kind == 'package' else data or b''
        body = {'job': uuid4().hex, 'kind': kind, 'name': service.name if service else 'Example service', 'command': command,
                'service_id': service.id if service else None, 'version': service.version if service else None,
                'filename': 'app.zip' if data else '', 'size': len(data)}
        job = self.manager.request(self.actor, 'begin', body)
        self.assertEqual(job, self.manager.request(self.actor, 'begin', body))
        for offset in range(0, len(data), 8192):
            part = {'job': job['id'], 'offset': offset, 'data': wire_b64(data[offset:offset + 8192])}
            accepted = self.manager.request(self.actor, 'write', part)
            self.assertEqual(accepted['offset'], self.manager.request(self.actor, 'write', part)['offset'])
        return job['id']

    def launch(self, identifier):
        self.manager.request(self.actor, 'launch', {'job': identifier})
        self.manager.workers[identifier].join(timeout=12)
        self.assertFalse(self.manager.workers[identifier].is_alive())
        return self.manager.request(self.actor, 'status', {'job': identifier})

    def service(self, identifier):
        with self.state.connect() as db:
            return get_service(db, identifier)

    def test_package_update_rollback_retention_and_data(self):
        first = self.launch(self.begin())
        self.assertEqual(first['status'], 'succeeded')
        original = self.service(first['service_id'])
        self.assertEqual((Path(original.spec['cwd']) / 'app.py').read_text(), 'print("v1")\n')
        app = self.manager.apps / original.spec['deployment']['app']
        (app / 'data' / 'important.txt').write_text('keep this')
        self.assertIn('SPMT_DATA_DIR', original.spec['script_source'])
        second = self.launch(self.begin(service=original, data=self.archive('v2')))
        self.assertEqual(second['status'], 'succeeded')
        current = self.service(original.id)
        self.assertEqual(current.version, 2)
        self.assertNotEqual(current.target, original.target)
        self.assertNotEqual(current.spec['cwd'], original.spec['cwd'])
        third = self.launch(self.begin(service=current, data=self.archive('v3')))
        self.assertEqual(third['status'], 'succeeded')
        self.assertFalse(Path(original.spec['cwd']).exists())
        self.assertEqual(len(list((app / 'releases').iterdir())), 2)
        rolled = self.launch(self.begin('rollback', '', self.service(original.id)))
        self.assertEqual(rolled['status'], 'succeeded')
        restored = self.service(original.id)
        self.assertEqual(restored.spec['cwd'], current.spec['cwd'])
        self.assertEqual(restored.version, 4)
        self.assertEqual((app / 'data' / 'important.txt').read_text(), 'keep this')
        self.assertEqual(list(self.manager.root.glob('*.upload')), [])
        self.assertEqual(len(list_services(self.state)), 1)

    def test_failed_start_restores_running_original_and_receipt(self):
        original = self.launch(self.begin())
        before = self.service(original['service_id'])
        failed = self.launch(self.begin(command='exit 42', service=before, data=self.archive('v2')))
        self.assertEqual(failed['status'], 'failed')
        self.assertTrue(failed['rolled_back'])
        self.assertIn('exited with 42', failed['error'])
        after = self.service(before.id)
        self.assertEqual(after.spec, before.spec)
        self.assertEqual(after.version, 3)
        self.assertEqual(self.driver.inspect(after).status, 'running')
        with self.state.connect() as db:
            self.assertEqual(db.execute('SELECT status FROM operation WHERE id=?', (failed['id'],)).fetchone()[0], 'failed')

    def test_invalid_package_does_not_stop_existing_service(self):
        original = self.launch(self.begin())
        before = self.service(original['service_id'])
        actions = len(self.driver.actions)
        failed = self.launch(self.begin(service=before, data=b'not a zip file'))
        self.assertEqual(failed['status'], 'failed')
        self.assertEqual(len(self.driver.actions), actions)
        self.assertEqual(self.service(before.id), before)

    def test_command_update_keeps_code_directory_and_job_retry_is_idempotent(self):
        first = self.launch(self.begin())
        before = self.service(first['service_id'])
        identifier = self.begin('command', 'python app.py --new-flag', before)
        updated = self.launch(identifier)
        self.assertEqual(updated['status'], 'succeeded')
        after = self.service(before.id)
        self.assertEqual(after.spec['cwd'], before.spec['cwd'])
        self.assertTrue(Path(before.spec['cwd']).exists())
        self.assertEqual(self.manager.request(self.actor, 'launch', {'job': identifier})['status'], 'succeeded')
        history = self.manager.request(self.actor, 'history', {'service_id': before.id})
        self.assertTrue(history['can_rollback'])
        self.assertEqual(len(history['jobs']), 2)

    def test_upload_resume_after_manager_restart_and_cancellation(self):
        identifier = self.begin()
        before = self.manager.request(self.actor, 'status', {'job': identifier})
        manager = ServiceDeployments(self.state, self.node, self.controller, self.root / 'docker.sock')
        self.assertEqual(before, manager.request(self.actor, 'status', {'job': identifier}))
        result = manager.request(self.actor, 'cancel', {'job': identifier})
        self.assertEqual(result['status'], 'cancelled')
        self.assertFalse((manager.root / (identifier + '.upload')).exists())

    def test_stale_service_revision_rejected_before_stop(self):
        first = self.launch(self.begin())
        before = self.service(first['service_id'])
        identifier = self.begin(service=before)
        with self.state.connect(write=True) as db:
            db.execute('UPDATE service SET version=version+1 WHERE id=?', (before.id,))
        actions = len(self.driver.actions)
        result = self.launch(identifier)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(len(self.driver.actions), actions)

    def test_interrupted_switch_is_recovered_on_panel_restart(self):
        first = self.launch(self.begin())
        before = self.service(first['service_id'])
        identifier = self.begin(service=before, data=self.archive('interrupted'))
        with patch.object(self.manager, 'wait_running', side_effect=SystemExit):
            interrupted = self.launch(identifier)
        self.assertEqual(interrupted['status'], 'deploying')
        self.assertNotEqual(self.service(before.id).spec, before.spec)
        self.manager.recover()
        recovered = self.manager.request(self.actor, 'status', {'job': identifier})
        self.assertEqual(recovered['status'], 'failed')
        self.assertTrue(recovered['rolled_back'])
        self.assertEqual(self.service(before.id).spec, before.spec)
        self.assertEqual(self.driver.inspect(self.service(before.id)).status, 'running')

    def fake_docker(self, job, args):
        if args[:2] == ['image', 'pull']:
            return 'Downloaded image'
        if args[:2] == ['container', 'create']:
            target = f'{len(self.created) + 1:064x}'
            self.created.append(target)
            self.names[target] = args[args.index('--name') + 1] if '--name' in args else 'generated-' + target[:8]
            Path(args[args.index('--cidfile') + 1]).write_text(target)
            return target
        if args[:2] == ['container', 'inspect']:
            return '/' + self.names[args[-1]]
        if args[:2] == ['container', 'rename']:
            target, name = args[2:]
            if name in (value for key, value in self.names.items() if key != target):
                raise HostError('container name already in use')
            self.names[target] = name
            return ''
        if args[:2] == ['container', 'rm']:
            self.names.pop(args[-1], None)
            self.removed.append(args[-1])
            return ''
        raise AssertionError(args)

    def test_docker_deploy_update_and_explicit_rollback(self):
        with patch.object(self.manager, 'docker', side_effect=self.fake_docker):
            initial = self.launch(self.begin('docker', 'docker run -d --rm --name web -p 8080:80 nginx:v1'))
            self.assertEqual(initial['status'], 'succeeded', initial)
            before = self.service(initial['service_id'])
            updated = self.launch(self.begin('docker', 'docker run -d --name web -p 8080:80 nginx:v2', before))
            self.assertEqual(updated['status'], 'succeeded', updated)
            current = self.service(before.id)
            self.assertNotEqual(before.target, current.target)
            self.assertEqual(self.names[current.target], 'web')
            rolled = self.launch(self.begin('rollback', '', current))
            self.assertEqual(rolled['status'], 'succeeded', rolled)
            restored = self.service(before.id)
            self.assertEqual(restored.target, before.target)
            self.assertEqual(self.names[before.target], 'web')
            self.assertEqual(self.driver.inspect(restored).status, 'running')

    def test_docker_start_failure_recovers_name_and_previous_container(self):
        with patch.object(self.manager, 'docker', side_effect=self.fake_docker):
            initial = self.launch(self.begin('docker', 'docker run -d --name web nginx:v1'))
            before = self.service(initial['service_id'])
            failed = self.launch(self.begin('docker', 'docker run -d --name web nginx:v2 exit 42', before))
            self.assertEqual(failed['status'], 'failed', failed)
            self.assertTrue(failed['rolled_back'], failed)
            self.assertEqual(self.names[before.target], 'web')
            self.assertEqual(self.service(before.id).target, before.target)
            self.assertEqual(len(self.names), 1)

    def test_docker_command_preserves_image_arguments(self):
        args = docker_arguments('docker run -dit --rm --name web -e MODE=demo -p 8080:80 nginx sh -c "echo --detach"')
        self.assertNotIn('-d', args)
        self.assertIn('-it', args)
        self.assertNotIn('--rm', args)
        self.assertEqual(args[-3:], ['sh', '-c', 'echo --detach'])

    def test_docker_runner_streams_bounded_output(self):
        identifier = self.begin('command', 'echo example')
        job = self.manager.load(identifier)
        with patch('spearmint.service_deployment.local_docker_command', return_value=([sys.executable, '-c', 'print("x" * 30000); print("complete")'], os.environ.copy())):
            output = self.manager.docker(job, ['image', 'pull', 'fixture'])
        self.assertTrue(output.endswith('complete'))
        saved = self.manager.load(identifier)
        self.assertLessEqual(len(saved['log']), 12000)

    def test_docker_retains_only_one_previous_container(self):
        with patch.object(self.manager, 'docker', side_effect=self.fake_docker):
            first = self.launch(self.begin('docker', 'docker run -d --name web nginx:v1'))
            second = self.launch(self.begin('docker', 'docker run -d --name web nginx:v2', self.service(first['service_id'])))
            third = self.launch(self.begin('docker', 'docker run -d --name web nginx:v3', self.service(first['service_id'])))
            self.assertEqual(third['status'], 'succeeded', third)
            self.assertIn(self.created[0], self.removed)
            self.assertEqual(len(self.names), 2)

    @unittest.skipUnless(os.name == 'nt', 'Windows native supervisor integration')
    def test_real_windows_package_logs_update_and_failed_start_rollback(self):
        native = process_driver(self.state)
        self.controller.drivers['process'] = native
        command = '"' + sys.executable + '" -u app.py'
        def code(version):
            data = BytesIO()
            with zipfile.ZipFile(data, 'w') as archive:
                archive.writestr('app.py', f'import time, os\nprint("{version}", os.environ["SPMT_DATA_DIR"], flush=True)\nwhile True: time.sleep(.2)\n')
            return data.getvalue()
        service = None
        try:
            first = self.launch(self.begin(command=command, data=code('native-v1')))
            self.assertEqual(first['status'], 'succeeded', first)
            service = self.service(first['service_id'])
            self.assertEqual(native.inspect(service).status, 'running')
            self.assertIn('native-v1', native.logs(service, 10).text)
            second = self.launch(self.begin(command=command, service=service, data=code('native-v2')))
            self.assertEqual(second['status'], 'succeeded', second)
            service = self.service(service.id)
            self.assertIn('native-v2', native.logs(service, 10).text)
            failed = self.launch(self.begin(command='exit 42', service=service, data=code('broken')))
            self.assertEqual(failed['status'], 'failed', failed)
            self.assertTrue(failed['rolled_back'], failed)
            service = self.service(service.id)
            self.assertEqual(native.inspect(service).status, 'running')
            self.assertIn('native-v2', native.logs(service, 10).text)
        finally:
            if service:
                current = self.service(service.id)
                native.apply(current, 'stop', native.inspect(current))


if __name__ == '__main__':
    unittest.main()
