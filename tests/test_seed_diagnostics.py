from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from io import BytesIO
from pathlib import Path
from subprocess import CalledProcessError
from tempfile import TemporaryDirectory
from threading import RLock
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock

from spearmint import seed_ssh, seed_transport, seed_wizard


class SeedDiagnosticsTest(unittest.TestCase):
    def test_ssh_preserves_stdout_and_bounded_stderr_separately(self):
        channel = MagicMock()
        channel.__enter__.return_value = channel
        channel.recv_ready.side_effect = [True, False, False]
        channel.recv.return_value = b'SPEARMINT_SEED_CHECKPOINT=archive\n'
        channel.recv_stderr_ready.side_effect = [True, False]
        channel.recv_stderr.return_value = b'x' * 12000 + b'GLIBC_2.38 not found'
        channel.exit_status_ready.return_value = True
        channel.recv_exit_status.return_value = 42
        connection = object.__new__(seed_ssh.Connection)
        connection.transport = SimpleNamespace(open_session=lambda **_: channel)
        output = BytesIO()
        with self.assertRaises(CalledProcessError) as caught:
            connection.run('seed', BytesIO(b'archive'), output, 2)
        self.assertEqual(caught.exception.returncode, 42)
        self.assertEqual(len(caught.exception.stderr), 8192)
        self.assertTrue(caught.exception.stderr.endswith(b'GLIBC_2.38 not found'))
        self.assertEqual(output.getvalue(), b'SPEARMINT_SEED_CHECKPOINT=archive\n')

    def test_diagnostic_redacts_credentials_and_limits_output(self):
        error = CalledProcessError(42, 'command containing a secret', stderr=(
            b'GLIBC_2.38 not found\n'
            b'https://host/setup#secret\npassword=short-secret\n'
            b'{"token": "short-token"}\n' + b'A' * 2000))
        phase, code, detail = seed_transport.diagnostic(error)
        self.assertEqual((phase, code), ('verify', 42))
        self.assertIn('GLIBC_2.38', detail)
        self.assertNotIn('short-secret', detail)
        self.assertNotIn('short-token', detail)
        self.assertNotIn('https://host', detail)
        self.assertNotIn('command containing', detail)
        self.assertNotIn('A' * 64, detail)
        self.assertLessEqual(len(detail), 2048)

    def test_uncertain_install_keeps_checkpoint_exit_and_stderr(self):
        task = Path(__file__).resolve().parents[1] / 'work/tmp/seed-diagnostics-tests'
        task.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(dir=task) as directory:
            work = Path(directory)
            archive = work / 'package.tar.gz'
            archive.write_bytes(b'fixture archive')

            def runner(command, source, output, timeout):
                output.write(b'SPEARMINT_SEED_CHECKPOINT=installer\n')
                raise CalledProcessError(43, command, stderr=b'The installed panel failed its health check')

            with self.assertRaises(seed_transport.UnconfirmedInstall) as caught:
                seed_transport.install(archive, work, host='192.0.2.1', target='linux-arm64',
                                       digest=sha256(archive.read_bytes()).hexdigest(), invitation_data=b'{}',
                                       origin='https://192.0.2.1:8765', port=8765, windows={}, quiet=True,
                                       runner=runner)
            phase, code, detail = seed_transport.diagnostic(caught.exception)
            self.assertEqual((phase, code), ('install', 43))
            self.assertIn('checkpoint=installer', detail)
            self.assertIn('failed its health check', detail)

    def test_wizard_returns_linux_failure_details(self):
        wizard = object.__new__(seed_wizard.SeedWizard)
        wizard.lock = RLock()
        wizard.workers = ThreadPoolExecutor(max_workers=1)
        job = seed_wizard.Job(('source', 'actor'), ['realm', 'actor'], '192.0.2.1', 22, status='installing')

        def fail(job):
            raise CalledProcessError(42, 'seed', stderr=b'libm.so.6: GLIBC_2.38 not found')

        wizard.schedule(job, fail)
        wizard.workers.shutdown(wait=True)
        view = job.view()
        self.assertEqual(view['error'], 'SEED_INSTALL')
        self.assertEqual(view['status'], 'failed')
        self.assertEqual(view['failure_phase'], 'verify')
        self.assertEqual(view['failure_exit'], 42)
        self.assertIn('GLIBC_2.38', view['failure_detail'])


if __name__ == '__main__':
    unittest.main()
