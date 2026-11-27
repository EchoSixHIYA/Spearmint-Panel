"""Exercise release directory promotion with Windows file handles open."""
import os
from pathlib import Path
from shutil import which
import subprocess
from tempfile import TemporaryDirectory
import time
import unittest


INSTALLER = Path(__file__).resolve().parents[1] / 'deploy/package/install-windows.ps1'
COMMAND = [
    'powershell.exe', '-NoProfile', '-NonInteractive', '-Command', '''
    $ErrorActionPreference = 'Stop'
    $tokens = $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $env:SPEARMINT_TEST_INSTALLER, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors) { throw $parseErrors[0] }
    $helper = $ast.Find({
        param($item)
        $item -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $item.Name -eq 'Move-StagedRelease'
    }, $false)
    . ([ScriptBlock]::Create($helper.Extent.Text))
    Move-StagedRelease $env:SPEARMINT_TEST_STAGE $env:SPEARMINT_TEST_RELEASE
''']


@unittest.skipUnless(os.name == 'nt' and which('powershell.exe'), 'Windows PowerShell required')
class WindowsReleaseRenameTest(unittest.TestCase):
    def setUp(self):
        work = Path.cwd() / 'work/tmp/windows-release-rename-tests'
        work.mkdir(parents=True, exist_ok=True)
        directory = TemporaryDirectory(dir=work)
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.stage = self.root / 'staged'
        self.release = self.root / 'release'
        self.file = self.stage / 'nested' / 'package.txt'
        self.file.parent.mkdir(parents=True)
        self.file.write_text('new package', encoding='ascii')
        self.env = {**os.environ, 'SPEARMINT_TEST_INSTALLER': str(INSTALLER),
                    'SPEARMINT_TEST_STAGE': str(self.stage), 'SPEARMINT_TEST_RELEASE': str(self.release)}

    def run_rename(self, timeout=45):
        return subprocess.run(COMMAND, env=self.env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              timeout=timeout, creationflags=subprocess.CREATE_NO_WINDOW)

    def test_rename_waits_until_a_nested_file_handle_closes(self):
        log = self.root / 'rename.log'
        with log.open('wb') as output:
            process = None
            try:
                with self.file.open('rb'):
                    process = subprocess.Popen(COMMAND, env=self.env, stdout=output, stderr=subprocess.STDOUT,
                                               creationflags=subprocess.CREATE_NO_WINDOW)
                    deadline = time.monotonic() + 12
                    while b'Retrying in' not in log.read_bytes() and process.poll() is None and time.monotonic() < deadline:
                        time.sleep(0.05)
                    self.assertIn(b'Retrying in', log.read_bytes())
                    self.assertFalse(self.release.exists())
                self.assertEqual(process.wait(timeout=15), 0, log.read_bytes())
            finally:
                if process is not None and process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
        self.assertIn(b'rename attempts', log.read_bytes())
        self.assertFalse(self.stage.exists())
        self.assertEqual((self.release/'nested/package.txt').read_text(encoding='ascii'), 'new package')

    def test_rename_times_out_with_the_original_filesystem_error(self):
        with self.file.open('rb'):
            result = self.run_rename()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'retry window expired', result.stdout)
        self.assertRegex(result.stdout, rb'0x800700(?:05|20|21)')
        self.assertTrue(self.file.is_file())
        self.assertFalse(self.release.exists())

    def test_destination_collision_fails_without_retry_or_replacement(self):
        self.release.mkdir()
        existing = self.release / 'previous.txt'
        existing.write_text('previous release', encoding='ascii')
        result = self.run_rename(timeout=12)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'rename attempt 1 failed', result.stdout)
        self.assertNotIn(b'Retrying in', result.stdout)
        self.assertEqual(existing.read_text(encoding='ascii'), 'previous release')
        self.assertTrue(self.file.is_file())
