"""Run a verified native installer independently of the panel it restarts."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from tempfile import NamedTemporaryFile, TemporaryDirectory
import time

from . import maintenance, update_release
from .platforms import WINDOWS, replace_file, secure_private


def write_record(path: Path, value: dict) -> None:
    with NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            secure_private(temporary)
            stream.write(json.dumps(value, separators=(',', ':')).encode())
            stream.flush()
            os.fsync(stream.fileno())
        except BaseException:
            stream.close()
            temporary.unlink(missing_ok=True)
            raise
    try:
        replace_file(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def read_record(path: Path) -> dict | None:
    try:
        return json.loads(path.read_bytes())
    except FileNotFoundError:
        return None


def supported() -> bool:
    if not getattr(sys, 'frozen', False):
        return False
    executable = Path(sys.executable).resolve()
    parent = executable.parent
    if WINDOWS:
        return parent.parent.name == 'releases' and re.fullmatch(r'[a-f0-9]{40}', parent.name) is not None
    current = Path.home() / '.local/opt/spearmint/current/spearmint'
    return current.is_file() and executable == current.resolve()


def launch(state_directory: Path, job: str) -> None:
    executable = str(Path(sys.executable).resolve())
    command = [executable, '--internal-grove-updater', str(state_directory), job]
    if WINDOWS:
        flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_BREAKAWAY_FROM_JOB
        subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         creationflags=flags, env={**os.environ, 'PYINSTALLER_RESET_ENVIRONMENT': '1'})
    else:
        subprocess.run(['systemd-run', '--user', '--quiet', '--collect', f'--unit=spearmint-update-{job}',
                        '--property=RuntimeMaxSec=900', '--expand-environment=no', '--', *command],
                       check=True, stdin=subprocess.DEVNULL, capture_output=True, timeout=10, env=installer_env())


def setting(flag: str, default=None):
    try:
        return sys.argv[sys.argv.index(flag) + 1]
    except (IndexError, ValueError):
        return default


def windows_settings(config) -> dict:
    settings = {'StateDirectory': str(config.state_dir), 'Bind': setting('--bind', '127.0.0.1'),
                'Port': setting('--port', '8765')}
    for name, flag in [('WebDirectory', '--web-dir'), ('Certificate', '--tls-cert'), ('PrivateKey', '--tls-key')]:
        value = setting(flag)
        if value is not None:
            settings[name] = str(Path(value).absolute())
    if config.grove_ca is not None:
        settings['GroveCA'] = str(config.grove_ca)
    return settings


def installer_env() -> dict:
    env = {name: value for name, value in os.environ.items()
           if not name.startswith('_PYI_') and name not in {'SPEARMINT_WEB_DIR', 'SPEARMINT_GITHUB_TOKEN'}}
    if not WINDOWS and 'LD_LIBRARY_PATH_ORIG' in env:
        env['LD_LIBRARY_PATH'] = env.pop('LD_LIBRARY_PATH_ORIG')
    else:
        env.pop('LD_LIBRARY_PATH', None)
    return env


def installer_args(bundle: Path, config: dict, job: dict, backup: Path, backup_sha: str, package_sha: str) -> list[str]:
    release = update_release.Release.model_validate(job['release'])
    if not WINDOWS:
        return ['sh', str(bundle / 'deployment/install-linux.sh'), '--upgrade',
                '--verify-backup', str(backup), '--expected-backup-sha256', backup_sha,
                '--expected-node', job['node'], '--expected-current-commit', job['previous'],
                '--expected-commit', release.commit, '--expected-package-sha256', package_sha, config['origin']]
    executable = Path(sys.executable).resolve()
    powershell = ['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass']
    script = (
        "$ErrorActionPreference='Stop'; "
        "$tasks=@(Get-ScheduledTask -TaskPath '\\' | Where-Object { $_.Actions.Count -eq 1 -and "
        "$_.Actions[0].Execute -eq $env:SPEARMINT_UPDATE_EXECUTABLE }); "
        "if ($tasks.Count -ne 1) { throw 'Expected one packaged Spearmint scheduled task' }; "
        "ConvertTo-Json -Compress @{ TaskName=$tasks[0].TaskName; TaskLogonType=[string]$tasks[0].Principal.LogonType }"
    )
    task = json.loads(subprocess.check_output(
        [*powershell, '-Command', script], timeout=15, text=True,
        env={**installer_env(), 'SPEARMINT_UPDATE_EXECUTABLE': str(executable)},
    ))
    arguments = {**config['windows'], **task, 'Origin': config['origin'], 'InstallDirectory': str(executable.parents[2]),
                 'VerifyBackup': str(backup), 'ExpectedBackupSha256': backup_sha, 'ExpectedNode': job['node'],
                 'ExpectedCurrentCommit': job['previous'], 'ExpectedCommit': release.commit,
                 'ExpectedPackageSha256': package_sha}
    return [*powershell, '-File', str(bundle / 'deployment/install-windows.ps1'), '-Upgrade',
            *(part for name, value in arguments.items() for part in (f'-{name}', value))]


def main(state_directory: str, job_id: str) -> int:
    from .state import State
    if not re.fullmatch(r'[a-f0-9]{32}', job_id):
        return 2
    directory = Path(state_directory)
    root = directory / 'grove-updates'
    job_path = root / 'local.json'
    job = read_record(job_path)
    if not job or job['job'] != job_id or job['status'] != 'installing':
        return 2
    result = root / f'{job_id}.result.json'
    log = root / f'{job_id}.installer.log'
    try:
        release = update_release.Release.model_validate(job['release'])
        target = job['target']
        folder = directory.with_name(directory.name + '-update-backups')
        folder.mkdir(mode=0o700, exist_ok=True)
        secure_private(folder, 0o700)
        backup = folder / job_id
        with TemporaryDirectory(prefix='apply-', dir=root) as temporary:
            bundle = Path(temporary)
            archive = root / f"{release.packages[target].sha256}.archive"
            checksum = update_release.extract(archive, bundle, release, target)
            maintenance.backup(State(directory), backup)
            backup_sha = maintenance.verify_backup(backup)['backup_sha256']
            args = installer_args(bundle / 'spearmint', job['config'], job, backup, backup_sha, checksum)
            with log.open('wb') as sink:
                secure_private(log)
                subprocess.run(args, check=True, stdin=subprocess.DEVNULL, stdout=sink,
                               stderr=subprocess.STDOUT, env=installer_env())
        write_record(result, {'status': 'succeeded', 'finished_at': int(time.time())})
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        with log.open('ab') as stream:
            secure_private(log)
            stream.write((str(error) + '\n').encode('utf-8', errors='replace'))
        write_record(result, {'status': 'failed', 'reason': 'installer_failed', 'finished_at': int(time.time())})
        return 1