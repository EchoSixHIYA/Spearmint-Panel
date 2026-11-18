"""Target-side Windows SSH seeding via the native package and Task Scheduler."""
from contextlib import contextmanager, suppress
import ctypes
from hashlib import sha256
from http.client import HTTPConnection, HTTPException
import json
import os
from pathlib import Path
import re
from shutil import copytree, disk_usage
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import monotonic, sleep
from urllib.parse import urlsplit

import psutil

from . import onboarding, seed_admission
from .config import Config
from .package_files import verify_package
from .peer.protocol import PeerError
from .platforms import WINDOWS, current_sid, secure_private
from .state import State, StateError


S4U = 2
TASK_READY = 3
TASK_RUNNING = 4


def fixed_path(value: str) -> Path:
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z]:[\\/][^<>:"|?*\x00-\x1f]*', value):
        raise ValueError('Use an absolute path on a fixed Windows drive')
    path = Path(value)
    if (any(part == '..' or part.endswith((' ', '.')) for part in path.parts[1:])
            or ctypes.windll.kernel32.GetDriveTypeW(path.anchor) != 3):
        raise ValueError('Use an absolute path on a fixed Windows drive')
    for parent in (*reversed(path.parents), path):
        try:
            attributes = parent.lstat().st_file_attributes
        except FileNotFoundError:
            continue
        if attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError('Choose a location outside junctions and other reparse points')
    return path


def directory(value: str) -> dict:
    if not value:
        roots = [path for path in os.listdrives() if ctypes.windll.kernel32.GetDriveTypeW(path) == 3]
        return {'items': [{'name': root, 'path': root} for root in roots], 'free': None, 'truncated': False}
    path = fixed_path(value)
    items = []
    with os.scandir(path) as files:
        for entry in files:
            if not entry.is_dir(follow_symlinks=False):
                continue
            if entry.stat(follow_symlinks=False).st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                continue
            items.append({'name': entry.name, 'path': entry.path})
            if len(items) > 100:
                break
    return {'items': items[:100], 'free': disk_usage(path).free, 'truncated': len(items) > 100}


@contextmanager
def install_lock(install: Path):
    import win32con
    import win32file

    lock = fixed_path(str(install / 'install.lock'))
    handle = win32file.CreateFile(str(lock), win32con.GENERIC_READ | win32con.GENERIC_WRITE, 0,
                                  None, win32con.OPEN_ALWAYS, win32con.FILE_ATTRIBUTE_NORMAL, None)
    try:
        yield
    finally:
        handle.Close()


def existing_task(folder, name):
    import pywintypes

    try:
        return folder.GetTask(name)
    except pywintypes.com_error as error:
        codes = [error.hresult]
        if error.excepinfo:
            codes.append(error.excepinfo[-1])
        if any((code & 0xffffffff) in {0x80070002, 0x8004130f} for code in codes):
            return None
        raise


def task_matches(task, binary: Path, arguments: str, sid: str) -> bool:
    import win32security

    principal = task.Definition.Principal
    if principal.UserId.upper().startswith('S-1-'):
        owner = principal.UserId.upper()
    else:
        owner = win32security.ConvertSidToStringSid(win32security.LookupAccountName(None, principal.UserId)[0])
    actions = task.Definition.Actions
    if actions.Count != 1:
        return False
    action = actions.Item(1)
    return (owner == sid and principal.LogonType == S4U and principal.RunLevel == 0 and action.Type == 0
            and Path(action.Path) == binary and Path(action.WorkingDirectory) == binary.parent and action.Arguments == arguments)


def register_task(scheduler, folder, name, binary, arguments, sid):
    task = scheduler.NewTask(0)
    task.RegistrationInfo.Description = 'Spearmint native management panel'
    task.Principal.UserId = sid
    task.Principal.LogonType = S4U
    task.Principal.RunLevel = 0
    task.Triggers.Create(8)  # At system startup.
    action = task.Actions.Create(0)
    action.Path = str(binary)
    action.WorkingDirectory = str(binary.parent)
    action.Arguments = arguments
    task.Settings.MultipleInstances = 2  # Ignore a new start if the task is running.
    task.Settings.ExecutionTimeLimit = 'PT0S'
    task.Settings.DisallowStartIfOnBatteries = False
    task.Settings.StopIfGoingOnBatteries = False
    task.Settings.RestartCount = 3
    task.Settings.RestartInterval = 'PT1M'
    return folder.RegisterTaskDefinition(name, task, 2, sid, None, S4U, None)


def listeners(port):
    return [conn for conn in psutil.net_connections(kind='tcp') if conn.status == psutil.CONN_LISTEN
            and conn.laddr.port == port and conn.laddr.ip in {'127.0.0.1', '0.0.0.0', '::'}]


def panel_health(binary: Path, config: Config, port: int) -> bool:
    try:
        pids = {conn.pid for conn in listeners(port) if conn.laddr.ip == '127.0.0.1' and conn.pid}
        if not any(Path(psutil.Process(pid).exe()) == binary for pid in pids):
            return False
        connection = HTTPConnection('127.0.0.1', port, timeout=1)
        try:
            connection.request('GET', '/healthz', headers={'Host': config.authority})
            response = connection.getresponse()
            if response.status != 200 or json.loads(response.read(256)) != {'status': 'ok'}:
                return False
            connection.request('GET', '/', headers={'Host': config.authority})
            response = connection.getresponse()
            return response.status == 200 and response.getheader('content-type', '').startswith('text/html')
        finally:
            connection.close()
    except (OSError, HTTPException, psutil.Error, ValueError):
        return False


def quote_task_argument(text: str) -> str:
    # Match the native package's existing installer and upgrade task arguments.
    return '"' + text + '\\' * (len(text) - len(text.rstrip('\\'))) + '"'


def install(bundle: Path, options: dict) -> dict:
    import pywintypes
    import win32com.client
    import win32security

    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise PeerError('SEED_WINDOWS_TASK_PERMISSION', 'The SSH account cannot register an S4U task')
    programs = fixed_path(options['programs'])
    state_path = fixed_path(options['state'])
    if (programs.is_relative_to(state_path) or state_path.is_relative_to(programs)
            or any(path.is_relative_to(bundle) or bundle.is_relative_to(path) for path in (programs, state_path))):
        raise ValueError('Use separate package, program and state directories')
    config = Config.from_env(state_dir=state_path, origin=options['origin'])
    port = options['port']
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError('Invalid panel port')
    verify_package(bundle, bundle, 'spearmint.exe')
    manifest = json.loads((bundle / 'build-manifest.json').read_bytes())
    if (manifest.get('os'), manifest.get('architecture'), manifest.get('commit')) != (
            'windows', 'amd64', options['commit']) or not re.fullmatch(r'[0-9a-f]{40}', manifest['commit']):
        raise ValueError('Extract the selected Windows native package')
    sid = win32security.ConvertSidToStringSid(current_sid())
    scheduler = win32com.client.Dispatch('Schedule.Service')
    scheduler.Connect()
    folder = scheduler.GetFolder('\\')
    name = 'Spearmint-' + sha256(str(state_path).casefold().encode()).hexdigest()[:12]
    release = fixed_path(str(programs / 'releases' / manifest['commit']))
    binary = release / 'spearmint.exe'
    arguments = f'--state-dir {quote_task_argument(str(state_path))} --origin {quote_task_argument(config.origin)} serve --bind 127.0.0.1 --port {port}'
    state = State(state_path)
    programs.mkdir(parents=True, exist_ok=True)
    with install_lock(programs):
        if os.path.lexists(programs / 'upgrade-recovery.json'):
            raise ValueError('Recover the interrupted upgrade before seeding')
        task = existing_task(folder, name)
        if task and not task_matches(task, binary, arguments, sid):
            raise PeerError('SEED_WINDOWS_TASK_CONFLICT', 'The existing scheduled task belongs to another installation')
        if (not task or task.State != TASK_RUNNING) and listeners(port):
            raise PeerError('SEED_WINDOWS_PORT', 'The panel port is in use')
        release.parent.mkdir(exist_ok=True)
        if not release.exists():
            with TemporaryDirectory(prefix='.install-', dir=release.parent) as temporary:
                staged = copytree(bundle, Path(temporary) / 'release')
                verify_package(bundle, staged, 'spearmint.exe')
                staged.rename(release)
        verify_package(bundle, release, 'spearmint.exe')
        with TemporaryDirectory(prefix='.invite-', dir=bundle.parent) as temporary:
            private = Path(temporary)
            secure_private(private, 0o700)
            invitation = private / 'grove.json'
            invitation.write_text(json.dumps(options['realm']), encoding='utf-8')
            handoff = onboarding.prepare(state, config, renew_if_expired=True, join_grove=invitation)
        created = False
        try:
            if not task:
                try:
                    task = register_task(scheduler, folder, name, binary, arguments, sid)
                except pywintypes.com_error as error:
                    raise PeerError('SEED_WINDOWS_TASK_PERMISSION', 'Task Scheduler rejected S4U registration') from error
                created = True
            if task.State == TASK_READY:
                task.Run('')
            deadline = monotonic() + 30
            while monotonic() < deadline:
                if panel_health(binary, config, port):
                    return {'node_id': state.identity()[0], 'setup': 'pending' if handoff else 'complete'}
                sleep(.3)
            raise PeerError('SEED_WINDOWS_STARTUP', 'Panel startup not confirmed by Task Scheduler and the local Web endpoints')
        except BaseException:
            if created:
                with suppress(OSError, RuntimeError, pywintypes.com_error):
                    current = existing_task(folder, name)
                    if current and task_matches(current, binary, arguments, sid):
                        current.Stop(0)
                        folder.DeleteTask(name, 0)
            raise


def enroll(options: dict) -> dict:
    # The frozen helper already executes under the authenticated SSH account.
    state = State(fixed_path(options['state']))
    config = Config.from_env(state_dir=state.directory, origin=options['origin'])
    action = options['action']
    if action not in {'request', 'finish', 'status'}:
        raise ValueError('Invalid enrollment action')
    return seed_admission.cli(state, config, action, payload=options.get('payload'))


def command(bundle: Path, args: list[str]) -> int:
    if not WINDOWS or len(args) != 1:
        return 2
    import pywintypes

    # Keep stdout as one ASCII JSON line independent of the SSH console code page.
    action = args[0]
    try:
        data = sys.stdin.buffer.read(seed_admission.LIMIT + 16385)
        if len(data) > seed_admission.LIMIT + 16384:
            raise ValueError('Windows seed request is too large')
        options = json.loads(data)
        if action == 'version':
            result = {'native_seed': 1}
        elif action == 'directory':
            result = directory(options['path'])
        elif action == 'install':
            result = install(bundle, options)
        elif action == 'enroll':
            result = enroll(options)
        else:
            raise ValueError('Unknown Windows seed operation')
        result = {'ok': result}
    except PeerError as error:
        result = {'error': error.code}
    except (OSError, ValueError, KeyError, TypeError, StateError, psutil.Error, pywintypes.com_error) as error:
        result = {'error': {'directory': 'SEED_DIRECTORY', 'install': 'SEED_INSTALL'}.get(action, 'SEED_WINDOWS_PACKAGE')}
        # Do not send paths, package contents or invitation data through the job UI.
        print(type(error).__name__, file=sys.stderr)
    print(json.dumps(result, ensure_ascii=True), flush=True)
    return 0
