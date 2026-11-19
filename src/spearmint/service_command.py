"""Convert an administrator's startup command to the existing process specification."""
import os
from hashlib import sha256
from pathlib import Path
import shutil

from .catalog import process_spec
from .onboarding import write_private
from .platforms import WINDOWS, secure_private
from .state import State, StateError, private_path


def command_spec(command: str, cwd: str | None, stop_timeout: int, endpoint: str | None, *, state: State) -> dict:
    if not command.strip() or '\0' in command or len(command.encode()) > 8192:
        raise StateError('Provide a startup command of at most 8 KiB')
    if WINDOWS:
        shell = str(Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/cmd.exe')
        argv = [shell, '/d', '/s', '/c', command]
    else:
        shell = shutil.which('sh') or '/bin/sh'
        argv = [shell, '-c', command]
    directory = Path(cwd).expanduser() if cwd else Path.home()
    spec = process_spec(argv, str(directory), stop_timeout, endpoint)
    path = write_command_script(state, command)
    argv = [shell, '/d', '/s', '/c', str(path)] if WINDOWS else [shell, str(path)]
    return {**spec, 'argv': argv, 'command': command, 'command_script': str(path)}


def command_script_path(state: State, command: str) -> Path:
    extension = '.cmd' if WINDOWS else '.sh'
    return state.directory / 'service-commands' / (sha256(command.encode('utf-8')).hexdigest() + extension)


def write_command_script(state: State, command: str) -> Path:
    path = command_script_path(state, command)
    scripts = path.parent
    if not scripts.exists():
        scripts.mkdir(mode=0o700)
        secure_private(scripts, 0o700)
    private_path(scripts, 0o700, directory=True)
    content = command.replace('\r\n', '\n').replace('\r', '\n')
    if WINDOWS:
        content = '@echo off\n@chcp 65001 >nul\n' + content
        content = content.replace('\n', '\r\n') + '\r\n'
    else:
        content = '#!/bin/sh\n' + content + '\n'
    write_private(path, content.encode('utf-8'))
    return path


def ensure_command_script(state: State, spec: dict) -> None:
    if not spec.get('command_script'):
        return
    path = command_script_path(state, spec['command'])
    if str(path) != spec['command_script']:
        raise StateError('The startup script belongs to a different state directory')
    if not path.exists():
        write_command_script(state, spec['command'])
