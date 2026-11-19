"""Convert an administrator's startup command to the existing process specification."""
import os
from pathlib import Path
import shlex
import shutil

from .catalog import process_spec
from .platforms import WINDOWS
from .state import StateError


def command_directory(command: str) -> Path:
    if WINDOWS:
        from .windows_services import command_arguments
        arguments = command_arguments(command)
    else:
        try:
            arguments = shlex.split(command)
        except ValueError:
            arguments = []
    # Prefer an explicitly named script, then an absolute program path.
    for argument in arguments[1:]:
        path = Path(os.path.expandvars(argument)).expanduser()
        if path.is_absolute() and path.suffix.lower() in {'.py', '.js', '.mjs', '.sh', '.cmd', '.bat', '.ps1'} and path.is_file():
            return path.parent
    if arguments:
        path = Path(os.path.expandvars(arguments[0])).expanduser()
        if path.is_absolute() and path.is_file():
            return path.parent
    return Path.home()


def command_spec(command: str, cwd: str | None, stop_timeout: int, endpoint: str | None) -> dict:
    if not command.strip() or '\0' in command or len(command.encode()) > 8192:
        raise StateError('Provide a startup command of at most 8 KiB')
    if WINDOWS:
        shell = str(Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/cmd.exe')
        argv = [shell, '/d', '/s', '/c', command]
    else:
        shell = shutil.which('sh') or '/bin/sh'
        argv = [shell, '-c', command]
    directory = Path(cwd).expanduser() if cwd else command_directory(command)
    spec = process_spec(argv, str(directory), stop_timeout, endpoint)
    return {**spec, 'command': command}
