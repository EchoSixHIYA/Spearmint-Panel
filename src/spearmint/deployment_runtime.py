"""Prepare immutable code environments and attach service-owned persistent data."""
from pathlib import Path
import os
import re
import shutil
import subprocess
import sys

from .platforms import WINDOWS
from .state import StateError


def python_command(command, cwd):
    for line in command.splitlines():
        match = re.match(r'\s*(?:python(?:3(?:\.\d+)?)?|py)(?:\.exe)?\s', line, re.I)
        if match:
            return True
    return (cwd / 'requirements.txt').is_file() or (cwd / 'pyproject.toml').is_file()


def python_executable():
    # A frozen panel executable is not a general-purpose Python interpreter.
    if not getattr(sys, 'frozen', False) and Path(sys._base_executable).is_file():
        return sys._base_executable
    for name in (('python', 'python3', 'py') if WINDOWS else ('python3', 'python')):
        found = shutil.which(name)
        if found and (not getattr(sys, 'frozen', False) or Path(found).resolve() != Path(sys.executable).resolve()):
            return found
    raise StateError('目标节点未找到 Python，请安装 Python 或在高级设置选择现有环境。')


def environment(cwd, app, *, venv=None):
    runtime_tmp = app / 'tmp' / 'runtime'
    runtime_tmp.mkdir(parents=True, exist_ok=True)
    result = {'SPMT_APP_DIR': str(cwd), 'SPMT_DATA_DIR': str(app / 'data'),
              'TEMP': str(runtime_tmp), 'TMP': str(runtime_tmp), 'TMPDIR': str(runtime_tmp),
              'npm_config_cache': str(runtime_tmp / 'npm-cache'), 'PIP_NO_CACHE_DIR': '1'}
    if venv is not None:
        scripts = venv / ('Scripts' if WINDOWS else 'bin')
        result.update(VIRTUAL_ENV=str(venv), PATH=str(scripts) + os.pathsep + os.environ.get('PATH', ''))
    return result


def data_directories(cwd, app, names):
    """Link only explicitly managed directories. Never replace a user's external path."""
    for name in names:
        destination = app / 'data' if name == 'data' else app / 'data' / name
        location = cwd / name
        destination.mkdir(parents=True, exist_ok=True)
        location.parent.mkdir(parents=True, exist_ok=True)
        linked = location.is_symlink() or getattr(location, 'is_junction', lambda: False)()
        if linked:
            if location.resolve() != destination.resolve():
                raise StateError(f'持久化目录 {name} 指向了其他位置，请核对后部署。')
            continue
        if location.exists():
            if not location.is_dir():
                raise StateError(f'持久化目录 {name} 在程序包中是文件。')
            # Seed packaged defaults without overwriting already established data.
            for source in location.rglob('*'):
                relative = source.relative_to(location)
                target = destination / relative
                if source.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                elif not target.exists():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source, target)
            shutil.rmtree(location)
        if WINDOWS:
            shell = str(Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/cmd.exe')
            completed = subprocess.run([shell, '/d', '/c', 'mklink', '/J', str(location), str(destination)],
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, creationflags=subprocess.CREATE_NO_WINDOW)
            if completed.returncode:
                raise StateError('无法连接持久化目录：' + completed.stdout.decode('utf-8', 'replace')[-500:])
        else:
            location.symlink_to(destination, target_is_directory=True)


def copy_release(source, destination, names):
    source = Path(source)
    def ignore(directory, entries):
        base = Path(directory).relative_to(source)
        return [name for name in entries if name in {'.venv', '__pycache__'} or (base / name).as_posix() in names]
    shutil.copytree(source, destination, symlinks=True, ignore=ignore)


def prepare(manager, job, cwd, app, settings, *, fresh):
    preparation = app / 'tmp' / ('prepare-' + job['id'])
    preparation.mkdir(parents=True, exist_ok=True)
    def preparation_env(venv=None):
        return {**environment(cwd, app, venv=venv), 'TEMP': str(preparation), 'TMP': str(preparation),
                'TMPDIR': str(preparation), 'npm_config_cache': str(preparation / 'npm-cache')}
    venv = None
    use_python = settings['runtime'] == 'python' or settings['runtime'] == 'auto' and python_command(job['command'], cwd)
    if use_python:
        previous = (job.get('before') or {}).get('spec', {}).get('deployment_environment', {})
        venv = Path(previous['VIRTUAL_ENV']) if not fresh and previous.get('VIRTUAL_ENV') else manager.state.directory / 'service-envs' / job['id']
        interpreter = venv / ('Scripts/python.exe' if WINDOWS else 'bin/python')
        if not interpreter.is_file():
            manager.note(job, '创建应用 Python 环境')
            pip = settings['runtime'] == 'python' or 'pip' in settings['prepare'] or (cwd / 'requirements.txt').is_file() or (cwd / 'pyproject.toml').is_file()
            manager.execute(job, [python_executable(), '-m', 'venv', *([] if pip else ['--without-pip']), str(venv)], cwd=cwd,
                            timeout=settings['prepare_timeout'], env=preparation_env())
        if fresh:
            requirements = cwd / 'requirements.txt'
            if requirements.is_file() or (cwd / 'pyproject.toml').is_file():
                manager.note(job, '安装应用依赖')
                args = [str(interpreter), '-m', 'pip', 'install', '--no-cache-dir', '--disable-pip-version-check']
                manager.execute(job, [*args, '-r', str(requirements)] if requirements.is_file() else [*args, '.'],
                                cwd=cwd, timeout=settings['prepare_timeout'], env=preparation_env(venv))
    env = environment(cwd, app, venv=venv)
    if fresh and settings['prepare'].strip():
        manager.note(job, '执行依赖准备命令')
        command = settings['prepare'] if WINDOWS else 'set -e\n' + settings['prepare']
        manager.execute_script(job, command, cwd, preparation_env(venv), timeout=settings['prepare_timeout'])
    return env


def docker_mounts(arguments):
    """Destinations explicitly supplied by docker run, with both flag spellings."""
    result = set()
    for index, item in enumerate(arguments):
        value = None
        if item in {'-v', '--volume', '--mount'} and index + 1 < len(arguments):
            value = arguments[index + 1]
        elif item.startswith(('--volume=', '--mount=')):
            value = item.split('=', 1)[1]
        elif item.startswith('-v') and len(item) > 2:
            value = item[2:]
        if value is None:
            continue
        if item.startswith('--mount'):
            fields = dict(part.split('=', 1) for part in value.split(',') if '=' in part)
            target = fields.get('target') or fields.get('dst') or fields.get('destination')
        else:
            # Match from the end so a Windows drive prefix stays in the source.
            parts = value.split(':')
            if parts and re.fullmatch(r'(?:ro|rw|z|Z|cached|delegated|consistent)(?:,.*)?', parts[-1]):
                parts.pop()
            target = parts[-1] if parts else None
        if target:
            result.add(target)
    return result


def container_data(arguments, previous, image, app):
    """Retain explicit and anonymous mounts; give image-declared data stable volumes."""
    from hashlib import sha256
    extra = []
    declared = docker_mounts(arguments)
    for mount in previous:
        target = mount.get('Destination')
        if not target or target in declared or mount.get('Type') not in {'volume', 'bind'}:
            continue
        source = mount.get('Name') if mount['Type'] == 'volume' else mount.get('Source')
        if source:
            extra.extend(['--mount', f"type={mount['Type']},source={source},target={target}" + (',readonly' if not mount.get('RW', True) else '')])
            declared.add(target)
    default = 'C:\\spmt-data' if image.get('Os') == 'windows' else '/data'
    volumes = set((image.get('Config') or {}).get('Volumes') or {}) | {default}
    for target in sorted(volumes - declared):
        name = 'spmt-' + app + '-' + sha256(target.encode()).hexdigest()[:12]
        extra.extend(['--mount', f'type=volume,source={name},target={target}'])
    supplied = any(value == 'SPMT_DATA_DIR' or value.startswith('SPMT_DATA_DIR=') or value.startswith('--env=SPMT_DATA_DIR') or value.startswith('-eSPMT_DATA_DIR') for value in arguments)
    if not supplied:
        extra.extend(['--env', 'SPMT_DATA_DIR=' + default])
    return extra
