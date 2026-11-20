"""Prepare application releases without changing the running service."""
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import stat
import tarfile
import zipfile

from .platforms import WINDOWS
from .state import StateError

MAX_UPLOAD = 1024 * 1024 * 1024
MAX_EXPANDED = 4 * MAX_UPLOAD
MAX_FILES = 100_000


def unpack(archive: Path, destination: Path, filename: str) -> Path:
    """Write regular files into a new release, retaining executable permission bits."""
    destination.mkdir(parents=True, exist_ok=False)
    total = count = 0

    def target(name, size):
        nonlocal total, count
        parts = PurePosixPath(name.replace('\\', '/'))
        if parts.is_absolute() or '..' in parts.parts or any(':' in part for part in parts.parts):
            raise StateError('压缩包中有无效的文件路径。')
        count += 1
        total += size
        if count > MAX_FILES or total > MAX_EXPANDED:
            raise StateError('压缩包展开后超过 4 GiB 或 100000 个文件。')
        if shutil.disk_usage(destination).free < size + 16 * 1024 * 1024:
            raise StateError('目标节点没有足够空间解压服务包。')
        return destination.joinpath(*parts.parts)

    if filename.lower().endswith('.zip'):
        with zipfile.ZipFile(archive) as source:
            for entry in source.infolist():
                path = target(entry.filename, entry.file_size)
                mode = entry.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise StateError('服务包请使用普通文件和目录，不包含符号链接。')
                if entry.is_dir():
                    path.mkdir(parents=True, exist_ok=True)
                    continue
                path.parent.mkdir(parents=True, exist_ok=True)
                with source.open(entry) as reader, path.open('xb') as writer:
                    shutil.copyfileobj(reader, writer, 1024 * 1024)
                if not WINDOWS:
                    path.chmod((mode & 0o777) or 0o644)
    elif filename.lower().endswith(('.tar', '.tar.gz', '.tgz', '.tar.xz', '.tar.bz2')):
        with tarfile.open(archive, 'r:*') as source:
            for entry in source:
                path = target(entry.name, entry.size)
                if entry.isdir():
                    path.mkdir(parents=True, exist_ok=True)
                elif entry.isfile():
                    path.parent.mkdir(parents=True, exist_ok=True)
                    with source.extractfile(entry) as reader, path.open('xb') as writer:
                        shutil.copyfileobj(reader, writer, 1024 * 1024)
                    if not WINDOWS:
                        path.chmod((entry.mode & 0o777) or 0o644)
                else:
                    raise StateError('服务包请使用普通文件和目录，不包含链接或设备文件。')
    else:
        raise StateError('请选择 ZIP、TAR 或 TAR.GZ 服务包。')
    entries = list(destination.iterdir())
    if not entries:
        raise StateError('服务包为空。')
    return entries[0] if len(entries) == 1 and entries[0].is_dir() else destination


def docker_invocation(command: str) -> tuple[list[str], str]:
    """Convert one docker run invocation to create arguments; no shell is invoked."""
    command = re.sub(r'(?:\\|\^)\r?\n\s*', ' ', command).strip()
    try:
        if WINDOWS:
            import ctypes
            from ctypes import wintypes
            count = ctypes.c_int()
            split = ctypes.windll.shell32.CommandLineToArgvW
            split.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
            split.restype = ctypes.POINTER(wintypes.LPWSTR)
            pointer = split(command, ctypes.byref(count))
            if not pointer:
                raise ValueError()
            try:
                words = [pointer[index] for index in range(count.value)]
            finally:
                ctypes.windll.kernel32.LocalFree(ctypes.cast(pointer, ctypes.c_void_p))
        else:
            words = shlex.split(command)
    except ValueError as error:
        raise StateError('Docker 命令的引号不完整。') from error
    prefix = 3 if words[:3] == ['docker', 'container', 'run'] else 2
    if words[:prefix] not in (['docker', 'run'], ['docker', 'container', 'run']) or len(words) <= prefix:
        raise StateError('请提供一条完整的 docker run 命令。')
    # Preserve image command arguments verbatim. Only process options preceding the image.
    boolean = {'--rm', '--detach', '--interactive', '--tty', '--privileged', '--read-only', '--init',
               '--publish-all', '--oom-kill-disable', '--sig-proxy', '--disable-content-trust', '--use-api-socket'}
    short_boolean = set('ditP')
    result = []
    options = words[prefix:]
    index = 0
    while index < len(options):
        item = options[index]
        if item == '--':
            if index + 1 >= len(options):
                raise StateError('Docker 命令缺少镜像名称。')
            image = options[index + 1]
            result.extend(options[index:]); break
        if not item.startswith('-'):
            image = item
            result.extend(options[index:]); break
        key = item.split('=', 1)[0]
        if key in {'--cidfile', '--attach', '--help', '--pull', '--name'}:
            if key in {'--cidfile', '--attach', '--help'}:
                raise StateError('请移除 --cidfile、--attach 和 --help，部署器会读取容器回执。')
            if key == '--pull':
                index += 1 if '=' in item else 2
                continue
        if key in {'--rm', '--detach'}:
            index += 1
            continue
        if item.startswith('-') and not item.startswith('--') and all(c in short_boolean for c in item[1:]):
            retained = ''.join(c for c in item[1:] if c != 'd')
            if retained:
                result.append('-' + retained)
            index += 1
            continue
        result.append(item)
        if '=' not in item and key not in boolean and not (len(item) > 2 and not item.startswith('--')):
            if index + 1 >= len(options):
                raise StateError(f'Docker 选项 {item} 缺少参数。')
            index += 1
            result.append(options[index])
        index += 1
    else:
        raise StateError('Docker 命令缺少镜像名称。')
    if any(value in {'&&', '||', ';', '|', '>', '>>'} for value in result):
        raise StateError('请仅填写 docker run 命令，不附加其他 shell 命令。')
    return result, image


def docker_arguments(command: str) -> list[str]:
    return docker_invocation(command)[0]
