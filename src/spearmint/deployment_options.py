"""Optional deployment settings. The basic archive/command form stays sufficient."""
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from .state import StateError


DEFAULTS = {'runtime': 'auto', 'prepare': '', 'prepare_timeout': 900,
            'readiness': {'mode': 'process', 'timeout': 120, 'stable': 2, 'command': '', 'url': '', 'port': 0},
            'data_paths': ['data']}


def options(value=None):
    value = {} if value is None else value
    if not isinstance(value, dict) or value.keys() - DEFAULTS.keys():
        raise StateError('请核对部署高级设置。')
    result = {**DEFAULTS, **value}
    if result['runtime'] not in {'auto', 'none', 'python'}:
        raise StateError('请选择自动环境、现有环境或 Python 虚拟环境。')
    if not isinstance(result['prepare'], str) or len(result['prepare'].encode()) > 8192 or '\0' in result['prepare']:
        raise StateError('准备命令最多 8 KiB。')
    if type(result['prepare_timeout']) is not int or not 10 <= result['prepare_timeout'] <= 3600:
        raise StateError('依赖准备超时需在 10 至 3600 秒之间。')
    ready = result['readiness']
    if not isinstance(ready, dict) or ready.keys() - DEFAULTS['readiness'].keys():
        raise StateError('请核对就绪检查设置。')
    ready = {**DEFAULTS['readiness'], **ready}
    if (ready['mode'] not in {'process', 'command', 'http', 'tcp'} or type(ready['timeout']) is not int
            or not 2 <= ready['timeout'] <= 3600 or type(ready['stable']) is not int
            or not 1 <= ready['stable'] <= min(30, ready['timeout'])):
        raise StateError('请选择就绪方式、等待时间和稳定时间。')
    if not isinstance(ready['command'], str) or len(ready['command'].encode()) > 4096 or '\0' in ready['command']:
        raise StateError('就绪检查命令最多 4 KiB。')
    if ready['mode'] == 'command' and not ready['command'].strip():
        raise StateError('请填写就绪检查命令。')
    if ready['mode'] == 'http':
        parsed = urlsplit(ready['url']) if isinstance(ready['url'], str) else None
        if not parsed or parsed.scheme not in {'http', 'https'} or parsed.hostname not in {'localhost', '127.0.0.1', '::1'}:
            raise StateError('就绪检查使用目标节点本机的 HTTP/HTTPS 地址。')
    if type(ready['port']) is not int or not 0 <= ready['port'] <= 65535 or ready['mode'] == 'tcp' and not ready['port']:
        raise StateError('请填写有效的本机就绪端口。')
    paths = result['data_paths']
    if not isinstance(paths, list) or len(paths) > 24:
        raise StateError('持久化目录最多 24 项。')
    checked = []
    for raw in paths:
        path = PurePosixPath(raw.replace('\\', '/')) if isinstance(raw, str) else None
        if (not path or not path.parts or path.is_absolute() or '..' in path.parts
                or any(':' in part or part.startswith('.') for part in path.parts) or len(raw) > 240):
            raise StateError('持久化目录使用程序包内的相对目录。')
        name = path.as_posix()
        if any(name == old or name.startswith(old + '/') or old.startswith(name + '/') for old in checked):
            raise StateError('持久化目录不能重复或相互嵌套。')
        checked.append(name)
    return {**result, 'readiness': ready, 'data_paths': checked}
