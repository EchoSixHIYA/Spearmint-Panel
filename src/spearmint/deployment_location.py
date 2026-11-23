"""Code ownership and directories for Spearmint-created applications."""
import json
from pathlib import Path

from .onboarding import write_private
from .state import StateError

MARKER = '.spearmint-application.json'


def owns_code(service):
    deployment = service.spec.get('deployment', {})
    return bool(service.managed and not service.existing_system_service and
                (deployment.get('source') == 'managed' or deployment.get('kind') in {'package', 'docker'}))


def location(value, default):
    if not isinstance(value, str) or len(value) > 1024 or '\0' in value:
        raise StateError('请填写有效的部署目录。')
    path = Path(value.strip()).expanduser() if value.strip() else default
    if not path.is_absolute():
        raise StateError('部署目录使用目标节点上的绝对路径。')
    return path.resolve()


def claim(path, default, app, node, *, create=False):
    """A custom location must be empty or already belong to this application."""
    expected = {'app': app, 'node': node}
    marker = path / MARKER
    if marker.exists():
        if json.loads(marker.read_text(encoding='utf-8')) != expected:
            raise StateError('部署目录已由另一个服务使用。')
    elif path != default.resolve() and path.exists() and (not path.is_dir() or any(path.iterdir())):
        raise StateError('部署目录已有文件，请选择空目录，或使用“登记已有代码”。')
    if create:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not marker.exists():
            write_private(marker, json.dumps(expected).encode())
