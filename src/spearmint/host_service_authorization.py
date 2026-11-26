"""Authorize node host-service access from the Grove page over local SSH."""
from base64 import b64decode, b64encode
from dataclasses import dataclass, field
from hashlib import sha256
from hmac import compare_digest
import stat
from subprocess import SubprocessError
import sys
from pathlib import Path
from typing import Literal
from threading import Event, RLock, Thread
from time import monotonic

from paramiko import SSHException
from pydantic import BaseModel, ConfigDict, Field

from . import docker_access, host_service_access, seed_ssh
from .host import HostError
from .peer.protocol import PeerError
from .state import audit


def trusted_host_key(observed: str) -> str:
    for path in Path('/etc/ssh').glob('ssh_host_*_key.pub'):
        try:
            valid = path.lstat()
            if not stat.S_ISREG(valid.st_mode) or valid.st_uid != 0 or valid.st_mode & 0o022 or valid.st_size > 8192:
                continue
            fields = path.read_bytes().split(None, 2)
            fingerprint = 'SHA256:' + b64encode(sha256(b64decode(fields[1], validate=True)).digest()).decode().rstrip('=')
            if compare_digest(observed, fingerprint):
                return fingerprint
        except (IndexError, OSError, ValueError):
            continue
    raise PeerError('HOST_SSH_HOST_KEY', '本机 SSH 证书与系统信任的主机密钥不符。')


class Authorization(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    job: str = Field(pattern=r'^[a-f0-9]{32}$')
    username: str = Field(min_length=1, max_length=128)
    secret: str = Field(min_length=1, max_length=10500, repr=False)
    key: bool = False
    port: int = Field(default=22, ge=1, le=65535)
    sudo_password: str = Field(default='', max_length=1024, repr=False)
    scope: Literal['systemd', 'docker'] = 'systemd'


class StatusRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    job: str = Field(pattern=r'^[a-f0-9]{32}$')


@dataclass
class Job:
    id: str
    owner: str
    status: str = 'connecting'
    error: str | None = None
    expires: float = field(default_factory=lambda: monotonic() + 900)
    scope: str = 'systemd'

    def view(self):
        return {'job': self.id, 'status': self.status, 'error': self.error, 'scope': self.scope}


class HostServiceAuthorization:
    def __init__(self, state, docker_socket: Path | None = None):
        self.state = state
        self.docker_socket = docker_socket
        self.lock = RLock()
        self.jobs: dict[str, Job] = {}
        self.worker: Thread | None = None
        self.stopping = Event()

    def enabled(self, scope):
        if scope == 'docker':
            return self.docker_socket is not None and docker_access.available(self.docker_socket)
        return host_service_access.available()

    def capabilities(self, scope='systemd'):
        supported = sys.platform == 'linux'
        return {'supported': supported, 'enabled': supported and self.enabled(scope), 'scope': scope,
                'account': host_service_access.account_name() if supported else None,
                'transport': 'node-local-ssh', 'port': 22}

    def start(self, actor, identity, body: Authorization):
        if sys.platform != 'linux':
            raise PeerError('NOT_FOUND', '此节点不需要 Linux 主机服务授权。')
        with self.lock:
            self.jobs = {key: value for key, value in self.jobs.items() if value.expires > monotonic()}
            if existing := self.jobs.get(body.job):
                if existing.owner != identity['actor'] or existing.scope != body.scope:
                    raise PeerError('CONFLICT', '此授权任务属于另一位管理员。')
                return existing.view()
            if self.stopping.is_set() or self.worker and self.worker.is_alive():
                raise PeerError('BUSY', '此节点正在处理主机授权，请等待当前任务完成。')
            job = Job(body.job, identity['actor'], scope=body.scope)
            with self.state.connect(write=True) as db:
                actor.require(db)
                audit(db, identity['actor'], identity['source'], self.event(body.scope, 'authorization_requested'), job.id)
            self.jobs[job.id] = job
            self.worker = Thread(target=self.run, args=(job, actor, identity, body), name='host-authorization', daemon=True)
            self.worker.start()
            return job.view()

    def status(self, identity, body: StatusRequest):
        with self.lock:
            job = self.jobs.get(body.job)
            if job is None or job.expires <= monotonic():
                raise PeerError('NOT_FOUND', '授权任务记录已过期。请重新检查节点授权状态。')
            if job.owner != identity['actor']:
                raise PeerError('DENIED', '此授权任务属于另一位管理员。')
            return job.view()

    def change(self, job, **values):
        with self.lock:
            for key, value in values.items():
                setattr(job, key, value)

    @staticmethod
    def event(scope, action):
        return ('docker_access.' if scope == 'docker' else 'host_services.') + action

    def run(self, job, actor, identity, body):
        connection = None
        error = None
        try:
            # SSH is opened by the owning node to itself. No public address or
            # inbound route from the user's browser/development PC is needed.
            if not self.enabled(body.scope):
                connection = seed_ssh.Connection('127.0.0.1', body.port)
                self.change(job, status='authenticating')
                connection.login(trusted_host_key(connection.fingerprint), body.username, body.secret, body.key)
                connection.system()
                with self.state.connect(read_only=True) as db:
                    actor.require(db)
                if self.stopping.is_set():
                    raise PeerError('HOST_AUTH_INTERRUPTED', 'Panel is stopping')
                self.change(job, status='authorizing')
                with self.state.lock('maintenance.lock', exclusive_now=True):
                    password = body.sudo_password or ('' if body.key else body.secret)
                    if body.scope == 'docker':
                        docker_access.ssh_enable(connection, host_service_access.account_name(), password,
                                                 configured=self.docker_socket)
                    else:
                        host_service_access.ssh_enable(connection, host_service_access.account_name(), password)
                if not self.enabled(body.scope):
                    raise HostError('Host helper did not become available')
        except PeerError as failure:
            error = {'SEED_SSH_AUTH': 'HOST_SSH_AUTH', 'SEED_HOST_KEY': 'HOST_SSH_CONNECTION'}.get(failure.code, failure.code)
        except (OSError, SSHException):
            error = 'HOST_SSH_CONNECTION'
        except (HostError, SubprocessError):
            error = 'HOST_ADMIN_AUTH'
        except Exception:
            # Only a stable reason code is returned/audited. SSH exceptions and
            # command output must not accidentally expose supplied credentials.
            error = 'HOST_AUTH_FAILED'
        finally:
            body.secret = ''
            body.sudo_password = ''
            if connection is not None:
                try:
                    connection.close()
                except (OSError, SSHException):
                    pass
        # Host configuration can have succeeded even if its final SSH reply was
        # lost. Verify locally before deciding whether a retry is necessary.
        if error and self.enabled(body.scope):
            error = None
        try:
            with self.state.connect(write=True) as db:
                audit(db, identity['actor'], identity['source'],
                      self.event(body.scope, 'authorization_failed' if error else 'authorized'), job.id, reason=error)
        finally:
            self.change(job, status='failed' if error else 'succeeded', error=error)

    def shutdown(self):
        self.stopping.set()
        if self.worker:
            self.worker.join(timeout=85)
