"""Run interactive SSH seeding on the selected, authorized Grove member."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
import json
import logging
import sqlite3
from pathlib import Path
from shlex import join
from subprocess import CalledProcessError, SubprocessError
from tempfile import TemporaryDirectory
from threading import RLock
from time import monotonic, sleep

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from paramiko import SSHException

from . import grove, grove_admission, grove_continuity, grove_quorum_join, grove_voters, mesh_enrollment, seed_admission, seed_packages, seed_ssh, seed_transport
from .peer.credentials import NODE_ID, RANDOM_ID
from .peer.grove_service_admin import require_admin_identity
from .peer.pairing import configured
from .peer.protocol import PeerError
from .state import StateError, audit
from . import host_service_access
from .host import HostError


METHOD = 'grove.seed.wizard.v2'
logger = logging.getLogger(__name__)
WAITING = {'host-check', 'ssh-login', 'package', 'reading', 'installing', 'admitting'}
LINUX_LOCATION = r'''
set -eu
umask 077
program=$1
state=$2
default=$HOME/.local/opt/spearmint
[ ! -L "$(dirname -- "$program")" ] && [ ! -L "$program" ] && [ ! -L "$state" ] || exit 2
if [ "$default" != "$program" ]; then
    if [ -L "$default" ]; then
        [ "$(readlink -f -- "$default")" = "$program" ] || exit 2
    else
        [ ! -e "$default" ] || exit 2
        [ ! -L "$program" ] && [ ! -L "$state" ] || exit 2
        mkdir -p -- "$program" "$(dirname -- "$default")"
        ln -s -- "$program" "$default"
    fi
fi
'''
LINUX_SERVICE = r'''
set -eu
uid=$(id -u)
if [ "$(loginctl show-user "$uid" --property=Linger --value)" != yes ]; then
    loginctl enable-linger "$(id -un)"
    [ "$(loginctl show-user "$uid" --property=Linger --value)" = yes ]
fi
'''


class SSHInput(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    username: str = Field(min_length=1, max_length=128)
    secret: str = Field(min_length=1, max_length=10500, repr=False)
    key: bool = False
    fingerprint: str = Field(default='', max_length=60)


@dataclass
class Job:
    owner: tuple[str, str]
    identity: list
    host: str
    port: int
    status: str = 'host-check'
    expire: float = field(default_factory=lambda: monotonic() + 900)
    connection: seed_ssh.Connection | None = None
    login: SSHInput | None = field(default=None, repr=False)
    platform: str | None = None
    origin: str | None = None
    package: seed_packages.SeedArchive | None = None
    current: str | None = None
    directory: dict | None = None
    paths: set[str] = field(default_factory=set)
    install: str | None = None
    state: str | None = None
    node: str | None = None
    error: str | None = None
    failed_stage: str | None = None
    failure_detail: str | None = None
    failure_phase: str | None = None
    failure_exit: int | None = None
    username: str = ''
    host_password: str = field(default='', repr=False)
    voting_requested: bool = False
    voter_job: str | None = None
    voter_status: str | None = None
    voter_reason: str | None = None

    @property
    def actor(self) -> str:
        return self.identity[1]

    @property
    def realm(self) -> str:
        return self.identity[0]

    def view(self):
        return {'status': self.status, 'fingerprint': self.connection.fingerprint if self.connection else None,
                'platform': self.platform, 'package': self.package.metadata if self.package else None,
                'path': self.current, 'directory': self.directory,
                'install': self.install, 'state': self.state, 'origin': self.origin, 'node_id': self.node,
                'error': self.error, 'failed_stage': self.failed_stage, 'failure_detail': self.failure_detail,
                'failure_phase': self.failure_phase, 'failure_exit': self.failure_exit, 'host_services_supported': True,
                'voting_supported': True, 'voting_requested': self.voting_requested, 'voter_job': self.voter_job,
                'voter_status': self.voter_status, 'voter_reason': self.voter_reason}

    def close(self):
        self.login = None
        self.host_password = ''
        if self.connection:
            self.connection.close()
            self.connection = None
        if self.package:
            self.package.close()


class SeedWizard:
    method = METHOD

    def __init__(self, state, remote):
        self.state, self.remote = state, remote
        self.jobs: dict[str, Job] = {}
        self.lock = RLock()
        self.workers = ThreadPoolExecutor(max_workers=4, thread_name_prefix='ssh-seed')

    def authorize(self, pair, identity):
        with self.state.connect(read_only=True) as db:
            db.execute('BEGIN')
            try:
                require_admin_identity(db, self.remote.local_id, pair, identity)
            except PeerError as error:
                if error.code == 'OFFLINE':
                    raise PeerError('SEED_GROVE_STATE', 'The executor is waiting for a current Grove directory') from error
                raise
            current = db.execute('SELECT anchor,recovery_proof FROM grove_login_continuity').fetchone()
            if current is None:
                raise PeerError('SEED_GROVE_STATE', 'The executor is waiting for its Grove quorum authorization')
            realm = db.execute('SELECT * FROM grove_realm WHERE id=?', (identity[0],)).fetchone()
            try:
                kind = 'login-continuity' if current['recovery_proof'] is None else 'login-recovery'
                directory = grove.directory_data(json.loads(realm['manifest']), grove.realm_data(realm), allow_expired=True)
                return grove_voters.extend(db, grove_continuity.snapshot_authorization(realm, directory, json.loads(current['anchor']), kind))
            except (KeyError, ValueError, TypeError, PeerError) as error:
                raise PeerError('SEED_GROVE_STATE', 'The executor is waiting for its Grove quorum authorization') from error

    async def dispatch(self, pair, params):
        loop = asyncio.get_running_loop()
        value = await self.remote.work(self.receive, pair, params, loop, rpc=pair is not None)
        return value

    def receive(self, pair, params, loop):
        action, identity, owner, job_id = (params.get(key) for key in ('action', 'identity', 'owner', 'job'))
        if (not isinstance(owner, str) or not RANDOM_ID.fullmatch(owner)
                or not isinstance(job_id, str) or not RANDOM_ID.fullmatch(job_id)):
            raise PeerError('INVALID_REQUEST', 'Invalid SSH seed request')
        anchor = self.authorize(pair, identity)
        key = (pair.node_id if pair else self.remote.local_id, owner)
        with self.lock:
            self.reap()
            job = self.jobs.get(job_id)
            if job and (job.owner != key or job.identity != identity):
                raise PeerError('DENIED', 'The seed request belongs to a different session')
            if action == 'start' and job is None:
                if len(self.jobs) >= 32 or sum(item.status not in ('failed', 'joined', 'uncertain') for item in self.jobs.values()) >= 8:
                    raise PeerError('BUSY', 'The seed executor is busy')
                try:
                    info = SSHInput.model_validate(params.get('connection'))
                    host = seed_ssh.hostname(info.host)
                    if info.fingerprint and not seed_ssh.FINGERPRINT.fullmatch(info.fingerprint):
                        raise ValueError
                    if not info.username.isprintable():
                        raise ValueError
                except (ValidationError, ValueError):
                    raise PeerError('INVALID_REQUEST', 'Invalid SSH connection details') from None
                if any(item.host == host and item.port == info.port and item.status in ('installing', 'admitting') for item in self.jobs.values()):
                    raise PeerError('BUSY', 'A job is already installing on this SSH host')
                job = self.jobs[job_id] = Job(key, identity, host, info.port, login=info)
                self.schedule(job, self.probe, loop)
            elif job is None:
                raise PeerError('NOT_FOUND', 'The seed request has expired or the executor restarted')
            elif action == 'verify' and job.status == 'verify-host':
                if params.get('fingerprint') != job.connection.fingerprint:
                    raise PeerError('SEED_HOST_KEY', 'The SSH host fingerprint has changed')
                job.status = 'ssh-login'
                self.schedule(job, self.login, params['fingerprint'], loop)
            elif action == 'directory' and job.status == 'choose':
                path = params.get('path')
                if not isinstance(path, str) or path not in job.paths:
                    raise PeerError('INVALID_REQUEST', 'Choose a directory returned by this SSH connection')
                if job.current != path:
                    job.status, job.error = 'reading', None
                    self.schedule(job, self.browse, path)
            elif action == 'install' and job.status == 'choose':
                voting = params.get('voting', False)
                if type(voting) is not bool:
                    raise PeerError('INVALID_REQUEST', 'Invalid voter membership option')
                if voting and self.remote.voter_service is None:
                    raise PeerError('UNSUPPORTED_METHOD', '请先升级发起节点再申请投票资格。')
                job.voting_requested = voting
                host_services = params.get('host_services', False)
                host_password = params.get('host_password', '')
                if type(host_services) is not bool or not isinstance(host_password, str) or len(host_password) > 1024:
                    raise PeerError('INVALID_REQUEST', 'Invalid host service authorization options')
                if not job.current or job.current != params.get('path') or not job.directory.get('writable'):
                    raise PeerError('INVALID_REQUEST', 'Choose a writable install directory')
                if any(item is not job and item.host == job.host and item.port == job.port and
                       item.status in ('installing', 'admitting') for item in self.jobs.values()):
                    raise PeerError('BUSY', 'A job is already installing on this SSH host')
                job.status, job.error = 'installing', None
                self.schedule(job, self.install, job_id, anchor, loop, pair is not None, host_services, host_password)
            elif action not in {'status', 'start', 'verify', 'directory', 'install'}:
                raise PeerError('INVALID_REQUEST', 'Unknown SSH seed action')
            job.expire = monotonic() + 900
            if job.voter_job:
                with self.state.connect(read_only=True) as db:
                    result = db.execute('SELECT status,reason FROM grove_voter_job WHERE id=?', (job.voter_job,)).fetchone()
                if result:
                    job.voter_status, job.voter_reason = result['status'], result['reason']
            return job.view()

    def reap(self):
        now = monotonic()
        for job_id, job in list(self.jobs.items()):
            if job.expire < now and job.status not in WAITING:
                job.close()
                del self.jobs[job_id]

    def reap_idle(self):
        with self.lock:
            self.reap()

    def shutdown(self):
        self.workers.shutdown(wait=False, cancel_futures=True)
        with self.lock:
            for job in self.jobs.values():
                job.close()

    def admission(self, pair, params):
        return seed_admission.handle(self.state, self.remote.mesh_enrollment_policy, pair, params)

    def schedule(self, job, function, *args):
        def perform():
            try:
                function(job, *args)
            except (PeerError, OSError, SSHException, SubprocessError, ValueError, StateError, TypeError, KeyError) as error:
                with self.lock:
                    job.failed_stage = job.status
                    job.failure_detail = error.detail if isinstance(error, (seed_ssh.WindowsSeedFailure, seed_ssh.SystemSeedFailure)) else (job.failure_detail if isinstance(error, PeerError) and error.code == 'SEED_HOST_AUTHORIZATION' else None)
                    if isinstance(error, seed_ssh.SystemSeedFailure):
                        job.failure_phase = 'account' if error.code == 'SEED_LINUX_ACCOUNT' else 'system'
                    if isinstance(error, SubprocessError):
                        job.failure_phase, job.failure_exit, job.failure_detail = seed_transport.diagnostic(error)
                    if job.status == 'reading' and job.directory is not None:
                        job.status, job.error = 'choose', 'SEED_DIRECTORY'
                        return
                    if not isinstance(error, PeerError):
                        logger.debug('SSH seed failed during %s (%s)', job.status, type(error).__name__)
                    job.error = error.code if isinstance(error, PeerError) else ('SEED_INSTALL' if job.status in ('installing', 'admitting') else 'SEED_SSH')
                    job.status = 'uncertain' if job.node or isinstance(error, seed_transport.UnconfirmedInstall) else 'failed'
                    job.close()
                    try:
                        with self.state.connect(write=True) as db:
                            audit(db, job.actor, job.owner[0], 'seed.wizard.failed', job.node or job.host,
                                  reason=' | '.join(filter(None, [job.error, job.failed_stage, job.failure_detail]))[:2048])
                    except (OSError, StateError, sqlite3.Error):
                        logger.warning('Unable to store the SSH seed failure receipt')
        self.workers.submit(perform)

    def probe(self, job, loop):
        connection = seed_ssh.Connection(job.host, job.port)
        with self.lock:
            job.connection = connection
            fingerprint = job.login.fingerprint
            job.status = 'ssh-login' if fingerprint else 'verify-host'
        if fingerprint:
            self.login(job, fingerprint, loop)

    def login(self, job, fingerprint, loop):
        login, job.login = job.login, None
        job.connection.login(fingerprint, login.username, login.secret, login.key)
        job.username = login.username
        job.host_password = login.secret if not login.key else ''
        del login
        platform, home = job.connection.system()
        if platform.startswith('windows'):
            job.host_password = ''
        with self.lock:
            job.platform, job.status = platform, 'package'
        future = asyncio.run_coroutine_threadsafe(self.remote.grove_updates.seed_package(platform), loop)
        try:
            package = future.result(timeout=700)
        except TimeoutError as error:
            future.cancel()
            raise PeerError('SEED_PACKAGE_FETCH', 'Timed out acquiring the native deployment package') from error
        except PeerError as error:
            if error.code != 'SEED_PACKAGE_RELEASE':
                raise
            try:
                package = seed_packages.acquire_local(self.state, platform)
            except PeerError:
                raise error from None
        host = f'[{job.host}]' if ':' in job.host else job.host
        start = '' if platform.startswith('windows') else home
        with self.lock:
            job.package = package
            job.origin = grove.origin(f'https://{host}:8765')
            job.paths = {start, '' if platform.startswith('windows') else '/'}
        if platform == 'windows-amd64':
            try:
                job.connection.prepare_windows(package)
            except (OSError, SSHException, SubprocessError) as error:
                raise PeerError('SEED_WINDOWS_STAGING', 'The Windows package could not be staged over SSH') from error
        with self.lock:
            job.status = 'reading'
        self.browse(job, start)

    def browse(self, job, path):
        path_class = seed_ssh.path_type(job.platform)
        if path and (not path_class(path).is_absolute() or not path.isprintable() or len(path) > 420):
            raise PeerError('SEED_DIRECTORY', 'Invalid install directory')
        data = job.connection.directory(job.platform, path)
        parent = str(path_class(path).parent) if path else None
        if parent == path:
            parent = '' if job.platform.startswith('windows') else None
        items = [item for item in data['items'] if isinstance(item['path'], str) and len(item['path']) <= 420
                 and item['path'].isprintable() and path_class(item['path']).is_absolute()]
        writable = False
        if path:
            if job.platform == 'windows-amd64':
                writable = data.get('writable') is True
            else:
                try:
                    job.connection.writable(job.platform, path)
                    writable = True
                except (SubprocessError, OSError, SSHException):
                    pass
            writable = writable and (data['free'] is None or data['free'] >= job.package.metadata['size'] * 4)
        location = path_class(path) / 'Spearmint' if path else None
        with self.lock:
            job.current = path
            job.paths = {item['path'] for item in items} | {p for p in (path, parent, '' if job.platform.startswith('windows') else '/') if p is not None}
            job.directory = {'items': sorted(items, key=lambda item: item['name'].casefold()), 'parent': parent,
                             'writable': writable, 'free': data['free'], 'truncated': data['truncated']}
            job.install = str(location / 'programs') if location else None
            job.state = str(location / 'state') if location else None
            job.status, job.error = 'choose', None

    def audit(self, job, job_id, event):
        with self.state.connect(write=True) as db:
            audit(db, job.actor, job.owner[0], 'seed.wizard.' + event, job.node or job_id)

    async def voters(self, nodes, params):
        async def request(node):
            try:
                if node == self.remote.local_id:
                    result = await self.remote.work(self.admission, None, params)
                else:
                    result = await self.remote.call(node, seed_admission.METHOD, params, diagnostic=True)
                return node, result
            except (PeerError, TimeoutError):
                return node, {}
        return dict(await asyncio.gather(*(request(node) for node in nodes)))

    def install(self, job, job_id, anchor, loop, delegated, host_services=False, host_password=''):
        def voters(params):
            future = asyncio.run_coroutine_threadsafe(self.voters(anchor['voters'], {**params, 'identity': job.identity}), loop)
            return future.result(timeout=25)

        invitations = voters({'action': 'invitation'})
        codes = [reply['code'] for reply in invitations.values() if 'code' in reply]
        if len(codes) <= len(anchor['voters']) // 2:
            raise PeerError('SEED_QUORUM', 'A Grove majority could not authorize this deployment')
        code = codes[0]
        realm, envelope, invitation, policy = grove_quorum_join.read_invitation(code)
        if anchor != invitation or realm['id'] != job.realm:
            raise PeerError('SEED_QUORUM', 'The deployment Grove authorization has changed')
        requester = None
        if delegated:
            with self.state.connect(read_only=True) as db:
                requester = configured(db, job.owner[0])
            if requester is None:
                raise PeerError('DENIED', 'The delegation source is no longer paired')
        self.authorize(requester, job.identity)
        windows = job.platform == 'windows-amd64'
        path = seed_ssh.path_type(job.platform)(job.install)
        if not windows:
            job.connection.prepare_linux(job.install, job.realm)
            if getattr(job.connection, 'linux_user', None):
                job.username = job.connection.linux_user
            if host_services:
                if job.package.metadata.get('host_services') != 1:
                    raise PeerError('SEED_HOST_PACKAGE', '请使用已发布且支持主机服务管理的部署包，再启用此安装选项。')
                try:
                    host_service_access.ssh_enable(job.connection, job.username, host_password or job.host_password)
                except (HostError, CalledProcessError, ValueError) as error:
                    if isinstance(error, HostError):
                        job.failure_detail = str(error)[:1500]
                    raise PeerError('SEED_HOST_AUTHORIZATION', '未能启用节点的主机服务管理。请核对 SSH 账号的 sudo 权限和管理员密码。') from error
                finally:
                    job.host_password = ''
                    host_password = ''
            else:
                job.host_password = ''
            job.connection.writable(job.platform, str(path.parent) if getattr(job.connection, 'linux_root', False) else job.current)
            try:
                job.connection.answer(join(['sh', '-c', LINUX_SERVICE]))
            except CalledProcessError:
                raise PeerError('SEED_SERVICE', 'The SSH account cannot enable its systemd user service at boot') from None
            job.connection.answer(join(['sh', '-c', LINUX_LOCATION, 'seed', job.install, job.state]))
            executable = path / 'current' / 'spearmint'
        self.audit(job, job_id, 'accepted')
        if windows:
            result = job.connection.windows_request('install', {
                'programs': job.install, 'state': job.state, 'origin': job.origin, 'port': 8765,
                'realm': realm, 'commit': job.package.metadata['commit'],
            }, timeout=105)
            node = result.get('node_id')
        else:
            with TemporaryDirectory(prefix='.seed-wizard-', dir=self.state.directory) as work:
                receipt = seed_transport.install(job.package.path, Path(work), host=job.host, target=job.platform,
                                                 digest=job.package.metadata['sha256'], invitation_data=grove.encoded(realm),
                                                 origin=job.origin, port=8765, windows={}, quiet=True,
                                                 runner=job.connection.run, linux_state=job.state, linux_host_services=host_services)
            node = receipt.node_id if receipt else None
        if not isinstance(node, str) or not NODE_ID.fullmatch(node):
            raise PeerError('SEED_INSTALL', 'The installer did not report the new Node ID')
        with self.lock:
            job.node, job.status = node, 'admitting'
        self.audit(job, job_id, 'started')

        def bootstrap(action, **payload):
            if windows:
                answer = job.connection.windows_request('enroll', {
                    'state': job.state, 'origin': job.origin, 'action': action, 'payload': payload,
                })
            else:
                arguments = [str(executable), '--state-dir', job.state, '--origin', job.origin, 'seed-enrollment', action]
                answer = json.loads(job.connection.answer(join(arguments), grove.encoded(payload) if payload else b'').decode('utf-8-sig'))
            if answer.get('node_id') != job.node:
                raise PeerError('SEED_IDENTITY', 'Installed node identity changed during enrollment')
            return answer

        response = bootstrap('request', invitation=code)
        if response.get('realm') != job.realm:
            proof = response['request']
            data = mesh_enrollment.request_data(policy, proof)
            if (data['node_id'], data['origin']) != (job.node, job.origin):
                raise PeerError('SEED_IDENTITY', 'SSH bootstrap does not match the newly installed node')
            digest = grove_continuity.anchor_digest(envelope)
            certificate = []
            replies = voters({'action': 'vote', 'request': proof})
            for node, reply in replies.items():
                try:
                    ballot = reply['ballot']
                    if grove_admission.validate_ballot(ballot, anchor, digest) == (node, job.node, job.origin):
                        certificate.append(ballot)
                except (KeyError, PeerError):
                    continue
            if len(certificate) <= len(anchor['voters']) // 2:
                raise PeerError('SEED_QUORUM', 'The installed node is waiting for Grove majority approval')
            replies = voters({'action': 'commit', 'request': proof, 'certificate': certificate})
            if sum(reply.get('admitted') is True for reply in replies.values()) <= len(anchor['voters']) // 2:
                raise PeerError('SEED_QUORUM', 'The installed node is waiting for voters to record admission')
            bootstrap('finish', invitation=code, certificate=certificate)
            deadline = monotonic() + 105
            while monotonic() < deadline:
                if bootstrap('status').get('realm') == job.realm:
                    break
                sleep(3)
            else:
                raise PeerError('SEED_QUORUM', 'The installed node is waiting to synchronize Grove membership')
        self.audit(job, job_id, 'joined')
        if job.voting_requested:
            job.voter_job = self.remote.voter_service.enqueue(job.node, True, job.identity, job_id)
            job.voter_status = 'pending'
        with self.lock:
            job.close()
            job.status = 'joined'
