"""Durable application deployment jobs executed by the owning Grove node."""
from contextlib import suppress
from collections import deque
from dataclasses import asdict, replace
from hashlib import sha256
import json
import logging
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import os
import socket
import sys
from urllib.request import ProxyHandler, Request, build_opener
from threading import Event, RLock, Thread
import time

from .catalog import DISPLAY_FIELDS, Service, get_service, list_services, register, require_idle, service_name
from .drivers import CONTAINER_ID, Observation
from .host import HostError, local_docker_command
from .platforms import WINDOWS
import psutil
from .onboarding import write_private
from .peer.grove_service_admin import GroveServiceAdmin
from .peer.projection import publish
from .peer.protocol import PeerError, parse_b64
from .peer.service_setup import LocalAdmin, acting_as
from .service_artifacts import MAX_UPLOAD, docker_arguments, docker_invocation, unpack
from .service_command import command_spec
from .deployment_options import options as deployment_options
from . import deployment_runtime
from .deployment_location import MARKER, claim, location, owns_code
from .state import StateError, audit

logger = logging.getLogger(__name__)
ID = re.compile(r'^[a-f0-9]{32}$')
FINAL = {'succeeded', 'failed', 'cancelled'}
CHUNK = 8192
BULK_CHUNK = 256 * 1024


def snapshot(service):
    return asdict(service) if service is not None else None


class ServiceDeployments:
    method = 'grove.deploy.v2'
    methods = {'grove.deploy.v1', method, 'grove.deploy.upload'}
    upload_method = 'grove.deploy.upload'

    def __init__(self, state, node_id, controller, docker_socket):
        self.state, self.node_id, self.controller = state, node_id, controller
        self.docker_socket = docker_socket
        self.root = state.directory / 'service-deployments'
        self.apps = state.directory / 'service-apps'
        self.lock = RLock()
        self.workers = {}
        self.cleaning = False
        self.stopping = Event()
        self.cache = state.directory / 'service-artifacts'
        self.cache.mkdir(mode=0o700, exist_ok=True)
        self.root.mkdir(mode=0o700, exist_ok=True)
        self.apps.mkdir(mode=0o700, exist_ok=True)

    def dispatch(self, pair, params):
        if params.keys() != {'identity', 'action', 'body'}:
            raise PeerError('INVALID_REQUEST', 'Invalid deployment request')
        actor = GroveServiceAdmin.from_wire(self.node_id, pair, params['identity'])
        return self.request(actor, params['action'], params['body'])

    def path(self, identifier):
        if not isinstance(identifier, str) or not ID.fullmatch(identifier):
            raise PeerError('INVALID_REQUEST', 'Invalid deployment ID')
        return self.root / (identifier + '.json')

    def load(self, identifier):
        try:
            return json.loads(self.path(identifier).read_text(encoding='utf-8'))
        except FileNotFoundError as error:
            raise PeerError('NOT_FOUND', '部署任务不存在。') from error

    def save(self, job, **changes):
        with self.lock:
            job.update(changes, updated_at=time.time())
            write_private(self.path(job['id']), json.dumps(job, ensure_ascii=False).encode('utf-8'))

    def view(self, job):
        return {key: job.get(key) for key in ('id', 'kind', 'name', 'command', 'service_id', 'status', 'phase',
                'size', 'offset', 'filename', 'sha256', 'error', 'log', 'created_at', 'updated_at', 'rolled_back',
                'options', 'received_bytes', 'upload_chunk', 'expected_sha256', 'readiness_result', 'directory')} | {
                    'received': job.get('received', []), 'options': job.get('options', deployment_options())}

    def service(self, identifier):
        with self.state.connect(read_only=True) as db:
            service = get_service(db, identifier)
        if service is None:
            raise PeerError('NOT_FOUND', '服务已取消登记。')
        return service

    def manifest(self, app):
        path = self.apps / app / 'manifest.json'
        return json.loads(path.read_text(encoding='utf-8')) if path.exists() else {}

    def request(self, actor, action, body):
        with self.state.connect(read_only=True) as db:
            actor.require(db)
        if not isinstance(body, dict):
            raise PeerError('INVALID_REQUEST', 'Invalid deployment body')
        try:
            with self.lock:
                if action == 'capabilities' and not body:
                    return {'deployment': 2, 'max_upload': MAX_UPLOAD, 'chunk': BULK_CHUNK, 'window': 2,
                            'bulk_upload': 1, 'options': 1, 'code_ownership': 1, 'managed_directory': 1,
                            'docker_authorization': 1 if sys.platform == 'linux' else 0,
                            'default_directory': str(self.apps), 'formats': ['zip', 'tar', 'tar.gz']}
                if action == 'list' and not body:
                    jobs = [json.loads(path.read_text(encoding='utf-8')) for path in self.root.glob('*.json')]
                    return {'jobs': [{k: v for k, v in self.view(job).items() if k not in {'command', 'log', 'options', 'received'}}
                                     for job in sorted(jobs, key=lambda item: item['created_at'], reverse=True)[:24]]}
                if action == 'history' and body.keys() == {'service_id'}:
                    service = self.service(body['service_id'])
                    app = service.spec.get('deployment', {}).get('app')
                    jobs = [json.loads(path.read_text(encoding='utf-8')) for path in self.root.glob('*.json')]
                    jobs = sorted((job for job in jobs if job.get('service_id') == service.id), key=lambda job: job['created_at'], reverse=True)
                    return {'jobs': [{key: value for key, value in self.view(job).items() if key not in {'command', 'log', 'options', 'received'}} for job in jobs[:12]],
                            'can_update': owns_code(service),
                            'options': service.spec.get('deployment_options', deployment_options()),
                            'can_rollback': bool(app and self.manifest(app).get('previous'))}
                if action == 'begin':
                    return self.begin(actor, body)
                job = self.load(body.get('job'))
                if action == 'status' and body.keys() == {'job'}:
                    return self.view(job)
                if action == 'write' and body.keys() == {'job', 'offset', 'data', 'sha256'}:
                    return self.write_bytes(actor, body['job'], body['offset'], parse_b64(body['data'], BULK_CHUNK), body['sha256'])
                if action == 'write' and body.keys() == {'job', 'offset', 'data'}:
                    if job.get('expected_sha256'):
                        raise PeerError('CONFLICT', '请使用分块传输入口继续此任务。')
                    if job['status'] != 'uploading' or type(body['offset']) is not int:
                        raise PeerError('CONFLICT', '任务当前不接受文件上传。')
                    data = parse_b64(body['data'], CHUNK)
                    upload = self.root / (job['id'] + '.upload')
                    offset = body['offset']
                    accepted = upload.stat().st_size if upload.exists() else 0
                    if offset < accepted:
                        with upload.open('rb') as stream:
                            stream.seek(max(0, offset))
                            if offset < 0 or stream.read(len(data)) != data or offset + len(data) > accepted:
                                raise PeerError('CONFLICT', '上传片段与已保存的文件不一致。')
                    elif offset == accepted and accepted + len(data) <= job['size']:
                        if shutil.disk_usage(self.root).free < len(data) + 16 * 1024 * 1024:
                            raise StateError('目标节点磁盘空间不足。')
                        with upload.open('ab') as stream:
                            stream.write(data)
                        accepted += len(data)
                    else:
                        raise PeerError('CONFLICT', '文件上传偏移量已变化，请重新查询任务。')
                    self.save(job, offset=accepted)
                    return self.view(job)
                if action == 'cancel' and body.keys() == {'job'}:
                    if job['status'] not in {'uploading', 'ready', 'cancelled'}:
                        raise PeerError('CONFLICT', '部署已开始，请等待回执后更新或回滚。')
                    self.save(job, status='cancelled', phase='已取消')
                    (self.root / (job['id'] + '.upload')).unlink(missing_ok=True)
                    return self.view(job)
                if action == 'launch' and body.keys() == {'job'}:
                    if job['status'] not in {'uploading', 'ready'}:
                        return self.view(job)
                    if self.stopping.is_set() or self.cleaning or any(thread.is_alive() for thread in self.workers.values()):
                        raise PeerError('BUSY', '目标节点正在部署其他服务，请稍后重试。')
                    if job['size'] and job.get('received_bytes', job['offset']) != job['size']:
                        raise PeerError('CONFLICT', '服务包尚未上传完整。')
                    self.save(job, status='deploying', phase='准备部署')
                    thread = Thread(target=self.run, args=(job, actor), name='service-deployment', daemon=True)
                    self.workers[job['id']] = thread
                    thread.start()
                    return self.view(job)
        except (StateError, HostError, OSError, ValueError, sqlite3.Error) as error:
            raise PeerError('DEPLOY_FAILED', str(error)[:1500]) from error
        raise PeerError('INVALID_REQUEST', 'Unknown deployment action')

    def begin(self, actor, body):
        expected = {'job', 'kind', 'name', 'command', 'service_id', 'version', 'filename', 'size'}
        if not expected <= body.keys() or body.keys() - expected - {'options', 'sha256', 'directory'} or not isinstance(body['kind'], str) or body['kind'] not in {'package', 'command', 'docker', 'rollback'} or not isinstance(body['name'], str):
            raise PeerError('INVALID_REQUEST', 'Invalid deployment configuration')
        identifier = body['job']
        path = self.path(identifier)
        identity = acting_as(actor)
        config = {key: body[key] for key in body.keys() - {'job'}}
        if path.exists():
            job = self.load(identifier)
            if job['request'] != config or job['actor'] != identity['actor']:
                raise PeerError('CONFLICT', '任务标识已被另一份部署配置使用。')
            return self.view(job)
        if sum(json.loads(path.read_text(encoding='utf-8'))['status'] not in FINAL for path in self.root.glob('*.json')) >= 8:
            raise PeerError('BUSY', '请先完成或取消已有部署任务。')
        size, filename, command = body['size'], body['filename'], body['command']
        if (type(size) is not int or not 0 <= size <= MAX_UPLOAD or not isinstance(filename, str)
                or len(filename) > 255 or not isinstance(command, str) or len(command.encode('utf-8')) > 8192 or '\0' in command):
            raise StateError('请核对服务包和启动命令，单个压缩包最多 1 GiB。')
        if body['kind'] != 'rollback' and not command.strip():
            raise StateError('请填写启动命令。')
        if body['kind'] == 'package' and (not size or not filename.lower().endswith(('.zip', '.tar', '.tar.gz', '.tgz', '.tar.xz', '.tar.bz2'))):
            raise StateError('请选择非空的 ZIP 或 TAR 服务包。')
        if body['kind'] != 'package' and (size or filename):
            raise StateError('此部署方式不接收服务包。')
        if body['kind'] == 'docker':
            docker_arguments(command)
        service = None
        if body['service_id'] is not None:
            if not isinstance(body['service_id'], str) or not ID.fullmatch(body['service_id']):
                raise StateError('无效的服务标识。')
            service = self.service(body['service_id'])
            if type(body['version']) is not int or service.version != body['version']:
                raise StateError('服务配置已变化，请刷新后重新部署。')
            if not owns_code(service):
                raise StateError('此服务登记的是已有代码，仅托管启停和日志；请自行更新原有代码。')
            if body['kind'] != 'rollback' and (service.driver == 'docker') != (body['kind'] == 'docker'):
                raise StateError('更新时请保留原来的服务运行类型。')
        elif body['kind'] == 'rollback':
            raise StateError('请先选择要回滚的服务。')
        name = service.name if service else service_name(body['name'] or '新服务 ' + identifier[:8])
        if service is None:
            with self.state.connect(read_only=True) as db:
                if db.execute('SELECT 1 FROM service WHERE name=?', (name,)).fetchone():
                    raise StateError('服务名称已登记，请从服务详情更新它。')
        app = service.spec.get('deployment', {}).get('app') if service else None
        settings = deployment_options(body.get('options', service.spec.get('deployment_options') if service else None))
        digest = body.get('sha256')
        if digest is not None and (not isinstance(digest, str) or re.fullmatch('[a-f0-9]{64}', digest) is None):
            raise StateError('请核对程序包摘要。')
        app = app or identifier
        default = self.apps / app
        previous_directory = service.spec.get('deployment', {}).get('directory', str(default)) if service else str(default)
        selected = location(body.get('directory', previous_directory), default)
        if service is None and selected != default.resolve() and (selected / MARKER).is_file():
            owner = json.loads((selected / MARKER).read_text(encoding='utf-8'))
            previous_app = owner.get('app')
            if owner.get('node') == self.node_id and isinstance(previous_app, str) and ID.fullmatch(previous_app):
                attempts = [json.loads(path.read_text(encoding='utf-8')) for path in self.root.glob('*.json')]
                attempts = [entry for entry in attempts if entry.get('app') == previous_app]
                occupied = any(entry.spec.get('deployment', {}).get('app') == previous_app for entry in list_services(self.state))
                if attempts and all(entry['status'] in FINAL for entry in attempts) and not occupied and not self.manifest(previous_app).get('current'):
                    # Reuse a failed first deployment's data, without claiming a registered application.
                    app, default = previous_app, self.apps / previous_app
        if service and selected != Path(previous_directory).resolve():
            raise StateError('更新沿用原部署目录，请勿更改服务的位置。')
        if body['kind'] == 'docker' and selected != default.resolve():
            raise StateError('Docker 数据位置请在启动命令中使用卷或绑定目录指定。')
        claim(selected, default, app, self.node_id)
        if body['kind'] == 'rollback' and not self.manifest(app).get('previous'):
            raise StateError('此服务没有可回滚的上一版。')
        if shutil.disk_usage(self.root).free < size + 32 * 1024 * 1024:
            raise StateError('目标节点没有足够空间接收服务包。')
        job = {'id': identifier, 'request': config, 'kind': body['kind'], 'name': name, 'command': command,
               'service_id': service.id if service else None, 'version': service.version if service else None,
               'app': app, 'filename': filename, 'size': size, 'offset': 0, 'status': 'uploading' if size else 'ready',
               'phase': '上传服务包' if size else '等待部署', 'actor': identity['actor'], 'source': identity['source'],
               'created_at': time.time(), 'log': '', 'error': None, 'before': None, 'after': None, 'directory': str(selected)}
        job.update(options=settings, expected_sha256=digest, upload_chunk=BULK_CHUNK if digest else CHUNK)
        if digest:
            job.update(received=[], received_bytes=0)
            cached = self.cache / (digest + '.archive')
            if size and cached.is_file() and cached.stat().st_size == size:
                destination = self.root / (identifier + '.upload')
                try:
                    os.link(cached, destination)
                except OSError:
                    shutil.copyfile(cached, destination)
                job.update(offset=size, received_bytes=size, received=list(range((size + BULK_CHUNK - 1) // BULK_CHUNK)),
                           status='ready', phase='已复用目标节点缓存')
        self.save(job)
        return self.view(job)

    def write_bytes(self, actor, identifier, offset, data, digest):
        with self.state.connect(read_only=True) as db:
            actor.require(db)
        with self.lock:
            job = self.load(identifier)
            if job['status'] != 'uploading' or type(offset) is not int or offset < 0:
                raise PeerError('CONFLICT', '任务当前不接受文件上传。')
            if (offset % BULK_CHUNK or len(data) != min(BULK_CHUNK, job['size'] - offset)
                    or not data or offset + len(data) > job['size'] or sha256(data).hexdigest() != digest):
                raise PeerError('CONFLICT', '上传片段不完整，请重新传输此片段。')
            path = self.root / (identifier + '.upload')
            received = set(job.get('received', []))
            index = offset // BULK_CHUNK
            if index in received:
                with path.open('rb') as stream:
                    stream.seek(offset)
                    if stream.read(len(data)) != data:
                        raise PeerError('CONFLICT', '续传内容与已上传文件不一致。')
            else:
                if shutil.disk_usage(self.root).free < len(data) + 32 * 1024 * 1024:
                    raise PeerError('DEPLOY_FAILED', '目标节点磁盘空间不足。')
                with path.open('r+b' if path.exists() else 'w+b') as stream:
                    stream.seek(offset)
                    stream.write(data)
                received.add(index)
            contiguous = 0
            while contiguous in received:
                contiguous += 1
            accepted = sum(min(BULK_CHUNK, job['size'] - part * BULK_CHUNK) for part in received)
            self.save(job, received=sorted(received), received_bytes=accepted, offset=min(job['size'], contiguous * BULK_CHUNK))
            return {key: job[key] for key in ('id', 'status', 'offset', 'received_bytes')}

    def note(self, job, phase, log=None):
        self.save(job, phase=phase, log=(job.get('log', '') + ('\n' + log if log else ''))[-12000:])

    def docker(self, job, args):
        argv, env = local_docker_command(self.docker_socket)
        return self.execute(job, [*argv, *args], env=env, timeout=900,
                            interruptible=args[:2] in (['image', 'pull'], ['container', 'create']))

    def execute_script(self, job, command, cwd, env, *, timeout, record=True):
        spec = command_spec(command, str(cwd), 8, None, state=self.state, environment=env)
        return self.execute(job, spec['argv'], cwd=cwd, env=env, timeout=timeout, record=record)

    def execute(self, job, argv, *, env=None, cwd=None, timeout=900, interruptible=True, record=True):
        chunks = deque(maxlen=128)
        output = bytearray()
        # Stream a bounded tail into the durable job instead of buffering all pull output.
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, env={**os.environ, **(env or {}), 'PIP_NO_CACHE_DIR': '1'}, cwd=cwd, start_new_session=not WINDOWS,
            creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP if WINDOWS else 0)
        def read():
            try:
                for data in iter(lambda: process.stdout.read1(8192), b''):
                    chunks.append(data)
            finally:
                process.stdout.close()
        reader = Thread(target=read, name='deployment-docker-output', daemon=True)
        reader.start()
        deadline, last = time.monotonic() + timeout, 0
        previous_log = job.get('log', '')
        try:
            while True:
                while chunks:
                    output.extend(chunks.popleft())
                if len(output) > 12000:
                    del output[:-12000]
                if record and time.monotonic() - last > 1:
                    self.save(job, log=(previous_log + '\n' + output.decode('utf-8', 'replace'))[-12000:])
                    last = time.monotonic()
                if process.poll() is not None and not reader.is_alive() and not chunks:
                    break
                if time.monotonic() >= deadline or interruptible and self.stopping.is_set():
                    raise HostError('准备或检查命令超时，或被面板停机中断。')
                time.sleep(.1)
            text = output.decode('utf-8', 'replace').strip()
            if record:
                self.save(job, log=(previous_log + '\n' + text)[-12000:])
            if process.returncode:
                raise HostError(f'命令退出码 {process.returncode}：' + (text[-1400:] or '命令未能完成操作。'))
            return text
        finally:
            if process.poll() is None:
                with suppress(psutil.NoSuchProcess):
                    parent = psutil.Process(process.pid)
                    for child in reversed(parent.children(recursive=True)):
                        with suppress(psutil.NoSuchProcess):
                            child.kill()
                    parent.kill()
                process.wait(timeout=5)
            reader.join(timeout=2)

    def probe(self, service, ready):
        if ready['mode'] == 'tcp':
            with socket.create_connection(('127.0.0.1', ready['port']), timeout=2):
                return
        if ready['mode'] == 'http':
            with build_opener(ProxyHandler({})).open(Request(ready['url']), timeout=2) as response:
                if not 200 <= response.status < 400:
                    raise HostError(f'HTTP {response.status}')
        if ready['mode'] == 'command':
            probe = {'log': ''}
            if service.driver == 'docker':
                argv, env = local_docker_command(self.docker_socket)
                shell = ['cmd', '/d', '/c'] if service.spec.get('image_os') == 'windows' else ['sh', '-c']
                self.execute(probe, [*argv, 'container', 'exec', service.target, *shell, ready['command']], env=env, timeout=3, record=False)
            else:
                self.execute_script(probe, ready['command'], Path(service.spec['cwd']),
                                    service.spec.get('deployment_environment', {}), timeout=3, record=False)

    def wait_running(self, service, *, restoring=False, job=None):
        driver = self.controller.drivers[service.driver]
        stable = None
        ready = deployment_options(service.spec.get('deployment_options'))['readiness']
        deadline = time.monotonic() + ready['timeout']
        detail, reported = '等待进程运行', 0
        while time.monotonic() < deadline:
            observed = driver.inspect(service)
            if observed.status == 'running' and observed.health not in {'starting', 'unhealthy'}:
                try:
                    self.probe(service, ready)
                    stable = stable or time.monotonic()
                    detail = '检查已通过，确认持续运行'
                    if time.monotonic() - stable >= ready['stable']:
                        self.controller.observe(service)
                        if job is not None:
                            self.save(job, readiness_result={'mode': ready['mode'], 'status': 'ready', 'at': time.time()})
                        return
                except (OSError, HostError, ValueError) as error:
                    stable = None
                    detail = str(error)[-800:]
            else:
                stable = None
                detail = observed.message or ('等待容器健康检查' if observed.health == 'starting' else '等待进程运行')
                if observed.status in {'failed', 'stopped', 'missing'} or observed.health == 'unhealthy':
                    raise HostError(observed.message or '服务启动后退出，请查看应用日志。')
            if job is not None and time.monotonic() - reported >= 2:
                self.save(job, readiness_result={'mode': ready['mode'], 'status': 'waiting', 'detail': detail})
                reported = time.monotonic()
            if restoring:
                time.sleep(.2)
            elif self.stopping.wait(.2):
                raise HostError('面板正在退出，部署已中断。')
        raise HostError(f"就绪检查超时（{ready['timeout']} 秒）：{detail}")

    def rename_container(self, job, target, name):
        actual = self.docker(job, ['container', 'inspect', '--format', '{{.Name}}', target]).splitlines()[-1].lstrip('/')
        if actual != name:
            self.docker(job, ['container', 'rename', target, name])

    def swap(self, job, service, spec, target):
        driver = self.controller.drivers[service.driver]
        if hasattr(driver, 'prepare_change'):
            driver.prepare_change(service)
        with self.state.connect(write=True) as db:
            current = get_service(db, service.id)
            if current is None or current.version != service.version:
                raise StateError('服务登记已变化，停止切换。')
            spec = {**{key: value for key, value in spec.items() if key not in DISPLAY_FIELDS},
                    **{key: current.spec[key] for key in DISPLAY_FIELDS if key in current.spec}}
            db.execute('UPDATE service SET spec=?, target=?, version=version+1 WHERE id=?',
                       (json.dumps(spec, sort_keys=True), target, service.id))
            publish(db, service.id)
        return replace(service, spec=spec, target=target, version=service.version + 1)

    def reserve(self, job, actor, service):
        with self.state.connect(write=True) as db:
            actor.require(db)
            current = require_idle(db, service.id)
            if current.version != service.version:
                raise StateError('服务登记已变化，请重新部署。')
            now = int(time.time())
            db.execute("INSERT INTO operation VALUES (?,?,?,?,?,?,'running',?,?,?)",
                       (job['id'], service.id, job['actor'], job['source'], 'deployment:' + job['id'],
                        'restart' if job['before'] else 'start', '服务部署任务', now, now))
            audit(db, job['actor'], job['source'], 'service.deployment.started', service.id, reason=job['id'])

    def run(self, job, actor):
        service = new_service = None
        reserved = False
        try:
            with self.state.lock('maintenance.lock', exclusive_now=True):
                control = self.apps / job['app']
                app_dir = Path(job.get('directory') or control)
                claim(app_dir, control, job['app'], self.node_id, create=True)
                control.mkdir(mode=0o700, exist_ok=True)
                (app_dir / 'data').mkdir(mode=0o700, exist_ok=True)
                before = self.service(job['service_id']) if job['service_id'] else None
                if before and not owns_code(before):
                    raise StateError('登记已有代码的服务不支持由 Spearmint 更新代码。')
                if before and before.version != job['version']:
                    raise StateError('服务在上传期间已变化，请刷新后重新部署。')
                observed = self.controller.drivers[before.driver].inspect(before) if before else Observation('stopped')
                if observed.status not in {'running', 'stopped', 'failed'}:
                    raise StateError('服务当前状态无法确认，请等待启停操作结束后部署。')
                self.save(job, before=snapshot(before), was_running=observed.status == 'running', old_manifest=self.manifest(job['app']))
                metadata = {'app': job['app'], 'release': job['id'], 'kind': job['kind'], 'source': 'managed', 'directory': str(app_dir)}
                settings = deployment_options(job.get('options'))
                if job['kind'] == 'rollback':
                    desired = self.manifest(job['app'])['previous']
                    spec, target = desired['spec'], desired['target']
                elif job['kind'] in {'package', 'command'}:
                    cwd = before.spec['cwd'] if before and job['kind'] == 'command' else str(app_dir / 'releases' / job['id'])
                    if job['kind'] == 'package':
                        self.note(job, '校验并解压服务包')
                        upload = self.root / (job['id'] + '.upload')
                        digest = sha256()
                        with upload.open('rb') as stream:
                            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                                digest.update(chunk)
                        self.save(job, sha256=digest.hexdigest())
                        if job.get('expected_sha256') and digest.hexdigest() != job['expected_sha256']:
                            raise StateError('服务包完整性校验失败，请重新上传。')
                        metadata['sha256'] = digest.hexdigest()
                        cwd = str(unpack(upload, Path(cwd), job['filename']))
                        cached = self.cache / (digest.hexdigest() + '.archive')
                        if not cached.exists():
                            temporary = cached.with_suffix('.new')
                            shutil.copyfile(upload, temporary)
                            temporary.replace(cached)
                    else:
                        old_options = deployment_options(before.spec.get('deployment_options')) if before else None
                        if before and (settings['prepare'].strip() or any(settings[key] != old_options[key] for key in ('runtime', 'data_paths'))):
                            destination = app_dir / 'releases' / job['id']
                            deployment_runtime.copy_release(cwd, destination, settings['data_paths'])
                            cwd = str(destination)
                        Path(cwd).mkdir(parents=True, exist_ok=True)
                    # External programs remain in their own directories; only managed releases get data links.
                    if Path(cwd).is_relative_to(app_dir / 'releases'):
                        deployment_runtime.data_directories(Path(cwd), app_dir, settings['data_paths'])
                    fresh = not before or job['kind'] == 'package' or cwd != before.spec.get('cwd')
                    environment = deployment_runtime.prepare(self, job, Path(cwd), app_dir, settings, fresh=fresh)
                    spec = command_spec(job['command'], cwd, before.spec['stop_timeout'] if before else 8, None, state=self.state,
                                        environment=environment)
                    spec.update(deployment=metadata, deployment_environment=environment, deployment_options=settings)
                    target = f"spearmint-workload-{before.id}-{job['id'][:8]}.service" if before else ''
                else:
                    arguments, image = docker_invocation(job['command'])
                    self.note(job, '拉取新版镜像')
                    platform = []
                    for index, option in enumerate(arguments):
                        if option.startswith('--platform='):
                            platform = [option]
                            break
                        if option == '--platform':
                            platform = [option, arguments[index + 1]]
                            break
                    try:
                        self.docker(job, ['image', 'pull', *platform, image])
                    except HostError:
                        self.docker(job, ['image', 'inspect', image])
                        self.note(job, '使用目标节点已缓存的镜像')
                    template = '{"Id":{{json .Id}},"Os":{{json .Os}},"Config":{"Volumes":{{json .Config.Volumes}}}}'
                    image_info = json.loads(self.docker(job, ['image', 'inspect', '--format', template, image]))
                    metadata['image_id'] = image_info['Id']
                    arguments = docker_arguments(job['command'], image_override=image_info['Id'])
                    mounts = self.docker(job, ['container', 'inspect', '--format', '{{json .Mounts}}', before.target]) if before else '[]'
                    extra = deployment_runtime.container_data(arguments[:arguments.index(image_info['Id'])], json.loads(mounts), image_info, job['app'])
                    arguments = [*extra, *arguments]
                    spec = {'stop_timeout': before.spec['stop_timeout'] if before else 8,
                            'command': job['command'], 'deployment': metadata, 'deployment_options': settings,
                            'image_os': image_info.get('Os', 'linux')}
                    target = ''
                if before:
                    service = before
                    self.reserve(job, actor, service)
                    reserved = True
                    observed = self.controller.drivers[service.driver].inspect(service)
                    if observed.status not in {'running', 'stopped', 'failed'}:
                        raise StateError('服务状态在准备期间发生变化，请重新核对后部署。')
                    self.save(job, was_running=observed.status == 'running')
                    if service.driver == 'docker':
                        original_name = self.docker(job, ['container', 'inspect', '--format', '{{.Name}}', service.target]).splitlines()[-1].lstrip('/')
                        before = replace(before, spec={**before.spec, 'container_name': original_name})
                        self.save(job, before=snapshot(before), original_name=original_name)
                    self.note(job, '停止旧版本')
                    if observed.status == 'running':
                        self.controller.drivers[service.driver].apply(service, 'stop', observed)
                    if self.controller.drivers[service.driver].inspect(service).status not in {'stopped', 'failed'}:
                        raise HostError('旧服务尚未完全停止，未切换版本。')
                if before and before.driver == 'docker':
                    if job['kind'] in {'docker', 'rollback'}:
                        self.rename_container(job, before.target, 'spmt-backup-' + job['id'])
                        self.save(job, renamed=True)
                if job['kind'] == 'docker':
                    self.note(job, '创建新版容器')
                    cidfile = self.root / (job['id'] + '.cid')
                    self.save(job, creating_container=True)
                    self.docker(job, ['container', 'create', '--pull=never', '--label', 'io.spearmint.deployment=' + job['id'],
                                      '--cidfile', str(cidfile), *arguments])
                    target = cidfile.read_text(encoding='utf-8').strip()
                    if not CONTAINER_ID.fullmatch(target):
                        raise HostError('Docker 未返回有效的容器 ID。')
                    self.save(job, new_container=target)
                    spec['container_name'] = self.docker(job, ['container', 'inspect', '--format', '{{.Name}}', target]).splitlines()[-1].lstrip('/')
                if job['kind'] == 'rollback' and before.driver == 'docker':
                    rollback_name = self.docker(job, ['container', 'inspect', '--format', '{{.Name}}', target]).splitlines()[-1].lstrip('/')
                    self.save(job, rollback_container=target, rollback_container_name=rollback_name)
                    self.rename_container(job, target, spec.get('container_name') or job['original_name'])
                with self.state.connect(read_only=True) as db:
                    actor.require(db)
                if before:
                    self.save(job, planned={'spec': spec, 'target': target})
                    new_service = self.swap(job, service, spec, target)
                else:
                    new_service = register(self.state, 'docker' if job['kind'] == 'docker' else 'process',
                                           job['name'], target, spec, managed=True, **acting_as(actor))
                    self.save(job, service_id=new_service.id)
                    self.reserve(job, actor, new_service)
                    reserved = True
                self.save(job, after=snapshot(new_service))
                self.note(job, '等待应用就绪')
                driver = self.controller.drivers[new_service.driver]
                driver.apply(new_service, 'start', driver.inspect(new_service))
                self.wait_running(new_service, job=job)
                manifest = {'current': snapshot(new_service), 'previous': snapshot(before)}
                write_private(control / 'manifest.json', json.dumps(manifest).encode('utf-8'))
                self.save(job, status='succeeded', phase='部署完成', error=None)
        except Exception as error:
            logger.info('Service deployment %s failed: %s', job['id'], type(error).__name__)
            if new_service:
                with suppress(Exception):
                    logs = self.controller.drivers[new_service.driver].logs(new_service, 10)
                    self.note(job, job['phase'], logs.text[-6000:])
            self.note(job, '恢复上一版' if job.get('before') else '部署失败', str(error)[:1500])
            recovery_error = None
            try:
                self.restore(job)
            except Exception as recovery:
                recovery_error = str(recovery)[:1500]
                logger.exception('Could not restore service deployment %s', job['id'])
            self.save(job, status='failed', phase='恢复失败' if recovery_error else '部署失败',
                      error=str(error)[:1500] + ('；恢复失败：' + recovery_error if recovery_error else ''),
                      rolled_back=bool(job.get('before')) and recovery_error is None)
        finally:
            if reserved:
                with self.state.connect(write=True) as db:
                    db.execute('UPDATE operation SET status=?,message=?,updated_at=? WHERE id=?',
                               ('succeeded' if job['status'] == 'succeeded' else 'failed',
                                '部署完成' if job['status'] == 'succeeded' else job.get('error'), int(time.time()), job['id']))
                    audit(db, job['actor'], job['source'], 'service.deployment.' + job['status'], job.get('service_id'), reason=job['id'])
            (self.root / (job['id'] + '.upload')).unlink(missing_ok=True)
            (self.root / (job['id'] + '.cid')).unlink(missing_ok=True)
            preparation_cache = Path(job.get('directory') or self.apps / job['app']) / 'tmp' / ('prepare-' + job['id'])
            if preparation_cache.exists():
                shutil.rmtree(preparation_cache, ignore_errors=True)
            self.cleanup(job)

    def restore(self, job):
        before = Service(**job['before']) if job.get('before') else None
        current = self.service(job['service_id']) if job.get('service_id') else None
        # No switch occurred if no reservation was made. Never stop the untouched service.
        with self.state.connect(read_only=True) as db:
            reserved = db.execute('SELECT 1 FROM operation WHERE id=?', (job['id'],)).fetchone()
        if current and reserved:
            driver = self.controller.drivers[current.driver]
            observation = driver.inspect(current)
            if observation.status in {'running', 'starting'}:
                driver.apply(current, 'stop', observation)
        new_container = job.get('new_container')
        cidfile = self.root / (job['id'] + '.cid')
        if not new_container and cidfile.exists():
            new_container = cidfile.read_text(encoding='utf-8').strip()
        if new_container and CONTAINER_ID.fullmatch(new_container) and (before or not current):
            self.docker(job, ['container', 'rm', '--force', new_container])
        if before and current and reserved:
            if job.get('rollback_container'):
                self.rename_container(job, job['rollback_container'], job['rollback_container_name'])
            if current.spec != before.spec or current.target != before.target:
                current = self.swap(job, current, before.spec, before.target)
            if job.get('original_name'):
                self.rename_container(job, before.target, job['original_name'])
            if job.get('was_running'):
                driver = self.controller.drivers[current.driver]
                driver.apply(current, 'start', driver.inspect(current))
                self.wait_running(current, restoring=True)
            self.controller.observe(current)
        if job.get('old_manifest') is not None:
            write_private(self.apps / job['app'] / 'manifest.json', json.dumps(job['old_manifest']).encode('utf-8'))

    def cleanup(self, job):
        """Keep the active release and one rollback; preserve application data and Docker volumes."""
        try:
            manifest = self.manifest(job['app'])
            services = [Service(**entry) for entry in (manifest.get('current'), manifest.get('previous')) if entry]
            if job.get('service_id'):
                with suppress(PeerError):
                    services.append(self.service(job['service_id']))
            control = self.apps / job['app']
            app_dir = Path(job.get('directory') or control)
            claim(app_dir, control, job['app'], self.node_id)
            releases = app_dir / 'releases'
            retained = set()
            for entry in services:
                cwd = Path(entry.spec.get('cwd', self.apps))
                if cwd.is_relative_to(releases):
                    retained.add(cwd.relative_to(releases).parts[0])
            if releases.exists():
                for directory in releases.iterdir():
                    if ID.fullmatch(directory.name) and directory.name not in retained and not directory.is_symlink():
                        shutil.rmtree(directory)
            retained_envs = {entry.spec.get('deployment_environment', {}).get('VIRTUAL_ENV') for entry in services}
            # Environments belong to releases, not to uploaded .venv directories.
            for path in self.state.directory.joinpath('service-envs').glob('*'):
                if not ID.fullmatch(path.name) or str(path) in retained_envs:
                    continue
                owner = self.root / (path.name + '.json')
                if owner.exists() and json.loads(owner.read_text(encoding='utf-8')).get('app') == job['app']:
                    shutil.rmtree(path)
            if job['status'] == 'succeeded' and job.get('old_manifest'):
                previous = job['old_manifest'].get('previous')
                targets = {entry.target for entry in services if entry.driver == 'docker'}
                if previous and previous['driver'] == 'docker' and previous['target'] not in targets:
                    try:
                        self.docker(job, ['container', 'rm', previous['target']])
                    except HostError as error:
                        if 'no such container' not in str(error).lower():
                            raise
            if job.get('cleanup_pending'):
                self.save(job, cleanup_pending=False)
            self.prune_archives()
        except Exception as error:
            self.save(job, cleanup_pending=True, cleanup_attempt=time.time())
            self.note(job, job['phase'], '旧版本清理待重试：' + str(error)[:500])

    def prune_archives(self):
        keep = set()
        for manifest in self.apps.glob('*/manifest.json'):
            contents = json.loads(manifest.read_text(encoding='utf-8'))
            for entry in (contents.get('current'), contents.get('previous')):
                if entry:
                    keep.add(entry['spec'].get('deployment', {}).get('sha256'))
        for path in self.root.glob('*.json'):
            job = json.loads(path.read_text(encoding='utf-8'))
            if job['status'] not in FINAL:
                keep.add(job.get('expected_sha256'))
        for path in self.cache.glob('*.archive'):
            if path.stem not in keep:
                path.unlink(missing_ok=True)

    def recover(self):
        for path in self.root.glob('*.json'):
            job = json.loads(path.read_text(encoding='utf-8'))
            if job['status'] == 'deploying':
                try:
                    if not job.get('service_id'):
                        candidates = [service for service in list_services(self.state) if service.spec.get('deployment', {}).get('release') == job['id']]
                        if candidates:
                            self.save(job, service_id=candidates[0].id, after=snapshot(candidates[0]))
                    self.restore(job)
                    self.save(job, status='failed', phase='部署中断', error='面板在部署期间退出，已恢复原服务配置。', rolled_back=bool(job.get('before')))
                except Exception as error:
                    self.save(job, status='failed', phase='需要恢复', error='部署中断，请检查服务：' + str(error)[:1500])
                finally:
                    (self.root / (job['id'] + '.upload')).unlink(missing_ok=True)
                    (self.root / (job['id'] + '.cid')).unlink(missing_ok=True)
                    self.cleanup(job)

    def reap(self):
        retries = []
        with self.lock:
            self.workers = {key: thread for key, thread in self.workers.items() if thread.is_alive()}
            paths = sorted(self.root.glob('*.json'), key=lambda path: path.stat().st_mtime, reverse=True)
            for index, path in enumerate(paths):
                job = json.loads(path.read_text(encoding='utf-8'))
                if job['status'] in {'uploading', 'ready'} and time.time() - job['updated_at'] > 86400:
                    self.save(job, status='cancelled', phase='上传任务已过期')
                    (self.root / (job['id'] + '.upload')).unlink(missing_ok=True)
                if job.get('cleanup_pending') and time.time() - job.get('cleanup_attempt', 0) > 60 and len(retries) < 2:
                    retries.append(job)
                if index >= 100 and job['status'] in FINAL and not job.get('cleanup_pending'):
                    path.unlink()
            if self.workers or self.cleaning:
                return
            self.cleaning = bool(retries)
        try:
            for job in retries:
                self.cleanup(job)
        finally:
            with self.lock:
                self.cleaning = False

    def shutdown(self):
        self.stopping.set()
        for thread in self.workers.values():
            thread.join(timeout=45)
