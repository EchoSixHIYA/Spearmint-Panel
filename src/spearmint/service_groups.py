"""Node-owned service groups and ordered operations over the service queue."""

from hashlib import sha256
import json
import logging
from threading import Event, Lock, Thread
import time
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .catalog import MAX_SERVICES, Service, get_service, service_name
from .control import ControlError
from .peer.operation_policy import required_version
from .peer.protocol import PeerError
from .peer.service_setup import LocalAdmin
from .state import audit
from .update_worker import read_record, write_record


LOG = logging.getLogger(__name__)
MAX_GROUPS = 16
SERVICE_ID = r'^[a-f0-9]{32}$'
GROUP_VERSION = r'^[a-f0-9]{64}$'


class Member(BaseModel):
    model_config = ConfigDict(strict=True, extra='forbid')
    service_id: str = Field(pattern=SERVICE_ID)
    status_only: bool = False


class GroupRef(BaseModel):
    model_config = ConfigDict(strict=True, extra='forbid')
    id: str = Field(pattern=SERVICE_ID)
    version: str = Field(pattern=GROUP_VERSION)


class GroupEdit(GroupRef):
    version: str | None = Field(default=None, pattern=GROUP_VERSION)
    name: str = Field(min_length=1, max_length=80)
    members: list[Member] = Field(min_length=1, max_length=MAX_SERVICES)


class GroupRun(GroupRef):
    action: Literal['start', 'stop']
    request_id: str = Field(pattern=SERVICE_ID)


def groups_from(services: list[Service]) -> dict[str, dict]:
    groups: dict[str, dict] = {}
    for service in services:
        for membership in service.spec.get('service_groups', []):
            group = groups.setdefault(membership['id'], {'id': membership['id'], 'name': membership['name'], 'members': []})
            group['members'].append({'service_id': service.id, 'status_only': membership['status_only'],
                                     'position': membership['position']})
    for group in groups.values():
        group['members'].sort(key=lambda entry: entry['position'])
        for member in group['members']:
            member.pop('position')
        group['version'] = sha256(json.dumps(group, ensure_ascii=False, sort_keys=True).encode()).hexdigest()
    return groups


class ServiceGroups:
    def __init__(self, state, controller, peer_operations):
        self.state, self.controller, self.peer_operations = state, controller, peer_operations
        self.path = state.directory / 'service-group-receipts.json'
        self.lock = Lock()
        self.stopping = Event()
        self.worker: Thread | None = None

    @staticmethod
    def services(db):
        return [Service.from_row(row) for row in db.execute('SELECT * FROM service ORDER BY id')]

    def receipts(self) -> dict:
        return read_record(self.path) or {}

    def public(self, services: list[Service]) -> list[dict]:
        receipts = self.receipts()
        return [{**group, 'operation': receipts.get(group_id)} for group_id, group in groups_from(services).items()]

    def recover(self):
        jobs = self.receipts()
        interrupted = [job for job in jobs.values() if job['status'] == 'running']
        for job in interrupted:
            job.update(status='uncertain', reason='PANEL_RESTARTED')
        if interrupted:
            write_record(self.path, jobs)

    def shutdown(self):
        self.stopping.set()
        if self.worker is not None:
            self.worker.join()

    def request(self, actor, action, body):
        try:
            if action == 'group-run':
                return self.start(actor, GroupRun.model_validate(body))
            selection = (GroupEdit if action == 'group-save' else GroupRef).model_validate(body)
            return self.edit(actor, selection)
        except ValidationError as error:
            raise PeerError('INVALID_REQUEST', 'Invalid service group parameters') from error

    def edit(self, actor, selection: GroupRef | GroupEdit) -> dict:
        identity = actor.actor if isinstance(actor, LocalAdmin) else actor
        with self.lock, self.state.connect(write=True) as db:
            actor.require(db)
            self.require_idle()
            services = self.services(db)
            groups = groups_from(services)
            before = groups.get(selection.id)
            editing = isinstance(selection, GroupEdit)
            name = service_name(selection.name) if editing else ''
            members = [item.model_dump() for item in selection.members] if editing else []
            if editing and before and (name, members) == (before['name'], before['members']):
                return before
            if not editing and before is None:
                return {'removed': True}
            if selection.version != (before['version'] if before else None):
                raise PeerError('CONFLICT', '服务组已变化，请刷新后重试。')
            if editing and before is None and len(groups) >= MAX_GROUPS:
                raise PeerError('CONFLICT', '此节点已达到服务组数量上限。')
            if editing and any(group['name'].casefold() == name.casefold() for key, group in groups.items() if key != selection.id):
                raise PeerError('CONFLICT', '此节点已有同名服务组。')
            proposed = {member['service_id']: {
                'id': selection.id, 'name': name, 'status_only': member['status_only'], 'position': position,
            } for position, member in enumerate(members)}
            if len(proposed) != len(members):
                raise PeerError('INVALID_REQUEST', '同一个服务只能在组内选一次。')

            available = {service.id: service for service in services}
            if proposed.keys() - available.keys():
                raise PeerError('NOT_FOUND', '所选服务已取消登记。')
            for service_id, entry in proposed.items():
                service = available[service_id]
                if not entry['status_only'] and (not service.managed or required_version(db, service_id) == 2):
                    raise PeerError('CONFLICT', f'{service.name} 仅能作为状态成员。')
                others = [member for member in service.spec.get('service_groups', []) if member['id'] != selection.id]
                if others and (not entry['status_only'] or any(not member['status_only'] for member in others)):
                    raise PeerError('CONFLICT', f'{service.name} 已归组。共享成员在每个组中都须设为仅显示状态。')

            for service in services:
                current = service.spec.get('service_groups', [])
                updated = [item for item in current if item['id'] != selection.id]
                if service.id in proposed:
                    updated.append(proposed[service.id])
                if updated == current:
                    continue
                spec = service.spec.copy()
                if updated:
                    spec['service_groups'] = updated
                else:
                    spec.pop('service_groups', None)
                db.execute('UPDATE service SET spec=? WHERE id=?', (json.dumps(spec, ensure_ascii=False), service.id))
            event = 'service.group.saved' if editing else 'service.group.removed'
            audit(db, identity.operation_actor, identity.address, event, selection.id)
            return groups_from(self.services(db))[selection.id] if editing else {'removed': True}

    def require_idle(self):
        if self.stopping.is_set() or (self.worker is not None and self.worker.is_alive()):
            raise PeerError('BUSY', '此节点有服务组操作正在执行。')

    def start(self, actor, intent: GroupRun):
        with self.lock, self.state.connect(read_only=True) as db:
            db.execute('BEGIN')
            actor.require(db)
            services = self.services(db)
            groups = groups_from(services)
            group = groups.get(intent.id)
            if group is None or group['version'] != intent.version:
                raise PeerError('CONFLICT', '服务组已变化，请刷新后重试。')
            previous = self.receipts()
            if (existing := previous.get(intent.id)) and existing['request_id'] == intent.request_id:
                if (existing['action'], existing['version']) != (intent.action, intent.version):
                    raise PeerError('CONFLICT', '此请求已经用于另一项操作。')
                return existing
            self.require_idle()
            ids = [member['service_id'] for member in group['members'] if not member['status_only']]
            if not ids:
                raise PeerError('CONFLICT', '此组只有状态成员。')
            if intent.action == 'stop':
                ids.reverse()
            versions = {service.id: service.version for service in services}
            for service_id in ids:
                self.require_member(db, service_id, versions[service_id], intent.action)
                if db.execute("SELECT 1 FROM operation WHERE service_id=? AND status IN ('queued','running')", (service_id,)).fetchone():
                    raise PeerError('CONFLICT', '组内有服务正在执行其他操作。')
            job = {'request_id': intent.request_id, 'version': intent.version, 'action': intent.action,
                   'status': 'running', 'completed': 0, 'total': len(ids), 'current_service_id': ids[0]}
            jobs = {key: value for key, value in previous.items() if key in groups}
            jobs[intent.id] = job
            write_record(self.path, jobs)
            self.worker = Thread(target=self.run, args=(actor, intent.id, jobs, ids, versions), daemon=True)
            self.worker.start()
            return job.copy()

    @staticmethod
    def require_member(db, service_id, version, action):
        service = get_service(db, service_id)
        if service is None or service.version != version or action not in service.actions or required_version(db, service_id) == 2:
            raise PeerError('CONFLICT', '服务登记或管理方式已变化。')
        return service

    def run(self, actor, group_id, jobs, ordered, versions):
        job = jobs[group_id]
        try:
            for service_id in ordered:
                if self.stopping.is_set():
                    raise InterruptedError
                job['current_service_id'] = service_id
                write_record(self.path, jobs)
                with self.state.connect(read_only=True) as db:
                    db.execute('BEGIN')
                    actor.require(db)
                    group = groups_from(self.services(db)).get(group_id)
                    if group is None or group['version'] != job['version']:
                        raise PeerError('CONFLICT', '服务组已变化。')
                    service = self.require_member(db, service_id, versions[service_id], job['action'])
                key = sha256(f"{job['request_id']}:{service_id}".encode()).hexdigest()[:32]
                action = job['action']
                if isinstance(actor, LocalAdmin):
                    operation_id = self.controller.submit(actor.actor, service_id, action, key, service_version=service.version)['id']
                else:
                    operation_id = self.peer_operations.grove_submit(actor, service_id, {
                        'request_id': key, 'action': action, 'service_version': service.version,
                    })['operation_id']
                self.wait_operation(operation_id)
                if action == 'start':
                    self.wait_ready(actor, service)
                job['completed'] += 1
            job.update(status='succeeded', current_service_id=None)
        except TimeoutError:
            job.update(status='uncertain', reason='OPERATION_UNCONFIRMED')
        except InterruptedError:
            job.update(status='uncertain', reason='PANEL_RESTARTED')
        except (PeerError, ControlError) as error:
            job.update(status='failed', reason=error.code or 'OPERATION_FAILED')
        except Exception:
            LOG.exception('Service group operation interrupted')
            job.update(status='uncertain', reason='OPERATION_UNCONFIRMED')
        finally:
            write_record(self.path, jobs)

    def wait_operation(self, operation_id):
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            with self.state.connect(read_only=True) as db:
                status = db.execute('SELECT status FROM operation WHERE id=?', (operation_id,)).fetchone()
            if status is None or status[0] == 'uncertain':
                raise TimeoutError
            if status[0] == 'succeeded':
                return
            if status[0] == 'failed':
                raise PeerError('OPERATION_FAILED', 'Member operation failed')
            if self.stopping.wait(.25):
                raise InterruptedError
        raise TimeoutError

    def wait_ready(self, actor, service):
        deadline = time.monotonic() + 60
        stable = None
        while time.monotonic() < deadline:
            with self.state.connect(read_only=True) as db:
                actor.require(db)
                self.require_member(db, service.id, service.version, 'start')
            observation = self.controller.observe(service)
            if observation.status == 'running' and observation.health not in {'starting', 'unhealthy'}:
                stable = stable or time.monotonic()
                if time.monotonic() - stable >= 2:
                    return
            else:
                stable = None
                if observation.status in {'failed', 'missing', 'stopped'}:
                    raise PeerError('SERVICE_NOT_READY', 'Member did not stay running')
            if self.stopping.wait(.5):
                raise InterruptedError
        raise PeerError('SERVICE_NOT_READY', 'Member did not become ready before timeout')
