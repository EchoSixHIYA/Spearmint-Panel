"""Register workloads through the owning Grove node."""

from dataclasses import dataclass
import sys
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .. import auth
from ..catalog import ACTIONS, RegistrationError, Service, TargetAlreadyRegistered, get_service, list_services, process_spec, register, service_name, validate_endpoint
from ..drivers import CONTAINER_ID, ContainerNotFound, DockerDriver, SystemUnitDriver
from ..host import DockerAccessError, HostError
from ..service_command import command_spec
from ..platforms import WINDOWS
from ..service_mode import ModeChangeError, change_mode
from ..state import StateError
from ..windows_services import WindowsServiceDriver, application_log
from .grove_service_admin import GroveServiceAdmin
from .outbound import account_admin
from .protocol import PeerError


METHOD = 'service.setup'
MAX_CANDIDATES = 64
Kind = Literal['systemd', 'windows', 'docker']


class Selection(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    kind: Kind


class RunningSelection(Selection):
    offset: int = Field(default=0, ge=0, le=100_000)


class Target(Selection):
    target: str = Field(min_length=1, max_length=256)


class Registration(Target):
    name: str = Field(min_length=1, max_length=80)


class Management(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    service_id: str = Field(pattern=r'^[a-f0-9]{32}$')
    version: int = Field(ge=1, le=2**53 - 1)


class Takeover(Registration):
    mode: Literal['observe', 'manage'] = 'manage'
    endpoint: str | None = Field(default=None, max_length=180)
    log_path: str | None = Field(default=None, max_length=420)


class NewService(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    name: str = Field(min_length=1, max_length=80)
    command: str | None = Field(default=None, min_length=1, max_length=8192)
    executable: str | None = Field(default=None, min_length=1, max_length=1024)
    arguments: list[str] = Field(default_factory=list, max_length=128)
    cwd: str | None = Field(default=None, min_length=1, max_length=1024)
    stop_timeout: int = Field(default=8, ge=1, le=30)
    endpoint: str | None = Field(default=None, max_length=180)


@dataclass(frozen=True)
class LocalAdmin:
    actor: auth.Actor

    def require(self, db):
        account_admin(db, self.actor)


def available_kinds() -> list[Kind]:
    if WINDOWS:
        return ['windows']
    return ['systemd', 'docker'] if sys.platform == 'linux' else []


def system_targets(state, kind: Kind) -> dict[str, str]:
    if kind == 'systemd':
        return {unit: unit for unit in sorted(SystemUnitDriver.allowed_units())}
    return {key: name for key, name in sorted(WindowsServiceDriver(state).allowed_services().items())}


def registration_view(service) -> dict:
    return {'id': service.id, 'target': service.target, 'name': service.name, 'version': service.version,
            'managed': service.managed,
            **({'command': service.spec['command']} if 'command' in service.spec else {})}


def acting_as(actor: GroveServiceAdmin | LocalAdmin) -> dict:
    identity = actor.actor if isinstance(actor, LocalAdmin) else actor
    return {'actor': identity.operation_actor, 'source': identity.address, 'authorize': actor.require}


class ServiceSetup:
    method = METHOD

    def __init__(self, state, local_id: str, docker_socket):
        self.state = state
        self.local_id = local_id
        self.docker = DockerDriver(docker_socket)
        self.docker_socket = docker_socket

    def dispatch(self, pair, params: dict) -> dict:
        if params.keys() != {'identity', 'action', 'body'}:
            raise PeerError('INVALID_REQUEST', 'Invalid service setup request')
        identity, action, body = params['identity'], params['action'], params['body']
        return self.setup(GroveServiceAdmin.from_wire(self.local_id, pair, identity), action, body)

    def setup(self, actor: GroveServiceAdmin | LocalAdmin, action: str, body: dict) -> dict:
        with self.state.connect() as db:
            db.execute('BEGIN')
            actor.require(db)
        try:
            if action == 'kinds' and body == {}:
                return {'kinds': available_kinds(), 'workflow': 2, 'checks': True, 'commands': True, 'scripts': True}
            if action == 'candidates':
                return self.candidates(Selection.model_validate(body).kind)
            if action == 'running':
                selection = RunningSelection.model_validate(body)
                return self.candidates(selection.kind, running_only=True, offset=selection.offset)
            if action == 'inspect':
                return self.inspect_target(Target.model_validate(body))
            if action in ('register', 'manage', 'take-over', 'create'):
                with self.state.lock('maintenance.lock', exclusive_now=True):
                    if action == 'register':
                        return self.register(actor, Registration.model_validate(body))
                    if action == 'take-over':
                        return self.take_over(actor, Takeover.model_validate(body))
                    if action == 'create':
                        return self.create(actor, NewService.model_validate(body))
                    return self.manage(actor, Management.model_validate(body))
        except ValidationError as error:
            raise PeerError('INVALID_REQUEST', 'Invalid service setup parameters') from error
        except ContainerNotFound as error:
            raise PeerError('NOT_FOUND', 'Target container was removed or replaced') from error
        except DockerAccessError as error:
            raise PeerError(error.code, str(error)) from error
        except (HostError, ModeChangeError) as error:
            raise PeerError('CONFLICT', 'The owning node could not verify the workload or its management permissions') from error
        except RegistrationError as error:
            raise PeerError('CONFLICT', str(error)) from error
        except StateError as error:
            raise PeerError('CONFLICT', str(error)) from error
        raise PeerError('INVALID_REQUEST', 'Unknown service setup action')

    def candidates(self, kind: Kind, *, running_only: bool = False, offset: int = 0) -> dict:
        if kind not in available_kinds():
            raise PeerError('NOT_FOUND', 'This node does not support this kind of service')
        registered = list_services(self.state, 'docker' if kind == 'docker' else 'process')
        if kind == 'docker':
            result = self.docker.available_containers({service.target for service in registered}, running_only=running_only)
            candidates = [{'target': item['id'], 'name': item['name']} for item in result['containers']]
        else:
            if running_only:
                if kind == 'systemd':
                    targets = {unit: unit for unit in sorted(SystemUnitDriver.running_units())}
                else:
                    targets = dict(sorted(WindowsServiceDriver(self.state).running_services().items()))
                    if not targets:
                        raise PeerError('SERVICE_DISCOVERY', 'The Windows service manager returned no running services')
            else:
                targets = system_targets(self.state, kind)
            registered = [service for service in registered if is_kind(service, kind)]
            occupied = {service.target for service in registered}
            candidates = [{'target': target, 'name': name} for target, name in targets.items() if target not in occupied]
            result = {'truncated': False}
        existing = [registration_view(service) for service in registered]
        end = offset + MAX_CANDIDATES
        return {'candidates': candidates[offset:end], 'registered': existing,
                'truncated': result['truncated'] or len(candidates) > end,
                **({'next_offset': end if len(candidates) > end else None,
                    'previous_offset': max(0, offset - MAX_CANDIDATES) if offset else None} if running_only else {})}

    def register(self, actor: GroveServiceAdmin | LocalAdmin, body: Registration) -> dict:
        kind, target = body.kind, body.target
        if kind not in available_kinds():
            raise PeerError('NOT_FOUND', 'This node does not support this kind of service')
        with self.state.connect() as db:
            db.execute('BEGIN')
            actor.require(db)
        audit_as = acting_as(actor)
        audit_as.pop('authorize')
        try:
            if kind == 'docker':
                if len(target) != 64 or any(char not in '0123456789abcdef' for char in target):
                    raise PeerError('INVALID_REQUEST', 'Select a container by its full ID')
                service = self.docker.register(self.state, body.name, target, **audit_as)
            else:
                if target not in system_targets(self.state, kind):
                    raise PeerError('DENIED', 'Service is outside the owning node’s configured list')
                if kind == 'systemd':
                    service = SystemUnitDriver.register(self.state, body.name, target, **audit_as)
                else:
                    service = WindowsServiceDriver(self.state).register(body.name, target, **audit_as)
        except TargetAlreadyRegistered as error:
            with self.state.connect() as db:
                service = get_service(db, error.service_id)
            if service is None or service.name != body.name.strip():
                raise PeerError('CONFLICT', 'The workload is already registered. Refresh the list') from error
        return {'service': registration_view(service)}

    def inspect_target(self, body: Target, log_path: str | None = None) -> dict:
        kind, target = body.kind, body.target
        if kind not in available_kinds():
            raise PeerError('NOT_FOUND', 'This node does not support this kind of service')
        if log_path and kind != 'windows':
            raise PeerError('INVALID_REQUEST', 'Only Windows services use an application log file')
        if kind == 'systemd':
            unit = SystemUnitDriver.configured_unit(target, host_permissions=True)
            if unit.get('ActiveState') != 'active' or int(unit.get('MainPID', 0)) <= 0:
                raise PeerError('SERVICE_STOPPED', 'The service is no longer running')
            permissions = SystemUnitDriver.delegation_status(target, host_permissions=True)
            from ..host_service_access import account_name, enable_command
            account = account_name()
            return {'ready': all(permissions.get('listed_actions', {}).get(action) for action in ACTIONS),
                    'observe_ready': True, 'logs_ready': bool(permissions.get('listed_logs')),
                    'control': permissions.get('listed_actions', {}), 'host_access': permissions.get('host_access', False),
                    'reason': permissions.get('reason'), 'account': account,
                    'enable_command': enable_command()}
        elif kind == 'windows':
            windows = WindowsServiceDriver(self.state)
            management = windows.management_status(target, host_permissions=True)
            if management.get('status') and management['status'] != 'running':
                raise PeerError('SERVICE_STOPPED', 'The service is no longer running')
            if not management['ready']:
                raise PeerError('HOST_PERMISSION', 'Require permission to control the Windows service')
            if log_path is None:
                log_path = windows.detect_log(target)
            if log_path is None:
                return {'ready': True, 'log_path': None}
            try:
                application_log(log_path, 1)
            except HostError as error:
                raise PeerError('SERVICE_LOG', str(error)) from error
            return {'ready': True, 'log_path': log_path}
        else:
            if not CONTAINER_ID.fullmatch(target):
                raise PeerError('INVALID_REQUEST', 'Select a container by its full ID')
            candidate = Service('', self.local_id, '', 'docker', target, {'stop_timeout': 8}, True, 1)
            if self.docker.inspect(candidate).status != 'running':
                raise PeerError('SERVICE_STOPPED', 'The container is no longer running')
            try:
                self.docker.logs(candidate, 1)
            except HostError as error:
                raise PeerError('SERVICE_LOG', str(error)) from error
        return {'ready': True}

    def take_over(self, actor: GroveServiceAdmin | LocalAdmin, body: Takeover) -> dict:
        kind, target = body.kind, body.target
        validate_endpoint(body.endpoint)
        checked = self.inspect_target(body, body.log_path)
        if body.mode == 'manage' and checked.get('ready') is not True:
            raise PeerError('HOST_SERVICE_ACCESS', '此节点尚未启用主机服务管理。请完成一次节点授权，或先以观察模式登记。')
        spec = {'endpoint': body.endpoint}
        driver = 'process'
        if kind == 'systemd':
            spec.update(runtime='systemd-system', host_permissions=True)
        elif kind == 'windows':
            if not checked.get('log_path'):
                raise PeerError('SERVICE_LOG', 'Provide the Windows service application log file')
            target = target.lower()
            spec.update(runtime='windows-service', host_permissions=True, log_path=checked['log_path'])
        else:
            driver = 'docker'
            spec['stop_timeout'] = 8
        try:
            service = register(self.state, driver, body.name, target, spec, managed=body.mode == 'manage', **acting_as(actor))
        except TargetAlreadyRegistered as error:
            with self.state.connect() as db:
                actor.require(db)
                service = get_service(db, error.service_id)
            if service is None or service.managed != (body.mode == 'manage') or service.name != service_name(body.name) or service.spec != spec:
                raise
        return {'service': registration_view(service)}

    def create(self, actor: GroveServiceAdmin | LocalAdmin, body: NewService) -> dict:
        try:
            if body.command is not None:
                if body.executable is not None or body.arguments:
                    raise StateError('Supply one startup command')
                spec = command_spec(body.command, body.cwd, body.stop_timeout, body.endpoint, state=self.state)
            elif body.executable is not None and body.cwd is not None:
                spec = process_spec([body.executable, *body.arguments], body.cwd, body.stop_timeout, body.endpoint)
            else:
                raise StateError('Provide a startup command')
        except StateError as error:
            raise PeerError('SERVICE_COMMAND', str(error)) from error
        name = service_name(body.name)
        with self.state.connect() as db:
            actor.require(db)
            row = db.execute('SELECT * FROM service WHERE name=?', (name,)).fetchone()
        if row is not None:
            service = Service.from_row(row)
            if service.driver != 'process' or not service.managed or service.spec != spec:
                raise RegistrationError('Service name is already registered')
        else:
            service = register(self.state, 'process', name, '', spec, managed=True, **acting_as(actor))
        return {'service': registration_view(service)}

    def manage(self, actor: GroveServiceAdmin | LocalAdmin, body: Management) -> dict:
        with self.state.connect() as db:
            db.execute('BEGIN')
            actor.require(db)
            service = get_service(db, body.service_id)
            if service is None or not (service.existing_system_service or service.driver == 'docker'):
                raise PeerError('NOT_FOUND', 'Unknown existing workload')
        actions = list(ACTIONS)
        if service.existing_systemd_unit:
            delegation = SystemUnitDriver.delegation_status(service.target, host_permissions=service.host_permissions)
            actions = [action for action in actions if delegation.get('listed_actions', {}).get(action)]
            if not actions:
                raise PeerError('HOST_PERMISSION', 'The owning node has no delegated systemd control for this service')
        elif service.managed and service.existing_windows_service:
            WindowsServiceDriver(self.state).verify_management(service.target, host_permissions=service.host_permissions)
        elif service.managed:
            self.docker.verify_management(service)
        service = change_mode(self.state, service.id, 'manage', docker_socket=self.docker_socket,
                              actor=actor.actor if isinstance(actor, LocalAdmin) else actor, version=body.version)
        return {'service': registration_view(service)}


def is_kind(service, kind: Kind) -> bool:
    return service.existing_systemd_unit if kind == 'systemd' else service.existing_windows_service
