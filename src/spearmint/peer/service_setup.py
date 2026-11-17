"""Register and configure existing workloads through the owning Grove node."""

import sys
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..catalog import ACTIONS, RegistrationError, TargetAlreadyRegistered, get_service, list_services
from ..drivers import ContainerNotFound, DockerDriver, SystemUnitDriver
from ..host import HostError
from ..platforms import WINDOWS
from ..service_mode import ModeChangeError, change_mode
from ..windows_services import WindowsServiceDriver
from .grove_service_admin import GroveServiceAdmin
from .protocol import PeerError


METHOD = 'service.setup'
MAX_CANDIDATES = 64
Kind = Literal['systemd', 'windows', 'docker']


class Selection(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    kind: Kind


class Registration(Selection):
    target: str = Field(min_length=1, max_length=256)
    name: str = Field(min_length=1, max_length=80)


class Management(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    service_id: str = Field(pattern=r'^[a-f0-9]{32}$')
    version: int = Field(ge=1, le=2**53 - 1)


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
            'managed': service.managed}


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
        actor = GroveServiceAdmin.from_wire(self.local_id, pair, identity)
        with self.state.connect() as db:
            db.execute('BEGIN')
            actor.require(db)
        try:
            if action == 'kinds' and body == {}:
                return {'kinds': available_kinds()}
            if action == 'candidates':
                return self.candidates(Selection.model_validate(body).kind)
            if action in ('register', 'manage'):
                with self.state.lock('maintenance.lock', exclusive_now=True):
                    if action == 'register':
                        return self.register(actor, Registration.model_validate(body))
                    return self.manage(actor, Management.model_validate(body))
        except ValidationError as error:
            raise PeerError('INVALID_REQUEST', 'Invalid service setup parameters') from error
        except ContainerNotFound as error:
            raise PeerError('NOT_FOUND', 'Target container was removed or replaced') from error
        except (HostError, ModeChangeError) as error:
            raise PeerError('CONFLICT', 'The owning node could not verify the workload or its management permissions') from error
        except RegistrationError as error:
            raise PeerError('CONFLICT', str(error)) from error
        raise PeerError('INVALID_REQUEST', 'Unknown service setup action')

    def candidates(self, kind: Kind) -> dict:
        if kind not in available_kinds():
            raise PeerError('NOT_FOUND', 'This node does not support this kind of service')
        registered = list_services(self.state, 'docker' if kind == 'docker' else 'process')
        if kind == 'docker':
            result = self.docker.available_containers({service.target for service in registered})
            candidates = [{'target': item['id'], 'name': item['name']} for item in result['containers']]
        else:
            targets = system_targets(self.state, kind)
            registered = [service for service in registered if is_kind(service, kind) and service.target in targets]
            occupied = {service.target for service in registered}
            candidates = [{'target': target, 'name': name} for target, name in targets.items() if target not in occupied]
            result = {'truncated': False}
        existing = [registration_view(service) for service in registered]
        return {'candidates': candidates[:MAX_CANDIDATES], 'registered': existing,
                'truncated': result['truncated'] or len(candidates) > MAX_CANDIDATES}

    def register(self, actor: GroveServiceAdmin, body: Registration) -> dict:
        kind, target = body.kind, body.target
        if kind not in available_kinds():
            raise PeerError('NOT_FOUND', 'This node does not support this kind of service')
        with self.state.connect() as db:
            db.execute('BEGIN')
            actor.require(db)
        audit_as = {'actor': actor.operation_actor, 'source': actor.address}
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

    def manage(self, actor: GroveServiceAdmin, body: Management) -> dict:
        with self.state.connect() as db:
            db.execute('BEGIN')
            actor.require(db)
            service = get_service(db, body.service_id)
            if service is None or not (service.existing_system_service or service.driver == 'docker'):
                raise PeerError('NOT_FOUND', 'Unknown existing workload')
        actions = list(ACTIONS)
        if service.existing_systemd_unit:
            delegation = SystemUnitDriver.delegation_status(service.target)
            actions = [action for action in actions if delegation.get('listed_actions', {}).get(action)]
            if not actions:
                raise PeerError('HOST_PERMISSION', 'The owning node has no delegated systemd control for this service')
        elif service.managed and service.existing_windows_service:
            WindowsServiceDriver(self.state).verify_management(service.target)
        elif service.managed:
            self.docker.verify_management(service)
        service = change_mode(self.state, service.id, 'manage', docker_socket=self.docker_socket,
                              actor=actor, version=body.version)
        return {'service': registration_view(service)}


def is_kind(service, kind: Kind) -> bool:
    return service.existing_systemd_unit if kind == 'systemd' else service.existing_windows_service
