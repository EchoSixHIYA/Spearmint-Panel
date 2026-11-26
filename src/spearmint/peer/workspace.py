"""Read and edit a Grove node's service workspace using its current login identity."""
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, ValidationError, field_validator

from ..catalog import get_service
from ..control import ControlError, operation_data
from ..platforms import capabilities
from ..service_details import update_service_details
from ..service_removal import unregister
from ..service_mode import change_mode, ModeChangeError
from ..state import StateError
from ..deployment_location import owns_code
from .grove_service_admin import GroveServiceAdmin, require_member
from .service_setup import LocalAdmin
from .protocol import PeerError


class Target(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    service_id: str = Field(pattern=r'^[a-f0-9]{32}$')


class Versioned(Target):
    version: int = Field(ge=1, le=2**53 - 1)


class AccessLink(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, str_strip_whitespace=True)
    label: str = Field(min_length=1, max_length=60)
    url: str = Field(min_length=1, max_length=400)

    @field_validator('label')
    @classmethod
    def printable_label(cls, value: str) -> str:
        if not value.isprintable():
            raise ValueError('Use a printable link name')
        return value

    @field_validator('url')
    @classmethod
    def web_address(cls, value: str) -> str:
        if not value.lower().startswith(('http://', 'https://')) or any(
                char == '\\' or char.isspace() or not char.isprintable() for char in value):
            raise ValueError('Use a complete HTTP or HTTPS address')
        address = HttpUrl(value)
        if address.username is not None or address.password is not None:
            raise ValueError('Do not include login credentials in the address')
        return value


class Details(Versioned):
    name: str = Field(min_length=1, max_length=80)
    endpoint: str | None = Field(default=None, max_length=180)
    access_links: list[AccessLink] | None = Field(default=None, max_length=8)


class Mode(Versioned):
    mode: str = Field(pattern=r'^(observe|manage)$')


class Workspace:
    method = 'grove.workspace.v1'

    def __init__(self, state, node_id, controller, metrics, docker_socket, groups=None):
        self.state, self.node_id, self.controller = state, node_id, controller
        self.metrics, self.docker_socket = metrics, docker_socket
        self.groups = groups

    def dispatch(self, pair, params):
        if params.keys() != {'identity', 'action', 'body'}:
            raise PeerError('INVALID_REQUEST', 'Invalid workspace request')
        if params['action'] == 'host':
            with self.state.connect(read_only=True) as db:
                require_member(db, self.node_id, pair)
            return self.host(params['body'])
        actor = GroveServiceAdmin.from_wire(self.node_id, pair, params['identity'], 'services')
        return self.request(actor, params['action'], params['body'])

    def host(self, body):
        if not isinstance(body, dict) or body.keys() - {'trend'} or type(body.get('trend', False)) is not bool:
            raise PeerError('INVALID_REQUEST', 'Invalid host metrics request')
        return {'node_id': self.node_id, 'platform': capabilities(), 'metrics': self.metrics.snapshot(),
                **({'trend': self.metrics.trend()} if body.get('trend') else {}), 'workspace': 1}

    def request(self, actor, action, body):
        if not isinstance(body, dict):
            raise PeerError('INVALID_REQUEST', 'Invalid workspace parameters')
        with self.state.connect(read_only=True) as db:
            actor.require(db)
        try:
            if action == 'host':
                return self.host(body)
            if action == 'detail':
                return self.detail(actor, Target.model_validate(body).service_id)
            if action in {'group-save', 'group-delete', 'group-run'} and self.groups is not None:
                return self.groups.request(actor, action, body)
            if action in {'edit', 'remove', 'mode'}:
                model = Details if action == 'edit' else Mode if action == 'mode' else Versioned
                selection = model.model_validate(body)
                identity = actor.actor if isinstance(actor, LocalAdmin) else actor
                with self.state.lock('maintenance.lock', exclusive_now=True):
                    if action == 'edit':
                        links = selection.access_links
                        update_service_details(self.state, selection.service_id, identity,
                            name=selection.name, endpoint=selection.endpoint, version=selection.version,
                            access_links=[link.model_dump() for link in links] if links is not None else None)
                    elif action == 'remove':
                        unregister(self.state, selection.service_id, actor=identity, version=selection.version)
                        return {'removed': True}
                    else:
                        change_mode(self.state, selection.service_id, selection.mode, actor=identity,
                                    docker_socket=self.docker_socket, version=selection.version)
                return self.detail(actor, selection.service_id)
        except ValidationError as error:
            raise PeerError('INVALID_REQUEST', 'Invalid workspace parameters') from error
        except (ControlError, ModeChangeError) as error:
            code = 'NOT_FOUND' if error.status == 404 else 'DENIED' if error.status in {401, 403} else 'CONFLICT'
            raise PeerError(code, str(error)) from error
        except StateError as error:
            raise PeerError('CONFLICT', str(error)) from error
        raise PeerError('INVALID_REQUEST', 'Unknown workspace action')

    def detail(self, actor, service_id):
        with self.state.connect(read_only=True) as db:
            actor.require(db)
            service = get_service(db, service_id)
            if service is None:
                raise PeerError('NOT_FOUND', 'Service is no longer registered')
            operation_actor = actor.actor.operation_actor if isinstance(actor, LocalAdmin) else actor.operation_actor
            operations = [operation_data(row, db=db) for row in db.execute(
                'SELECT * FROM operation WHERE service_id=? AND actor=? ORDER BY rowid DESC LIMIT 12',
                (service_id, operation_actor))]
            protected = db.execute('SELECT 1 FROM service_protection WHERE service_id=?', (service_id,)).fetchone() is not None
            mapped = db.execute("SELECT 1 FROM frp_exposure WHERE service_id=? AND status IN ('starting','running','revoking')", (service_id,)).fetchone() is not None
        observation = self.controller.observe(service)
        described = self.controller.describe(service)
        foreground = service.driver == 'process' and not service.existing_system_service
        stopped = described['observation']['status'] in {'stopped', 'failed'} and not described['observation']['stale']
        return {**described, 'node_id': self.node_id, 'operations': operations, 'command': service.spec.get('command'),
                'access_links': service.spec.get('access_links', []),
                'deployment': service.spec.get('deployment'), 'can_deploy': owns_code(service),
                'resources': self.controller.service_metrics.snapshot(service, observation),
                'can_edit_details': True, 'can_unregister': not protected and not mapped and (not foreground or stopped),
                'unregister_reason': '请先撤销此服务的公网映射，再取消登记。' if mapped else '请先停止此程序，再取消登记。' if foreground and not stopped else None,
                'can_change_mode': not foreground, 'managed': service.managed, 'approval_required': False}
