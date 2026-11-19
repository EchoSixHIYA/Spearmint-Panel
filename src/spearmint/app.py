import asyncio
from contextlib import asynccontextmanager
from functools import partial
import logging
import sqlite3
from typing import Literal
import re
import secrets
from time import perf_counter
from urllib.parse import urlsplit

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.concurrency import run_in_threadpool

from . import auth, grove, grove_updates, grove_admission, grove_login, grove_metadata, grove_password, grove_quorum_join, grove_web_join, mesh_enrollment, onboarding, passkeys, seed_admission, seed_wizard
from .build_info import deployment_host, deployment_web, running_build
from .catalog import RegistrationError, TargetAlreadyRegistered, get_service, list_services
from .config import Config
from .control import ControlError, Controller, operation_data
from .drivers import CONTAINER_REFERENCE, ContainerNotFound, DockerDriver, Driver, ProcessDriver, SystemUnitDriver
from .host import HostError
from .metrics import Metrics
from .peer.approval_format import ENVELOPE_LIMIT
from .peer import evidence, evidence_exchange, frp_access, grove_service_admin, quarantine, service_setup
from .peer.operations import change_service_access, service_access
from .frp_runtime import MAX_TTL, list_exposures
from .peer.protocol import PeerError, decode_json, parse_b64, wire_b64
from .peer.services import PeerServices, parse_logs
from .service_details import update_service_details
from .service_mode import ModeChangeError, change_mode
from .service_removal import unregister
from .terminal_service import TerminalService
from .seeding import SeedDeployments
from .state import State, StateError
from .platforms import capabilities
from .native_process import process_driver
from .windows_services import ServiceManagerError, WindowsServiceDriver


class Credentials(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    enrollment_token: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-]{43}$")


class GroveCredentials(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    code: str | None = Field(default=None, pattern=r'^[0-9]{6}$')


class GroveQuorumJoin(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    invitation: str = Field(min_length=1, max_length=grove_quorum_join.LIMIT)
    credentials: GroveCredentials | None = None


class GroveNodeNote(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    note: str = Field(max_length=80)


class GrovePasswordChange(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


class GroveRoleChange(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    role: Literal['node_admin', 'remote_operator']


class GroveMemberAdmission(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    node_id: str = Field(pattern=r'^spm1-[a-f0-9]{64}$')
    origin: str = Field(min_length=1, max_length=512)


class GroveMemberSource(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    node_id: str = Field(pattern=r'^spm1-[a-f0-9]{64}$')


class ServiceAccessChange(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    directory: bool
    status: bool
    logs: bool
    actions: list[Literal["start", "stop", "restart"]] | None = Field(default=None, max_length=3)
    hours: int | None = Field(default=None, ge=1, le=90 * 24)


class SetupCredentials(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-]{43}$")
    username: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")
    password: str = Field(min_length=12, max_length=256)
    confirmation: str = Field(min_length=12, max_length=256)
    grove_name: str | None = Field(default=None, min_length=1, max_length=40)


class GroveRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    request: str = Field(min_length=1, max_length=12000, pattern=r'^[A-Za-z0-9_-]+$')


class GroveStart(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    kind: Literal['login', 'join']
    realm: dict | None = None
    setup_token: str | None = Field(default=None, pattern=r'^[A-Za-z0-9_-]{43}$')
    verification_origin: str | None = Field(default=None, max_length=512)
    invitation_code: str | None = Field(default=None, max_length=grove_web_join.INVITATION_LIMIT)


class GroveBrowserInvitation(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    code: str = Field(min_length=1, max_length=grove_web_join.INVITATION_LIMIT)


class GroveName(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    name: str = Field(min_length=1, max_length=40)


class SeedCheckRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    revision: str = Field(pattern=r'^[a-f0-9]{64}$')


class SeedRequest(SeedCheckRequest):
    retry_started: bool = False


class FirstFactorRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    method: Literal["totp", "passkey"]


class FactorFlow(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    flow_id: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")


class TotpResponse(FactorFlow):
    code: str = Field(pattern=r"^[0-9]{6}$")


class RecoveryResponse(FactorFlow):
    code: str = Field(pattern=r"^[A-Za-z0-9_-]{22}$")


class PasskeyOptionsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    username: str = Field(min_length=1, max_length=64)


class PasskeyResponse(FactorFlow):
    credential: dict


class LocalQuarantine(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    reason: str = Field(min_length=1, max_length=160)


class FrpStart(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    provider: str = Field(pattern=r'^[a-z0-9][a-z0-9-]{0,31}$')
    protocol: Literal['http', 'https', 'tcp']
    ttl: int = Field(ge=1, le=MAX_TTL)
    domain: str | None = Field(default=None, min_length=1, max_length=253)
    public_port: int | None = Field(default=None, ge=1, le=65535)


class SystemdRegistration(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    name: str = Field(min_length=1, max_length=80)
    unit: str = Field(min_length=1, max_length=128)


class WindowsServiceRegistration(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    name: str = Field(min_length=1, max_length=80)
    service: str = Field(min_length=1, max_length=256)


class DockerRegistration(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    name: str = Field(min_length=1, max_length=80)
    container: str = Field(pattern=f"^{CONTAINER_REFERENCE}$")


class ServiceMode(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    mode: Literal["observe", "manage"]
    version: int = Field(ge=1, le=2**63 - 1)


class ServiceDetails(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    name: str = Field(min_length=1, max_length=80)
    endpoint: str | None = Field(max_length=180)
    version: int = Field(ge=1, le=2**63 - 1)


class ActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["start", "stop", "restart"]


class RemoteAction(ActionRequest):
    model_config = ConfigDict(extra="forbid", strict=True)
    service_version: int = Field(gt=0, lt=2**63)


class RemoteIntent(RemoteAction):
    operator_key_id: str = Field(pattern=r"^op1-[0-9a-f]{64}$", min_length=68, max_length=68)


class RemoteApproval(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    challenge: str = Field(min_length=1, max_length=10923)
    issuer_signature: str = Field(min_length=86, max_length=86)
    operator_signature: str = Field(min_length=86, max_length=86)


def address_of(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def require_actor(request: Request) -> auth.Actor:
    actor = auth.actor_for(request.app.state.store, request.cookies.get(auth.COOKIE, ""), address_of(request))
    if actor is None:
        raise HTTPException(401, "Sign in required")
    return actor


def require_origin(request: Request) -> None:
    if request.headers.getlist("origin") != [request.app.state.config.origin]:
        raise HTTPException(403, "Unexpected request origin")


def require_write(request: Request, actor: auth.Actor = Depends(require_actor)) -> auth.Actor:
    require_origin(request)
    token = request.headers.get("x-csrf-token", "")
    if not secrets.compare_digest(token.encode(), actor.csrf_token.encode()):
        raise HTTPException(403, "Invalid CSRF token")
    return actor


def require_admin(actor: auth.Actor = Depends(require_actor)) -> auth.Actor:
    if actor.role != "node_admin":
        raise HTTPException(403, "Node administrator required")
    return actor


def require_admin_write(actor: auth.Actor = Depends(require_write)) -> auth.Actor:
    return require_admin(actor)


def idempotency_key(request: Request) -> str:
    keys = request.headers.getlist("idempotency-key")
    if len(keys) != 1 or re.fullmatch(r"[A-Za-z0-9._-]{1,128}", keys[0]) is None:
        raise HTTPException(400, "Provide one valid Idempotency-Key")
    return keys[0]


def session_data(actor: auth.Actor) -> dict:
    result = {"username": actor.username, "csrf_token": actor.csrf_token, "role": actor.role}
    if actor.grove:
        result.update(grove=True, display_name=actor.display_name)
    return result


def set_session(store: State, request: Request, response: Response, session: tuple[str, str]) -> dict[str, str]:
    token, _ = session
    actor = auth.actor_for(store, token, address_of(request))
    if actor is None:
        raise HTTPException(401, "Sign in required")
    response.set_cookie(auth.COOKIE, token, max_age=auth.SESSION_SECONDS, path="/", secure=True, httponly=True, samesite="strict")
    return session_data(actor)


async def passkey_body(request: Request) -> PasskeyResponse:
    require_origin(request)
    raw = bytearray()
    async for chunk in request.stream():
        if len(raw) + len(chunk) > 32 * 1024:
            raise HTTPException(413, "Passkey response exceeds 32 KiB")
        raw.extend(chunk)
    try:
        return PasskeyResponse.model_validate(decode_json(raw))
    except ValueError as exc:
        raise HTTPException(422, "Invalid Passkey response") from exc


async def read_approval(request: Request) -> dict:
    raw = bytearray()
    async for chunk in request.stream():
        if len(raw) + len(chunk) > ENVELOPE_LIMIT:
            raise HTTPException(413, "Approval file exceeds 16 KiB")
        raw.extend(chunk)
    try:
        return RemoteApproval.model_validate(decode_json(raw)).model_dump()
    except ValueError as exc:
        raise HTTPException(422, "Invalid approval file") from exc


async def grove_body(request: Request) -> dict:
    return await read_grove_body(request, 16 * 1024)


async def read_grove_body(request: Request, limit: int) -> dict:
    raw = bytearray()
    async for chunk in request.stream():
        if len(raw) + len(chunk) > limit:
            raise HTTPException(413, 'Grove request exceeds its size limit')
        raw.extend(chunk)
    try:
        return decode_json(raw)
    except ValueError:
        raise HTTPException(422, 'Invalid Grove request') from None


def grove_model(model, data):
    try:
        return model.model_validate(data)
    except ValidationError:
        raise HTTPException(422, 'Invalid Grove request') from None


def create_app(config: Config, *, drivers: dict[str, Driver] | None = None, native_loopback_setup: bool = False) -> FastAPI:
    store = State(config.state_dir)
    node_id, schema = store.verify_schema()
    seeds = SeedDeployments(store, config.seed_targets)
    seeds.recover_confirmed_starts()
    build, packaged_web, package_digest = running_build()
    package = {'package_checksums_sha256': package_digest} if package_digest is not None else {}
    controller = Controller(store, drivers if drivers is not None else {
        "process": process_driver(store), "docker": DockerDriver(config.docker_socket),
    })
    metrics = Metrics(config.state_dir)
    enrollment_policy = mesh_enrollment.load_policy(store)
    route_mode = config.route_mode
    if route_mode is None:
        handoff = None
        if enrollment_policy is None:
            try:
                handoff = onboarding.read_record(store)
            except (OSError, StateError):
                pass
        route_mode = 'adaptive' if enrollment_policy is not None or (handoff and handoff.get('grove_invitation')) else 'legacy'
    remote = PeerServices(store, node_id, controller, config.authority, route_mode=route_mode,
                          neighbor_minimum=config.neighbor_minimum, neighbor_target=config.neighbor_target,
                          dial_enabled=config.mesh_dial_enabled, advertise_ip=config.mesh_advertise_ip,
                          advertise_port=config.mesh_advertise_port)
    peers = remote.manager
    remote.grove_config = config
    remote.seed_deployments = seeds
    wizard = seed_wizard.SeedWizard(store, remote)
    remote.seed_wizard = wizard
    remote.service_setup = service_setup.ServiceSetup(store, node_id, config.docker_socket)
    terminals = TerminalService(store, node_id)
    remote.terminals = terminals
    remote.mesh_enrollment_policy = enrollment_policy
    remote.manager.use_system_egress = bool(enrollment_policy and enrollment_policy.bind_ip)
    host = deployment_host(capabilities(), schema)
    updates = grove_updates.UpdateCoordinator(store, remote, config, build, host)
    remote.grove_updates = updates

    def deployment_status() -> dict:
        return {'build': build, 'web': deployment_web(config.web_dir, packaged_web), 'host': host, **package}

    remote.deployment_status = deployment_status

    async def synchronize_enrollment():
        while True:
            try:
                await run_in_threadpool(wizard.reap_idle)
                await run_in_threadpool(terminals.reap)
                pending_seed = await run_in_threadpool(seed_admission.pending, store)
                if pending_seed is not None:
                    await seed_admission.finish(store, config, remote, pending_seed)
                else:
                    policy = enrollment_policy or await run_in_threadpool(mesh_enrollment.load_policy, store)
                    if policy and policy.bind_ip:
                        remote.manager.use_system_egress = True
                        await run_in_threadpool(mesh_enrollment.enroll, store, config, policy)
            except (PeerError, StateError, OSError, ValueError, KeyError, TypeError, sqlite3.Error) as error:
                logging.getLogger(__name__).debug('Mesh enrollment deferred: %s', error)
            await asyncio.sleep(12)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        with controller.running(), metrics.running():
            async with remote.running():
                task = asyncio.create_task(synchronize_enrollment())
                rollout = asyncio.create_task(updates.run())
                try:
                    yield
                finally:
                    task.cancel()
                    rollout.cancel()
                    await asyncio.gather(task, rollout, return_exceptions=True)
                    wizard.shutdown()
                    await run_in_threadpool(terminals.shutdown)

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.store = store
    app.state.config = config

    @app.middleware("http")
    async def control_headers(request: Request, call_next):
        if request.headers.getlist("host") != [config.authority]:
            return JSONResponse({"detail": "Unexpected Host"}, status_code=400)
        response = await call_next(request)
        if not request.url.path.startswith("/assets/"):
            response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        policy = "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        response.headers["Content-Security-Policy"] = policy + ("; connect-src 'self' https:; style-src 'self' 'unsafe-inline'" if request.url.path == '/' else '')
        return response

    @app.exception_handler(RequestValidationError)
    async def invalid_input(_request: Request, _error: RequestValidationError):
        return JSONResponse({"detail": "Invalid request data"}, status_code=422)

    @app.exception_handler(ControlError)
    async def control_failure(_request: Request, error: ControlError):
        return JSONResponse({"detail": str(error), **({"code": error.code} if error.code else {})}, status_code=error.status)

    @app.exception_handler(TargetAlreadyRegistered)
    async def registration_conflict(_request: Request, error: TargetAlreadyRegistered):
        return JSONResponse({"detail": str(error), "code": "TARGET_ALREADY_REGISTERED",
                             "service_id": error.service_id}, status_code=409)

    @app.exception_handler(auth.LoginLimited)
    async def login_limited(_request: Request, error: auth.LoginLimited):
        return JSONResponse({"detail": "Try again later"}, status_code=429,
                            headers={"Retry-After": str(error.retry_after)})

    @app.exception_handler(auth.FactorReenrollmentRequired)
    async def factor_reenrollment(_request: Request, _error: auth.FactorReenrollmentRequired):
        return JSONResponse({
            "detail": "Enroll a new factor from the local console", "code": "FACTOR_REENROLLMENT_REQUIRED",
        }, status_code=503)

    @app.exception_handler(auth.SessionReauthenticationRequired)
    async def reauthentication_required(_request: Request, _error: auth.SessionReauthenticationRequired):
        return JSONResponse({
            "detail": "Sign in again with a factor before changing factors or revoking sessions",
            "code": "REAUTHENTICATION_REQUIRED",
        }, status_code=403)

    @app.exception_handler(StateError)
    async def state_unavailable(_request: Request, _error: StateError):
        return JSONResponse({"detail": "Local state is unavailable"}, status_code=503)

    @app.exception_handler(PeerError)
    async def peer_failure(_request: Request, error: PeerError):
        status = {
            "NOT_FOUND": 404, "DEPLOYMENT_UNSUPPORTED": 404, "INVALID_REQUEST": 400, "BUSY": 429, "PROTOCOL": 502, "TIMEOUT": 504,
            "DENIED": 403, "CONFLICT": 409, "DIRECTORY_CHANGED": 409, "EXPIRED": 410, "SESSION_REQUIRED": 401,
            "HOST_PERMISSION": 409, "SERVICE_STOPPED": 409, "SERVICE_LOG": 409, "SERVICE_COMMAND": 400,
            "DOCKER_MISSING": 409, "DOCKER_UNAVAILABLE": 409, "DOCKER_PERMISSION": 409,
            "SERVICE_DISCOVERY": 409,
            "TERMINAL_CLOSED": 409, "TERMINAL_IO": 503, "FILE_UNAVAILABLE": 409,
            "REAUTHENTICATION_REQUIRED": 403, "APPROVAL_VERSION_REQUIRED": 409, "POLICY_CONFLICT": 409,
            "GROVE_INVITATION_EXPIRED": 410,
        }.get(error.code, 503)
        return JSONResponse({"detail": str(error), "code": error.code}, status_code=status)

    @app.get("/healthz")
    def health():
        return {"status": "ok"}

    @app.post('/api/v1/mesh/enrollment/{action}')
    def mesh_enroll(action: Literal['vote','issue','register'], request: Request, body: dict = Depends(grove_body)):
        policy = enrollment_policy
        if policy is None or node_id not in policy.voters:
            raise PeerError('NOT_FOUND', 'This panel does not issue Mesh certificates')
        fields = {'request'}
        if action != 'vote':
            fields.add('votes')
        if action == 'register':
            fields.add('certificate')
        if body.keys() != fields:
            raise PeerError('INVALID_REQUEST', 'Invalid Mesh enrollment message')
        proof = body['request']
        data = mesh_enrollment.request_data(policy, proof)
        if action == 'vote':
            return {'vote': mesh_enrollment.vote(store, policy, proof, data)}
        mesh_enrollment.verify_votes(policy, proof, body['votes'])
        if action == 'issue':
            return {'certificate': wire_b64(mesh_enrollment.issue(store, policy, data))}
        source = mesh_enrollment.ingress_source(policy, request.client.host if request.client else '',
                                               request.headers.getlist('x-forwarded-for'))
        try:
            mesh_enrollment.register(store, policy, data, parse_b64(body['certificate'], 8192), source)
        except ValueError as error:
            raise PeerError('DENIED', 'Invalid Mesh enrollment certificate or address') from error
        return {'registered': True}

    @app.get("/api/v1/setup")
    def setup_status(request: Request):
        status = onboarding.status(store)
        if status["required"] and local_setup(request):
            return status | {"browser_setup": True}
        return status

    def local_setup(request: Request) -> bool:
        return (native_loopback_setup and request.url.scheme == "https"
                and onboarding.loopback_host(urlsplit(config.origin).hostname)
                and onboarding.loopback_host(address_of(request))
                and not any(name in request.headers for name in ("forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto")))

    @app.post("/api/v1/setup")
    def finish_setup(body: SetupCredentials, request: Request, response: Response):
        require_origin(request)
        if body.password != body.confirmation:
            raise HTTPException(422, "Passwords do not match")
        if body.grove_name is not None and (not body.grove_name.strip() or not body.grove_name.strip().isprintable()):
            raise HTTPException(422, 'Choose a printable Grove name')
        try:
            session = onboarding.complete(store, body.token, body.username, body.password, address_of(request),
                                          local_browser=local_setup(request))
        except onboarding.SetupUnavailable:
            raise HTTPException(409, "Initial setup is unavailable or the node-owner code expired") from None
        if body.grove_name:
            actor = auth.actor_for(store, session[0], address_of(request))
            grove.create(store, config, body.grove_name, actor)
        return set_session(store, request, response, session)

    @app.get('/api/v1/auth/grove/info')
    def grove_info():
        info = grove.describe(store)
        if info['configured'] and not info['local_issuer']:
            info['member_login'] = grove_login.available(store)
        return info

    @app.post('/api/v1/auth/grove/member-login')
    def grove_member_login(body: GroveCredentials, request: Request, response: Response):
        require_origin(request)
        session = grove_login.login(store, body.username, body.password, body.code, address_of(request))
        if session is None:
            raise HTTPException(401, 'Invalid Grove account or authentication factor')
        return set_session(store, request, response, session)

    @app.get('/api/v1/auth/grove/password')
    def grove_password_status(actor: auth.Actor = Depends(require_actor)):
        return {'available': grove_password.available(store, actor)}

    @app.post('/api/v1/auth/grove/password')
    async def grove_change_password(body: GrovePasswordChange, actor: auth.Actor = Depends(require_write)):
        if secrets.compare_digest(body.current_password.encode(), body.new_password.encode()):
            raise HTTPException(422, 'Choose a different Grove password')
        return await remote.change_grove_password(actor, body.current_password, body.new_password)

    @app.get('/api/v1/grove')
    def grove_details(_actor: auth.Actor = Depends(require_admin)):
        details = grove.describe(store, private=True)
        if details.get('local_issuer'):
            details['continuity_configured'] = len(config.grove_login_replicas) >= 2
        return details

    @app.post('/api/v1/grove/retire-issuer')
    async def retire_grove_issuer(actor: auth.Actor = Depends(require_admin_write)):
        return await remote.retire_grove_issuer(actor, config.grove_continuity_voters or config.grove_login_replicas,
                                               selected=bool(config.grove_continuity_voters))

    @app.get('/api/v1/grove/node-notes')
    def grove_node_notes(_actor: auth.Actor = Depends(require_actor)):
        return grove_metadata.notes(store)

    @app.put('/api/v1/grove/node-notes/{node_id}')
    def set_grove_node_note(node_id: str, request: Request, data: dict = Depends(grove_body), actor: auth.Actor = Depends(require_admin_write)):
        require_origin(request)
        body = grove_model(GroveNodeNote, data)
        return grove_metadata.save_note(store, actor, node_id, body.note)

    @app.post('/api/v1/grove/operators/{user_id}/revoke')
    async def revoke_grove_operator(user_id: str, actor: auth.Actor = Depends(require_admin_write)):
        return await remote.revoke_grove_operator(actor, user_id)

    @app.post('/api/v1/grove/users/{user_id}/role')
    async def approve_grove_role(user_id: str, body: GroveRoleChange, actor: auth.Actor = Depends(require_admin_write)):
        return await remote.approve_grove_role(actor, user_id, body.role)

    @app.post('/api/v1/grove/members/admit')
    async def admit_grove_member(body: GroveMemberAdmission, actor: auth.Actor = Depends(require_admin_write)):
        return await remote.approve_grove_member(actor, body.node_id, body.origin)

    @app.post('/api/v1/grove/join-from-member')
    async def join_grove_from_member(body: GroveMemberSource, actor: auth.Actor = Depends(require_admin_write)):
        return await remote.join_grove_as_member(actor, body.node_id)

    @app.post('/api/v1/grove/join-from-invitation')
    async def join_grove_from_invitation(body: GroveBrowserInvitation, actor: auth.Actor = Depends(require_admin_write)):
        return await remote.join_grove_from_invitation(actor, body.code)

    @app.post('/api/v1/grove/join-with-quorum')
    async def join_grove_with_quorum(request: Request, actor: auth.Actor = Depends(require_admin_write)):
        body = grove_model(GroveQuorumJoin, await read_grove_body(request, grove_quorum_join.LIMIT + 2048))
        credentials = body.credentials.model_dump() if body.credentials else None
        peers.use_system_egress = True
        code = await run_in_threadpool(grove_quorum_join.prepare, store, config, actor, body.invitation, credentials)
        deadline = asyncio.get_running_loop().time() + 18
        while True:
            try:
                result = await remote.join_grove_from_invitation(actor, code)
            except PeerError as error:
                if error.code not in {'GROVE_PAIRING_REQUIRED', 'GROVE_ADMISSION_PENDING'} or asyncio.get_running_loop().time() >= deadline:
                    raise
                await asyncio.sleep(0.5)
            else:
                (store.directory / grove_quorum_join.PENDING).unlink(missing_ok=True)
                return result

    @app.post('/api/v1/auth/grove/quorum-join/{action}')
    def grove_quorum_join_action(action: str, request: Request, data: dict = Depends(grove_body)):
        if enrollment_policy is None:
            raise PeerError('OFFLINE', 'Grove quorum admission is unavailable')
        if action == 'vote' and data.keys() == {'request', 'credentials'}:
            credentials = grove_model(GroveCredentials, data['credentials'])
            return grove_quorum_join.vote(store, enrollment_policy, data['request'], credentials, address_of(request))
        if action == 'commit' and data.keys() == {'request', 'certificate'}:
            return grove_quorum_join.commit(store, enrollment_policy, data['request'], data['certificate'])
        raise PeerError('INVALID_REQUEST', 'Invalid Grove admission request')

    @app.post('/api/v1/grove/sync-directory', responses={204: {'description': 'Checked without a report'}})
    async def grove_sync_directory(report: bool = False, _actor: auth.Actor = Depends(require_admin_write)):
        result = await remote.refresh_grove(report=report)
        if isinstance(result, dict):
            return result
        if result in {'not-configured', 'changed', 'frozen'}:
            raise PeerError('CONFLICT', 'Grove configuration is missing, changed, or awaiting recovery')
        if result == 'unavailable':
            raise PeerError('OFFLINE', 'No current Grove directory could be retrieved')
        return Response(status_code=204)

    @app.get('/api/v1/grove/updates/release')
    async def grove_update_release(actor: auth.Actor = Depends(require_admin)):
        await remote.work(updates.identity, actor)
        return await updates.find_release()

    @app.get('/api/v1/grove/updates')
    def grove_update_status(_actor: auth.Actor = Depends(require_admin)):
        return updates.group_status()

    @app.post('/api/v1/grove/updates', status_code=202)
    async def grove_start_update(body: grove_updates.StartUpdate, actor: auth.Actor = Depends(require_admin_write)):
        return await updates.start(body, actor)

    @app.post('/api/v1/grove/seed-wizard/{source}/{job}/{action}')
    async def seed_wizard_request(source: str, job: str, action: str, request: Request,
                                  actor: auth.Actor = Depends(require_admin_write)):
        if (re.fullmatch(r'spm1-[a-f0-9]{64}', source) is None or not re.fullmatch(r'[a-f0-9]{32}', job)
                or action not in {'start', 'verify', 'directory', 'install', 'status'}):
            raise PeerError('INVALID_REQUEST', 'Invalid seed wizard request')
        body = await read_grove_body(request, 13 * 1024)
        fields = {'start': {'connection'}, 'verify': {'fingerprint'}, 'directory': {'path'}, 'install': {'path'}, 'status': set()}
        if body.keys() != fields[action]:
            raise PeerError('INVALID_REQUEST', 'Invalid seed wizard request body')
        pair = None if source == node_id else remote.pair_for(source)
        try:
            identity = await remote.work(grove_service_admin.source_identity, store, node_id, pair, actor)
        except PeerError as error:
            if error.code == 'OFFLINE':
                raise PeerError('SEED_GROVE_STATE', 'This panel is waiting for a current Grove directory') from error
            raise
        params = body | {'action': action, 'job': job, 'identity': identity,
                         'owner': auth.digest(actor.token_hash.hex()).hex()[:32]}
        if pair is None:
            return await wizard.dispatch(None, params)
        try:
            return await remote.call(source, seed_wizard.METHOD, params, diagnostic=True)
        except PeerError as error:
            if error.code in {'OFFLINE', 'NO_ROUTE', 'ROUTE_LOST', 'TIMEOUT'}:
                raise PeerError('SEED_SOURCE_OFFLINE', 'The selected executor is not reachable over Mesh') from error
            raise

    @app.post('/api/v1/peers/{target}/terminal/{identifier}/{action}')
    async def terminal_request(target: str, identifier: str, action: Literal['open', 'exchange', 'close', 'files'],
                               body: dict = Depends(grove_body), actor: auth.Actor = Depends(require_admin_write)):
        if re.fullmatch(r'[a-f0-9]{32}', identifier) is None:
            raise PeerError('INVALID_REQUEST', 'Invalid terminal session ID')
        owner = auth.digest(actor.token_hash.hex()).hex()[:32]
        if target in ('local', node_id):
            return await remote.work(terminals.request, service_setup.LocalAdmin(actor), node_id, owner, identifier, action, body)
        pair = remote.pair_for(target)
        identity = await remote.work(grove_service_admin.source_identity, store, node_id, pair, actor)
        return await remote.call(target, terminals.method, {'identity': identity, 'owner': owner, 'session': identifier,
                                                           'action': action, 'body': body}, diagnostic=True)

    @app.post('/api/v1/peers/{node_id}/service-setup/{action}')
    async def remote_service_setup(node_id: str, action: Literal['kinds', 'candidates', 'register', 'manage', 'running', 'inspect', 'take-over', 'create'],
                                   body: dict = Depends(grove_body), actor: auth.Actor = Depends(require_admin_write)):
        if node_id in ('local', remote.local_id):
            return await remote.work(remote.service_setup.setup, service_setup.LocalAdmin(actor), action, body)
        pair = remote.pair_for(node_id)
        identity = await remote.work(grove_service_admin.source_identity, store, remote.local_id, pair, actor)
        return await remote.call(node_id, service_setup.METHOD, {'identity': identity, 'action': action, 'body': body},
                                 diagnostic=True)

    @app.get('/api/v1/grove/seed-targets')
    def seed_targets(_actor: auth.Actor = Depends(require_admin)):
        return seeds.list()

    @app.get('/api/v1/grove/seed-targets/from/{node_id}')
    async def seed_targets_from(node_id: str, _actor: auth.Actor = Depends(require_admin)):
        return await remote.seed_catalog(node_id)

    @app.post('/api/v1/grove/seed-targets/{target_id}/check')
    def check_seed(target_id: str, body: SeedCheckRequest | None = None, actor: auth.Actor = Depends(require_admin_write)):
        return seeds.check(target_id, actor, body.revision if body is not None else None)

    @app.post('/api/v1/grove/seed-targets/{target_id}/install', status_code=202)
    def install_seed(target_id: str, body: SeedRequest, tasks: BackgroundTasks,
                     actor: auth.Actor = Depends(require_admin_write)):
        view, target, realm, attempt = seeds.submit(actor, target_id, body.revision, retry_started=body.retry_started)
        tasks.add_task(seeds.install, actor, target, realm, attempt)
        return view

    @app.post('/api/v1/grove')
    def create_grove(body: GroveName, actor: auth.Actor = Depends(require_admin_write)):
        return grove.create(store, config, body.name, actor)

    @app.get('/api/v1/grove/browser-invitation')
    async def browser_invitation(_actor: auth.Actor = Depends(require_admin)):
        info = await run_in_threadpool(grove.describe, store)
        if not info['configured'] or info['frozen'] or info['issuer_paused']:
            raise PeerError('OFFLINE', 'Grove browser invitations are unavailable')
        if info.get('issuer_retired'):
            if enrollment_policy is not None and node_id in enrollment_policy.voters:
                code = await run_in_threadpool(grove_quorum_join.invitation, store, enrollment_policy)
                if code is not None:
                    return {'code': code}
            return {'code': await run_in_threadpool(grove_admission.invitation_code, store)}
        realm = info['realm']
        if info['local_issuer']:
            envelope = await run_in_threadpool(grove_web_join.invitation, store, config, realm['id'])
        else:
            try:
                envelope = await remote.call(realm['issuer_node'], grove_web_join.INVITATION_METHOD,
                                             {'realm_id': realm['id']}, diagnostic=True)
            except PeerError as error:
                if error.code == 'UNSUPPORTED_METHOD':
                    raise PeerError('GROVE_SIGNER_UPGRADE_REQUIRED', 'The original signer does not support browser invitations') from error
                if error.code in {'NOT_FOUND', 'OFFLINE', 'TIMEOUT', 'ROUTE_LOST', 'DENIED'}:
                    raise PeerError('GROVE_SIGNER_REQUIRED', 'This Grove still requires the original signer to issue invitations') from error
                raise
        code = grove_web_join.invitation_code(envelope, config.origin)
        if grove_web_join.read_invitation(code, config.origin)['realm'] != realm:
            raise PeerError('DENIED', 'Invitation belongs to another Grove')
        return {'code': code}

    @app.post('/api/v1/auth/grove/invitation/candidates')
    def grove_invitation_candidates(request: Request, data: dict = Depends(grove_body)):
        require_origin(request)
        body = grove_model(GroveBrowserInvitation, data)
        return grove_web_join.read_invitation(body.code, config.origin)

    @app.get('/api/v1/auth/grove/verification-status')
    async def grove_verification_status(
        realm_id: str = Query(pattern=r'^grv1-[a-f0-9]{32}$'),
        public_key: str = Query(pattern=r'^[A-Za-z0-9_-]{43}$'),
    ):
        info = await run_in_threadpool(grove.describe, store)
        realm = info.get('realm')
        if realm is None or realm['id'] != realm_id or realm['public_key'] != public_key:
            raise PeerError('NOT_FOUND', 'Grove is unavailable on this panel')
        if info.get('issuer_retired') or info['frozen'] or info['issuer_paused']:
            raise PeerError('OFFLINE', 'Grove browser joins are unavailable')
        if not info['local_issuer'] and (
            not await run_in_threadpool(grove_login.available, store) or remote.connection_for(realm['issuer_node']) is None
        ):
            raise PeerError('OFFLINE', 'This member is waiting for its verifier or issuer Mesh path')
        return JSONResponse({'realm_id': realm_id, 'public_key': public_key, 'origin': config.origin, 'ready': True},
                            headers={'Access-Control-Allow-Origin': '*'})

    @app.post('/api/v1/auth/grove/start')
    def grove_start(request: Request, response: Response, data: dict = Depends(grove_body)):
        require_origin(request)
        body = grove_model(GroveStart, data)
        directory_origins = None
        if body.invitation_code is not None:
            invite = grove_web_join.read_invitation(body.invitation_code, config.origin)
            if body.kind != 'join' or body.realm != invite['realm'] or body.verification_origin not in invite['origins']:
                raise PeerError('DENIED', 'Select a verifier advertised in the Grove invitation')
            directory_origins = sorted(invite['origins'], key=lambda candidate: candidate != body.verification_origin)
        actor = auth.actor_for(store, request.cookies.get(auth.COOKIE, ''), address_of(request))
        if actor is not None:
            require_write(request, actor)
        target, browser = grove.start(store, config, body.kind, address_of(request), realm=body.realm,
                                      setup_token=body.setup_token, actor=actor, local_browser=local_setup(request),
                                      verification_origin=body.verification_origin, directory_origins=directory_origins)
        response.set_cookie(grove.COOKIE, browser, max_age=grove.FLOW_TTL, secure=True, httponly=True, samesite='lax', path='/')
        return {'authorize_url': target}

    @app.post('/api/v1/auth/grove/inspect')
    def grove_inspect(data: dict = Depends(grove_body), actor: auth.Actor = Depends(require_write)):
        body = grove_model(GroveRequest, data)
        if 'verification_origin' in grove.request_data(body.request):
            return grove_web_join.inspect(store, config, body.request, actor)
        return grove.inspect(store, body.request, actor)

    @app.post('/api/v1/auth/grove/join-destination')
    def grove_join_destination(request: Request, data: dict = Depends(grove_body)):
        require_origin(request)
        body = grove_model(GroveRequest, data)
        join_request = grove.request_data(body.request)
        info = grove.describe(store)
        if (join_request.get('verification_origin') != config.origin or not info['configured']
                or join_request['realm_id'] != info['realm']['id'] or info.get('issuer_retired')):
            raise PeerError('DENIED', 'This panel is not the Grove member selected for the request')
        if not grove_login.available(store):
            raise PeerError('OFFLINE', 'This member has no current Grove login verifiers')
        return {'name': info['realm']['name']}

    @app.post('/api/v1/auth/grove/approve')
    async def grove_approve(data: dict = Depends(grove_body), actor: auth.Actor = Depends(require_write)):
        body = grove_model(GroveRequest, data)
        parsed = grove.request_data(body.request)
        if 'verification_origin' not in parsed:
            return {'redirect_url': await run_in_threadpool(grove.approve, store, body.request, actor)}
        realm, join_request, params = await run_in_threadpool(grove_web_join.verification, store, config, body.request, actor)
        result = await remote.call(realm['issuer_node'], grove_web_join.METHOD, params, diagnostic=True)
        redirect = result.get('redirect_url')
        prefix = join_request['origin'] + '/#/grove-return/'
        if not isinstance(redirect, str) or not redirect.startswith(prefix) or re.fullmatch(
            r'[A-Za-z0-9_-]{1,12000}', redirect[len(prefix):]
        ) is None:
            raise PeerError('INVALID_REQUEST', 'Unexpected browser join response')
        return {'redirect_url': redirect}

    @app.post('/api/v1/auth/grove/finish')
    def grove_finish(request: Request, response: Response, tasks: BackgroundTasks, data: dict = Depends(grove_body)):
        require_origin(request)
        body = grove_model(GroveRequest, data)
        session, joined = grove.finish(store, config, body.request, request.cookies.get(grove.COOKIE, ''), address_of(request))
        response.delete_cookie(grove.COOKIE, secure=True, httponly=True, samesite='lax', path='/')
        result = set_session(store, request, response, session)
        if joined:
            tasks.add_task(remote.request_grove_sync)
        return result

    @app.post('/api/v1/auth/grove/directory')
    def grove_directory(data: dict = Depends(grove_body)):
        body = grove_model(GroveRequest, data)
        return grove.directory_reply(store, body.request)

    @app.post('/api/v1/grove/members/{node_id}/disable', status_code=204)
    def grove_disable_member(node_id: str, actor: auth.Actor = Depends(require_admin_write)):
        grove.set_member(store, actor, node_id, False)

    @app.get("/api/v1/auth/first-factor")
    def first_factor_info(actor: auth.Actor = Depends(require_actor)):
        status = auth.first_factor_status(store, actor)
        try:
            passkeys.relying_party(config.origin)
            status["passkey_available"] = not status["grove_totp"]
        except StateError:
            status["passkey_available"] = False
        return status

    @app.post("/api/v1/auth/first-factor")
    def first_factor_begin(body: FirstFactorRequest, actor: auth.Actor = Depends(require_write)):
        if body.method == "passkey":
            passkeys.relying_party(config.origin)
        try:
            return auth.begin_first_factor(store, actor, body.method)
        except auth.FirstFactorUnavailable:
            raise HTTPException(409, "Initial authenticator setup is unavailable for this account") from None

    @app.post("/api/v1/session")
    def create_session(credentials: Credentials, request: Request, response: Response):
        require_origin(request)
        enrollment_actor = None
        if credentials.enrollment_token is not None:
            enrollment_actor = auth.actor_for(store, request.cookies.get(auth.COOKIE, ""), address_of(request))
            if enrollment_actor is not None:
                require_write(request, enrollment_actor)
        session = auth.login(
            store, credentials.username, credentials.password, address_of(request),
            enrollment_token=credentials.enrollment_token, enrollment_actor=enrollment_actor,
        )
        if session is None:
            raise HTTPException(401, "Invalid username or password")
        if isinstance(session, auth.LoginFlow):
            response.status_code = 202
            return session
        return set_session(store, request, response, session)

    @app.post("/api/v1/auth/totp/finish")
    def totp_finish(body: TotpResponse, request: Request, response: Response):
        require_origin(request)
        result = auth.finish_totp(store, body.flow_id, body.code, address_of(request))
        if result is None:
            raise HTTPException(401, "Invalid or expired verification")
        _, session = result
        return set_session(store, request, response, session)

    @app.post("/api/v1/auth/recovery/finish")
    def recovery_finish(body: RecoveryResponse, request: Request):
        require_origin(request)
        flow = auth.finish_recovery(store, body.flow_id, body.code, address_of(request))
        if flow is None:
            raise HTTPException(401, "Invalid or expired recovery")
        return flow

    @app.post("/api/v1/auth/totp/register/options")
    def totp_options(body: FactorFlow, request: Request):
        require_origin(request)
        uri = auth.totp_rebind_options(store, body.flow_id, address_of(request), config.authority)
        if uri is None:
            raise HTTPException(401, "Invalid or expired enrollment")
        return {"provisioning_uri": uri}

    @app.post("/api/v1/auth/totp/register/finish")
    def totp_register(body: TotpResponse, request: Request):
        require_origin(request)
        codes = auth.finish_totp_rebind(store, body.flow_id, body.code, address_of(request))
        if codes is None:
            raise HTTPException(401, "Invalid or expired verification")
        return {"recovery_codes": codes}

    @app.post("/api/v1/auth/passkey/options")
    def passkey_options(body: PasskeyOptionsRequest, request: Request):
        require_origin(request)
        return passkeys.login_options(store, body.username, address_of(request), config.origin)

    @app.post("/api/v1/auth/passkey/finish")
    def passkey_finish(request: Request, response: Response, body: PasskeyResponse = Depends(passkey_body)):
        result = passkeys.finish_login(store, body.flow_id, body.credential, address_of(request), config.origin)
        if result is None:
            raise HTTPException(401, "Invalid or expired Passkey verification")
        _, session = result
        return set_session(store, request, response, session)

    @app.post("/api/v1/auth/passkey/register/options")
    def passkey_register_options(body: FactorFlow, request: Request):
        require_origin(request)
        options = passkeys.register_options(store, body.flow_id, address_of(request), config.origin)
        if options is None:
            raise HTTPException(401, "Invalid or expired enrollment")
        return {"public_key": options}

    @app.post("/api/v1/auth/passkey/register/finish")
    def passkey_register_finish(request: Request, body: PasskeyResponse = Depends(passkey_body)):
        codes = passkeys.finish_registration(store, body.flow_id, body.credential, address_of(request), config.origin)
        if codes is None:
            raise HTTPException(401, "Invalid or expired Passkey enrollment")
        return {"recovery_codes": codes}

    @app.get("/api/v1/session")
    def session_info(actor: auth.Actor = Depends(require_actor)):
        return session_data(actor)

    @app.delete("/api/v1/session", status_code=204)
    def delete_session(actor: auth.Actor = Depends(require_write)):
        auth.logout(store, actor)
        response = Response(status_code=204)
        response.delete_cookie(auth.COOKIE, path="/", secure=True, httponly=True, samesite="strict")
        return response

    @app.get("/api/v1/sessions")
    def sessions(actor: auth.Actor = Depends(require_actor)):
        rows = auth.list_sessions(store, actor)
        if rows is None:
            raise HTTPException(401, "Sign in required")
        return rows

    @app.delete("/api/v1/sessions/{session_id}", status_code=204)
    def revoke_session(session_id: str, actor: auth.Actor = Depends(require_write)):
        revoked_current = auth.revoke_session(store, actor, session_id)
        if revoked_current is None:
            raise HTTPException(404, "Unknown session")
        response = Response(status_code=204)
        if revoked_current:
            response.delete_cookie(auth.COOKIE, path="/", secure=True, httponly=True, samesite="strict")
        return response

    @app.get("/api/v1/node")
    def node(_actor: auth.Actor = Depends(require_actor)):
        return {"node_id": node_id, "platform": capabilities(), "build": build, "deployment_host": host, **package}

    @app.get('/api/v1/node/web-bundle')
    def node_web_bundle(include_deployment: bool = False, _actor: auth.Actor = Depends(require_admin)):
        if include_deployment:
            sample = deployment_status()
            return {**sample['web'], 'deployment': {'node_id': node_id, 'origin': config.origin,
                                                    'build': sample['build'], 'host': sample['host'], **package}}
        return deployment_web(config.web_dir, packaged_web)

    @app.get('/api/v1/grove/deployments/{node_id}')
    async def peer_deployment(node_id: str, _actor: auth.Actor = Depends(require_admin)):
        return await remote.peer_deployment(node_id)

    @app.get('/api/v1/grove/deployments/{node_id}/member-directory')
    async def peer_deployment_directory(node_id: str, _actor: auth.Actor = Depends(require_admin)):
        return await remote.peer_deployment_directory(node_id)

    def peer_rows():
        return remote.statuses() or ([peers.status] if peers.status["status"] == "error" else [])

    @app.get("/api/v1/peers")
    async def peer_status(watch: bool = False, _actor: auth.Actor = Depends(require_admin)):
        if watch and remote.adaptive:
            remote.adaptive.watch_statuses()
        return peer_rows()

    @app.get("/api/v1/mesh/overview")
    async def mesh_overview(actor: auth.Actor = Depends(require_admin)):
        if remote.adaptive:
            remote.adaptive.watch_statuses()
        directories = await remote.visible_directories(actor)
        return {"peers": peer_rows(), "directories": directories}

    @app.get("/api/v1/peers/{node_id}/ping")
    async def peer_ping(node_id: str, response: Response, _actor: auth.Actor = Depends(require_admin)):
        if node_id not in peers.pairs:
            raise HTTPException(404, "Unknown peer")
        try:
            started = perf_counter()
            result = await remote.call(node_id, "peer.ping", {}, diagnostic=True)
            response.headers["Server-Timing"] = f"peer;dur={(perf_counter() - started) * 1000:.3f}"
            return result
        except PeerError as exc:
            raise HTTPException(503, str(exc)) from exc

    @app.post("/api/v1/peers/{node_id}/quarantine")
    def quarantine_peer(node_id: str, body: LocalQuarantine, actor: auth.Actor = Depends(require_admin_write)):
        return {'local_quarantine': quarantine.set_state(store, node_id, body.reason,
                                                         actor=actor.operation_actor, source=actor.address)}

    @app.delete("/api/v1/peers/{node_id}/quarantine")
    def release_peer(node_id: str, actor: auth.Actor = Depends(require_admin_write)):
        return {'local_quarantine': quarantine.set_state(store, node_id, None,
                                                         actor=actor.operation_actor, source=actor.address)}

    @app.get("/api/v1/peers/{node_id}/route")
    async def peer_route(node_id: str, probe: bool = False, _actor: auth.Actor = Depends(require_admin)):
        failure = {}
        if probe:
            candidate = remote.routing.lookup(node_id)
            try:
                route = await remote.verify_route(node_id)
                selected = True
            except PeerError as error:
                route = remote.routing.lookup(node_id) or candidate
                if route is None:
                    raise
                selected = False
                failure = {'connection_error': {'code': error.code, 'detail': str(error)}}
        else:
            binding = remote.adaptive.active.get(node_id) if remote.adaptive else None
            selected = bool(binding and remote.adaptive.live(binding))
            route = binding.route if selected else await remote.routing.find(node_id)
        return {**route.public_data(), 'business_session_selected': selected,
                'diagnostics': remote.adaptive.status(node_id) if remote.adaptive else None,
                'discovery': remote.routing.status(), **failure}

    @app.get("/api/v1/peers/{node_id}/services")
    async def remote_services(node_id: str, refresh: bool = False, actor: auth.Actor = Depends(require_admin)):
        return await remote.grove_directory(actor, await remote.directory(node_id, refresh=refresh))

    @app.get("/api/v1/services/remote")
    async def remote_service_directory(actor: auth.Actor = Depends(require_admin)):
        return await remote.visible_directories(actor)

    @app.get("/api/v1/peers/{node_id}/services/{service_id}/status")
    async def remote_status(node_id: str, service_id: str,
                            connection_id: str | None = Query(None, pattern=r"^[a-f0-9]{32}$"),
                            directory_generation: int | None = Query(None, ge=0, le=2**53 - 1),
                            actor: auth.Actor = Depends(require_admin)):
        result = await remote.grove_service(node_id, actor, 'status', {'service_id': service_id},
                                           connection_id=connection_id, directory_generation=directory_generation)
        if result is not None:
            return result
        return await remote.status(node_id, service_id, connection_id=connection_id, directory_generation=directory_generation)

    @app.get("/api/v1/peers/{node_id}/services/{service_id}/logs")
    async def remote_logs(node_id: str, service_id: str, tail: int = Query(200, ge=1, le=500),
                          connection_id: str | None = Query(None, pattern=r"^[a-f0-9]{32}$"),
                          directory_generation: int | None = Query(None, ge=0, le=2**53 - 1),
                          actor: auth.Actor = Depends(require_admin)):
        result = await remote.grove_service(node_id, actor, 'logs', {'service_id': service_id, 'tail': tail},
                                           connection_id=connection_id, directory_generation=directory_generation)
        if result is not None:
            return parse_logs(result)
        return await remote.logs(node_id, service_id, tail, connection_id=connection_id, directory_generation=directory_generation)

    @app.get("/api/v1/peers/{node_id}/services/{service_id}/actions")
    async def remote_account_actions(node_id: str, service_id: str,
                                     connection_id: str | None = Query(None, pattern=r"^[a-f0-9]{32}$"),
                                     directory_generation: int | None = Query(None, ge=0, le=2**53 - 1),
                                     explain: bool = False,
                                     service_version: int | None = Query(None, ge=1, le=2**63 - 1),
                                     actor: auth.Actor = Depends(require_admin)):
        result = await remote.grove_service(node_id, actor, 'actions', {'service_id': service_id, 'service_version': service_version},
                                           connection_id=connection_id, directory_generation=directory_generation)
        if result is not None:
            return result if explain else {'actions': result['actions']}
        return await remote.account_actions(node_id, service_id, connection_id=connection_id, explain=explain,
                                            service_version=service_version, directory_generation=directory_generation)

    @app.post("/api/v1/peers/{node_id}/services/{service_id}/actions", status_code=202)
    async def remote_account_action(node_id: str, service_id: str, body: RemoteAction,
                                    connection_id: str | None = Query(None, pattern=r"^[a-f0-9]{32}$"),
                                    directory_generation: int | None = Query(None, ge=0, le=2**53 - 1),
                                    actor: auth.Actor = Depends(require_admin_write), key: str = Depends(idempotency_key)):
        return await remote.account_action(node_id, service_id, body.model_dump(), key, actor,
                                           connection_id=connection_id, directory_generation=directory_generation)

    @app.get("/api/v1/peers/{node_id}/services/{service_id}/actions/request")
    async def remote_account_receipt(node_id: str, service_id: str,
                                     actor: auth.Actor = Depends(require_admin), key: str = Depends(idempotency_key)):
        return await remote.account_receipt(node_id, service_id, key, actor)

    async def frp_dispatch(actor: auth.Actor, method: str, service_id: str, *, node_id: str | None = None,
                           key: str | None = None, options: dict | None = None):
        params = {'service_id': service_id, **(options or {})}
        if key is not None:
            params['request_id'] = frp_access.request_id(actor, key)
        frp_access.validate(method, params)
        if node_id is not None:
            return await remote.frp_request(node_id, method, params, actor)
        return await remote.work(frp_access.handle, store, remote.local_id, actor, method, params)

    @app.get("/api/v1/frp/exposures")
    def frp_exposures(_actor: auth.Actor = Depends(require_admin)):
        return list_exposures(store, include_service_names=True)

    @app.get("/api/v1/services/{service_id}/frp")
    async def frp_view(service_id: str, actor: auth.Actor = Depends(require_admin)):
        return await frp_dispatch(actor, 'frp.view', service_id)

    @app.post("/api/v1/services/{service_id}/frp", status_code=202)
    async def frp_start(service_id: str, body: FrpStart, actor: auth.Actor = Depends(require_admin_write),
                        key: str = Depends(idempotency_key)):
        return await frp_dispatch(actor, 'frp.start', service_id, key=key, options=body.model_dump())

    @app.post("/api/v1/services/{service_id}/frp/{exposure_id}/revoke", status_code=202)
    async def frp_revoke(service_id: str, exposure_id: str, actor: auth.Actor = Depends(require_admin_write),
                         key: str = Depends(idempotency_key)):
        return await frp_dispatch(actor, 'frp.revoke', service_id, key=key, options={'exposure_id': exposure_id})

    @app.get("/api/v1/services/{service_id}/frp/requests/{key}")
    async def frp_receipt(service_id: str, key: str, actor: auth.Actor = Depends(require_admin)):
        return await frp_dispatch(actor, 'frp.receipt', service_id, key=key)

    @app.get("/api/v1/peers/{node_id}/services/{service_id}/frp")
    async def remote_frp_view(node_id: str, service_id: str, actor: auth.Actor = Depends(require_admin)):
        return await frp_dispatch(actor, 'frp.view', service_id, node_id=node_id)

    @app.post("/api/v1/peers/{node_id}/services/{service_id}/frp", status_code=202)
    async def remote_frp_start(node_id: str, service_id: str, body: FrpStart,
                               actor: auth.Actor = Depends(require_admin_write), key: str = Depends(idempotency_key)):
        return await frp_dispatch(actor, 'frp.start', service_id, node_id=node_id, key=key, options=body.model_dump())

    @app.post("/api/v1/peers/{node_id}/services/{service_id}/frp/{exposure_id}/revoke", status_code=202)
    async def remote_frp_revoke(node_id: str, service_id: str, exposure_id: str,
                                actor: auth.Actor = Depends(require_admin_write), key: str = Depends(idempotency_key)):
        return await frp_dispatch(actor, 'frp.revoke', service_id, node_id=node_id, key=key,
                                  options={'exposure_id': exposure_id})

    @app.get("/api/v1/peers/{node_id}/services/{service_id}/frp/requests/{key}")
    async def remote_frp_receipt(node_id: str, service_id: str, key: str, actor: auth.Actor = Depends(require_admin)):
        return await frp_dispatch(actor, 'frp.receipt', service_id, node_id=node_id, key=key)

    @app.post("/api/v1/peers/{node_id}/services/{service_id}/operation-prepare")
    async def remote_prepare(node_id: str, service_id: str, body: RemoteIntent,
                             _actor: auth.Actor = Depends(require_admin_write)):
        return await remote.prepare(node_id, service_id, body.model_dump())

    @app.post("/api/v1/peers/{node_id}/services/{service_id}/operation-submit", status_code=202)
    async def remote_submit(node_id: str, service_id: str, request: Request,
                            _actor: auth.Actor = Depends(require_admin_write)):
        return await remote.submit(node_id, service_id, await read_approval(request))

    @app.get("/api/v1/peers/{node_id}/services/{service_id}/operations")
    async def remote_operations(node_id: str, service_id: str, request_id: str | None = Query(None, pattern=r"^[a-f0-9]{32}$"),
                                _actor: auth.Actor = Depends(require_admin)):
        return await remote.history(node_id, service_id, request_id=request_id)

    @app.get("/api/v1/peers/{node_id}/services/{service_id}/operations/{request_id}")
    async def remote_receipt(node_id: str, service_id: str, request_id: str, _actor: auth.Actor = Depends(require_admin)):
        return await remote.get_operation(node_id, service_id, request_id)

    @app.get("/api/v1/operations/remote")
    async def recent_remote_operations(pending: bool = False, actor: auth.Actor = Depends(require_admin)):
        return await remote.work(remote.outbound.recent_history, actor, None, pending)

    @app.get("/api/v1/operations/remote/review")
    async def remote_operations_for_review(actor: auth.Actor = Depends(require_admin)):
        return await remote.work(partial(remote.outbound.recent_history, review_only=True), actor)

    @app.get("/api/v1/operations/remote/{node_id}/{service_id}/{request_id}")
    async def saved_remote_operation(node_id: str, service_id: str, request_id: str,
                                     actor: auth.Actor = Depends(require_admin)):
        if (re.fullmatch(r"spm1-[a-f0-9]{64}", node_id) is None
                or any(re.fullmatch(r"[a-f0-9]{32}", value) is None for value in (service_id, request_id))):
            raise HTTPException(404, "Unknown remote operation")
        rows = await remote.work(remote.outbound.recent_history, actor, (node_id, service_id, request_id))
        if not rows:
            raise HTTPException(404, "Unknown remote operation")
        return rows[0]

    @app.get("/api/v1/mesh/services")
    async def mesh_services(actor: auth.Actor = Depends(require_actor)):
        return await remote.scoped_services(actor)

    @app.post("/api/v1/mesh/peers/{node_id}/services/{service_id}/operation-prepare")
    async def mesh_prepare(node_id: str, service_id: str, body: RemoteIntent, actor: auth.Actor = Depends(require_write)):
        return await remote.prepare(node_id, service_id, body.model_dump(), actor)

    @app.post("/api/v1/mesh/peers/{node_id}/services/{service_id}/operation-submit", status_code=202)
    async def mesh_submit(node_id: str, service_id: str, request: Request, actor: auth.Actor = Depends(require_write)):
        return await remote.submit(node_id, service_id, await read_approval(request), actor)

    @app.get("/api/v1/mesh/peers/{node_id}/services/{service_id}/operations")
    async def mesh_history(node_id: str, service_id: str, actor: auth.Actor = Depends(require_actor)):
        return await remote.history(node_id, service_id, actor)

    @app.get("/api/v1/mesh/peers/{node_id}/services/{service_id}/operations/{request_id}")
    async def mesh_receipt(node_id: str, service_id: str, request_id: str, actor: auth.Actor = Depends(require_actor)):
        return await remote.get_operation(node_id, service_id, request_id, actor)

    @app.get("/api/v1/mesh/operation-audit")
    def mesh_operation_audit(limit: int = Query(100, ge=1, le=200), _actor: auth.Actor = Depends(require_admin)):
        with store.connect() as db:
            rows = db.execute("SELECT * FROM peer_operation_audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]

    @app.get("/api/v1/metrics")
    def host_metrics(_actor: auth.Actor = Depends(require_admin)):
        return metrics.snapshot()

    @app.get("/api/v1/metrics/trend")
    def host_metric_trend(_actor: auth.Actor = Depends(require_admin)):
        return metrics.trend()

    @app.get('/api/v1/security/evidence')
    def security_evidence(before: int | None = Query(default=None, ge=1, lt=2**63),
                          limit: int = Query(20, ge=1, le=100), _actor: auth.Actor = Depends(require_admin)):
        page = evidence.list_conflicts(store, before=before, limit=limit)
        shared = evidence_exchange.local_shares(store)
        return {'conflicts': [{**row, 'term': str(row['term']), 'shared_until': (shared or {}).get(row['term'])}
                              for row in page['conflicts']],
                'next_before': str(page['next_before']) if page['next_before'] is not None else None,
                'can_share': shared is not None}

    @app.get('/api/v1/security/evidence/inbox')
    def evidence_inbox(_actor: auth.Actor = Depends(require_admin)):
        return [{**row, 'term': str(row['term'])} for row in evidence_exchange.inbox(store)]

    @app.get('/api/v1/security/evidence/inbox/{observer}/{proof_id}')
    def evidence_inbox_download(observer: str, proof_id: str, _actor: auth.Actor = Depends(require_admin)):
        document = evidence_exchange.received_report(store, observer, proof_id)
        return JSONResponse(document, headers={
            'Content-Disposition': f'attachment; filename="spearmint-{proof_id}.json"',
        })

    @app.get('/api/v1/security/evidence/{term}')
    def evidence_download(term: int, _actor: auth.Actor = Depends(require_admin)):
        if not 1 <= term < 2**63:
            raise HTTPException(422, 'Invalid policy term')
        document = evidence.export_report(store, term)
        return JSONResponse(document, headers={
            'Content-Disposition': f'attachment; filename="spearmint-policy-conflict-{term}.json"',
        })

    @app.post('/api/v1/security/evidence/{term}/share')
    def share_evidence(term: int, actor: auth.Actor = Depends(require_admin_write)):
        return evidence_exchange.set_share(store, term, True, actor.operation_actor, actor.address)

    @app.delete('/api/v1/security/evidence/{term}/share')
    def unshare_evidence(term: int, actor: auth.Actor = Depends(require_admin_write)):
        return evidence_exchange.set_share(store, term, False, actor.operation_actor, actor.address)

    @app.get('/api/v1/peers/{node_id}/evidence')
    async def shared_peer_evidence(node_id: str, before: int | None = Query(default=None, ge=1, lt=2**63),
                                   _actor: auth.Actor = Depends(require_admin)):
        page = await remote.shared_evidence(node_id, before)
        return {'reports': [{**row, 'term': str(row['term'])} for row in page['reports']],
                'next_before': str(page['next_before']) if page['next_before'] is not None else None}

    @app.post('/api/v1/peers/{node_id}/evidence/{term}')
    async def receive_peer_evidence(node_id: str, term: int, actor: auth.Actor = Depends(require_admin_write)):
        if not 1 <= term < 2**63:
            raise HTTPException(422, 'Invalid policy term')
        return await remote.receive_evidence(node_id, term, actor)

    @app.get("/api/v1/audit")
    def audit_events(limit: int = Query(20, ge=1, le=200), _actor: auth.Actor = Depends(require_admin)):
        with store.connect() as db:
            rows = db.execute(
                """SELECT audit.id, recorded_at, audit.actor, audit.source, event, target, reason, count,
                          operation.service_id
                   FROM audit LEFT JOIN operation ON audit.target=operation.id AND audit.event LIKE 'operation.%'
                   ORDER BY recorded_at DESC, audit.id DESC LIMIT ?""", (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    @app.get("/api/v1/services")
    def services(_actor: auth.Actor = Depends(require_admin)):
        return [{**controller.describe(service), 'approval_required': False} for service in list_services(store)]

    @app.get("/api/v1/services/systemd-units")
    def systemd_units(_actor: auth.Actor = Depends(require_admin)):
        registered = {item.target for item in list_services(store, "process") if item.existing_systemd_unit}
        return {"units": sorted(SystemUnitDriver.allowed_units() - registered)}

    @app.get("/api/v1/services/systemd-units/candidate")
    def systemd_candidate(unit: str = Query(min_length=1, max_length=128), _actor: auth.Actor = Depends(require_admin)):
        if unit not in SystemUnitDriver.allowed_units():
            raise HTTPException(403, "This systemd unit is outside the node's configured list")
        try:
            properties = SystemUnitDriver.configured_unit(unit)
        except HostError:
            return {"readable": False, "reason": "unit_unavailable"}
        status = {"active": "running", "inactive": "stopped", "failed": "failed", "activating": "starting",
                  "deactivating": "stopping", "reloading": "starting", "refreshing": "starting"}
        return {"readable": True, "status": status.get(properties.get("ActiveState"), "unknown")}

    @app.post("/api/v1/services/systemd-units", status_code=201)
    def register_unit(body: SystemdRegistration, actor: auth.Actor = Depends(require_admin_write)):
        if body.unit not in SystemUnitDriver.allowed_units():
            raise HTTPException(403, "This systemd unit is outside the node's configured list")
        with store.lock("maintenance.lock", exclusive_now=True):
            try:
                service = SystemUnitDriver.register(store, body.name, body.unit, actor=actor.operation_actor, source=actor.address)
            except TargetAlreadyRegistered:
                raise
            except RegistrationError as error:
                raise HTTPException(409, str(error)) from error
            except HostError as error:
                raise HTTPException(409, "Cannot identify the configured systemd service") from error
        return {"id": service.id}

    @app.get("/api/v1/services/docker-containers")
    def docker_containers(_actor: auth.Actor = Depends(require_admin)):
        registered = {service.target for service in list_services(store, "docker")}
        try:
            return DockerDriver(config.docker_socket).available_containers(registered)
        except HostError as error:
            raise HTTPException(503, str(error)) from error

    @app.get("/api/v1/services/docker-containers/resolve")
    def resolve_docker_container(container: str = Query(pattern=f"^{CONTAINER_REFERENCE}$"),
                                 _actor: auth.Actor = Depends(require_admin)):
        try:
            return {"id": DockerDriver(config.docker_socket).resolve(container)}
        except ContainerNotFound as error:
            raise HTTPException(404, str(error)) from error
        except HostError as error:
            raise HTTPException(503, str(error)) from error

    @app.get("/api/v1/services/windows-services")
    def windows_services(_actor: auth.Actor = Depends(require_admin)):
        registered = {item.target for item in list_services(store, "process") if item.existing_windows_service}
        try:
            allowed = WindowsServiceDriver(store).allowed_services()
        except HostError as error:
            raise HTTPException(503, str(error)) from error
        return {"services": [name for key, name in sorted(allowed.items()) if key not in registered]}

    @app.get("/api/v1/services/windows-services/candidate")
    def windows_candidate(service: str = Query(min_length=1, max_length=256), _actor: auth.Actor = Depends(require_admin)):
        driver = WindowsServiceDriver(store)
        target = service.lower()
        try:
            allowed = driver.allowed_services()
        except HostError as error:
            raise HTTPException(503, str(error)) from error
        if target not in allowed:
            raise HTTPException(403, "This Windows service is outside the node's configured list")
        try:
            observed = driver.observe_target(target)
        except ServiceManagerError as error:
            return {"readable": False, "reason": error.reason}
        except HostError:
            return {"readable": False, "reason": "query_failed"}
        return {"readable": True, "status": observed.status}

    @app.post("/api/v1/services/windows-services", status_code=201)
    def register_windows_service(body: WindowsServiceRegistration, actor: auth.Actor = Depends(require_admin_write)):
        with store.lock("maintenance.lock", exclusive_now=True):
            driver = WindowsServiceDriver(store)
            try:
                allowed = driver.allowed_services()
            except HostError as error:
                raise HTTPException(503, str(error)) from error
            if body.service.lower() not in allowed:
                raise HTTPException(403, "This Windows service is outside the node's configured list")
            try:
                service = driver.register(body.name, body.service, actor=actor.operation_actor, source=actor.address)
            except TargetAlreadyRegistered:
                raise
            except (RegistrationError, HostError) as error:
                raise HTTPException(409, str(error)) from error
        return {"id": service.id}

    @app.post("/api/v1/services/docker-containers", status_code=201)
    def register_container(body: DockerRegistration, actor: auth.Actor = Depends(require_admin_write)):
        with store.lock("maintenance.lock", exclusive_now=True):
            try:
                service = DockerDriver(config.docker_socket).register(
                    store, body.name, body.container, actor=actor.operation_actor, source=actor.address)
            except TargetAlreadyRegistered:
                raise
            except RegistrationError as error:
                raise HTTPException(409, str(error)) from error
            except ContainerNotFound as error:
                raise HTTPException(404, str(error)) from error
            except HostError as error:
                raise HTTPException(503, str(error)) from error
        return {"id": service.id}

    @app.get("/api/v1/services/{service_id}")
    def service_detail(service_id: str, actor: auth.Actor = Depends(require_admin)):
        with store.connect(read_only=True) as db:
            db.execute("BEGIN")
            service = get_service(db, service_id)
            if service is None:
                raise HTTPException(404, "Unknown service ID")
            rows = db.execute(
                "SELECT * FROM operation WHERE service_id=? AND actor=? ORDER BY rowid DESC LIMIT 12",
                (service_id, actor.operation_actor),
            ).fetchall()
            protected = db.execute('SELECT 1 FROM service_protection WHERE service_id=?', (service_id,)).fetchone() is not None
            operations = [operation_data(row, db=db) for row in rows]
        return {**controller.describe(service), "operations": operations,
                'can_edit_details': True,
                'approval_required': False,
                'can_unregister': not protected and (service.driver == 'docker' or service.existing_system_service)}

    @app.put("/api/v1/services/{service_id}/details")
    def edit_service_details(service_id: str, body: ServiceDetails, actor: auth.Actor = Depends(require_admin_write)):
        with store.lock("maintenance.lock", exclusive_now=True):
            service = update_service_details(store, service_id, actor, name=body.name, endpoint=body.endpoint,
                                             version=body.version)
        return {"name": service.name, "endpoint": service.spec.get("endpoint"),
                "actions": service.actions, "version": service.version}

    @app.delete("/api/v1/services/{service_id}", status_code=204)
    def unregister_service(service_id: str, version: int = Query(ge=1, le=2**63 - 1),
                           actor: auth.Actor = Depends(require_admin_write)):
        with store.lock("maintenance.lock", exclusive_now=True):
            unregister(store, service_id, actor=actor, version=version)
        return Response(status_code=204)

    @app.get("/api/v1/services/{service_id}/access")
    def local_service_access(service_id: str, _actor: auth.Actor = Depends(require_admin)):
        return service_access(store, service_id)

    @app.put("/api/v1/services/{service_id}/access/{node_id}", status_code=204)
    def update_service_access(service_id: str, node_id: str, body: ServiceAccessChange,
                              actor: auth.Actor = Depends(require_admin_write)):
        with store.lock("maintenance.lock", exclusive_now=True):
            change_service_access(store, service_id, node_id, actor, revision=body.revision,
                                  permissions={"directory": body.directory, "status": body.status, "logs": body.logs},
                                  actions=body.actions, hours=body.hours)
        return Response(status_code=204)

    @app.put("/api/v1/services/{service_id}/mode")
    def set_service_mode(service_id: str, body: ServiceMode, actor: auth.Actor = Depends(require_admin_write)):
        with store.lock("maintenance.lock", exclusive_now=True):
            try:
                service = change_mode(store, service_id, body.mode, docker_socket=config.docker_socket,
                                      actor=actor, version=body.version)
            except ModeChangeError as error:
                raise HTTPException(error.status, str(error)) from error
            except HostError as error:
                raise HTTPException(409, str(error)) from error
        return {"version": service.version, "actions": service.actions}

    @app.get("/api/v1/services/{service_id}/windows-management")
    def windows_management(service_id: str, _actor: auth.Actor = Depends(require_admin)):
        with store.connect() as db:
            service = get_service(db, service_id)
        if service is None or not service.existing_windows_service:
            raise HTTPException(404, "Unknown Windows service registration")
        return WindowsServiceDriver(store).management_status(service.target, host_permissions=service.host_permissions)

    @app.get("/api/v1/services/{service_id}/systemd-management")
    def systemd_management(service_id: str, check_delegation: bool = False, _actor: auth.Actor = Depends(require_admin)):
        with store.connect() as db:
            service = get_service(db, service_id)
        if service is None or not service.existing_systemd_unit:
            raise HTTPException(404, "Unknown systemd service registration")
        if check_delegation:
            return SystemUnitDriver.delegation_status(service.target, host_permissions=service.host_permissions)
        return SystemUnitDriver.management_status(service.target, host_permissions=service.host_permissions)

    @app.post("/api/v1/services/{service_id}/actions", status_code=202)
    def service_action(service_id: str, body: ActionRequest, request: Request,
                       service_version: int | None = Query(None, ge=1, le=2**53 - 1),
                       actor: auth.Actor = Depends(require_admin_write)):
        key = idempotency_key(request)
        return controller.submit(actor, service_id, body.action, key, service_version=service_version)

    @app.get("/api/v1/services/{service_id}/actions/request")
    def local_action_receipt(service_id: str, actor: auth.Actor = Depends(require_admin),
                             key: str = Depends(idempotency_key)):
        with store.connect(read_only=True) as db:
            db.execute("BEGIN")
            row = db.execute("SELECT * FROM operation WHERE actor=? AND request_key=? AND service_id=?",
                             (actor.operation_actor, key, service_id)).fetchone()
            return operation_data(row, db=db) if row is not None else None

    @app.get("/api/v1/operations/local")
    def local_operations(actor: auth.Actor = Depends(require_admin)):
        with store.connect(read_only=True) as db:
            db.execute("BEGIN")
            rows = db.execute("""
                SELECT o.*, s.name AS service_name
                FROM operation o LEFT JOIN service s ON s.id=o.service_id
                WHERE o.actor=?
                ORDER BY o.updated_at DESC, o.rowid DESC LIMIT 50
                """, (actor.operation_actor,)).fetchall()
            return [{**operation_data(row, db=db), "service_name": row["service_name"]} for row in rows]

    @app.get("/api/v1/operations/{operation_id}")
    def operation(operation_id: str, actor: auth.Actor = Depends(require_admin)):
        with store.connect(read_only=True) as db:
            db.execute("BEGIN")
            row = db.execute("SELECT * FROM operation WHERE id=? AND actor=?", (operation_id, actor.operation_actor)).fetchone()
            if row is None:
                raise HTTPException(404, "Unknown operation ID")
            return operation_data(row, db=db)

    @app.get("/api/v1/services/{service_id}/logs")
    def service_logs(service_id: str, tail: int = Query(200, ge=1, le=500), _actor: auth.Actor = Depends(require_admin)):
        with store.connect() as db:
            service = get_service(db, service_id)
        if service is None:
            raise HTTPException(404, "Unknown service ID")
        return controller.logs(service, tail)

    @app.get("/")
    def index():
        index_path = config.web_dir / "index.html"
        if not index_path.is_file():
            raise HTTPException(503, "Web assets missing. Build the frontend before starting the panel")
        return FileResponse(index_path)

    if (config.web_dir / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=config.web_dir / "assets"), name="assets")
    return app
