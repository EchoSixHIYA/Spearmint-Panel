"""Change the catalog management mode without running a workload action."""

from dataclasses import replace
from pathlib import Path
import time
from typing import Literal

from . import auth
from .catalog import Service, get_service, process_spec, require_idle
from .drivers import DockerDriver, SystemUnitDriver
from .native_process import process_driver
from .peer.grove_service_admin import GroveServiceAdmin
from .peer.projection import publish
from .state import State, StateError, audit
from .windows_services import WindowsServiceDriver


class ModeChangeError(StateError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def change_mode(state: State, service_id: str, mode: Literal["observe", "manage"], *,
                docker_socket: Path, actor: auth.Actor | GroveServiceAdmin | None = None,
                version: int | None = None) -> Service:
    managed = mode == "manage"
    with state.connect() as db:
        service = get_service(db, service_id)
    if service is None:
        raise ModeChangeError(404, "Unknown service ID")
    foreground = service.driver == "process" and not service.existing_system_service
    if foreground and (actor is not None or not managed):
        raise ModeChangeError(409, "Foreground process entries support enabling management from the node terminal")
    if version is not None and version != service.version:
        # An immediate retry can observe its own completed change.
        if service.managed != managed or service.version != version + 1:
            raise ModeChangeError(409, "The service changed. Refresh its details before changing mode")

    changing = service.managed != managed
    # The CLI can explicitly refresh a service registration's version.
    update = changing or (version is None and not foreground)
    if update:
        if service.existing_systemd_unit and managed:
            SystemUnitDriver.configured_unit(service.target, host_permissions=service.host_permissions)
            SystemUnitDriver.require_sudo()
        elif service.existing_windows_service and managed:
            WindowsServiceDriver(state).verify_management(service.target, host_permissions=service.host_permissions)
        elif service.driver == "docker" and managed:
            DockerDriver(docker_socket).verify_management(service)
        elif foreground:
            spec = service.spec
            if not {"argv", "cwd", "stop_timeout"} <= spec.keys():
                raise StateError("Review the recovered foreground process command and working directory")
            process_spec(spec["argv"], spec["cwd"], spec["stop_timeout"], spec.get("endpoint"))
            if process_driver(state).inspect(service).status not in {"stopped", "failed"}:
                raise StateError("Stop the previous process before enabling management")

    with state.connect(write=True) as db:
        if isinstance(actor, GroveServiceAdmin):
            actor.require(db)
        elif actor is not None:
            session = auth.active_session(db, actor.token_hash, int(time.time()))
            if session is None or session["id"] != actor.account_id:
                raise ModeChangeError(401, "Sign in required")
            if session["role"] != "node_admin":
                raise ModeChangeError(403, "Node administrator required")
        if get_service(db, service_id) != service:
            raise ModeChangeError(409, "The service changed. Refresh its details before changing mode")
        if update or version is None:
            try:
                require_idle(db, service_id)
            except StateError as error:
                raise ModeChangeError(409, str(error)) from error
        if not update:
            return service
        db.execute("UPDATE service SET managed=?, version=version+1 WHERE id=?", (int(managed), service_id))
        publish(db, service_id)
        audit(db, actor.operation_actor if actor else "admin", actor.address if actor else "local",
              f"service.mode.{mode}", service_id)
        return replace(service, managed=managed, version=service.version + 1)
