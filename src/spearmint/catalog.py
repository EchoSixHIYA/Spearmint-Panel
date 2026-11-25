from dataclasses import dataclass
import json
import os
from pathlib import Path
import sqlite3
from uuid import uuid4

from .state import State, StateError, audit


ACTIONS = ("start", "stop", "restart")
MAX_SERVICES = 32
DISPLAY_FIELDS = ("access_links", "service_groups")


class RegistrationError(StateError):
    pass


class TargetAlreadyRegistered(RegistrationError):
    def __init__(self, service_id: str) -> None:
        super().__init__("Runtime target is already registered")
        self.service_id = service_id


@dataclass(frozen=True)
class Service:
    id: str
    node_id: str
    name: str
    driver: str
    target: str
    spec: dict
    managed: bool
    version: int

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "Service":
        return cls(
            row["id"], row["node_id"], row["name"], row["driver"], row["target"],
            json.loads(row["spec"]), bool(row["managed"]), row["version"],
        )

    @property
    def actions(self) -> tuple[str, ...]:
        return ACTIONS if self.managed else ()

    def runtime_spec(self) -> dict:
        return {name: value for name, value in self.spec.items() if name not in DISPLAY_FIELDS}

    @property
    def existing_systemd_unit(self) -> bool:
        return self.driver == "process" and self.spec.get("runtime") == "systemd-system"

    @property
    def existing_windows_service(self) -> bool:
        return self.driver == "process" and self.spec.get("runtime") == "windows-service"

    @property
    def existing_system_service(self) -> bool:
        return self.existing_systemd_unit or self.existing_windows_service

    @property
    def logs_available(self) -> bool:
        return not self.existing_windows_service or bool(self.spec.get('log_path'))

    @property
    def host_permissions(self) -> bool:
        return self.spec.get('host_permissions') is True


def get_service(db: sqlite3.Connection, service_id: str) -> Service | None:
    row = db.execute("SELECT * FROM service WHERE id=?", (service_id,)).fetchone()
    return Service.from_row(row) if row else None


def list_services(state: State, driver: str | None = None) -> list[Service]:
    with state.connect() as db:
        if driver is None:
            rows = db.execute("SELECT * FROM service ORDER BY name").fetchall()
        else:
            rows = db.execute("SELECT * FROM service WHERE driver=? ORDER BY name", (driver,)).fetchall()
    return [Service.from_row(row) for row in rows]


def service_name(name: str) -> str:
    name = name.strip()
    if not name or len(name) > 80 or not name.isprintable():
        raise RegistrationError("Service name must contain 1 to 80 printable characters")
    return name


def validate_endpoint(endpoint: str | None) -> None:
    if endpoint is not None and (len(endpoint) > 180 or not endpoint.isprintable()):
        raise StateError("Endpoint must be printable and at most 180 characters")


def register(state: State, driver: str, name: str, target: str, spec: dict, *,
             managed: bool, actor: str = "admin", source: str = "local", authorize=None) -> Service:
    name = service_name(name)
    node_id = state.verify()
    service_id = uuid4().hex
    if driver == "process" and spec.get("runtime") not in {"systemd-system", "windows-service"}:
        target = f"spearmint-workload-{service_id}.service"
    with state.connect(write=True) as db:
        if authorize is not None:
            authorize(db)
        existing = db.execute("SELECT id, spec FROM service WHERE driver=? AND target=?", (driver, target)).fetchone()
        if existing is not None and json.loads(existing["spec"]).get("runtime") == spec.get("runtime"):
            raise TargetAlreadyRegistered(existing["id"])
        if db.execute("SELECT COUNT(*) FROM service").fetchone()[0] >= MAX_SERVICES:
            raise RegistrationError(f"At most {MAX_SERVICES} services may be registered")
        try:
            db.execute(
                "INSERT INTO service VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
                (service_id, node_id, name, driver, target, json.dumps(spec, sort_keys=True), int(managed)),
            )
        except sqlite3.IntegrityError as exc:
            raise RegistrationError("Service name or runtime target is already registered") from exc
        audit(db, actor, source, "service.registered", service_id)
    return Service(service_id, node_id, name, driver, target, spec, managed, 1)


def process_spec(argv: list[str], cwd: str, stop_timeout: int, endpoint: str | None) -> dict:
    if (
        not argv or not Path(argv[0]).is_absolute() or not Path(cwd).is_absolute()
        or any("\0" in value for value in [*argv, cwd])
        or sum(len(value.encode()) + 1 for value in [*argv, cwd]) > 8192
    ):
        raise StateError("Provide absolute executable and working directory paths and at most 8 KiB of arguments")
    if not Path(argv[0]).is_file() or not os.access(argv[0], os.X_OK):
        raise StateError("Executable is missing or cannot be executed by this account")
    if not Path(cwd).is_dir() or not os.access(cwd, os.X_OK):
        raise StateError("Working directory is missing or cannot be accessed by this account")
    if not 1 <= stop_timeout <= 30:
        raise StateError("Stop timeout must be between 1 and 30 seconds")
    validate_endpoint(endpoint)
    return {"argv": argv, "cwd": cwd, "stop_timeout": stop_timeout, "endpoint": endpoint}


def require_idle(db: sqlite3.Connection, service_id: str) -> Service:
    service = get_service(db, service_id)
    if service is None:
        raise StateError("Unknown service ID")
    active = db.execute(
        "SELECT 1 FROM operation WHERE service_id=? AND status IN ('queued','running')", (service_id,)
    ).fetchone()
    if active:
        raise StateError("Service has an active operation")
    return service
