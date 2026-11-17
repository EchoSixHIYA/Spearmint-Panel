"""Remove a service registration while leaving the workload in place."""

import sqlite3
import time

from . import auth, frp_runtime
from .catalog import get_service, require_idle
from .control import ControlError
from .native_process import process_driver
from .peer.operation_policy import required_version
from .peer.projection import publish
from .state import State, StateError, audit


def latest_operation(db: sqlite3.Connection, service_id: str) -> str | None:
    row = db.execute("SELECT id FROM operation WHERE service_id=? ORDER BY rowid DESC LIMIT 1", (service_id,)).fetchone()
    return row[0] if row else None


def unregister(state: State, service_id: str, *, actor: auth.Actor | None = None,
               version: int | None = None) -> None:
    frp_runtime.reconcile(state)
    with state.connect() as db:
        db.execute("BEGIN")
        service = get_service(db, service_id)
        previous_operation = latest_operation(db, service_id) if service else None
    if service is None and actor is None:
        raise StateError("Unknown service ID")
    if service is not None and service.driver == "process" and not service.existing_system_service:
        if actor is not None:
            raise ControlError(409, "Unregister foreground processes from the node terminal")
        if process_driver(state).inspect(service).status not in {"stopped", "failed"}:
            raise ControlError(409, "Stop the managed process before unregistering it")

    with state.connect(write=True) as db:
        if actor is not None:
            session = auth.active_session(db, actor.token_hash, int(time.time()))
            if session is None or session["id"] != actor.account_id:
                raise ControlError(401, "Sign in required")
            if session["role"] != "node_admin":
                raise ControlError(403, "Node administrator required")
        current = get_service(db, service_id)
        if current is None and actor is not None:
            return
        if current != service or (version is not None and version != current.version):
            raise ControlError(409, "The service changed. Refresh its details before unregistering")
        if actor is not None and required_version(db, service_id) == 2:
            raise ControlError(409, "Unregister services requiring independent approval from the node terminal")
        try:
            require_idle(db, service_id)
        except StateError as error:
            raise ControlError(409, str(error)) from error
        if latest_operation(db, service_id) != previous_operation:
            raise ControlError(409, "The service changed during the check. Retry unregistering")
        if db.execute("SELECT 1 FROM frp_exposure WHERE service_id=? AND status IN (?,?,?)",
                      (service_id, *frp_runtime.ACTIVE)).fetchone():
            raise ControlError(409, "Revoke the active FRP mappings before unregistering this service")
        db.execute("DELETE FROM service WHERE id=?", (service_id,))
        publish(db, service_id)
        audit(db, actor.operation_actor if actor else "admin", actor.address if actor else "local",
              "service.unregistered", service_id)
