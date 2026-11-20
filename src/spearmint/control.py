from contextlib import contextmanager
from dataclasses import asdict
import logging
import sqlite3
from threading import BoundedSemaphore, Event, Lock, Thread
import time
from uuid import uuid4

from . import auth
from .catalog import Service, get_service, list_services
from .drivers import Driver, Observation, TRANSITIONAL
from .host import HostError, HostTimeout
from .peer.policy import dispatch_authorized
from .peer.grove_service_admin import OPERATION_KEY, operation_origin
from .peer.operation_policy import audit_execution, operation_result_reason
from .state import State, audit
from .service_metrics import ServiceMetrics


logger = logging.getLogger(__name__)
OBSERVATION_TTL = 8
MAX_PENDING = 16


class ControlError(RuntimeError):
    def __init__(self, status: int, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


def operation_data(row: sqlite3.Row, *, db: sqlite3.Connection | None = None) -> dict:
    data = {key: row[key] for key in ("id", "service_id", "action", "status", "message", "created_at", "updated_at")}
    if db is not None and row["status"] in {"failed", "uncertain"}:
        if reason := operation_result_reason(db, row, local=True):
            data["reason"] = reason
    return data


class Controller:
    def __init__(self, state: State, drivers: dict[str, Driver]) -> None:
        self.state = state
        self.drivers = drivers
        self.cache: dict[str, tuple[float, Observation, float | None, str | None]] = {}
        self.cache_lock = Lock()
        self.stop_event = Event()
        self.threads: list[Thread] = []
        self.log_slots = {driver: BoundedSemaphore(2) for driver in drivers}
        self.service_metrics = ServiceMetrics(drivers)

    @contextmanager
    def running(self):
        self.recover()
        self.stop_event.clear()
        for driver in self.drivers:
            for worker in (self.watch, self.dispatch):
                thread = Thread(target=worker, args=(driver,), name=f"{worker.__name__}-{driver}", daemon=True)
                thread.start()
                self.threads.append(thread)
        try:
            with self.service_metrics.running():
                yield
        finally:
            self.stop_event.set()
            for thread in self.threads:
                thread.join()
            self.threads.clear()

    def recover(self) -> None:
        with self.state.connect(write=True) as db:
            db.execute("DELETE FROM peer_challenge")
            rows = db.execute("SELECT * FROM operation WHERE status IN ('queued','running')").fetchall()
            for row in rows:
                if row["status"] == "queued":
                    self.finish(db, row, "failed", "Panel restarted before the operation was dispatched",
                                reason="RESTART_BEFORE_DISPATCH")
                else:
                    self.finish(db, row, "uncertain", "Panel restarted before the outcome was confirmed. Check the current service state",
                                reason="PANEL_RESTARTED")

    @staticmethod
    def finish(db: sqlite3.Connection, operation: sqlite3.Row, status: str, message: str | None,
               *, reason: str | None = None) -> None:
        updated_at = int(time.time())
        db.execute(
            "UPDATE operation SET status=?, message=?, updated_at=? WHERE id=?",
            (status, message, updated_at, operation["id"]),
        )
        audit(db, operation["actor"], operation["source"], f"operation.{operation['action']}.{status}", operation["id"],
              reason=reason, recorded_at=updated_at)
        audit_execution(db, operation, status, reason or status.upper())

    def submit(self, actor: auth.Actor, service_id: str, action: str, key: str, *, service_version: int | None = None) -> dict:
        now = int(time.time())
        with self.state.connect(write=True) as db:
            session = auth.active_session(db, actor.token_hash, now)
            if session is None or session["id"] != actor.account_id:
                raise ControlError(401, "Sign in required")
            if session["role"] != "node_admin":
                raise ControlError(403, "Node administrator required")
            operation_actor = session["operation_actor"]
            previous = db.execute(
                "SELECT * FROM operation WHERE actor=? AND request_key=?", (operation_actor, key),
            ).fetchone()
            if previous:
                if (previous["service_id"], previous["action"]) != (service_id, action):
                    raise ControlError(409, "Idempotency key was used for a different request")
                return operation_data(previous, db=db)
            result = self.enqueue(db, service_id, action, key, operation_actor, actor.address, now, service_version=service_version)
            if session['grove_user'] is not None:
                db.execute('INSERT INTO grove_operation VALUES (?,?,?)', (result['id'], actor.token_hash, actor.account_id))
            return result

    @staticmethod
    def enqueue(db: sqlite3.Connection, service_id: str, action: str, key: str, actor: str, source: str, now: int,
                *, remote: bool = False, service_version: int | None = None) -> dict:
        service = get_service(db, service_id)
        if service is None:
            raise ControlError(404, "Unknown service ID")
        if service_version is not None and service.version != service_version:
            raise ControlError(409, "The service registration changed before submission", code="SERVICE_VERSION_CHANGED")
        if action not in service.actions:
            raise ControlError(403, "This service is registered in observe mode")
        pending = db.execute("SELECT service_id FROM operation WHERE status IN ('queued','running')").fetchall()
        if any(row[0] == service_id for row in pending):
            raise ControlError(409, "This service already has an active operation")
        if len(pending) >= MAX_PENDING:
            raise ControlError(503, "The operation queue is full")
        operation_id = uuid4().hex
        db.execute(
            "INSERT INTO operation VALUES (?, ?, ?, ?, ?, ?, 'queued', NULL, ?, ?)",
            (operation_id, service_id, actor, source, key, action, now, now),
        )
        if remote:
            db.execute("INSERT INTO peer_operation_origin (operation_id) VALUES (?)", (operation_id,))
        audit(db, actor, source, f"operation.{action}.queued", operation_id)
        return operation_data(db.execute("SELECT * FROM operation WHERE id=?", (operation_id,)).fetchone())

    def claim(self, driver: str) -> tuple[sqlite3.Row, Service] | None:
        query = """SELECT operation.* FROM operation JOIN service ON service.id=operation.service_id
                   WHERE operation.status='queued' AND service.driver=? ORDER BY operation.rowid LIMIT 1"""
        with self.state.connect() as db:
            if db.execute(query, (driver,)).fetchone() is None:
                return None
        with self.state.connect(write=True) as db:
            operation = db.execute(query, (driver,)).fetchone()
            if operation is None:
                return None
            grove_operation = db.execute('SELECT * FROM grove_operation WHERE operation_id=?', (operation['id'],)).fetchone()
            if grove_operation:
                current = auth.active_session(db, grove_operation['token_hash'], int(time.time()))
                if current is None or current['role'] != 'node_admin' or current['id'] != grove_operation['account_id']:
                    self.finish(db, operation, 'failed', 'Grove authorization changed before dispatch', reason='POLICY_CHANGED')
                    return None
            if operation['request_key'].startswith('grove-admin:'):
                version = OPERATION_KEY.fullmatch(operation['request_key'])
                local_id = db.execute('SELECT node_id FROM node').fetchone()[0]
                service = get_service(db, operation['service_id'])
                authorized = (version is not None and service is not None and service.version == int(version[1])
                              and operation_origin(db, operation, local_id))
            else:
                authorized = dispatch_authorized(db, operation)
            if not authorized:
                self.finish(db, operation, "failed", "Remote authorization changed before dispatch", reason="POLICY_CHANGED")
                return None
            service = get_service(db, operation["service_id"])
            self.finish(db, operation, "running", None)
            return operation, service

    def dispatch(self, driver: str) -> None:
        while not self.stop_event.is_set():
            try:
                job = self.claim(driver)
                if job:
                    self.execute(*job)
                    continue
            except sqlite3.Error:
                logger.exception("Cannot update the operation queue")
            self.stop_event.wait(0.2)

    def execute(self, operation: sqlite3.Row, service: Service) -> None:
        driver = self.drivers[service.driver]
        action = operation["action"]
        issued = False
        reason = None
        try:
            before = driver.inspect(service)
            if action not in service.actions:
                reason = "POLICY_CHANGED"
                raise HostError("This service is registered in observe mode")
            if before.status in TRANSITIONAL or before.status in {"unknown", "missing"}:
                reason = "RUNTIME_NOT_READY"
                raise HostError(before.message or "The current runtime state does not allow this operation")
            if (action == "start" and before.status == "running") or (action == "stop" and before.status in {"stopped", "failed"} and not before.pid):
                status, message = "succeeded", "Already in the requested state"
            else:
                issued = True
                driver.apply(service, action, before)
                after = self.observe(service)
                expected = {"stopped", "failed"} if action == "stop" else {"running"}
                if after.status in TRANSITIONAL or after.status == "unknown":
                    status, message = "uncertain", "The runtime outcome could not be confirmed"
                    reason = "OUTCOME_UNCONFIRMED"
                elif after.status not in expected or (action == "restart" and before.instance == after.instance
                                                       and not service.existing_windows_service):
                    status, message = "failed", after.message or "The runtime did not reach the requested state"
                    reason = "STATE_NOT_REACHED"
                else:
                    status, message = "succeeded", after.message
        except HostTimeout:
            status = "uncertain" if issued else "failed"
            message = "Host command timed out. Check the current service state"
            reason = "HOST_TIMEOUT"
        except HostError as exc:
            status, message = "failed", str(exc)
            reason = reason or "HOST_ERROR"
            if issued and self.observe(service).status in {*TRANSITIONAL, "unknown"}:
                status = "uncertain"
        except Exception:
            logger.exception("Unexpected service operation error")
            status, message = ("uncertain" if issued else "failed"), "Service operation could not be confirmed"
            reason = "HOST_ERROR"
        self.observe(service)
        with self.state.connect(write=True) as db:
            self.finish(db, operation, status, message, reason=reason)

    def watch(self, driver: str) -> None:
        while not self.stop_event.is_set():
            try:
                for service in list_services(self.state, driver):
                    if self.stop_event.is_set():
                        return
                    self.observe(service)
            except sqlite3.Error:
                logger.exception("Cannot refresh registered services")
            self.stop_event.wait(2)

    def observe(self, service: Service) -> Observation:
        started = time.time()
        try:
            observation = self.drivers[service.driver].inspect(service)
        except HostError as exc:
            observation = Observation("unknown", str(exc))
        except Exception:
            logger.exception("Unexpected runtime observation error")
            observation = Observation("unknown", "Could not read the service state")
        with self.cache_lock:
            cached = self.cache.get(service.id)
            if cached is None or started >= cached[0]:
                if observation.status != "unknown":
                    last_seen, last_status = started, observation.status
                else:
                    last_seen, last_status = cached[2:] if cached else (None, None)
                self.cache[service.id] = (started, observation, last_seen, last_status)
        return observation

    def describe(self, service: Service) -> dict:
        with self.cache_lock:
            cached = self.cache.get(service.id)
        checked, observation, last_seen, last_status = cached or (None, Observation("unknown"), None, None)
        stale = checked is None or time.time() - checked > OBSERVATION_TTL
        data = asdict(observation)
        data.pop("instance")
        data.pop("shared_process")
        if stale:
            data.update(status="unknown", message="Waiting for a fresh host observation", health=None, pid=0)
        return {
            "id": service.id, "node_id": service.node_id, "name": service.name, "driver": service.driver,
            "actions": service.actions, "version": service.version, "endpoint": service.spec.get("endpoint"),
            "logs_available": service.logs_available,
            **({"runtime": service.spec["runtime"]} if service.existing_system_service else {}),
            **({"registered_target": service.target} if service.existing_system_service or service.driver == "docker" else {}),
            "observation": {
                **data, "source": service.driver, "checked_at": checked, "last_seen_at": last_seen,
                "last_status": last_status, "stale": stale or observation.status == "unknown",
            },
        }

    def logs(self, service: Service, tail: int) -> dict:
        slot = self.log_slots[service.driver]
        if not slot.acquire(blocking=False):
            raise ControlError(429, "Too many concurrent log requests")
        try:
            snapshot = self.drivers[service.driver].logs(service, tail)
            return {**asdict(snapshot), "source": service.driver, "checked_at": time.time()}
        except HostError as exc:
            raise ControlError(503, str(exc)) from exc
        finally:
            slot.release()
