"""Observe and control explicitly configured Windows services through SCM."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import time

from .catalog import Service, register
from .drivers import LOG_LIMIT, LogSnapshot, Observation, format_log_snapshot
from .host import Capture, HostError, HostTimeout
from .onboarding import write_private
from .platforms import WINDOWS, process_start, read_file
from .state import State, StateError, private_path


RUNTIME = "windows-service"
ALLOWLIST = "windows-services.json"
MAX_ALLOWLIST_BYTES = 64 * 1024


class ServiceManagerError(HostError):
    def __init__(self, winerror: int) -> None:
        super().__init__(f"Windows Service Control Manager request failed ({winerror})")
        self.reason = {5: "access_denied", 1060: "missing", 1072: "missing"}.get(winerror, "scm_error")


def valid_name(name: str) -> bool:
    return 1 <= len(name) <= 256 and name.isprintable() and not any(char in name for char in '/\\')


def parse_allowlist(names: object) -> dict[str, str]:
    if not isinstance(names, list) or any(not isinstance(name, str) or not valid_name(name) or name != name.strip()
                                          for name in names):
        raise HostError("Invalid Windows service name in the allowlist")
    entries = {name.lower(): name for name in names}
    if len(entries) != len(names):
        raise HostError("The Windows service allowlist contains duplicate names")
    return entries


class WindowsServiceDriver:
    def __init__(self, state: State):
        self.state = state

    def allowed_services(self) -> dict[str, str]:
        if not WINDOWS:
            return {}
        path = self.state.directory / ALLOWLIST
        try:
            private_path(path, 0o600)
            if path.stat().st_size > MAX_ALLOWLIST_BYTES:
                raise HostError("The Windows service allowlist is too large")
            return parse_allowlist(json.loads(read_file(path)))
        except FileNotFoundError:
            pass
        except (OSError, ValueError, StateError) as error:
            raise HostError("Cannot read the private Windows service allowlist") from error
        names = (value.strip() for value in os.environ.get("SPEARMINT_WINDOWS_SERVICES", "").split(","))
        return {name.lower(): name for name in names if valid_name(name)}

    def set_allowlist(self, names: list[str]) -> None:
        if not WINDOWS:
            raise HostError("Windows system services require a Windows node")
        parse_allowlist(names)
        encoded = (json.dumps(names, ensure_ascii=False, indent=2) + "\n").encode()
        if len(encoded) > MAX_ALLOWLIST_BYTES:
            raise HostError("The Windows service allowlist is too large")
        write_private(self.state.directory / ALLOWLIST, encoded)

    def running_services(self) -> dict[str, str]:
        allowed = self.allowed_services()
        if not allowed:
            return {}
        import pywintypes
        import win32service as scm

        try:
            with self.manager(scm, scm.SC_MANAGER_ENUMERATE_SERVICE) as manager:
                services = scm.EnumServicesStatus(manager, scm.SERVICE_WIN32, scm.SERVICE_ACTIVE)
        except pywintypes.error as error:
            raise ServiceManagerError(error.winerror) from error
        return {name.lower(): display for name, display, status in services
                if name.lower() in allowed and status[1] == scm.SERVICE_RUNNING}

    @staticmethod
    @contextmanager
    def manager(scm, access):
        manager = scm.OpenSCManager(None, None, access)
        try:
            yield manager
        finally:
            manager.Close()

    @contextmanager
    def open_service(self, name: str, *, start: bool = False, stop: bool = False):
        if name.lower() not in self.allowed_services():
            raise HostError("This Windows service is outside the node's configured list")
        import pywintypes
        import win32service as scm

        access = scm.SERVICE_QUERY_STATUS
        if start:
            access |= scm.SERVICE_START
        if stop:
            access |= scm.SERVICE_STOP
        try:
            with self.manager(scm, scm.SC_MANAGER_CONNECT) as manager:
                handle = scm.OpenService(manager, name, access)
                try:
                    yield scm, handle
                finally:
                    handle.Close()
        except pywintypes.error as error:
            raise ServiceManagerError(error.winerror) from error

    @staticmethod
    def observation(scm, handle) -> Observation:
        status = scm.QueryServiceStatusEx(handle)
        if not status["ServiceType"] & scm.SERVICE_WIN32:
            raise HostError("Only Windows Win32 services can be registered")
        phase = {
            scm.SERVICE_RUNNING: "running", scm.SERVICE_START_PENDING: "starting",
            scm.SERVICE_STOP_PENDING: "stopping", scm.SERVICE_STOPPED: "stopped",
        }.get(status["CurrentState"], "unknown")
        if phase == "stopped" and status["Win32ExitCode"] not in {0, 1077}:  # ERROR_SERVICE_NEVER_STARTED
            return Observation("failed", f"Windows service exited with code {status['Win32ExitCode']}")
        pid = status["ProcessId"] if phase == "running" else 0
        instance = str(pid) if pid else None
        if pid:
            try:
                instance = f"{pid}:{process_start(pid)}"
            except OSError:
                pass
        return Observation(phase, instance=instance, pid=pid)

    def register(self, name: str, service: str, *, actor: str = "admin", source: str = "local") -> Service:
        target = service.lower()
        self.observe_target(target)
        return register(self.state, "process", name, target, {"runtime": RUNTIME}, managed=False, actor=actor, source=source)

    def observe_target(self, target: str) -> Observation:
        with self.open_service(target) as (scm, handle):
            return self.observation(scm, handle)

    def verify_management(self, target: str) -> None:
        with self.open_service(target, start=True, stop=True) as (scm, handle):
            self.observation(scm, handle)

    def control_rights(self, target: str) -> dict[str, bool | None]:
        rights = {}
        for action in ('start', 'stop'):
            try:
                with self.open_service(target, **{action: True}):
                    rights[action] = True
            except ServiceManagerError as error:
                rights[action] = False if error.reason == 'access_denied' else None
            except HostError:
                rights[action] = None
        return rights

    def management_status(self, target: str) -> dict:
        try:
            allowed = self.allowed_services()
        except HostError:
            return {"ready": False, "reason": "invalid_allowlist"}
        if target.lower() not in allowed:
            return {"ready": False, "reason": "not_allowed"}
        try:
            with self.open_service(target) as (scm, handle):
                observed = self.observation(scm, handle)
        except ServiceManagerError as error:
            return {"ready": False, "reason": error.reason}
        except HostError:
            return {"ready": False, "reason": "query_failed"}
        try:
            with self.open_service(target, start=True, stop=True):
                pass
        except ServiceManagerError as error:
            if error.reason == "access_denied":
                return {"ready": False, "reason": "control_denied", "status": observed.status,
                        "control_rights": self.control_rights(target)}
            return {"ready": False, "reason": error.reason, "status": observed.status}
        except HostError:
            return {"ready": False, "reason": "query_failed", "status": observed.status}
        return {"ready": True, "status": observed.status}

    def inspect(self, service: Service) -> Observation:
        return self.observe_target(service.target)

    def wait(self, scm, handle, expected: str, pending: str) -> None:
        deadline = time.monotonic() + 15
        while True:
            observed = self.observation(scm, handle)
            if observed.status == expected or (expected == "stopped" and observed.status == "failed"):
                return
            if observed.status != pending:
                raise HostError(observed.message or "Windows service did not reach the requested state")
            if time.monotonic() >= deadline:
                raise HostTimeout("Windows service did not finish its transition")
            time.sleep(0.2)

    def apply(self, service: Service, action: str, before: Observation) -> None:
        with self.open_service(service.target, start=action != "stop", stop=action != "start") as (scm, handle):
            if self.observation(scm, handle) != before:
                raise HostError("Windows service changed state before the requested action")
            if action != "start" and before.status == "running":
                scm.ControlService(handle, scm.SERVICE_CONTROL_STOP)
                self.wait(scm, handle, "stopped", "stopping")
            if action != "stop":
                scm.StartService(handle, None)
                self.wait(scm, handle, "running", "starting")

    def logs(self, service: Service, tail: int) -> LogSnapshot:
        path = service.spec.get('log_path')
        if not path:
            raise HostError('No application log file has been configured for this Windows service')
        self.observe_target(service.target)
        return application_log(path, tail)


def application_log(path: str, tail: int) -> LogSnapshot:
    try:
        file = Path(path)
        if not file.is_absolute() or len(file.drive) != 2 or ':' in file.name:
            raise ValueError
        file = file.resolve(strict=True)
        if len(file.drive) != 2 or not file.is_file():
            raise ValueError
        with file.open('rb') as stream:
            size = stream.seek(0, os.SEEK_END)
            stream.seek(max(0, size - LOG_LIMIT))
            data = stream.read(LOG_LIMIT)
    except (OSError, ValueError) as error:
        raise HostError('The Windows application log must be a readable local file') from error
    return format_log_snapshot(Capture(0, data, b'', size > LOG_LIMIT), tail, 'Cannot read the Windows application log')
