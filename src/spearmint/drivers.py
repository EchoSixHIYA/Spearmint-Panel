from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Protocol

from .catalog import ACTIONS, Service, register
from .host import Capture, HostError, HostTimeout, capture, rootless_command
from .state import State, StateError


LOG_LIMIT = 256 * 1024
CONTAINER_ID = re.compile(r"[0-9a-f]{64}")
CONTAINER_REFERENCE = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}"
CONTAINER_LIST_LIMIT = 100
TRANSITIONAL = {"starting", "stopping"}


@dataclass(frozen=True)
class Observation:
    status: str
    message: str | None = None
    health: str | None = None
    instance: str | None = None
    pid: int = 0


@dataclass(frozen=True)
class LogSnapshot:
    text: str
    truncated: bool


class Driver(Protocol):
    def inspect(self, service: Service) -> Observation: ...
    def apply(self, service: Service, action: str, before: Observation) -> None: ...
    def logs(self, service: Service, tail: int) -> LogSnapshot: ...


def log_snapshot(argv: list[str], tail: int, error: str, env: dict[str, str] | None = None) -> LogSnapshot:
    result = capture(argv, timeout=5, limit=LOG_LIMIT, merge=True, env=env)
    return format_log_snapshot(result, tail, error)


def format_log_snapshot(result: Capture, tail: int, error: str) -> LogSnapshot:
    if result.code and not result.truncated:
        raise HostError(error)
    text = result.stdout.decode("utf-8", "replace")
    text = "".join(character for character in text if character in "\n\t" or character.isprintable())
    lines = text.splitlines(keepends=True)
    data = "".join(lines[-tail:]).encode("utf-8")
    truncated = result.truncated or len(lines) > tail or len(data) > LOG_LIMIT
    return LogSnapshot(data[:LOG_LIMIT].decode("utf-8", "ignore"), truncated)


class ProcessDriver:
    ctl = ["/usr/bin/systemctl", "--user", "--no-pager"]
    unit_fields = (
        "LoadState,ActiveState,MainPID,ControlGroup,InvocationID,Result,Description,Transient,"
        "ActiveEnterTimestampMonotonic,ExecMainStartTimestampMonotonic"
    )

    @staticmethod
    def description(service: Service) -> str:
        digest = hashlib.sha256(json.dumps(service.spec, sort_keys=True).encode()).hexdigest()
        return f"Spearmint managed {service.id} {digest}"

    def unit(self, service: Service) -> dict[str, str]:
        result = capture([*self.ctl, "show", "--property", self.unit_fields, service.target])
        properties = dict(line.split("=", 1) for line in result.stdout.decode("utf-8", "replace").splitlines() if "=" in line)
        if result.truncated or not properties.get("LoadState"):
            raise HostError("Cannot query the systemd user manager")
        if properties["LoadState"] == "not-found":
            return {}
        if result.code or properties["LoadState"] != "loaded" or properties.get("Transient") != "yes" or (
            properties.get("Description") != self.description(service)
        ):
            raise HostError("The systemd unit is not owned by this service configuration")
        return properties

    @staticmethod
    def populated(properties: dict[str, str]) -> bool:
        group = properties.get("ControlGroup", "")
        if not group:
            return False
        root = Path("/sys/fs/cgroup")
        location = root / group.lstrip("/") / "cgroup.events"
        if not location.resolve().is_relative_to(root):
            raise HostError("Invalid systemd cgroup path")
        try:
            return "populated 1" in location.read_text().splitlines()
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise HostError("Cannot verify the workload cgroup") from exc

    def inspect(self, service: Service) -> Observation:
        unit = self.unit(service)
        if not unit:
            return Observation("stopped")
        active = unit.get("ActiveState")
        pid = int(unit.get("MainPID", 0))
        invocation = unit.get("InvocationID")
        if active in {"activating", "reloading", "refreshing"}:
            return Observation("starting", instance=invocation, pid=pid)
        if active == "active" and pid:
            return Observation("running", instance=invocation, pid=pid)
        if active == "deactivating" or self.populated(unit) or pid:
            return Observation("stopping", instance=invocation, pid=pid)
        if active == "inactive":
            return Observation("stopped", instance=invocation)
        if active == "failed":
            entered = int(unit.get("ActiveEnterTimestampMonotonic", 0))
            started = int(unit.get("ExecMainStartTimestampMonotonic", 0))
            if unit.get("Result") == "timeout" and entered >= started > 0:
                return Observation("stopped", "Stop timeout elapsed and systemd cleared the process group", instance=invocation)
            return Observation("failed", "The systemd workload failed. Check its journal", instance=invocation)
        return Observation("unknown", "Unrecognized systemd service state", instance=invocation)

    def stop(self, service: Service) -> None:
        if not self.unit(service):
            return
        result = capture([*self.ctl, "stop", service.target], timeout=service.spec["stop_timeout"] + 5)
        if result.code and self.inspect(service).status not in {"stopped", "failed"}:
            raise HostError("systemd could not stop the workload")

    def start(self, service: Service) -> None:
        unit = self.unit(service)
        if unit and unit.get("ActiveState") not in {"failed", "inactive"}:
            raise HostError("The workload changed state before it could be started")
        if unit and unit.get("ActiveState") == "failed":
            if self.populated(unit) or int(unit.get("MainPID", 0)):
                raise HostError("The workload still has live processes")
            result = capture([*self.ctl, "reset-failed", service.target])
            if result.code and self.unit(service):
                raise HostError("Could not clear the previous systemd failure")
            unit = self.unit(service)
        if unit:
            result = capture([*self.ctl, "start", service.target], timeout=10)
            if not result.code:
                return
            if self.unit(service):
                raise HostError("systemd could not start the workload. Check its journal")
        argv = service.spec["argv"]
        if not Path(argv[0]).is_file():
            raise HostError("Registered executable is missing")
        if not Path(service.spec["cwd"]).is_dir():
            raise HostError("Registered working directory is missing")
        result = capture([
            "/usr/bin/systemd-run", "--user", "--no-ask-password", f"--unit={service.target}",
            f"--description={self.description(service)}", "--service-type=exec", "--expand-environment=no",
            f"--working-directory={service.spec['cwd']}", "--property=KillMode=control-group",
            "--property=TimeoutStartSec=8s", f"--property=TimeoutStopSec={service.spec['stop_timeout']}s",
            "--property=Restart=no", "--property=StandardOutput=journal", "--property=StandardError=journal",
            "--", *argv,
        ], timeout=10)
        if result.code:
            raise HostError("systemd could not launch the registered executable. Check permissions and the journal")

    def apply(self, service: Service, action: str, before: Observation) -> None:
        if action == "stop" or (action == "restart" and before.status == "running"):
            self.stop(service)
            if self.inspect(service).status not in {"stopped", "failed"}:
                raise HostError("The workload process group did not stop")
        if action != "stop":
            self.start(service)

    def logs(self, service: Service, tail: int) -> LogSnapshot:
        self.unit(service)
        return log_snapshot([
            "/usr/bin/journalctl", "--user", "--user-unit", service.target, "--no-pager",
            "-o", "short-iso-precise", "-n", str(tail),
        ], tail, "Cannot read the workload journal")


class SystemUnitDriver(ProcessDriver):
    ctl = ["/usr/bin/systemctl", "--system", "--no-ask-password", "--no-pager"]
    sudo = ["/usr/bin/sudo", "-n", "--"]

    @staticmethod
    def allowed_units() -> set[str]:
        if sys.platform != "linux":
            return set()
        names = os.environ.get("SPEARMINT_SYSTEMD_UNITS", "").split(",")
        return {name for name in map(str.strip, names)
                if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,119}\.service", name)}

    @classmethod
    def running_units(cls) -> set[str]:
        allowed = cls.allowed_units()
        if not allowed:
            return set()
        result = capture([*cls.ctl, 'list-units', '--type=service', '--state=running', '--plain', '--no-legend', '--full'],
                         limit=128 * 1024)
        if result.code or result.truncated:
            raise HostError('Cannot read the running systemd services')
        return {line.split()[0] for line in result.stdout.decode('utf-8', 'replace').splitlines() if line.strip()} & allowed

    @classmethod
    def configured_unit(cls, target: str, *, timeout: float = 4) -> dict[str, str]:
        if target not in cls.allowed_units():
            raise HostError("The system service is outside this node's configured unit list")
        result = capture([*cls.ctl, "show", "--property", "Id," + cls.unit_fields, target], timeout=timeout)
        unit = dict(line.split("=", 1) for line in result.stdout.decode("utf-8", "replace").splitlines() if "=" in line)
        if result.code or result.truncated or unit.get("Id") != target or unit.get("LoadState") != "loaded" or unit.get("Transient") != "no":
            raise HostError("Cannot identify the configured systemd service")
        return unit

    @classmethod
    def register(cls, state: State, name: str, unit: str, *, actor: str = "admin", source: str = "local") -> Service:
        cls.configured_unit(unit)
        return register(state, "process", name, unit, {"runtime": "systemd-system"},
                        managed=False, actor=actor, source=source)

    def unit(self, service: Service) -> dict[str, str]:
        return self.configured_unit(service.target)

    @staticmethod
    def sudo_blocked() -> bool:
        try:
            with Path("/proc/self/status").open(encoding="ascii", errors="replace") as status:
                return any(line.split() == ["NoNewPrivs:", "1"] for line in status)
        except OSError:
            return False

    @classmethod
    def management_status(cls, target: str, *, timeout: float = 4) -> dict:
        if target not in cls.allowed_units():
            return {"ready": False, "reason": "not_allowed"}
        try:
            cls.configured_unit(target, timeout=timeout)
        except HostError:
            return {"ready": False, "reason": "unit_unavailable"}
        if cls.sudo_blocked():
            return {"ready": False, "reason": "sudo_blocked"}
        return {"ready": True}

    @classmethod
    def require_sudo(cls) -> None:
        if cls.sudo_blocked():
            raise HostError("The panel runs with NoNewPrivileges and cannot use delegated sudo commands")

    @staticmethod
    def journal_arguments(target: str) -> list[str]:
        return ["--quiet", "--no-pager", "--unit=" + target, "--lines=501", "--output=short-iso-precise"]

    @classmethod
    def delegation_status(cls, target: str) -> dict:
        management = cls.management_status(target)
        if not management["ready"]:
            return management
        deadline = time.monotonic() + 5

        def listed(command: list[str]) -> bool:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            try:
                result = capture([cls.sudo[0], "-n", "-k", "-l", "--", *command],
                                 timeout=remaining, limit=4096)
            except HostError:
                return False
            return result.code == 0 and not result.truncated

        actions = {action: listed([*cls.ctl, action, target]) for action in ACTIONS}
        journal = cls.journal_arguments(target)
        logs = listed(["/usr/bin/journalctl", *journal]) or listed(["/usr/bin/journalctl", "--system", *journal])
        return {**management, "listed_actions": actions, "listed_logs": logs}

    def apply(self, service: Service, action: str, before: Observation) -> None:
        if action not in service.actions:
            raise HostError("The requested systemd action is not allowed for this service")
        self.unit(service)
        self.require_sudo()
        result = capture([*self.sudo, *self.ctl, action, service.target], timeout=45)
        if result.code:
            raise HostError("systemd could not complete the delegated service action")

    def logs(self, service: Service, tail: int) -> LogSnapshot:
        self.unit(service)
        self.require_sudo()
        journal = self.journal_arguments(service.target)
        command = [*self.sudo, "/usr/bin/journalctl"]
        deadline = time.monotonic() + 5
        result = capture([*command, *journal], timeout=5, limit=LOG_LIMIT)
        if result.code and not result.truncated:
            # Existing exact-command delegations may allow only the system journal.
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise HostTimeout("Reading the delegated system service journal timed out")
            result = capture([*command, "--system", *journal], timeout=remaining, limit=LOG_LIMIT)
        return format_log_snapshot(result, tail, "Cannot read the delegated system service journal")


class ContainerNotFound(HostError):
    pass


class DockerDriver:
    template = (
        '{"id":{{json .Id}},"status":{{json .State.Status}},"pid":{{json .State.Pid}},'
        '"started":{{json .State.StartedAt}},"health":{{with index .State "Health"}}{{json .Status}}{{else}}null{{end}}}'
    )

    def __init__(self, socket: Path) -> None:
        self.socket = socket

    def available_containers(self, registered: set[str], *, running_only: bool = False) -> dict:
        argv, env = rootless_command(self.socket)
        template = '{"id":{{json .ID}},"name":{{json .Names}},"state":{{json .State}}}'
        selection = ['--filter', 'status=running'] if running_only else ['--all']
        result = capture([*argv, "container", "ls", *selection, "--no-trunc", "--format", template],
                         env=env, limit=64 * 1024)
        if result.code and not result.truncated:
            raise HostError("Cannot list containers on the configured Docker engine")
        output = result.stdout
        if result.truncated and not output.endswith(b"\n"):
            output = output.rpartition(b"\n")[0]
        containers = []
        for line in output.splitlines():
            try:
                item = json.loads(line)
                if (CONTAINER_ID.fullmatch(item["id"]) is None or not re.fullmatch(CONTAINER_REFERENCE, item["name"])
                        or not re.fullmatch(r"[a-z]{1,20}", item["state"])):
                    raise ValueError
            except (KeyError, TypeError, ValueError) as error:
                raise HostError("Docker returned invalid container list metadata") from error
            if item["id"] not in registered and (not running_only or item['state'] == 'running'):
                containers.append({key: item[key] for key in ("id", "name", "state")})
        containers.sort(key=lambda item: (item["name"].casefold(), item["id"]))
        return {"containers": containers[:CONTAINER_LIST_LIMIT],
                "truncated": result.truncated or len(containers) > CONTAINER_LIST_LIMIT}

    def details(self, argv: list[str], env: dict[str, str], target: str) -> dict | None:
        result = capture([*argv, "container", "inspect", "--format", self.template, "--", target], env=env)
        if result.truncated:
            raise HostError("Docker inspect exceeded its output limit")
        if result.code:
            if b"No such container:" in result.stderr or b"No such object:" in result.stderr:
                return None
            raise HostError("Cannot inspect the container on the configured Rootless Docker daemon")
        try:
            value = json.loads(result.stdout)
            if CONTAINER_ID.fullmatch(value["id"]) is None:
                raise ValueError
        except (ValueError, KeyError, TypeError) as exc:
            raise HostError("Docker returned invalid container metadata") from exc
        return value

    def resolve(self, reference: str) -> str:
        if re.fullmatch(CONTAINER_REFERENCE, reference) is None:
            raise HostError("Provide a container name or ID")
        argv, env = rootless_command(self.socket)
        details = self.details(argv, env, reference)
        if details is None:
            raise ContainerNotFound("Container does not exist on the configured Docker engine")
        return details["id"]

    def register(self, state: State, name: str, reference: str, *, managed: bool = False,
                 stop_timeout: int = 8, actor: str = "admin", source: str = "local") -> Service:
        if not 1 <= stop_timeout <= 30:
            raise StateError("Stop timeout must be between 1 and 30 seconds")
        target = self.resolve(reference)
        if CONTAINER_ID.fullmatch(reference) and target != reference:
            raise ContainerNotFound("Container ID no longer exists on the configured Docker engine")
        return register(state, "docker", name, target, {"stop_timeout": stop_timeout},
                        managed=managed, actor=actor, source=source)

    def registered(self, service: Service) -> tuple[list[str], dict[str, str], dict | None]:
        if CONTAINER_ID.fullmatch(service.target) is None:
            raise HostError("Registered container target is invalid")
        argv, env = rootless_command(self.socket)
        details = self.details(argv, env, service.target)
        if details is not None and details["id"] != service.target:
            raise HostError("Docker returned a different container ID")
        return argv, env, details

    def verify_management(self, service: Service) -> None:
        _, _, details = self.registered(service)
        if details is None:
            raise ContainerNotFound("Registered container ID no longer exists")

    def inspect(self, service: Service) -> Observation:
        _, _, details = self.registered(service)
        if details is None:
            return Observation("missing", "Registered container ID no longer exists")
        status = {
            "created": "stopped", "exited": "stopped", "running": "running", "restarting": "starting",
            "removing": "stopping", "dead": "failed",
        }.get(details["status"], "unknown")
        return Observation(status, health=details["health"], instance=details["started"], pid=details["pid"])

    def apply(self, service: Service, action: str, before: Observation) -> None:
        argv, env, details = self.registered(service)
        if details is None or details["started"] != before.instance or details["pid"] != before.pid:
            raise HostError("Container changed state before the requested action")
        if details["status"] in {"paused", "restarting", "removing"}:
            raise HostError("Container is paused or changing state")
        timeout = ["--time", str(service.spec["stop_timeout"])] if action != "start" else []
        result = capture([*argv, "container", action, *timeout, "--", service.target], env=env, timeout=service.spec["stop_timeout"] + 5)
        if result.code:
            raise HostError(f"Rootless Docker could not {action} the registered container")

    def logs(self, service: Service, tail: int) -> LogSnapshot:
        argv, env, details = self.registered(service)
        if details is None:
            raise HostError("Registered container ID no longer exists")
        return log_snapshot(
            [*argv, "container", "logs", "--tail", str(tail), "--timestamps", "--", service.target],
            tail, "Docker could not read the registered container logs", env,
        )
