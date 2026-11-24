"""Detached native workload supervisors for Windows, macOS and non-systemd Linux."""
import hashlib
import json
import locale
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from uuid import uuid4

import psutil

from .catalog import Service, get_service
from .drivers import LOG_LIMIT, Driver, LogSnapshot, Observation, ProcessDriver, SystemUnitDriver
from .host import HostError, HostTimeout
from .service_command import ensure_command_script
from .platforms import WINDOWS, boot_id, process_start, read_file, secure_private, systemd_available, replace_file
from .state import State, private_path
from .windows_services import WindowsServiceDriver


START_CONFIRMATION_SECONDS = 10


class RegisteredProcessDriver:
    def __init__(self, workload: Driver, state: State):
        self.state = state
        self.workload = workload
        self.system_units = SystemUnitDriver()
        self.windows_services = WindowsServiceDriver(state)

    def backend(self, service: Service) -> Driver:
        if service.existing_windows_service:
            return self.windows_services
        return self.system_units if service.existing_systemd_unit else self.workload

    def inspect(self, service: Service) -> Observation:
        return self.backend(service).inspect(service)

    def apply(self, service: Service, action: str, before: Observation) -> None:
        if action != 'stop':
            ensure_command_script(self.state, service.spec)
        self.backend(service).apply(service, action, before)

    def logs(self, service: Service, tail: int) -> LogSnapshot:
        return self.backend(service).logs(service, tail)

    def prepare_change(self, service: Service) -> None:
        backend = self.backend(service)
        if isinstance(backend, NativeProcessDriver):
            backend.prepare_change(service)


def process_driver(state: State) -> Driver:
    workload = ProcessDriver() if systemd_available() else NativeProcessDriver(state)
    return RegisteredProcessDriver(workload, state)


def signature(service: Service) -> str:
    return hashlib.sha256(json.dumps(service.runtime_spec(), sort_keys=True).encode()).hexdigest()


def linux_identity(pid=None):
    """Kernel identities survive wall-clock corrections and WSL clock drift."""
    if not sys.platform.startswith('linux'):
        return None, None
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if pid is None:
        return boot, None
    # The main task view also gives the kernel value under qemu-user, which
    # synthesizes /proc/<self>/stat at guest exec time instead of fork time.
    fields = Path(f'/proc/{pid}/task/{pid}/stat').read_text().rpartition(')')[2].split()
    return boot, fields[19]  # Field 22, counted after the parenthesized process name.


def alive(pid: int, birth: str, *, ticks=None, kernel_boot=None) -> bool:
    try:
        process = psutil.Process(pid)
        if ticks is not None and kernel_boot is not None:
            current_boot, current_ticks = linux_identity(pid)
            return (current_boot, current_ticks) == (kernel_boot, ticks) and process.status() != psutil.STATUS_ZOMBIE
        return str(process.create_time()) == birth and process.status() != psutil.STATUS_ZOMBIE
    except (psutil.Error, OSError, IndexError):
        return False


def starting_status(service: Service, instance: str, guardian: int) -> dict:
    result = {"spec": signature(service), "boot": boot_id(), "instance": instance,
            "guardian_pid": guardian, "guardian_start": process_start(guardian), "pid": 0,
            "child_start": "", "status": "starting"}
    kernel_boot, ticks = linux_identity(guardian)
    if kernel_boot is not None:
        result.update(kernel_boot=kernel_boot, guardian_ticks=ticks)
    return result


def write_status(path: Path, status: dict) -> None:
    fd, name = tempfile.mkstemp(prefix=".status-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(status, stream)
            stream.flush()
            os.fsync(stream.fileno())
        replace_file(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


class NativeProcessDriver:
    def __init__(self, state: State):
        self.state = state
        self.children: dict[str, subprocess.Popen] = {}

    def directory(self, service: Service) -> Path:
        if len(service.id) != 32 or any(char not in "0123456789abcdef" for char in service.id):
            raise HostError("Invalid service identity")
        self.state.verify()
        directory = self.state.directory / f"workload-{service.id}"
        if not directory.exists():
            directory.mkdir(mode=0o700)
            secure_private(directory, 0o700)
        private_path(directory, 0o700, directory=True)
        return directory

    def read_status(self, service: Service, path: Path) -> dict | None:
        try:
            private_path(path, 0o600)
            status = json.loads(read_file(path))
            if status["spec"] != signature(service):
                raise HostError("The workload belongs to a different service configuration")
            current_boot, _ = linux_identity()
            same_boot = status['kernel_boot'] == current_boot if status.get('kernel_boot') else status['boot'] == boot_id()
            if not same_boot:
                return None
            return status
        except FileNotFoundError:
            return None
        except (ValueError, KeyError, TypeError) as error:
            raise HostError("Invalid native workload state") from error

    def inspect(self, service: Service) -> Observation:
        return self.observe(service, self.directory(service))

    def observe(self, service: Service, directory: Path) -> Observation:
        child = self.children.get(service.id)
        if child is not None and child.poll() is not None:
            self.children.pop(service.id, None)
        status = self.read_status(service, directory / "status.json")
        if status is None:
            return Observation("stopped")
        if status["status"] in {"stopped", "failed"}:
            return Observation(status["status"], status.get("message"), instance=status["instance"])
        guard = alive(status["guardian_pid"], status["guardian_start"], ticks=status.get('guardian_ticks'), kernel_boot=status.get('kernel_boot'))
        child_live = bool(status.get("pid")) and alive(status["pid"], status["child_start"], ticks=status.get('child_ticks'), kernel_boot=status.get('kernel_boot'))
        if not guard:
            if child_live:
                return Observation("unknown", "Supervisor exited while the workload is still alive; reconcile it locally", instance=status["instance"], pid=status["pid"])
            return Observation("failed", "Native supervisor exited unexpectedly", instance=status["instance"])
        phase = status["status"] if status["status"] in {"starting", "stopping"} else "running"
        return Observation(phase, instance=status["instance"], pid=status.get("pid", 0))

    def stop(self, service: Service) -> None:
        directory = self.directory(service)
        before = self.observe(service, directory)
        if before.status in {"stopped", "failed"}:
            return
        if before.status == "unknown":
            raise HostError(before.message)
        write_status(directory / "stop.json", {"instance": before.instance})
        deadline = time.monotonic() + service.spec["stop_timeout"] + 5
        while time.monotonic() < deadline:
            if self.observe(service, directory).status in {"stopped", "failed"}:
                child = self.children.pop(service.id, None)
                if child is not None:
                    child.wait(timeout=2)
                return
            time.sleep(0.05)
        raise HostTimeout("Native supervisor did not confirm workload termination")

    def prepare_change(self, service: Service) -> None:
        """Discard a completed supervisor record before installing a different specification."""
        with self.state.lock(f"workload-action-{service.id}.lock", exclusive_now=True):
            directory = self.directory(service)
            status = self.read_status(service, directory / 'status.json')
            if status is None:
                return
            if self.observe(service, directory).status not in {'stopped', 'failed'}:
                raise HostError('Stop the workload before changing its startup configuration')
            deadline = time.monotonic() + 3
            while alive(status['guardian_pid'], status['guardian_start'], ticks=status.get('guardian_ticks'), kernel_boot=status.get('kernel_boot')):
                if time.monotonic() >= deadline:
                    raise HostTimeout('Previous supervisor has not exited')
                time.sleep(.05)
            (directory / 'status.json').unlink(missing_ok=True)
            (directory / 'stop.json').unlink(missing_ok=True)

    def start(self, service: Service) -> None:
        directory = self.directory(service)
        if self.observe(service, directory).status not in {"stopped", "failed"}:
            raise HostError("Workload changed state before it could be started")
        directory.joinpath("stop.json").unlink(missing_ok=True)
        command = [sys.executable, "--internal-supervisor"] if getattr(sys, "frozen", False) else [sys.executable, "-m", "spearmint.native_process"]
        instance = uuid4().hex
        with (directory / "supervisor.log").open("ab") as output:
            child = subprocess.Popen([*command, str(self.state.directory), service.id, instance, "tracked"], stdin=subprocess.PIPE,
                stdout=output, stderr=output, close_fds=True, start_new_session=not WINDOWS,
                creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP if WINDOWS else 0)
        self.children[service.id] = child
        # The supervisor waits for a byte on stdin. If the panel exits before recording
        # this launch, closing the pipe lets the supervisor exit without starting a workload.
        try:
            with child.stdin as gate:
                write_status(directory / "status.json", starting_status(service, instance, child.pid))
                gate.write(b"\n")
        except OSError as error:
            raise HostError("Native supervisor launch could not be recorded") from error
        deadline = time.monotonic() + START_CONFIRMATION_SECONDS
        while time.monotonic() < deadline:
            observation = self.observe(service, directory)
            if observation.instance == instance:
                if observation.status == "running":
                    return
                if observation.status == "failed":
                    raise HostError(observation.message or "Native workload failed")
            if child.poll() is not None:
                raise HostError("Native supervisor could not start: " + (directory / "supervisor.log").read_text(errors="replace")[-1200:])
            time.sleep(0.05)
        raise HostTimeout("Native workload startup was not confirmed")

    def apply(self, service: Service, action: str, before: Observation) -> None:
        with self.state.lock(f"workload-action-{service.id}.lock", exclusive_now=True):
            if action == "stop" or action == "restart":
                self.stop(service)
            if action != "stop":
                self.start(service)

    def logs(self, service: Service, tail: int) -> LogSnapshot:
        path = self.directory(service) / "workload.log"
        try:
            private_path(path, 0o600)
            with path.open("rb") as stream:
                size = stream.seek(0, os.SEEK_END)
                stream.seek(max(0, size - LOG_LIMIT))
                raw = stream.read(LOG_LIMIT)
        except FileNotFoundError:
            return LogSnapshot("", False)
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            decoded = raw.decode(locale.getencoding() if WINDOWS else "utf-8", "replace")
        text = "".join(c for c in decoded if c in "\n\t" or c.isprintable())
        lines = text.splitlines(keepends=True)
        return LogSnapshot("".join(lines[-tail:]), size > LOG_LIMIT or len(lines) > tail)


class WindowsChild:
    def __init__(self, argv: list[str], cwd: str, command: str | None = None):
        import win32api
        import win32con
        import win32job
        import win32pipe
        import win32process
        import win32security

        self.job = win32job.CreateJobObject(None, "Spearmint-" + uuid4().hex)
        limits = win32job.QueryInformationJobObject(self.job, win32job.JobObjectExtendedLimitInformation)
        limits['BasicLimitInformation']['LimitFlags'] = win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        win32job.SetInformationJobObject(self.job, win32job.JobObjectExtendedLimitInformation, limits)
        attributes = win32security.SECURITY_ATTRIBUTES()
        attributes.bInheritHandle = True
        read_handle, write_handle = win32pipe.CreatePipe(attributes, 0)
        import msvcrt
        self.output = os.fdopen(msvcrt.open_osfhandle(int(read_handle.Detach()), os.O_RDONLY), 'rb')
        win32api.SetHandleInformation(int(msvcrt.get_osfhandle(self.output.fileno())), win32con.HANDLE_FLAG_INHERIT, 0)
        startup = win32process.STARTUPINFO()
        startup.dwFlags = win32con.STARTF_USESTDHANDLES
        startup.hStdOutput = write_handle
        startup.hStdError = write_handle
        import win32file
        null = win32file.CreateFile('NUL', win32con.GENERIC_READ, win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                                    attributes, win32con.OPEN_EXISTING, 0, None)
        startup.hStdInput = null
        try:
            commandline = subprocess.list2cmdline(argv)
            if command is not None:
                commandline = subprocess.list2cmdline(argv[:1]) + ' /d /s /c "' + command + '"'
            process, thread, self.pid, _ = win32process.CreateProcess(argv[0], commandline, None, None,
                True, win32con.CREATE_SUSPENDED | win32con.CREATE_NO_WINDOW, None, cwd, startup)
            self.process = process
            try:
                win32job.AssignProcessToJobObject(self.job, process)
                win32process.ResumeThread(thread)
            except BaseException:
                win32process.TerminateProcess(process, 1)
                raise
            finally:
                thread.Close()
        finally:
            write_handle.Close()
            null.Close()

    def poll(self):
        import win32process
        code = win32process.GetExitCodeProcess(self.process)
        return None if code == 259 else code

    def terminate(self):
        import win32job
        win32job.TerminateJobObject(self.job, 0)

    def close(self):
        self.job.Close()
        self.process.Close()


def supervise(state_dir: str, service_id: str, instance: str | None = None, launch: str | None = None) -> int:
    from queue import Queue, Empty, Full
    from threading import Event, Thread

    if launch is not None and (launch != "tracked" or sys.stdin.buffer.read(1) != b"\n"):
        return 1
    os.umask(0o077)
    state = State(Path(state_dir))
    state.verify()
    with state.connect() as db:
        service = get_service(db, service_id)
    if service is None or service.driver != "process" or service.existing_system_service:
        return 1
    driver = NativeProcessDriver(state)
    directory = driver.directory(service)
    status_path = directory / "status.json"
    with state.lock(f"workload-supervisor-{service.id}.lock", exclusive_now=True):
        status = starting_status(service, instance or uuid4().hex, os.getpid())
        write_status(status_path, status)
        child = None
        stop = Event()
        if not WINDOWS:
            signal.signal(signal.SIGTERM, lambda *_: stop.set())
            signal.signal(signal.SIGINT, lambda *_: stop.set())
        queue = Queue(maxsize=16)

        def read_output(pipe):
            try:
                while True:
                    data = pipe.read1(8192)
                    if not data:
                        break
                    try:
                        queue.put_nowait(data)
                    except Full:
                        pass  # Keep draining a noisy workload; resident memory stays bounded.
            except OSError:
                pass

        try:
            ensure_command_script(state, service.spec)
            if WINDOWS:
                command = service.spec.get('command')
                if service.spec.get('command_script'):
                    command = '"' + service.spec['command_script'] + '"'
                child = WindowsChild(service.spec["argv"], service.spec["cwd"], command)
                pipe = child.output
            else:
                child = subprocess.Popen(service.spec["argv"], cwd=service.spec["cwd"], stdin=subprocess.DEVNULL,
                                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
                pipe = child.stdout
            status.update(pid=child.pid, child_start=process_start(child.pid), status="running")
            if status.get('kernel_boot'):
                _, status['child_ticks'] = linux_identity(child.pid)
            write_status(status_path, status)
            reader = Thread(target=read_output, args=(pipe,), daemon=True)
            reader.start()
            stopping = None
            log_path = directory / "workload.log"
            with log_path.open("ab") as log:
                while True:
                    try:
                        request = json.loads(read_file(directory / "stop.json"))
                        if request.get("instance") == status["instance"]:
                            stop.set()
                    except (FileNotFoundError, ValueError):
                        pass
                    if stop.is_set() and stopping is None:
                        stopping = time.monotonic()
                        status["status"] = "stopping"
                        write_status(status_path, status)
                        if WINDOWS:
                            child.terminate()
                        else:
                            try:
                                os.killpg(child.pid, signal.SIGTERM)
                            except ProcessLookupError:
                                pass
                    if stopping is not None and time.monotonic() - stopping >= service.spec["stop_timeout"]:
                        if not WINDOWS:
                            try:
                                os.killpg(child.pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                    try:
                        data = queue.get(timeout=0.05)
                        # Retain a bounded log on disk as well as bounded pipe buffers.
                        if log.tell() + len(data) > 4 * LOG_LIMIT:
                            log.seek(0)
                            log.truncate()
                        log.write(data)
                        log.flush()
                    except Empty:
                        pass
                    code = child.poll()
                    if code is not None:
                        if WINDOWS:
                            child.terminate()
                        else:
                            try:
                                os.killpg(child.pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                        reader.join(timeout=1)
                        while not queue.empty():
                            log.write(queue.get_nowait())
                        status.update(status="stopped" if stop.is_set() or code == 0 else "failed",
                                      message=None if stop.is_set() or code == 0 else f"Workload exited with code {code}")
                        break
        except Exception as error:
            status.update(status="failed", message=f"Native workload launch failed: {type(error).__name__}: {error}")
        finally:
            if child is not None:
                if WINDOWS:
                    child.terminate()
                    child.close()
                else:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    child.wait()
                pipe.close()
            write_status(status_path, status)
    return 0


if __name__ == "__main__":
    raise SystemExit(supervise(*sys.argv[1:]))
