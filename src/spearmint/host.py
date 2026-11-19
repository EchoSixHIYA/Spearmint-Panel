from dataclasses import dataclass
from pathlib import Path
import json
import os
from queue import Queue, Empty, Full
import shutil
import stat
import subprocess
from threading import Thread, Event
import time

import psutil

from .platforms import WINDOWS


class HostError(RuntimeError):
    pass


class HostTimeout(HostError):
    pass


class DockerAccessError(HostError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Capture:
    code: int
    stdout: bytes
    stderr: bytes
    truncated: bool


def capture(
    argv: list[str], *, env: dict[str, str] | None = None, timeout: float = 4,
    limit: int = 16 * 1024, merge: bool = False,
) -> Capture:
    deadline = time.monotonic() + timeout
    try:
        process = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT if merge else subprocess.PIPE,
            env=env, start_new_session=not WINDOWS,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW if WINDOWS else 0,
        )
    except OSError as exc:
        raise HostError(f"{Path(argv[0]).name}: {type(exc).__name__}") from exc

    stdout, stderr = bytearray(), bytearray()
    truncated = False
    queue = Queue(maxsize=8)
    cancelled = Event()

    def read_pipe(pipe, target):
        try:
            while not cancelled.is_set():
                chunk = pipe.read1(8192)
                while not cancelled.is_set():
                    try:
                        queue.put((target, chunk), timeout=0.1)
                        break
                    except Full:
                        continue
                if not chunk:
                    break
        finally:
            pipe.close()

    pipes = [(process.stdout, stdout)] + ([(process.stderr, stderr)] if process.stderr is not None else [])
    workers = [Thread(target=read_pipe, args=pair, daemon=True) for pair in pipes]
    for worker in workers:
        worker.start()
    open_pipes = len(workers)
    with process:
        try:
            while open_pipes and not truncated:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise HostTimeout(f"{Path(argv[0]).name} timed out")
                try:
                    target, data = queue.get(timeout=remaining)
                except Empty:
                    raise HostTimeout(f"{Path(argv[0]).name} timed out") from None
                if not data:
                    open_pipes -= 1
                    continue
                available = limit - len(stdout) - len(stderr)
                target.extend(data[:available])
                truncated = len(data) > available
            if not truncated:
                process.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as exc:
            raise HostTimeout(f"{Path(argv[0]).name} timed out") from exc
        finally:
            cancelled.set()
            if process.returncode is None:
                try:
                    parent = psutil.Process(process.pid)
                    children = parent.children(recursive=True)
                    for child in reversed(children):
                        try:
                            child.kill()
                        except psutil.NoSuchProcess:
                            pass
                    parent.kill()
                except psutil.NoSuchProcess:
                    pass
            process.wait()
            for worker in workers:
                worker.join(timeout=1)
    return Capture(process.returncode, bytes(stdout), bytes(stderr), truncated)


def command(argv: list[str], *, env: dict[str, str] | None = None, timeout: float = 4) -> str:
    result = capture(argv, env=env, timeout=timeout)
    if result.truncated:
        raise HostError(f"{Path(argv[0]).name} exceeded its output limit")
    if result.code:
        message = result.stderr.decode("utf-8", "replace").strip().splitlines()
        raise HostError(message[-1][:200] if message else f"{Path(argv[0]).name} exited with {result.code}")
    return result.stdout.decode("utf-8", "replace").strip()


def docker_command(socket: Path) -> tuple[list[str], dict[str, str]]:
    executable = shutil.which("docker")
    if executable is None:
        raise DockerAccessError('DOCKER_MISSING', 'Docker CLI is not installed')
    if WINDOWS:
        endpoint = str(socket).replace("\\", "/")
        if endpoint != "//./pipe/docker_engine":
            raise HostError("Docker requires the local Docker Desktop named pipe")
        env = {key: value for key, value in os.environ.items() if not key.startswith("DOCKER_")}
        return [executable, "--host", "npipe:" + endpoint], env
    if not socket.is_absolute():
        raise HostError("Docker requires an absolute local Unix socket path")
    default = Path(f'/run/user/{os.getuid()}/docker.sock')
    if socket == default and not socket.exists():
        socket = Path('/var/run/docker.sock')
    try:
        info = socket.lstat()
    except OSError as exc:
        raise DockerAccessError('DOCKER_UNAVAILABLE', 'Local Docker socket is unavailable') from exc
    if not stat.S_ISSOCK(info.st_mode):
        raise DockerAccessError('DOCKER_UNAVAILABLE', 'Local Docker endpoint is not a Unix socket')
    if not os.access(socket, os.R_OK | os.W_OK):
        raise DockerAccessError('DOCKER_PERMISSION', 'The panel account cannot access the local Docker socket')
    env = {key: value for key, value in os.environ.items() if not key.startswith("DOCKER_")}
    env.update({"LC_ALL": "C", "DOCKER_CONFIG": str(Path.home() / ".config/spearmint/docker-cli")})
    return [executable, "--host", f"unix://{socket}"], env


def local_docker_command(socket: Path) -> tuple[list[str], dict[str, str]]:
    argv, env = docker_command(socket)
    try:
        options = json.loads(command(argv + ["info", "--format", "{{json .SecurityOptions}}"], env=env))
    except (HostError, ValueError) as exc:
        raise DockerAccessError('DOCKER_UNAVAILABLE', 'The local Docker daemon did not respond') from exc
    if not isinstance(options, list):
        raise DockerAccessError('DOCKER_UNAVAILABLE', 'Docker returned invalid daemon metadata')
    return argv, env


def check_docker(socket: Path) -> str:
    local_docker_command(socket)
    return str(socket)
