"""Local FRP leases with a process supervisor independent of the panel."""

from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256
import os
from pathlib import Path
from queue import Empty, Full, Queue
import signal
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory
from threading import Event, Thread
import time
from uuid import uuid4

from .frp import Plan, Settings, verify_config
from .native_process import WindowsChild, alive
from .peer.protocol import PeerError
from .platforms import WINDOWS, process_start
from .state import State, StateError, audit


ACTIVE = ('starting', 'running', 'revoking')
MAX_ACTIVE = 16
MAX_TTL = 86400
CLAIM_TIMEOUT = 15
POLL_INTERVAL = 0.2
PUBLIC_FIELDS = ('id', 'service_id', 'provider', 'protocol', 'public_address', 'local_address',
                 'created_at', 'expires_at', 'status', 'health', 'detail')


@dataclass(frozen=True)
class Request:
    origin: str
    id: str
    digest: bytes
    service_id: str
    actor: str
    authorize: Callable[[sqlite3.Connection, str, str], None]

    def previous(self, db: sqlite3.Connection) -> dict | None:
        row = db.execute('''
            SELECT e.*, r.digest FROM frp_request r JOIN frp_exposure e ON e.id=r.exposure_id
            WHERE r.origin=? AND r.request_id=?
        ''', (self.origin, self.id)).fetchone()
        if row is None:
            return None
        if row['digest'] != self.digest:
            raise PeerError('CONFLICT', 'Idempotency key was used for a different FRP request')
        self.check(db, row)
        return public_data(row)

    def check(self, db: sqlite3.Connection, row) -> None:
        if row['service_id'] != self.service_id:
            raise PeerError('NOT_FOUND', 'Unknown FRP mapping')
        self.authorize(db, row['protocol'], row['provider'])

    def record(self, db: sqlite3.Connection, exposure: str) -> None:
        db.execute('INSERT INTO frp_request VALUES (?,?,?,?)', (self.origin, self.id, self.digest, exposure))


def public_data(row: sqlite3.Row) -> dict:
    return {key: row[key] for key in PUBLIC_FIELDS}


def read(db: sqlite3.Connection, exposure: str) -> sqlite3.Row | None:
    return db.execute('SELECT * FROM frp_exposure WHERE id=?', (exposure,)).fetchone()


def finish(db: sqlite3.Connection, exposure: str, status: str, detail: str | None = None) -> None:
    row = read(db, exposure)
    if row is None or row['status'] not in ACTIVE:
        return
    # A revoke received while the supervisor was stopping still has a durable receipt.
    if row['status'] == 'revoking' and status != 'revoked':
        status, detail = 'revoked', None
    db.execute('UPDATE frp_exposure SET status=?, health=NULL, detail=? WHERE id=?', (status, detail, exposure))
    audit(db, 'frp', 'local', f'frp.exposure.{status}', exposure, reason=detail)


def reconcile(state: State) -> None:
    now = time.time()
    with state.connect(write=True) as db:
        rows = db.execute("SELECT * FROM frp_exposure WHERE status IN ('starting','running','revoking')").fetchall()
        for row in rows:
            pid = row['guardian_pid']
            if pid is not None and alive(pid, row['guardian_start']):
                continue
            if pid is None and row['status'] == 'starting' and now < min(row['created_at'] + CLAIM_TIMEOUT, row['expires_at']):
                continue
            if pid is None and now >= row['expires_at'] and row['status'] == 'starting':
                finish(db, row['id'], 'expired')
            else:
                finish(db, row['id'], 'failed', 'Supervisor is no longer running')


def list_exposures(state: State, *, include_service_names: bool = False) -> list[dict]:
    reconcile(state)
    with state.connect() as db:
        rows = db.execute('''
            SELECT e.*, s.name AS service_name FROM frp_exposure e
            LEFT JOIN service s ON s.id=e.service_id
            ORDER BY e.status NOT IN ('starting','running','revoking'), e.created_at DESC, e.id
            LIMIT 100
        ''')
        if include_service_names:
            return [{**public_data(row), 'service_name': row['service_name']} for row in rows]
        return [public_data(row) for row in rows]


def wait_status(state: State, exposure: str, pending: str, timeout: float) -> dict:
    deadline = time.monotonic() + timeout
    while True:
        reconcile(state)
        with state.connect() as db:
            row = read(db, exposure)
        if row is None:
            raise StateError('Unknown FRP mapping ID')
        if row['status'] != pending or time.monotonic() >= deadline:
            return public_data(row)
        time.sleep(POLL_INTERVAL)


def launch(state: State, exposure: str, binary: Path) -> None:
    frozen = getattr(sys, 'frozen', False)
    entry = ['--internal-frp-supervisor'] if frozen else ['-m', 'spearmint.frp_runtime']
    argv = [sys.executable, *entry, str(state.directory), exposure, str(binary)]
    env = {**os.environ, 'PYINSTALLER_RESET_ENVIRONMENT': '1'} if frozen else None
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             env=env, close_fds=True, start_new_session=not WINDOWS,
                             creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP if WINDOWS else 0)
    Thread(target=child.wait, name='frp-supervisor-reaper', daemon=True).start()


def start(state: State, provider: str, service_id: str, protocol: str, binary: Path | None, ttl: int, *,
          domain: str | None = None, public_port: int | None = None,
          request: Request | None = None, settings: Settings | None = None) -> dict:
    if not (WINDOWS or sys.platform == 'linux'):
        raise StateError('Managed FRP leases are available on Windows and Linux')
    if type(ttl) is not int or not 1 <= ttl <= MAX_TTL:
        raise StateError(f'FRP duration must be between 1 and {MAX_TTL} seconds')
    with state.lock('maintenance.lock', exclusive_now=request is not None):
        state.verify()
        reconcile(state)
        if request:
            with state.connect() as db:
                db.execute('BEGIN')
                previous = request.previous(db)
                if previous is not None:
                    return previous
                request.authorize(db, protocol, provider)
        if binary is None or not binary.is_absolute() or not binary.is_file():
            if request:
                raise PeerError('UNAVAILABLE', 'The service owner must configure an installed frpc')
            raise StateError('The service owner must install frpc first')
        settings = settings or Settings.load(state.directory / 'frp.toml')
        plan = settings.plan(state, provider, service_id, protocol, domain=domain, public_port=public_port)
        content = Plan.config_json(plan.client_config())
        exposure = uuid4().hex
        created = time.time()
        with state.connect(write=True) as db:
            if request:
                request.authorize(db, protocol, provider)
            if db.execute("SELECT count(*) FROM frp_exposure WHERE status IN ('starting','running','revoking')").fetchone()[0] >= MAX_ACTIVE:
                raise StateError(f'At most {MAX_ACTIVE} FRP mappings may be active on this node')
            if db.execute("SELECT 1 FROM frp_exposure WHERE public_address=? AND status IN ('starting','running','revoking')",
                          (plan.address,)).fetchone():
                raise StateError('This public address already has an active FRP mapping')
            db.execute('''
                INSERT INTO frp_exposure (id,service_id,provider,protocol,domain,public_port,public_address,
                    local_address,config_sha256,created_at,expires_at,origin_node,status)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,'starting')
            ''', (exposure, service_id, provider, protocol, domain, plan.public_port, plan.address,
                  plan.summary()['local_address'], sha256(content.encode()).hexdigest(), created, created + ttl,
                  request.origin if request else None))
            if request:
                request.record(db, exposure)
            audit(db, request.actor if request else 'admin', request.origin if request else 'local',
                  'frp.exposure.requested', exposure)
        try:
            launch(state, exposure, binary)
        except OSError:
            with state.connect(write=True) as db:
                finish(db, exposure, 'failed', 'Could not start the FRP supervisor')
        if request:
            with state.connect() as db:
                return public_data(read(db, exposure))
    return wait_status(state, exposure, 'starting', 5)


def revoke(state: State, exposure: str, *, request: Request | None = None) -> dict:
    with state.lock('maintenance.lock', exclusive_now=request is not None):
        state.verify()
        with state.connect(write=True) as db:
            if request:
                previous = request.previous(db)
                if previous is not None:
                    return previous
            row = read(db, exposure)
            if row is None:
                if request:
                    raise PeerError('NOT_FOUND', 'Unknown FRP mapping')
                raise StateError('Unknown FRP mapping ID')
            if request:
                request.check(db, row)
                request.record(db, exposure)
            if row['status'] in ('starting', 'running'):
                db.execute("UPDATE frp_exposure SET status='revoking', health=NULL WHERE id=?", (exposure,))
                audit(db, request.actor if request else 'admin', request.origin if request else 'local',
                      'frp.exposure.revoke_requested', exposure)
            if request:
                return public_data(read(db, exposure))
    return wait_status(state, exposure, 'revoking', 5)


def require_stopped(state: State, *, operation: str = "restoring") -> None:
    reconcile(state)
    with state.connect() as db:
        if db.execute("SELECT 1 FROM frp_exposure WHERE status IN ('starting','running','revoking')").fetchone():
            raise StateError(f'Revoke active FRP mappings before {operation} this node')


def clear_restored(db: sqlite3.Connection) -> None:
    rows = db.execute("SELECT id FROM frp_exposure WHERE status IN ('starting','running','revoking')").fetchall()
    for (exposure,) in rows:
        # The offline restore checks local workers before replacing the database.
        finish(db, exposure, 'revoked', 'Restored mapping is inactive')


def linux_child(argv: list[str], directory: Path) -> subprocess.Popen:
    import ctypes

    parent = os.getpid()
    prctl = ctypes.CDLL(None, use_errno=True).prctl

    def bind_to_supervisor():
        # Linux PR_SET_PDEATHSIG also closes the proxy if the supervisor is killed.
        if prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
            os._exit(125)

    return subprocess.Popen(argv, cwd=directory, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, preexec_fn=bind_to_supervisor)


def stop_child(child) -> None:
    if WINDOWS:
        import win32event

        try:
            child.terminate()
            if win32event.WaitForSingleObject(child.process, 3000) != win32event.WAIT_OBJECT_0:
                raise OSError('frpc termination is pending')
        finally:
            child.close()
        return
    if child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            child.kill()
    child.wait()


def observe(output, proxy: str, events: Queue) -> None:
    prefix = f'[{proxy}] '.encode()
    for line in iter(lambda: output.readline(8192), b''):
        line = line.rstrip()
        if line.endswith(prefix + b'start proxy success'):
            health = 'ready'
        elif line.endswith(prefix + b'health check failed'):
            health = 'backend_unavailable'
        elif line.endswith(prefix + b'health check success'):
            health = 'backend_ready'
        elif prefix + b'start error: ' in line:
            health = 'provider_rejected'
        elif line.endswith(b' try to connect to server...'):
            health = 'connecting'
        else:
            continue
        try:
            events.put_nowait(health)
        except Full:
            pass


def watch(state: State, row: sqlite3.Row, child, output, proxy: str, stop: Event) -> tuple[str, str | None]:
    events = Queue(maxsize=32)
    reader = Thread(target=observe, args=(output, proxy, events), daemon=True)
    reader.start()
    expiry = row['expires_at']
    deadline = time.monotonic() + max(0, expiry - time.time())
    health = 'connecting'
    while True:
        if time.time() >= expiry or time.monotonic() >= deadline:
            return 'expired', None
        with state.connect() as db:
            current = read(db, row['id'])
        if current is None or current['status'] != 'running':
            return 'revoked', None
        if stop.is_set():
            return 'failed', 'FRP supervisor was stopped'
        code = child.poll()
        if code is not None:
            return 'failed', f'frpc exited with code {code}'
        try:
            update = events.get(timeout=min(POLL_INTERVAL, max(0, deadline - time.monotonic())))
        except Empty:
            continue
        if update == 'backend_ready':
            if health != 'backend_unavailable':
                continue
            update = 'connecting'
        if update != health:
            with state.connect(write=True) as db:
                db.execute("UPDATE frp_exposure SET health=? WHERE id=? AND status='running'", (update, row['id']))
            health = update


def supervise(state_dir: str, exposure: str, frpc: str) -> int:
    os.umask(0o077)
    state = State(Path(state_dir))
    local_id = state.verify()
    stop = Event()
    if not WINDOWS:
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
        signal.signal(signal.SIGINT, lambda *_: stop.set())
    with state.connect(write=True) as db:
        row = read(db, exposure)
        if row is None or row['status'] != 'starting' or row['guardian_pid'] is not None:
            return 1
        if time.time() >= row['expires_at']:
            finish(db, exposure, 'expired')
            return 0
        db.execute('UPDATE frp_exposure SET guardian_pid=?, guardian_start=? WHERE id=?',
                   (os.getpid(), process_start(os.getpid()), exposure))
    try:
        settings = Settings.load(state.directory / 'frp.toml')
        plan = settings.plan(state, row['provider'], row['service_id'], row['protocol'],
                             domain=row['domain'], public_port=row['public_port'] if row['protocol'] == 'tcp' else None)
        config = plan.client_config()
        content = Plan.config_json(config)
        if sha256(content.encode()).hexdigest() != row['config_sha256']:
            raise StateError('FRP mapping configuration changed before startup')
        verify_config(Path(frpc), state.directory, content)
        with TemporaryDirectory(prefix='.frp-run-', dir=state.directory) as temporary:
            path = Path(temporary) / 'frpc.json'
            path.write_text(content, encoding='utf-8')
            argv = [frpc, '-c', str(path)]
            child = None
            output = None
            try:
                with state.connect(write=True) as db:
                    current = read(db, exposure)
                    if current is None or current['status'] != 'starting':
                        finish(db, exposure, 'revoked')
                        return 0
                    if time.time() >= row['expires_at']:
                        finish(db, exposure, 'expired')
                        return 0
                    if row['origin_node'] not in (None, local_id):
                        from .peer.frp_access import check_remote_start

                        check_remote_start(db, state, local_id, row)
                    child = WindowsChild(argv, temporary) if WINDOWS else linux_child(argv, Path(temporary))
                    output = child.output if WINDOWS else child.stdout
                    db.execute("UPDATE frp_exposure SET status='running',health='connecting' WHERE id=?", (exposure,))
                    audit(db, 'frp', 'local', 'frp.exposure.started', exposure)
                status, detail = watch(state, row, child, output, config['proxies'][0]['name'], stop)
            finally:
                if child is not None:
                    try:
                        stop_child(child)
                    finally:
                        if output is not None:
                            output.close()
    except Exception as error:
        status, detail = 'failed', f'FRP supervisor error: {type(error).__name__}'
    with state.connect(write=True) as db:
        finish(db, exposure, status, detail)
    return 1 if status == 'failed' else 0


if __name__ == '__main__':
    raise SystemExit(supervise(*sys.argv[1:]))
