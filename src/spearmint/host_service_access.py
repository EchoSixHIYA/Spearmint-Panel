"""Node-wide Linux service access, provisioned once by a host administrator."""
from base64 import b64encode
import json
import os
from pathlib import Path
import socket
import sys
import subprocess
from shlex import join

from .host import HostError, HostTimeout

PROTOCOL = 1
MARKER = '# Spearmint host service access v1'


def account_name():
    if os.name == 'posix':
        import pwd
        return pwd.getpwuid(os.getuid()).pw_name
    import getpass
    return getpass.getuser()


def enable_command():
    binary = Path(sys.executable) if getattr(sys, 'frozen', False) else Path.home() / '.local/opt/spearmint/current/spearmint'
    return join(['sudo', str(binary), 'host-services', 'enable', '--user', account_name()])

# Standalone code is embedded so native packages can install a root-owned copy without
# executing code from the panel user's writable installation directory afterward.
WORKER = r'''# Spearmint host service access v1
# SPDX-License-Identifier: AGPL-3.0-only
import concurrent.futures, json, os, re, selectors, signal, socket, struct, subprocess, sys, threading, time
UNIT = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.@:\\-]{0,245}\.service')
LIMIT = 256 * 1024

def capture(argv, timeout=5, limit=LIMIT):
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    output = bytearray()
    truncated = False
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise TimeoutError('Host command timed out')
            for key, _ in selector.select(min(remaining, .5)):
                data = os.read(key.fd, 8192)
                if not data:
                    selector.unregister(key.fd)
                    continue
                available = limit - len(output)
                output.extend(data[:available])
                if len(data) > available:
                    truncated = True
                    break
            if truncated: break
        if not truncated: process.wait(timeout=max(.1, deadline - time.monotonic()))
        return {'code': process.returncode if not truncated else 0, 'text': output.decode('utf-8', 'replace'), 'truncated': truncated}
    finally:
        selector.close()
        if process.poll() is None:
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            process.wait(timeout=2)
        process.stdout.close()

def handle(body):
    if not isinstance(body, dict): raise ValueError('Invalid host request')
    action = body.get('action')
    if action == 'ping' and body.keys() == {'action'}:
        return {'protocol': 1, 'control': True, 'logs': True}
    unit = body.get('unit')
    if not isinstance(unit, str) or not UNIT.fullmatch(unit): raise ValueError('Invalid service unit')
    if action not in {'check', 'start', 'stop', 'restart', 'logs'}: raise ValueError('Unsupported host operation')
    expected = {'action', 'unit', 'tail'} if action == 'logs' else {'action', 'unit'}
    if body.keys() != expected: raise ValueError('Unexpected host request fields')
    info = capture(['/usr/bin/systemctl', '--system', '--no-ask-password', '--no-pager', 'show',
                    '--property=Id,LoadState,Transient', unit], limit=8192)
    properties = dict(line.split('=', 1) for line in info['text'].splitlines() if '=' in line)
    if info['code'] or info['truncated'] or properties.get('Id') != unit or properties.get('LoadState') != 'loaded' or properties.get('Transient') != 'no':
        raise ValueError('Select an existing system service')
    if action == 'check': return {'control': True, 'logs': True}
    if action == 'logs':
        tail = body['tail']
        if type(tail) is not int or not 1 <= tail <= 501: raise ValueError('Invalid log tail')
        result = capture(['/usr/bin/journalctl', '--system', '--quiet', '--no-pager', '--unit=' + unit,
                          '--lines=' + str(tail), '--output=short-iso-precise'])
    else:
        result = capture(['/usr/bin/systemctl', '--system', '--no-ask-password', '--no-pager', action, unit], timeout=45, limit=8192)
    if result['code']: raise RuntimeError(result['text'][-1000:] or 'Host operation failed')
    return result

def serve(uid):
    if int(os.environ.get('LISTEN_PID', '0')) != os.getpid() or os.environ.get('LISTEN_FDS') != '1':
        raise RuntimeError('Start the host helper through its systemd socket')
    server = socket.socket(fileno=3)
    slots = threading.BoundedSemaphore(8)
    def answer(connection):
        try:
            connection.settimeout(50)
            peer = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if peer[1] not in {uid, 0}: return
            with connection.makefile('rb') as stream:
                raw = stream.readline(4097)
                if len(raw) > 4096 or not raw.endswith(b'\n'): return
                try: result = {'result': handle(json.loads(raw))}
                except (TimeoutError, subprocess.TimeoutExpired) as error: result = {'error':str(error)[:1000],'timeout':True}
                except Exception as error: result = {'error': str(error)[:1000]}
                connection.sendall(json.dumps(result, ensure_ascii=False).encode('utf-8') + b'\n')
        finally:
            connection.close()
            slots.release()
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as workers:
        while True:
            connection, _ = server.accept()
            if slots.acquire(blocking=False): workers.submit(answer, connection)
            else: connection.close()

if __name__ == '__main__': serve(int(sys.argv[1]))
'''


def socket_path(uid=None):
    return Path(f'/run/spearmint-host-{os.getuid() if uid is None else uid}.sock')


def request(action: str, unit: str | None = None, *, tail: int = 501, timeout=6):
    if sys.platform != 'linux':
        raise HostError('Host service access is only available on Linux')
    body = {'action': action}
    if unit is not None:
        body['unit'] = unit
    if action == 'logs':
        body['tail'] = tail
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout)
            connection.connect(str(socket_path()))
            connection.sendall(json.dumps(body).encode() + b'\n')
            with connection.makefile('rb') as stream:
                raw = stream.readline(2 * 1024 * 1024 + 1)
            if not raw.endswith(b'\n') or len(raw) > 2 * 1024 * 1024:
                raise ValueError('Invalid host helper response')
            response = json.loads(raw)
            if response.get('error'):
                if response.get('timeout'):
                    raise HostTimeout(response['error'])
                raise HostError(response['error'])
            result = response['result']
            if not isinstance(result, dict):
                raise ValueError('Invalid host helper response')
            return result
    except socket.timeout as error:
        raise HostTimeout('主机管理操作超时，请核对服务当前状态。') from error
    except (OSError, KeyError, ValueError) as error:
        raise HostError('此节点尚未启用主机服务管理，或主机管理服务暂不可用。') from error


def available():
    if sys.platform != 'linux' or not socket_path().exists():
        return False
    try:
        return request('ping', timeout=2).get('protocol') == PROTOCOL
    except HostError:
        return False


def bootstrap_source(username: str, *, plan=False) -> str:
    """Return the reviewed installer used by both CLI and SSH seeding; contains no credentials."""
    return BOOTSTRAP.replace('WORKER_BASE64', b64encode(WORKER.encode()).decode()).replace('PLAN_BOOL', repr(bool(plan))).replace('ACCOUNT_JSON', repr(username))


def enable(username: str):
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise HostError('请由主机管理员执行一次 sudo ./spearmint host-services enable --user <面板用户>。')
    result = subprocess.run(['/usr/bin/python3', '-I', '-B', '-c', bootstrap_source(username)], capture_output=True, timeout=65)
    if result.returncode:
        raise HostError(result.stderr.decode('utf-8', 'replace')[-1500:])
    return json.loads(result.stdout)


def plan(username: str):
    if sys.platform != 'linux':
        raise HostError('主机服务管理配置适用于 Linux 节点。')
    result = subprocess.run(['/usr/bin/python3', '-I', '-B', '-c', bootstrap_source(username, plan=True)], capture_output=True, timeout=10)
    if result.returncode:
        raise HostError(result.stderr.decode('utf-8', 'replace')[-1500:])
    return json.loads(result.stdout)


def ssh_enable(connection, username: str, password: str = ''):
    result = ssh_bootstrap(connection, bootstrap_source(username), password)
    if result.get('enabled') is not True:
        raise HostError('目标机没有确认主机服务管理已启用。')
    return result


def ssh_bootstrap(connection, script: str, password: str = ''):
    try:
        connection.answer('/usr/bin/test -x /usr/bin/python3', timeout=5)
    except subprocess.CalledProcessError as error:
        raise HostError('目标机缺少 /usr/bin/python3；主机服务管理需要系统已有 Python3，普通面板不受影响。') from error
    command = ['/usr/bin/python3', '-I', '-B', '-c', script]
    try:
        if getattr(connection, 'linux_root', False) and getattr(connection, 'linux_user', None):
            output = connection.root_answer(join(command), timeout=65)
        elif getattr(connection, 'linux_root', False):
            output = connection.answer(join(command), timeout=65)
        else:
            output = connection.answer(join(['/usr/bin/env', 'LC_ALL=C', '/usr/bin/sudo', '-n', '--', *command]), timeout=65)
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or b'').decode('utf-8', 'replace').lower()
        if getattr(connection, 'linux_root', False):
            raise HostError('主机管理服务未能安装：' + detail[-800:]) from error
        if password and 'password' not in detail and 'terminal is required' not in detail:
            raise HostError('主机管理服务未能安装：' + detail[-800:]) from error
        if not password or '\n' in password or '\r' in password:
            raise HostError('目标机需要一次 sudo 授权。请填写主机管理员密码，或关闭系统服务管理仅安装普通面板。') from error
        # The password travels on SSH stdin, never in command arguments or job receipts.
        output = connection.answer(join(['/usr/bin/env', 'LC_ALL=C', '/usr/bin/sudo', '-S', '-p', '', '--', *command]),
                                   input_data=(password + '\n').encode('utf-8'), timeout=65)
    return json.loads(output)


BOOTSTRAP = r'''
import base64, fcntl, json, os, pathlib, pwd, shutil, socket, stat, subprocess, tempfile, time
if not PLAN_BOOL and os.geteuid() != 0: raise RuntimeError('A host administrator must enable service management once')
account = pwd.getpwnam(ACCOUNT_JSON)
if account.pw_uid == 0: raise RuntimeError('Select the dedicated non-root panel account')
if not pathlib.Path('/run/systemd/system').is_dir(): raise RuntimeError('A running systemd manager is required')
if not pathlib.Path('/usr/bin/python3').is_file(): raise RuntimeError('The host helper requires /usr/bin/python3')
uid = account.pw_uid
name = 'spearmint-host-' + str(uid)
marker = '# Spearmint host service access v1'
worker = base64.b64decode('WORKER_BASE64').decode('utf-8')
compile(worker,'<host-worker>','exec')
service = marker + '\n[Unit]\nDescription=Spearmint host service management\n[Service]\nType=simple\nExecStart=/usr/bin/python3 -I -B /usr/local/lib/spearmint/' + name + '.py ' + str(uid) + '\nUser=root\nGroup=root\nNoNewPrivileges=true\nProtectSystem=strict\nProtectHome=true\nPrivateTmp=true\nRestrictAddressFamilies=AF_UNIX\nCapabilityBoundingSet=\nUMask=0077\n'
socket_unit = marker + '\n[Unit]\nDescription=Spearmint host service access socket\n[Socket]\nListenStream=/run/' + name + '.sock\nSocketUser=' + str(uid) + '\nSocketMode=0600\nRemoveOnStop=true\n[Install]\nWantedBy=sockets.target\n'
files = {
 '/usr/local/lib/spearmint/' + name + '.py': worker,
 '/etc/systemd/system/' + name + '.service': service,
 '/etc/systemd/system/' + name + '.socket': socket_unit,
}
if PLAN_BOOL:
 print(json.dumps({'user':account.pw_name,'uid':uid,'files':files,'business_services_restarted':False}))
 raise SystemExit(0)
lock_fd = os.open('/run/' + name + '-install.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
backup = pathlib.Path('/var/lib/spearmint-host') / str(uid) / str(time.time_ns())
socket_name = 'spearmint-host-' + str(uid) + '.socket'
service_name = 'spearmint-host-' + str(uid) + '.service'
def state(action, unit):
 return subprocess.run(['/usr/bin/systemctl',action,unit],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5).returncode == 0
was_enabled = state('is-enabled', socket_name)
was_active = state('is-active', socket_name)
worker_active = state('is-active', service_name)
changed = []
for name, content in files.items():
 path = pathlib.Path(name)
 if path.is_symlink(): raise RuntimeError('Host helper path is a symlink: ' + name)
 if path.exists():
  if path.stat().st_uid != 0 or not path.read_text().startswith(marker): raise RuntimeError('Unrecognized existing host helper file: ' + name)
  if path.read_text() == content: continue
 changed.append((path, content))
if changed:
 backup.mkdir(parents=True, mode=0o700)
 previous = {}
 for path, content in changed:
  previous[str(path)] = {'content':path.read_text(),'mode':stat.S_IMODE(path.stat().st_mode)} if path.exists() else None
 (backup / 'previous.json').write_text(json.dumps(previous))
 os.chmod(backup / 'previous.json', 0o600)
try:
 for path, content in changed:
  path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
  if path.parent.is_symlink() or path.parent.stat().st_uid != 0 or stat.S_IMODE(path.parent.stat().st_mode) & 0o022:
   raise RuntimeError('Host helper directory must be root-owned and not group/world writable')
  fd, temporary = tempfile.mkstemp(dir=path.parent)
  try:
   with os.fdopen(fd,'w') as stream: stream.write(content); stream.flush(); os.fsync(stream.fileno())
   os.chmod(temporary,0o644)
   os.replace(temporary,path)
  finally:
   pathlib.Path(temporary).unlink(missing_ok=True)
 subprocess.run(['/usr/bin/systemctl','daemon-reload'],check=True,timeout=15)
 subprocess.run(['/usr/bin/systemctl','enable','--now','spearmint-host-' + str(uid) + '.socket'],check=True,timeout=20)
 if changed: subprocess.run(['/usr/bin/systemctl','try-restart','spearmint-host-' + str(uid) + '.service'],check=True,timeout=15)
 healthy = False
 for attempt in range(12):
  try:
   with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
    connection.settimeout(3)
    connection.connect('/run/spearmint-host-' + str(uid) + '.sock')
    connection.sendall(b'{"action":"ping"}\n')
    with connection.makefile('rb') as stream: answer=json.loads(stream.readline(4096))
    healthy = answer.get('result',{}).get('protocol') == 1
    if healthy: break
  except (OSError,ValueError): pass
  time.sleep(.2)
 if not healthy: raise RuntimeError('The host service did not pass its local readiness check')
except Exception:
 if not was_active: subprocess.run(['/usr/bin/systemctl','stop',socket_name,service_name],timeout=15)
 if not was_enabled: subprocess.run(['/usr/bin/systemctl','disable',socket_name],timeout=15)
 if changed:
  for name, old in previous.items():
   path=pathlib.Path(name)
   if old is None: path.unlink(missing_ok=True)
   else: path.write_text(old['content']); os.chmod(path,old['mode'])
  subprocess.run(['/usr/bin/systemctl','daemon-reload'],timeout=15)
  subprocess.run(['/usr/bin/systemctl','reset-failed',service_name],timeout=15)
  if was_active: subprocess.run(['/usr/bin/systemctl','start',socket_name],timeout=15)
  if worker_active: subprocess.run(['/usr/bin/systemctl','try-restart',service_name],timeout=15)
 raise
print(json.dumps({'enabled':True,'user':account.pw_name,'uid':uid,'files':list(files),'backup':str(backup) if changed else None}))
'''
