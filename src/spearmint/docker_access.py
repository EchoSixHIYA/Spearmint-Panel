"""Host-authorized local Docker access through a per-account Unix socket."""
import json
import os
from pathlib import Path
import stat
import sys

FORMAT = 'spearmint-docker-access-v1'


def endpoint(configured: Path) -> Path:
    """Prefer this account's rootless daemon; fall back only when it is absent."""
    if sys.platform == 'linux' and configured == Path(f'/run/user/{os.getuid()}/docker.sock'):
        try:
            configured.lstat()
        except FileNotFoundError:
            return Path('/var/run/docker.sock')
        except OSError:
            pass
    return configured


def proxy_for(configured: Path) -> Path | None:
    if sys.platform != 'linux':
        return None
    uid = os.getuid()
    record = Path(f'/etc/spearmint/docker-access-{uid}.json')
    proxy = Path(f'/run/spearmint-docker-{uid}.sock')
    try:
        info = record.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 4096:
            return None
        value = json.loads(record.read_bytes())
        if value != {'format': FORMAT, 'uid': uid, 'upstream': str(endpoint(configured))}:
            return None
        info = proxy.lstat()
        if stat.S_ISSOCK(info.st_mode) and info.st_uid == uid and not info.st_mode & 0o077 and os.access(proxy, os.R_OK | os.W_OK):
            return proxy
    except (OSError, ValueError):
        pass
    return None


def available(configured: Path) -> bool:
    from .host import HostError, local_docker_command
    try:
        local_docker_command(configured)
        return True
    except HostError:
        return False


def bootstrap_source(username: str, configured: Path | None = None, *, optional=False, plan=False) -> str:
    return (BOOTSTRAP.replace('ACCOUNT_VALUE', repr(username))
            .replace('ENDPOINT_VALUE', repr(str(configured) if configured is not None else None))
            .replace('OPTIONAL_VALUE', repr(bool(optional))).replace('PLAN_VALUE', repr(bool(plan))))


def ssh_enable(connection, username: str, password: str = '', *, configured: Path | None = None, optional=False):
    from .host import HostError
    from .host_service_access import ssh_bootstrap
    result = ssh_bootstrap(connection, bootstrap_source(username, configured, optional=optional), password)
    if result.get('enabled') is not True and not (optional and result.get('reason') == 'docker-unavailable'):
        raise HostError('目标机没有确认 Docker 管理授权已启用。')
    return result


BOOTSTRAP = r'''
import fcntl, http.client, json, os, pathlib, pwd, socket, stat, subprocess, tempfile, time
if not PLAN_VALUE and os.geteuid() != 0: raise RuntimeError('A host administrator must authorize Docker access')
account = pwd.getpwnam(ACCOUNT_VALUE)
uid = account.pw_uid
if uid == 0: raise RuntimeError('Select the non-root panel account')
upstream = ENDPOINT_VALUE
if upstream is None or upstream == '/run/user/' + str(uid) + '/docker.sock':
 candidate = '/run/user/' + str(uid) + '/docker.sock'
 upstream = candidate if pathlib.Path(candidate).exists() else '/var/run/docker.sock'
if not pathlib.Path(upstream).is_absolute() or any(ord(c) < 32 for c in upstream): raise ValueError('Use a local Docker Unix socket')

def request(path, url):
 with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
  connection.settimeout(4)
  connection.connect(path)
  connection.sendall(('GET ' + url + ' HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n').encode())
  response = http.client.HTTPResponse(connection)
  response.begin()
  body = response.read(8193)
  if response.status != 200 or len(body) > 8192: raise RuntimeError('Docker readiness failed')
  return body

if not PLAN_VALUE:
 try:
  if not stat.S_ISSOCK(os.stat(upstream).st_mode): raise RuntimeError('Docker endpoint is not a socket')
  if request(upstream,'/_ping').strip() != b'OK': raise RuntimeError('Invalid Docker ping')
  if not isinstance(json.loads(request(upstream,'/version')).get('ApiVersion'),str): raise RuntimeError('Invalid Docker version')
 except (OSError,ValueError,RuntimeError,http.client.HTTPException):
  if OPTIONAL_VALUE:
   print(json.dumps({'enabled':False,'reason':'docker-unavailable'}))
   raise SystemExit(0)
  raise RuntimeError('Start the local Docker daemon before authorizing it')

proxyd = next((p for p in ('/usr/lib/systemd/systemd-socket-proxyd','/lib/systemd/systemd-socket-proxyd') if pathlib.Path(p).is_file()), None)
if proxyd is None or not pathlib.Path('/run/systemd/system').is_dir(): raise RuntimeError('systemd socket proxy is required')

name = 'spearmint-docker-' + str(uid)
marker = '# Spearmint Docker access v1'
proxy = '/run/' + name + '.sock'
def quote(value): return '"' + value.replace('\\','\\\\').replace('"','\\"').replace('%','%%').replace('$','$$') + '"'
service = marker + '\n[Unit]\nDescription=Spearmint local Docker access\nRequires=' + name + '.socket\nAfter=' + name + '.socket\n[Service]\nExecStart=' + quote(proxyd) + ' ' + quote(upstream) + '\nUser=root\nGroup=root\nNoNewPrivileges=yes\nProtectSystem=strict\nRestrictAddressFamilies=AF_UNIX\nCapabilityBoundingSet=CAP_DAC_OVERRIDE\nUMask=0077\n'
socket_unit = marker + '\n[Unit]\nDescription=Spearmint Docker access socket\n[Socket]\nListenStream=' + proxy + '\nSocketUser=' + str(uid) + '\nSocketMode=0600\nRemoveOnStop=yes\n[Install]\nWantedBy=sockets.target\n'
record = {'format':'spearmint-docker-access-v1','uid':uid,'upstream':upstream}
record_path = '/etc/spearmint/docker-access-' + str(uid) + '.json'
files = {'/etc/systemd/system/' + name + '.service':service,
         '/etc/systemd/system/' + name + '.socket':socket_unit,
         record_path:json.dumps(record) + '\n'}
if PLAN_VALUE:
 print(json.dumps({'enabled':False,'uid':uid,'upstream':upstream,'files':files,'business_services_restarted':False}))
 raise SystemExit(0)
lock_fd = os.open('/run/' + name + '-install.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
fcntl.flock(lock_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
socket_name, service_name = name + '.socket', name + '.service'
def state(action,unit): return subprocess.run(['/usr/bin/systemctl',action,unit],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5).returncode == 0
was_enabled, was_active, worker_active = state('is-enabled',socket_name), state('is-active',socket_name), state('is-active',service_name)
changed, previous = [], {}
for filename,content in files.items():
 path = pathlib.Path(filename)
 if path.is_symlink(): raise RuntimeError('Unrecognized Docker access path')
 if path.exists():
  old = path.read_text()
  recognized = json.loads(old).get('format') == record['format'] if filename == record_path else old.startswith(marker)
  if path.stat().st_uid != 0 or not recognized: raise RuntimeError('Unrecognized Docker access configuration')
  if old == content: continue
 changed.append((path,content))
 previous[filename] = {'content':path.read_text(),'mode':stat.S_IMODE(path.stat().st_mode)} if path.exists() else None
backup = pathlib.Path('/var/lib/spearmint-host') / str(uid) / ('docker-' + str(time.time_ns()))
if changed:
 backup.mkdir(parents=True,mode=0o700)
 (backup/'previous.json').write_text(json.dumps(previous))
 os.chmod(backup/'previous.json',0o600)
try:
 for path,content in changed:
  path.parent.mkdir(parents=True,exist_ok=True,mode=0o755)
  if path.parent.is_symlink() or path.parent.stat().st_uid != 0 or path.parent.stat().st_mode & 0o022: raise RuntimeError('Docker access directory must be root-owned')
  fd,temporary = tempfile.mkstemp(dir=path.parent)
  try:
   with os.fdopen(fd,'w') as output: output.write(content); output.flush(); os.fsync(output.fileno())
   os.chmod(temporary,0o644)
   os.replace(temporary,path)
  finally: pathlib.Path(temporary).unlink(missing_ok=True)
 subprocess.run(['/usr/bin/systemctl','daemon-reload'],check=True,timeout=15)
 subprocess.run(['/usr/bin/systemctl','enable','--now',socket_name],check=True,timeout=20)
 if changed: subprocess.run(['/usr/bin/systemctl','try-restart',service_name],check=True,timeout=15)
 if request(proxy,'/_ping').strip() != b'OK': raise RuntimeError('Docker access did not become ready')
except Exception:
 if not was_active: subprocess.run(['/usr/bin/systemctl','stop',socket_name,service_name],timeout=15)
 if not was_enabled: subprocess.run(['/usr/bin/systemctl','disable',socket_name],timeout=15)
 for filename,old in previous.items():
  path = pathlib.Path(filename)
  if old is None: path.unlink(missing_ok=True)
  else: path.write_text(old['content']); os.chmod(path,old['mode'])
 subprocess.run(['/usr/bin/systemctl','daemon-reload'],timeout=15)
 if was_active: subprocess.run(['/usr/bin/systemctl','start',socket_name],timeout=15)
 if worker_active: subprocess.run(['/usr/bin/systemctl','try-restart',service_name],timeout=15)
 raise
print(json.dumps({'enabled':True,'uid':uid,'upstream':upstream,'proxy':proxy,'backup':str(backup) if changed else None}))
'''
