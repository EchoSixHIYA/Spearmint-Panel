"""A short-lived SSH connection owned by the node executing a seed request."""
from base64 import b64encode
from contextlib import suppress
from hashlib import sha256
from io import BytesIO, StringIO
from ipaddress import ip_address
import json
from pathlib import PurePosixPath, PureWindowsPath
import re
import secrets
from shlex import join
import socket
from stat import S_ISDIR
from subprocess import CalledProcessError, TimeoutExpired
from threading import Thread
from time import monotonic, sleep

import paramiko

from .peer.protocol import PeerError


FINGERPRINT = re.compile(r'SHA256:[A-Za-z0-9+/]{43}')
WINDOWS_PROBE = 'echo %PROCESSOR_ARCHITECTURE% %PROCESSOR_ARCHITEW6432%'
WINDOWS_RECEIPT = b'SPEARMINT_WINDOWS_SEED='
MINIMUM_GLIBC = (2, 17)
LINUX_PROBE = r'''printf 'SPMT_OS=%s\n' "$(uname -s 2>/dev/null)";
printf 'SPMT_ARCH=%s\n' "$(uname -m 2>/dev/null)";
printf 'SPMT_HOME=%s\n' "$HOME";
printf 'SPMT_UID=%s\n' "$(id -u 2>/dev/null)";
printf 'SPMT_LIBC=%s\n' "$(getconf GNU_LIBC_VERSION 2>/dev/null || (ldd --version 2>&1 | head -n 1))"'''


class SystemSeedFailure(PeerError):
    def __init__(self, code: str, detail: str):
        super().__init__(code, 'The SSH system probe did not confirm a supported installation account')
        self.detail = detail


class WindowsSeedFailure(PeerError):
    def __init__(self, code: str, detail: str):
        super().__init__(code, 'The native Windows helper did not return a receipt')
        self.detail = detail


def hostname(value: str) -> str:
    try:
        return str(ip_address(value.strip('[]')))
    except ValueError:
        if re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?', value):
            return value.lower()
    raise ValueError('Use an IP address or DNS hostname')


def cmd(command: str, *, unicode: bool = False) -> str:
    return 'cmd.exe /d ' + ('/u ' if unicode else '') + '/v:off /s /c "' + command + '"'


def windows_path(value: str) -> PureWindowsPath:
    return PureWindowsPath(value[1:] if re.match(r'^/[A-Za-z]:/', value) else value)


def authenticate(connection: paramiko.Transport, username: str, secret: str, key: bool):
    if not key:
        connection.auth_password(username, secret, fallback=False)
        return
    for parser in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            private = parser.from_private_key(StringIO(secret))
        except paramiko.PasswordRequiredException:
            raise PeerError('SEED_SSH_AUTH', 'Use an unencrypted private key or password for this connection') from None
        except (paramiko.SSHException, ValueError):
            continue
        connection.auth_publickey(username, private)
        return
    raise PeerError('SEED_SSH_AUTH', 'Unsupported SSH private key')


class Connection:
    def __init__(self, host: str, port: int):
        self.windows_stage: tuple[str, PureWindowsPath] | None = None
        self.linux_root = False
        self.linux_user = None
        self.socket = socket.create_connection((host, port), timeout=6)
        self.transport = paramiko.Transport(self.socket)
        self.transport.channel_timeout = 8
        try:
            self.transport.start_client(timeout=6)
            digest = b64encode(sha256(self.transport.get_remote_server_key().asbytes()).digest()).decode().rstrip('=')
            self.fingerprint = 'SHA256:' + digest
        except BaseException:
            self.close()
            raise

    def login(self, expected: str, username: str, secret: str, key: bool):
        if not secrets.compare_digest(expected, self.fingerprint):
            raise PeerError('SEED_HOST_KEY', 'SSH host fingerprint does not match')
        try:
            self.transport.auth_timeout = 8
            authenticate(self.transport, username, secret, key)
            if not self.transport.is_authenticated():
                raise paramiko.AuthenticationException()
        except paramiko.AuthenticationException:
            raise PeerError('SEED_SSH_AUTH', 'SSH rejected the provided credentials') from None
        self.transport.set_keepalive(12)

    def close(self):
        if self.windows_stage is not None and self.transport.is_authenticated():
            name, staging = self.windows_stage
            self.windows_stage = None
            with suppress(OSError, paramiko.SSHException, CalledProcessError, TimeoutExpired, UnicodeError):
                with paramiko.SFTPClient.from_transport(self.transport) as sftp:
                    sftp.get_channel().settimeout(5)
                    home = windows_path(sftp.normalize('.'))
                    target = windows_path(sftp.normalize(name))
                    safe = target == staging == home / name and home.is_absolute()
                if safe and self.windows_cwd() == staging.parent:
                    self.answer(cmd(f'rmdir /s /q {name}'), timeout=6)
        self.transport.close()
        self.socket.close()

    def run(self, command, source, output, timeout: float, *, limit: int = 128 * 1024, privileged: bool = False):
        if getattr(self, 'linux_user', None) and not privileged:
            from .seed_linux import command as user_command
            command = user_command(self.linux_user, self.linux_home, self.linux_uid, command)
        deadline = monotonic() + timeout
        with self.transport.open_session(timeout=min(timeout, 6)) as channel:
            channel.settimeout(timeout)
            channel.exec_command(command)
            writer_error = []

            def send():
                try:
                    if hasattr(source, 'read'):
                        while block := source.read(128 * 1024):
                            channel.sendall(block)
                    channel.shutdown_write()
                except (OSError, EOFError, paramiko.SSHException) as error:
                    writer_error.append(error)

            sender = Thread(target=send, daemon=True)
            sender.start()
            size = 0
            diagnostic = bytearray()
            try:
                while monotonic() < deadline:
                    if channel.recv_ready():
                        data = channel.recv(32768)
                        size += len(data)
                        if size > limit:
                            raise PeerError('LIMIT', 'SSH output exceeds the seed response limit')
                        output.write(data)
                    elif channel.recv_stderr_ready():
                        data = channel.recv_stderr(32768)
                        size += len(data)
                        if size > limit:
                            raise PeerError('LIMIT', 'SSH output exceeds the seed response limit')
                        diagnostic.extend(data)
                        del diagnostic[:-8192]
                    elif channel.exit_status_ready():
                        status = channel.recv_exit_status()
                        if status or writer_error:
                            raise CalledProcessError(status or 255, 'seed', stderr=bytes(diagnostic))
                        return
                    else:
                        sleep(.02)
                raise TimeoutExpired('seed', timeout, stderr=bytes(diagnostic))
            finally:
                channel.close()
                sender.join(3)

    def answer(self, command, input_data: bytes = b'', *, timeout: float = 12) -> bytes:
        output = BytesIO()
        self.run(command, BytesIO(input_data), output, timeout)
        return output.getvalue().strip()

    def root_answer(self, command, input_data: bytes = b'', *, timeout: float = 65) -> bytes:
        if not getattr(self, 'linux_root', False):
            raise PeerError('DENIED', 'Root SSH preparation is unavailable')
        output = BytesIO()
        self.run(command, BytesIO(input_data), output, timeout, privileged=True)
        return output.getvalue().strip()

    def prepare_linux(self, program: str, realm: str):
        if not getattr(self, 'linux_root', False):
            return
        from .seed_linux import PREPARE, account_for
        account, home = account_for(realm)
        try:
            result = self.root_answer(join(['sh', '-c', PREPARE, 'seed', account, home,
                                          str(PurePosixPath(program).parent)]))
        except CalledProcessError as error:
            detail = 'root SSH runtime preparation failed; exit=' + str(error.returncode)
            from .seed_transport import diagnostic
            detail += '; ' + diagnostic(error)[2][-1000:]
            if error.returncode == 46:
                detail += '; choose /opt or a directory accessible to the dedicated runtime account'
            raise SystemSeedFailure('SEED_LINUX_ACCOUNT', detail) from error
        lines = [line.removeprefix(b'SPMT_RUNNER_UID=') for line in result.splitlines() if line.startswith(b'SPMT_RUNNER_UID=')]
        if len(lines) != 1 or not lines[0].isdigit() or int(lines[0]) == 0:
            raise SystemSeedFailure('SEED_LINUX_ACCOUNT', 'The dedicated runtime account did not return a non-root UID')
        self.linux_user, self.linux_home, self.linux_uid = account, home, int(lines[0])

    def system(self):
        try:
            lines = self.answer(LINUX_PROBE).decode('utf-8', errors='replace').splitlines()
        except CalledProcessError:
            lines = []
        fields = dict(line.split('=', 1) for line in lines if re.match(r'^SPMT_(OS|ARCH|HOME|UID|LIBC)=', line))
        if fields.get('SPMT_OS') == 'Linux':
            machine, uid, home = fields.get('SPMT_ARCH', ''), fields.get('SPMT_UID', ''), fields.get('SPMT_HOME', '')
            detail = f'system=Linux; architecture={machine[:40]}; uid={uid[:12]}'
            if not uid.isdigit() or not PurePosixPath(home).is_absolute():
                raise SystemSeedFailure('SEED_SYSTEM_PROBE', detail)
            libc = fields.get('SPMT_LIBC', '')
            version = re.search(r'(?:glibc|GNU C Library|GNU libc)[^0-9]*([0-9]+)\.([0-9]+)', libc, re.IGNORECASE)
            if 'musl' in libc.lower() or (version and tuple(map(int, version.groups())) < MINIMUM_GLIBC):
                raise SystemSeedFailure('SEED_SYSTEM_LIBC', f'{detail}; libc={libc[:160]}; requires glibc 2.17 or later')
            target = {'x86_64': 'linux-amd64', 'amd64': 'linux-amd64', 'aarch64': 'linux-arm64', 'arm64': 'linux-arm64'}.get(machine)
            if target:
                self.linux_root = uid == '0'
                return target, '/opt' if self.linux_root else home
            raise SystemSeedFailure('SEED_SYSTEM_ARCH', detail)
        else:
            try:
                architectures = self.answer(cmd(WINDOWS_PROBE)).split()
            except CalledProcessError:
                architectures = []
            if b'AMD64' in architectures and b'ARM64' not in architectures:
                return 'windows-amd64', ''
        raise SystemSeedFailure('SEED_SYSTEM_PROBE', 'The SSH probe returned neither Linux system fields nor a Windows AMD64 platform')

    def prepare_windows(self, package):
        name = 'spearmint-seed-' + secrets.token_hex(16)
        cwd = self.windows_cwd()
        with paramiko.SFTPClient.from_transport(self.transport) as sftp:
            sftp.get_channel().settimeout(15)
            home = windows_path(sftp.normalize('.'))
            if not home.is_absolute() or not home.drive.endswith(':') or home != cwd:
                raise PeerError('SEED_WINDOWS_STAGING', 'SFTP needs a private local Windows home directory')
            sftp.mkdir(name, mode=0o700)
            staging = windows_path(sftp.normalize(name))
            if staging != home / name:
                raise PeerError('SEED_WINDOWS_STAGING', 'Unexpected Windows staging directory')
            self.windows_stage = name, staging
            receipt = sftp.put(str(package.path), name + '/package.zip')
            if receipt.st_size != package.metadata['size']:
                raise PeerError('SEED_WINDOWS_STAGING', 'The transferred package size does not match')
        # Invoke only fixed commands. User-selected paths and invitation data are sent as JSON.
        try:
            output = self.answer(cmd(rf'cd {name} && "%SystemRoot%\System32\certutil.exe" -hashfile package.zip SHA256'),
                                 timeout=30)
            if package.metadata['sha256'].encode() not in {line.strip().lower() for line in output.splitlines()}:
                raise PeerError('SEED_WINDOWS_STAGING', 'The transferred package digest does not match')
            self.answer(cmd(rf'cd {name} && "%SystemRoot%\System32\tar.exe" -xf package.zip && del /q package.zip'),
                        timeout=90)
        except (CalledProcessError, TimeoutExpired) as error:
            raise PeerError('SEED_WINDOWS_STAGING', 'Windows could not unpack the verified package') from error
        if self.windows_request('version', {}).get('native_seed') != 1:
            raise WindowsSeedFailure('SEED_WINDOWS_PACKAGE', 'version:unexpected_protocol_version')

    def windows_cwd(self) -> PureWindowsPath:
        return windows_path(self.answer(cmd('cd', unicode=True)).decode('utf-16-le').strip())

    def windows_request(self, action: str, data: dict, *, timeout: float = 20) -> dict:
        if action not in {'version', 'directory', 'install', 'enroll'} or self.windows_stage is None:
            raise ValueError('Invalid Windows seed helper request')
        name, _ = self.windows_stage
        code = {'version': 'SEED_WINDOWS_PACKAGE', 'directory': 'SEED_DIRECTORY'}.get(action, 'SEED_INSTALL')
        command = cmd(rf'cd {name} && spearmint\spearmint.exe --internal-windows-seed {action}')
        try:
            payload = json.dumps(data).encode() + b'\n'
            raw = self.answer(command, payload, timeout=timeout)
        except CalledProcessError as error:
            raise WindowsSeedFailure(code, f'{action}:exit=0x{error.returncode & 0xffffffff:08X}') from error
        except TimeoutExpired as error:
            raise WindowsSeedFailure(code, f'{action}:timeout') from error
        try:
            receipts = [line.removeprefix(WINDOWS_RECEIPT) for line in raw.splitlines() if line.startswith(WINDOWS_RECEIPT)]
            result = json.loads(receipts[0] if len(receipts) == 1 else raw)
            if not isinstance(result, dict) or result.keys() not in ({'ok'}, {'error'}):
                raise ValueError('Invalid Windows seed receipt')
        except ValueError as error:
            raise WindowsSeedFailure(code, f'{action}:invalid_receipt') from error
        if 'error' in result:
            code = result['error']
            if not isinstance(code, str) or not re.fullmatch(r'[A-Z_0-9]{1,48}', code):
                code = 'SEED_INSTALL'
            raise PeerError(code, 'The target rejected the native Windows operation')
        if not isinstance(result['ok'], dict):
            raise WindowsSeedFailure(code, f'{action}:invalid_receipt')
        return result['ok']

    def directory(self, target: str, path: str):
        if target.startswith('windows'):
            return self.windows_request('directory', {'path': path})
        with paramiko.SFTPClient.from_transport(self.transport) as sftp:
            sftp.get_channel().settimeout(8)
            canonical = sftp.normalize(path)
            items = []
            for info in sftp.listdir_iter(canonical, read_aheads=2):
                if info.st_mode is not None and S_ISDIR(info.st_mode) and path_name(info.filename):
                    items.append({'name': info.filename, 'path': str(PurePosixPath(canonical) / info.filename)})
                    if len(items) > 100:
                        break
        free = self.answer(join(['df', '-kP', '--', canonical])).splitlines()[-1].split()[3]
        return {'items': items[:100], 'free': int(free) * 1024, 'truncated': len(items) > 100}

    def writable(self, target: str, path: str):
        self.answer(join(['sh', '-c', 'test -d "$1" && test -w "$1" && test -x "$1"', 'seed', path]))


def path_name(value: str):
    return bool(value and value not in ('.', '..') and len(value) <= 255 and value.isprintable())


def path_type(target: str):
    return PureWindowsPath if target.startswith('windows') else PurePosixPath
