"""A short-lived SSH connection owned by the node executing a seed request."""
from base64 import b64encode
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
WINDOWS_PROBE = r'''
$ErrorActionPreference = 'Stop'
$arch = [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITEW6432')
if (!$arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
[ordered]@{os='Windows'; arch=$arch; home=$env:USERPROFILE} | ConvertTo-Json -Compress
'''
WINDOWS_DIRECTORY = r'''
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$path = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('DIRECTORY'))
if (!$path) {
    $items = @(Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match '^[a-zA-Z]:\\$' } |
        ForEach-Object { @{name=$_.Root; path=$_.Root} })
    @{items=$items; free=$null; truncated=$false} | ConvertTo-Json -Compress -Depth 4
} else {
    $parent = Get-Item -LiteralPath $path
    if (!$parent.PSIsContainer -or ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)) { exit 2 }
    $items = @(Get-ChildItem -LiteralPath $parent.FullName -Directory |
        Where-Object { !($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } | Select-Object -First 101 |
        ForEach-Object { @{name=$_.Name; path=$_.FullName} })
    @{items=@($items | Select-Object -First 100); free=$parent.PSDrive.Free; truncated=($items.Count -gt 100)} |
        ConvertTo-Json -Compress -Depth 4
}
'''


def hostname(value: str) -> str:
    try:
        return str(ip_address(value.strip('[]')))
    except ValueError:
        if re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?', value):
            return value.lower()
    raise ValueError('Use an IP address or DNS hostname')


def powershell(script: str) -> str:
    script = "$OutputEncoding = [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)\n" + script
    return 'powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand ' + b64encode(script.encode('utf-16-le')).decode()


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
        self.transport.close()
        self.socket.close()

    def run(self, command, source, output, timeout: float, *, limit: int = 128 * 1024):
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
            try:
                while monotonic() < deadline:
                    if channel.recv_ready():
                        data = channel.recv(32768)
                        size += len(data)
                        if size > limit:
                            raise PeerError('LIMIT', 'SSH output exceeds the seed response limit')
                        output.write(data)
                    elif channel.recv_stderr_ready():
                        channel.recv_stderr(32768)
                    elif channel.exit_status_ready():
                        status = channel.recv_exit_status()
                        if status or writer_error:
                            raise CalledProcessError(status or 255, 'seed')
                        return
                    else:
                        sleep(.02)
                raise TimeoutExpired('seed', timeout)
            finally:
                channel.close()
                sender.join(3)

    def answer(self, command, input_data: bytes = b'', *, timeout: float = 12) -> bytes:
        output = BytesIO()
        self.run(command, BytesIO(input_data), output, timeout)
        return output.getvalue().strip()

    def system(self):
        try:
            lines = self.answer('uname -s; uname -m; printf "%s\n" "$HOME"; id -u').decode().splitlines()
        except CalledProcessError:
            lines = []
        if len(lines) == 4 and lines[0] == 'Linux':
            if lines[3] == '0':
                raise PeerError('SEED_SYSTEM', 'Use the dedicated non-root account for the systemd user service')
            target = {'x86_64': 'linux-amd64', 'aarch64': 'linux-arm64'}.get(lines[1])
            if target:
                return target, lines[2]
        else:
            try:
                result = json.loads(self.answer(powershell(WINDOWS_PROBE)).decode('utf-8-sig'))
            except (ValueError, CalledProcessError):
                result = {}
            if result.get('os') == 'Windows' and result.get('arch') == 'AMD64':
                return 'windows-amd64', result['home']
        raise PeerError('SEED_SYSTEM', 'This SSH host does not have a supported Spearmint platform')

    def directory(self, target: str, path: str):
        if target.startswith('windows'):
            script = WINDOWS_DIRECTORY.replace('DIRECTORY', b64encode(path.encode()).decode())
            return json.loads(self.answer(powershell(script)).decode('utf-8-sig'))
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
        if target.startswith('windows'):
            # Use an exclusive, immediately removed file to verify the account's effective access.
            value = b64encode(path.encode()).decode()
            script = r'''
$ErrorActionPreference = 'Stop'
$directory = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('DIRECTORY'))
$item = Get-Item -LiteralPath $directory
if (!$item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { exit 2 }
$test = Join-Path $directory ('.spearmint-check-' + [Guid]::NewGuid().ToString('N'))
$handle = [IO.FileStream]::new($test, 'CreateNew', 'ReadWrite', 'None', 1, 'DeleteOnClose')
$handle.Dispose()
'''
            self.answer(powershell(script.replace('DIRECTORY', value)))
        else:
            self.answer(join(['sh', '-c', 'test -d "$1" && test -w "$1" && test -x "$1"', 'seed', path]))


def path_name(value: str):
    return bool(value and value not in ('.', '..') and len(value) <= 255 and value.isprintable())


def path_type(target: str):
    return PureWindowsPath if target.startswith('windows') else PurePosixPath
