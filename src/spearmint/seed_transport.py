"""Transfer a pinned native bundle to a configured SSH deployment account."""

import base64
from collections.abc import Callable
from contextlib import nullcontext
import hashlib
from ipaddress import IPv4Address, IPv4Network
import json
import os
from pathlib import Path, PureWindowsPath
import re
import shlex
import shutil
import subprocess
import sys
from tempfile import TemporaryFile
from typing import BinaryIO, NamedTuple

from .platforms import secure_private

HOST = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,252}')
NODE_RECEIPT = re.compile(rb'^SPEARMINT_SEED_NODE_ID=(spm1-[a-f0-9]{64})(?: (pending|complete|join-required))?\r?\n', re.MULTILINE)
LINGER_RECEIPT = re.compile(rb'^SPEARMINT_SEED_LINGER=(yes|no|unknown)\r?$', re.MULTILINE)
PREFLIGHT_RECEIPT = re.compile(rb'^SPEARMINT_SEED_PREFLIGHT=ready\r?$', re.MULTILINE)
STARTUP_RECEIPT = re.compile(rb'^SPEARMINT_SEED_STARTUP=confirmed\r?\n', re.MULTILINE)
WINDOWS_FAILURE_RECEIPT = re.compile(rb'^SPEARMINT_SEED_FAILURE=([0-9]{2})\r?\n', re.MULTILINE)
INSTALL_CHECKPOINTS = ('preflight', 'received', 'archive', 'installer')
CHECKPOINT_RECEIPT = re.compile(
    rb'^SPEARMINT_SEED_CHECKPOINT=(' + '|'.join(INSTALL_CHECKPOINTS).encode('ascii') + rb')\r?\n',
    re.MULTILINE,
)
DEFAULT_INSTALL_TIMEOUT = 240
MIN_INSTALL_TIMEOUT = 60
MAX_INSTALL_TIMEOUT = 3600
PREFLIGHT_TIMEOUT = 25
PROGRESS_FILE = 'ssh-receipt.log'
TRANSFER_FILE = 'transfer'
CLIENT_LOG_FILE = 'ssh-client.log'
# OpenSSH's disconnect exit can reach Python as -1 or its unsigned Windows equivalent.
SSH_DISCONNECT_CODES = frozenset({255, -1, 0xFFFFFFFF})


class InstallReceipt(NamedTuple):
    node_id: str | None
    setup: str | None = None
    linger: str | None = None


class LocalArchiveMismatch(ValueError):
    pass


class SSHConnectionRejected(subprocess.SubprocessError):
    def __init__(self, stage: str, message: str):
        super().__init__(message)
        self.stage = stage


class UnconfirmedInstall(subprocess.SubprocessError):
    def __init__(self, stage: str, message: str, checkpoint: str | None, reported_node_id: str | None = None,
                 *, returncode: int | None = None, stderr: bytes | None = None):
        super().__init__(message)
        self.stage = stage
        self.checkpoint = checkpoint
        self.reported_node_id = reported_node_id
        self.returncode = returncode
        self.stderr = stderr


def diagnostic(error: subprocess.SubprocessError) -> tuple[str, int | None, str]:
    """Expose a bounded error summary, never SSH arguments or first-run links."""
    _, stage, message = failure(error)
    raw = getattr(error, 'stderr', None) or b''
    text = raw.decode('utf-8', errors='replace') if isinstance(raw, bytes) else str(raw)
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', text)
    # Some installers print setup URLs or authorization data while failing.
    if re.search(r'-----BEGIN .*PRIVATE KEY-----', text):
        text = '[private key omitted]'
    text = re.sub(r'https?://[^\s<>]+', '[url omitted]', text, flags=re.IGNORECASE)
    text = re.sub(r'(?im)\b(password|passwd|secret|token|invitation|authorization|setup[_-]?code)'
                  r'([\s\"\x27]*[:=][^\r\n]*)', r'\1=[redacted]', text)
    text = re.sub(r'[A-Za-z0-9_+/=-]{64,}', '[opaque value omitted]', text)
    text = ''.join(char for char in text if char in '\n\t' or char.isprintable()).strip()
    checkpoint = getattr(error, 'checkpoint', None)
    summary = '\n'.join(part for part in (message, f'checkpoint={checkpoint}' if checkpoint else '', text) if part)
    return stage, getattr(error, 'returncode', None), summary[-2048:]


LINUX_INSTALL = r'''
set -eu
umask 077
[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = "$1" ] || { echo 'Target architecture does not match the package' >&2; exit 40; }
uid=$(id -u) || exit 40
[ "$uid" -ne 0 ] || { echo 'Use the dedicated non-root Spearmint account' >&2; exit 40; }
for tool in systemctl systemd-run curl ss; do
    command -v "$tool" >/dev/null || { printf 'The Linux installer requires %s\n' "$tool" >&2; exit 44; }
done
# A non-interactive SSH session can lack the environment of the running user manager.
if [ -z "${XDG_RUNTIME_DIR:-}" ] && [ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ]; then
    runtime_dir=/run/user/$uid
    if [ -d "$runtime_dir" ] && [ ! -L "$runtime_dir" ] &&
        [ "$(stat -c %u -- "$runtime_dir" 2>/dev/null)" = "$uid" ]; then
        export XDG_RUNTIME_DIR="$runtime_dir"
    fi
fi
systemctl --user show-environment >/dev/null || { echo 'The SSH account has no accessible systemd user manager' >&2; exit 44; }
digest=$2
invitation=$3
port=$4
origin=$5
grove_ca=$6
mode=$7
staged_archive=$8
archive_size=$9
shift 9
state_directory=
if [ "${1:-}" = --seed-state ]; then
    state_directory=$2
    shift 2
fi
if [ -n "$grove_ca" ] && { [ ! -f "$grove_ca" ] || [ ! -r "$grove_ca" ]; }; then
    echo 'The Grove CA file is unavailable to the deployment account' >&2
    exit 49
fi
if [ "$#" -gt 0 ]; then
    certificate=$4
    key=$6
    if [ ! -f "$certificate" ] || [ ! -r "$certificate" ] ||
        [ ! -f "$key" ] || [ ! -r "$key" ] || [ -L "$key" ] ||
        [ "$(stat -c '%u:%a' -- "$key")" != "$uid:600" ]; then
        echo 'Use a readable certificate and a regular private key owned by the deployment account with mode 0600' >&2
        exit 50
    fi
fi
if [ -n "$staged_archive" ]; then
    if [ ! -f "$staged_archive" ] || [ ! -r "$staged_archive" ] ||
        ! archive_size=$(stat -Lc %s -- "$staged_archive"); then
        echo 'The staged package is unavailable to the deployment account' >&2
        exit 47
    fi
fi
staging=${TMPDIR:-/tmp}
if [ ! -d "$staging" ] || [ ! -w "$staging" ] || [ ! -x "$staging" ]; then
    echo 'The Linux staging directory is unavailable to the deployment account' >&2
    exit 46
fi
if [ -n "$archive_size" ]; then
    usage=$(LC_ALL=C df -k --output=avail -- "$staging") || exit 46
    free=$(printf '%s\n' "$usage" | awk 'NR == 2 {print $1}')
    case "$free" in
        ''|*[!0-9]*) echo 'Could not read available Linux staging space' >&2; exit 46 ;;
    esac
    required=$((archive_size / 1024 + (archive_size % 1024 != 0)))
    if [ "$free" -lt "$required" ]; then
        echo 'Insufficient Linux staging space' >&2
        exit 48
    fi
fi
report_linger() {
    if linger=$(timeout 5s loginctl show-user "$uid" --property=Linger --value 2>/dev/null); then
        case "$linger" in
            yes|no) ;;
            *) linger=unknown ;;
        esac
    else
        linger=unknown
    fi
    printf 'SPEARMINT_SEED_LINGER=%s\n' "$linger"
}
if [ "$mode" = check ]; then
    if [ -n "$staged_archive" ]; then
        checksum=$(sha256sum < "$staged_archive") || exit 47
        if [ "${checksum%% *}" != "$digest" ]; then
            echo 'The staged package checksum does not match' >&2
            exit 55
        fi
    fi
    report_linger
    printf 'SPEARMINT_SEED_PREFLIGHT=ready\n'
    exit 0
fi
work=$(mktemp -d -- "$staging/spearmint-seed.XXXXXXXXXX") || exit 46
trap 'rm -rf -- "$work"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
printf 'SPEARMINT_SEED_CHECKPOINT=preflight\n'
archive="$work/package.tar.gz"
archive_failure=41
if [ -n "$staged_archive" ]; then
    archive_failure=47
    cat -- "$staged_archive" > "$archive" || exit "$archive_failure"
else
    cat > "$archive" || exit "$archive_failure"
fi
if [ -n "$archive_size" ] && [ "$(stat -Lc %s -- "$archive")" != "$archive_size" ]; then
    echo 'Native archive size mismatch' >&2
    exit "$archive_failure"
fi
printf 'SPEARMINT_SEED_CHECKPOINT=received\n'
(cd -- "$work" && printf '%s  package.tar.gz\n' "$digest" | sha256sum -c --status) ||
    { echo 'Native archive checksum mismatch' >&2; exit "$archive_failure"; }
printf 'SPEARMINT_SEED_CHECKPOINT=archive\n'
tar -xzf "$archive" -C "$work" || exit 42
bundle="$work/spearmint"
"$bundle/spearmint" --verify-package "$bundle" || exit 42
printf '%s' "$invitation" | base64 -d > "$work/grove.json" || exit 42
validate_invitation() {
    if [ -n "$grove_ca" ]; then
        set -- --grove-ca "$grove_ca"
    fi
    "$bundle/spearmint" --origin "$origin" "$@" validate-config --join-grove "$work/grove.json"
}
validate_invitation || exit 42
if [ -n "$grove_ca" ]; then
    set -- "$@" --grove-ca "$grove_ca"
fi
printf 'SPEARMINT_SEED_CHECKPOINT=installer\n'
if [ -n "$state_directory" ]; then
    export SPEARMINT_SEED_STATE_DIRECTORY="$state_directory"
fi
sh "$bundle/deployment/install-linux.sh" --join-grove "$work/grove.json" --port "$port" "$@" "$origin" || exit 43
report_linger
printf 'SPEARMINT_SEED_STARTUP=confirmed\n'
'''

WINDOWS_BOOTSTRAP = r'''
$ErrorActionPreference = 'Stop'
$source = [Console]::OpenStandardInput()
$header = New-Object IO.MemoryStream
try {
    while (($byte = $source.ReadByte()) -ne 10) {
        if ($byte -lt 0 -or $header.Length -ge 32768) { throw 'Invalid seed receiver header.' }
        $header.WriteByte($byte)
    }
    $encoded = [Text.Encoding]::ASCII.GetString($header.ToArray())
    $script = [Convert]::FromBase64String($encoded)
} finally { $header.Dispose() }
$sha256 = [Security.Cryptography.SHA256]::Create()
try { $digest = [BitConverter]::ToString($sha256.ComputeHash($script)).Replace('-', '') }
finally { $sha256.Dispose() }
if ($digest -ine 'RECEIVER_SHA256') { throw 'Seed receiver checksum mismatch.' }
& ([ScriptBlock]::Create([Text.Encoding]::UTF8.GetString($script))) $source
'''

WINDOWS_HEADER = r'''
param([IO.Stream]$source)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$stage = 40
try {
$header = New-Object IO.MemoryStream
try {
    while (($byte = $source.ReadByte()) -ne 10) {
        if ($byte -lt 0 -or $header.Length -ge 16384) { throw 'Invalid seed transfer header.' }
        $header.WriteByte($byte)
    }
    $inputData = [Text.Encoding]::UTF8.GetString($header.ToArray()) | ConvertFrom-Json
} finally { $header.Dispose() }
if ($env:OS -ne 'Windows_NT' -or [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'X64') {
    throw 'Target architecture does not match the package.'
}
if ((Get-ExecutionPolicy) -eq 'Restricted') {
    $stage = 45
    throw 'Windows PowerShell execution policy is Restricted. Have the target administrator review the native installer.'
}
function Assert-FixedPath([string]$p) {
    $resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($p)
    $root = [IO.Path]::GetPathRoot($resolved)
    if ($root -notmatch '^[a-zA-Z]:\\$' -or [IO.DriveInfo]::new($root).DriveType -ne 'Fixed') {
        throw 'Use a local fixed disk.'
    }
}
if ($inputData.windows.TaskLogonType -eq 'S4U') {
    $stage = 51
    foreach ($path in @($inputData.windows.InstallDirectory, $inputData.windows.StateDirectory,
                        $inputData.windows.Certificate, $inputData.windows.PrivateKey, $inputData.windows.GroveCA)) {
        if ($path) { Assert-FixedPath $path }
    }
    if (-not $inputData.windows.InstallDirectory -or -not $inputData.windows.StateDirectory) {
        Assert-FixedPath $env:LOCALAPPDATA
    }
}
$stage = 46
$parent = $env:TEMP
if ($inputData.staging_directory) {
    if ($inputData.staging_directory -notmatch '^[a-zA-Z]:[\\/]') {
        throw 'Use an absolute Windows drive path for the target staging directory.'
    }
    $parent = [IO.Path]::GetFullPath($inputData.staging_directory)
    Assert-FixedPath $parent
    $item = Get-Item -LiteralPath $parent
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'The SSH staging directory must be an existing local directory.'
    }
}
$parent = [IO.Path]::GetFullPath($parent)
$bytes = $inputData.archive_size
$stagedArchive = $null
if ($inputData.target_archive) {
    $stage = 47
    if ($inputData.target_archive -notmatch '^[a-zA-Z]:[\\/]') { throw 'Use an absolute path to the staged package.' }
    $stagedArchive = [IO.Path]::GetFullPath($inputData.target_archive)
    Assert-FixedPath $stagedArchive
    $file = [IO.File]::OpenRead($stagedArchive)
    try { $bytes = $file.Length } finally { $file.Dispose() }
}
$stage = 46
if (-not [IO.Directory]::Exists($parent)) { throw 'Missing staging directory.' }
if ($bytes -gt [IO.DriveInfo]::new([IO.Path]::GetPathRoot($parent)).AvailableFreeSpace) {
    $stage = 48
    throw 'Insufficient staging space.'
}
'''

WINDOWS_S4U_CHECK = r'''
if ($inputData.windows.TaskLogonType -eq 'S4U') {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $name = $inputData.windows.TaskName
        if (-not $name) { $name = 'Spearmint' }
        $task = Get-ScheduledTask -TaskPath '\' -TaskName $name -ErrorAction SilentlyContinue | Where-Object TaskName -EQ $name
        if (-not $task) {
            $stage = 52
            throw 'Registering an S4U startup task requires administrator rights.'
        }
    }
}
'''

WINDOWS_LISTENER_CHECK = r'''
$bind = $inputData.windows.Bind
if ($bind -and $bind -ne '127.0.0.1') {
    $stage = 53
    if (-not (Get-NetIPAddress -AddressFamily IPv4 -IPAddress $bind -ErrorAction SilentlyContinue)) {
        throw 'The configured LAN address is not assigned to this target.'
    }
}
function Assert-ReadableFile([string]$path) {
    if ($path) {
        $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($path)
        [IO.File]::OpenRead($full).Dispose()
    }
}
$stage = 54
Assert-ReadableFile $inputData.windows.Certificate
Assert-ReadableFile $inputData.windows.PrivateKey
$stage = 49
Assert-ReadableFile $inputData.windows.GroveCA
$stage = 46
'''

WINDOWS_STAGED_ARCHIVE_CHECK = r'''
if ($stagedArchive) {
    $stage = 47
    $actual = (Get-FileHash -LiteralPath $stagedArchive -Algorithm SHA256).Hash
    if ($actual -ine $inputData.sha256) {
        $stage = 55
        throw 'The staged package checksum does not match.'
    }
}
$stage = 46
'''

WINDOWS_STAGING = r'''
$work = Join-Path $parent ('spearmint-seed-' + [guid]::NewGuid().ToString('N'))
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
$user = [Security.Principal.WindowsIdentity]::GetCurrent().User
foreach ($sid in @($user, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'), [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
}
$workItem = [IO.DirectoryInfo]::new($work)
if ($PSVersionTable.PSEdition -eq 'Core') {
    [IO.FileSystemAclExtensions]::Create($workItem, $acl)
} else {
    $workItem.Create($acl)
}
try {
'''

WINDOWS_INSTALL = r'''
    function Report($checkpoint) { [Console]::WriteLine('SPEARMINT_SEED_CHECKPOINT=' + $checkpoint) }
    Report 'preflight'
    $stage = 41
    $archive = Join-Path $work 'package.zip'
    $packageSource = $source
    if ($stagedArchive) {
        $stage = 47
        $packageSource = [IO.File]::OpenRead($stagedArchive)
    }
    try {
        $stream = [IO.File]::Open($archive, 'CreateNew', 'Write', 'None')
        try { $packageSource.CopyTo($stream) } finally { $stream.Dispose() }
    } finally {
        if ($packageSource -ne $source) { $packageSource.Dispose() }
    }
    $hash = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::OpenRead($archive)
    try {
        if ($stream.Length -ne $bytes) { throw 'Archive size mismatch.' }
        Report 'received'
        $digest = [BitConverter]::ToString($hash.ComputeHash($stream)).Replace('-', '')
    }
    finally { $stream.Dispose(); $hash.Dispose() }
    if ($digest -ine $inputData.sha256) { throw 'Archive checksum mismatch.' }
    Report 'archive'
    $stage = 42
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory($archive, $work)
    $bundle = Join-Path $work 'spearmint'
    & (Join-Path $bundle 'spearmint.exe') --verify-package $bundle
    if ($LASTEXITCODE -ne 0) { throw 'Native package verification failed.' }
    $invitation = Join-Path $work 'grove.json'
    [IO.File]::WriteAllBytes($invitation, [Convert]::FromBase64String($inputData.invitation))
    & (Join-Path $bundle 'spearmint.exe') --origin $inputData.origin validate-config --join-grove $invitation
    if ($LASTEXITCODE -ne 0) { throw 'The package or Grove invitation does not support this installation.' }
    $options = @{ Origin = $inputData.origin; Port = $inputData.port; JoinGrove = $invitation }
    foreach ($option in $inputData.windows.PSObject.Properties) { $options[$option.Name] = $option.Value }
    $stage = 43
    Report 'installer'
    $LASTEXITCODE = 0
    & (Join-Path $bundle 'deployment\install-windows.ps1') @options
    if (-not $? -or $LASTEXITCODE -ne 0) { throw 'Native installer failed.' }
'''

WINDOWS_CLEANUP = r'''
} finally {
    $resolved = [IO.Path]::GetFullPath($work)
    if ($resolved -eq $workItem.FullName -and (Split-Path -Parent $resolved).TrimEnd('\') -eq $parent.TrimEnd('\') -and
        (Split-Path -Leaf $resolved) -match '^spearmint-seed-[a-f0-9]{32}$' -and
        -not ((Get-Item -LiteralPath $resolved).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Remove-Item -LiteralPath $resolved -Recurse -Force -ErrorAction SilentlyContinue
    }
}
'''

WINDOWS_ERROR = r'''
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    [Console]::WriteLine('SPEARMINT_SEED_FAILURE=' + $stage)
    exit $stage
}
'''

WINDOWS_OPTIONS = {
    'install_directory': 'InstallDirectory', 'state_directory': 'StateDirectory', 'task_name': 'TaskName',
    'bind': 'Bind', 'certificate': 'Certificate', 'private_key': 'PrivateKey', 'task_logon_type': 'TaskLogonType',
    'grove_ca': 'GroveCA',
    'staging_directory': 'StagingDirectory',
}
TASK_LOGON_TYPES = ('Interactive', 'S4U')
WINDOWS_LAN_NETWORKS = tuple(IPv4Network(network) for network in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))


def validate_windows_options(options: dict[str, str]) -> None:
    if options.get('TaskLogonType', 'Interactive') not in TASK_LOGON_TYPES:
        raise ValueError('Use Interactive or S4U for the Windows task logon type.')
    name = options.get('TaskName')
    if name is not None and not re.fullmatch(r'[^\\/:*?"<>|\[\]\x00-\x1f]{1,120}', name):
        raise ValueError('Use a valid Windows scheduled task name of at most 120 characters.')
    if 'StagingDirectory' in options:
        validate_windows_staging(options['StagingDirectory'])
    certificate = options.get('Certificate')
    key = options.get('PrivateKey')
    if bool(certificate) != bool(key):
        raise ValueError('Windows native HTTPS requires both the certificate and private key.')
    bind = options.get('Bind', '127.0.0.1')
    if bind == '127.0.0.1':
        return
    try:
        address = IPv4Address(bind)
    except ValueError:
        address = None
    if address is None or not any(address in network for network in WINDOWS_LAN_NETWORKS):
        raise ValueError('Use 127.0.0.1 or an explicit private IPv4 address for the Windows listener.')
    if not certificate:
        raise ValueError('A Windows LAN listener requires the certificate and private key.')


def validate_linux_grove_ca(value: str) -> None:
    if not absolute_linux_path(value):
        raise ValueError('Use an absolute Linux path to the target Grove CA file')


def absolute_linux_path(value: str) -> bool:
    return value.startswith('/') and len(value) <= 1024 and value.isprintable()


def linux_listener_args(bind: str | None, certificate: str | None, key: str | None) -> list[str]:
    if bind is not None:
        try:
            first_octet = IPv4Address(bind).packed[0]
        except ValueError:
            first_octet = 0
        if not 1 <= first_octet < 224:
            raise ValueError('Use one concrete IPv4 listen address for Linux')
    if certificate is None and key is None and bind in (None, '127.0.0.1'):
        return []
    if certificate is None or key is None or not all(absolute_linux_path(path) for path in (certificate, key)):
        raise ValueError('Linux native HTTPS requires absolute TLS certificate and private key paths')
    return ['--bind', bind or '127.0.0.1', '--tls-cert', certificate, '--tls-key', key]


def validate_windows_staging(value: str) -> None:
    path = PureWindowsPath(value)
    if not value.isprintable() or not path.is_absolute() or not re.fullmatch(r'[A-Za-z]:', path.drive):
        raise ValueError('Use an absolute Windows drive path for the target staging directory')


def validate_windows_archive(value: str) -> None:
    path = PureWindowsPath(value)
    if (not value.isprintable() or not path.is_absolute() or not re.fullmatch(r'[A-Za-z]:', path.drive)
            or path.suffix.lower() != '.zip' or ':' in path.name):
        raise ValueError('Use an absolute Windows drive path to a staged ZIP archive')


def validate_target_archive(value: str, target: str) -> None:
    if target == 'windows-amd64':
        validate_windows_archive(value)
    elif not absolute_linux_path(value) or not value.endswith('.tar.gz'):
        raise ValueError('Use an absolute Linux path to a staged .tar.gz archive')

# Keep these codes in sync with the two fixed target-side commands.
REMOTE_FAILURES = {
    40: ('failed', 'target', 'Target preflight failed'),
    41: ('failed', 'transfer', 'Target could not receive or verify the transferred archive'),
    42: ('failed', 'verify', 'Target could not unpack or validate the native package and invitation'),
    43: ('uncertain', 'install', 'Native installer did not confirm startup; inspect the target before retrying'),
    44: ('failed', 'systemd', 'Linux startup preflight failed; check the SSH account’s systemd user manager, curl and ss'),
    45: ('failed', 'script-policy', 'Target PowerShell execution policy is Restricted; have the target administrator review the native installer'),
    46: ('failed', 'staging', 'The target staging directory or its capacity information is unavailable'),
    47: ('failed', 'target-archive', 'The staged archive could not be read or verified on the target'),
    48: ('failed', 'staging-space', 'The target staging disk has insufficient free space for the archive'),
    49: ('failed', 'grove-ca', 'The deployment account cannot read the target Grove CA file'),
    50: ('failed', 'tls-files', 'The Linux TLS certificate is unreadable or the private key is missing or has incorrect ownership or permissions'),
    51: ('failed', 'windows-task-paths', 'Windows S4U task paths must be on local fixed disks'),
    52: ('failed', 'windows-task-permission', 'Creating a Windows S4U startup task requires an administrator token on the target'),
    53: ('failed', 'windows-bind', 'The configured LAN address is not assigned to the Windows target'),
    54: ('failed', 'windows-tls-files', 'The deployment account cannot read the Windows panel certificate or private key'),
    55: ('failed', 'target-archive-checksum', 'The staged archive on the target does not match the configured SHA-256'),
}
FAILURE_STAGES = frozenset(stage for _, stage, _ in REMOTE_FAILURES.values()) | {
    'timeout', 'ssh', 'ssh-auth', 'ssh-host-key', 'local', 'receipt',
}


def failure(error: subprocess.SubprocessError) -> tuple[str, str, str]:
    if isinstance(error, UnconfirmedInstall):
        return 'uncertain', error.stage, str(error)
    if isinstance(error, SSHConnectionRejected):
        return 'failed', error.stage, str(error)
    if isinstance(error, subprocess.TimeoutExpired):
        return 'uncertain', 'timeout', 'SSH timed out; check the target installation before retrying'
    if isinstance(error, subprocess.CalledProcessError):
        return REMOTE_FAILURES.get(error.returncode, ('uncertain', 'ssh', f'OpenSSH exited with status {error.returncode}'))
    return 'uncertain', 'ssh', 'SSH installation outcome is unavailable'


SSH_OPTIONS = (
    'BatchMode=yes', 'StrictHostKeyChecking=yes', 'ForwardAgent=no', 'ForwardX11=no',
    'ConnectTimeout=15', 'ClearAllForwardings=yes', 'ControlPath=none',
    'ServerAliveInterval=15', 'ServerAliveCountMax=3',
)


def output_tail(stream: BinaryIO) -> bytes:
    end = stream.seek(0, os.SEEK_END)
    size = min(end, 8193)
    stream.seek(end - size)
    output = stream.read(size)
    return output.partition(b'\n')[2] if end > 8192 else output


def last_checkpoint(output: bytes) -> str | None:
    checkpoints = CHECKPOINT_RECEIPT.findall(output)
    return checkpoints[-1].decode('ascii') if checkpoints else None


def node_receipt(output: bytes) -> tuple[str | None, str | None]:
    nodes = NODE_RECEIPT.findall(output)
    if len(nodes) == 1:
        node, setup = nodes[0]
        return node.decode('ascii'), setup.decode('ascii') or None
    return None, None


def confirmed_before_disconnect(output: bytes) -> bool:
    confirmations = list(STARTUP_RECEIPT.finditer(output))
    if len(confirmations) != 1 or confirmations[0].end() != len(output) or WINDOWS_FAILURE_RECEIPT.search(output):
        return False
    nodes = list(NODE_RECEIPT.finditer(output))
    return len(nodes) == 1 and last_checkpoint(output[:nodes[0].start()]) == 'installer' and last_checkpoint(output) == 'installer'


def read_install_output(work: Path) -> bytes:
    try:
        with (work / PROGRESS_FILE).open('rb') as receipt:
            return output_tail(receipt)
    except OSError:
        return b''


def linux_linger(output: bytes, target: str) -> str | None:
    if target == 'windows-amd64':
        return None
    matches = LINGER_RECEIPT.findall(output)
    return matches[0].decode('ascii') if len(matches) == 1 else None


def install_receipt(output: bytes, target: str) -> InstallReceipt | None:
    node_id, setup = node_receipt(output)
    linger = linux_linger(output, target)
    return InstallReceipt(node_id, setup, linger) if node_id or linger else None


def check_target(work: Path, *, host: str, target: str, windows: dict,
                 ssh: str, config: Path, digest: str = '', target_archive: str | None = None, archive_size: int | None = None,
                 linux_grove_ca: str | None = None,
                 linux_listener: tuple[str | None, str | None, str | None] = (None, None, None)) -> str | None:
    if target_archive is not None and not re.fullmatch('[a-f0-9]{64}', digest):
        raise ValueError('A staged archive check requires a SHA-256 digest')
    output = _deploy(None, work, host=host, target=target, digest=digest, invitation_data=b'',
                     origin='', port=0, windows=windows, ssh=ssh, config=config, quiet=True,
                     target_archive=target_archive, archive_size=archive_size, linux_grove_ca=linux_grove_ca,
                     linux_listener=linux_listener, check_only=True, timeout=PREFLIGHT_TIMEOUT)
    if len(PREFLIGHT_RECEIPT.findall(output)) != 1:
        raise SSHConnectionRejected('ssh', 'The target did not return a preflight receipt')
    return linux_linger(output, target)


def install(archive_path: Path | None, work: Path, *, host: str, target: str, digest: str, invitation_data: bytes,
            origin: str, port: int, windows: dict, ssh: str = 'ssh', config: Path | None = None,
            quiet: bool = False, linux_grove_ca: str | None = None, linux_listener: tuple[str | None, str | None, str | None] = (None, None, None),
            target_archive: str | None = None, timeout: int = DEFAULT_INSTALL_TIMEOUT,
            capture_progress: bool = False, before_connect: Callable[[], None] | None = None,
            runner=None, linux_state: str = '') -> InstallReceipt | None:
    if archive_path is None and target_archive is None:
        raise ValueError('No native archive was provided')
    if type(timeout) is not int or not MIN_INSTALL_TIMEOUT <= timeout <= MAX_INSTALL_TIMEOUT:
        raise ValueError(f'Use an SSH install timeout from {MIN_INSTALL_TIMEOUT} to {MAX_INSTALL_TIMEOUT} seconds')
    output = _deploy(archive_path, work, host=host, target=target, digest=digest, invitation_data=invitation_data,
                     origin=origin, port=port, windows=windows, ssh=ssh, config=config, quiet=quiet,
                     linux_grove_ca=linux_grove_ca, linux_listener=linux_listener,
                     target_archive=target_archive, check_only=False, timeout=timeout,
                     capture_progress=capture_progress, before_connect=before_connect, runner=runner, linux_state=linux_state)
    if len(STARTUP_RECEIPT.findall(output)) != 1:
        raise UnconfirmedInstall('receipt', 'SSH ended without a startup confirmation', last_checkpoint(output),
                                 node_receipt(output)[0])
    return install_receipt(output, target)


def _deploy(archive_path: Path | None, work: Path, *, host: str, target: str, digest: str, invitation_data: bytes,
            origin: str, port: int, windows: dict, ssh: str, config: Path | None, quiet: bool, check_only: bool, timeout: int,
            linux_grove_ca: str | None = None, target_archive: str | None = None,
            linux_listener: tuple[str | None, str | None, str | None] = (None, None, None),
            archive_size: int | None = None, capture_progress: bool = False,
            before_connect: Callable[[], None] | None = None, runner=None, linux_state: str = '') -> bytes:
    if target_archive is not None:
        if archive_path is not None:
            raise ValueError('A staged target archive requires no local archive')
        validate_target_archive(target_archive, target)
    if linux_grove_ca is not None:
        if target == 'windows-amd64':
            raise ValueError('The Linux Grove CA option requires a Linux target')
        validate_linux_grove_ca(linux_grove_ca)
    listener = linux_listener_args(*linux_listener)
    if listener and target == 'windows-amd64':
        raise ValueError('The Linux listener option requires a Linux target')
    ssh_config = ['-F', str(config)] if config is not None else []
    invitation = base64.b64encode(invitation_data).decode('ascii')
    header = b''
    if archive_path is not None:
        archive_size = archive_path.stat().st_size
    if target == 'windows-amd64':
        validate_windows_options(windows)
        windows = windows.copy()
        staging = windows.pop('StagingDirectory', None)
        options = json.dumps({'sha256': digest, 'invitation': invitation, 'origin': origin,
                              'port': port, 'windows': windows, 'staging_directory': staging,
                              'target_archive': target_archive,
                              'archive_size': archive_size}).encode('utf-8')
        if len(options) > 16384:
            raise ValueError('Windows installation options are too large')
        script = WINDOWS_HEADER + WINDOWS_S4U_CHECK + WINDOWS_LISTENER_CHECK
        if check_only:
            script += WINDOWS_STAGED_ARCHIVE_CHECK + WINDOWS_STAGING + '\n' + WINDOWS_CLEANUP
            marker = 'SPEARMINT_SEED_PREFLIGHT=ready'
        else:
            script += WINDOWS_STAGING + WINDOWS_INSTALL + WINDOWS_CLEANUP
            marker = 'SPEARMINT_SEED_STARTUP=confirmed'
        script += f"[Console]::WriteLine('{marker}')\n" + WINDOWS_ERROR
        # Keep the command within cmd.exe's limit and bind it to this receiver.
        receiver = script.encode('utf-8')
        bootstrap = WINDOWS_BOOTSTRAP.replace('RECEIVER_SHA256', hashlib.sha256(receiver).hexdigest())
        command = ('powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand '
                   + base64.b64encode(bootstrap.encode('utf-16-le')).decode('ascii'))
        header = base64.b64encode(receiver) + b'\n' + options + b'\n'
    else:
        architecture = 'aarch64' if target == 'linux-arm64' else 'x86_64'
        arguments = ['sh', '-c', LINUX_INSTALL, 'spearmint-seed', architecture,
                     digest, invitation, str(port), origin, linux_grove_ca or '',
                     'check' if check_only else 'install', target_archive or '',
                     str(archive_size) if archive_size is not None else '']
        if linux_state:
            arguments.extend(('--seed-state', linux_state))
        arguments.extend(listener)
        command = shlex.join(arguments)
    payload = None
    if header or archive_path is not None:
        payload = work / TRANSFER_FILE
        with payload.open('wb') as output:
            output.write(header)
            if archive_path is not None:
                checksum = hashlib.sha256()
                with archive_path.open('rb') as archive:
                    while chunk := archive.read(1024 * 1024):
                        checksum.update(chunk)
                        output.write(chunk)
                if checksum.hexdigest() != digest or output.tell() != len(header) + archive_size:
                    raise LocalArchiveMismatch('The local native archive does not match the configured SHA-256 or size')
    source = payload.open('rb') if payload is not None else nullcontext(subprocess.DEVNULL)
    with source as archive, (
        (work / PROGRESS_FILE).open('xb+') if capture_progress else TemporaryFile(dir=work)
    ) as receipt:
        if capture_progress:
            secure_private(work / PROGRESS_FILE, 0o600)
        options = [value for setting in SSH_OPTIONS for value in ('-o', setting)]
        environment = os.environ.copy()
        if getattr(sys, 'frozen', False) and sys.platform.startswith('linux'):
            environment.pop('LD_LIBRARY_PATH', None)
            if original := environment.get('LD_LIBRARY_PATH_ORIG'):
                environment['LD_LIBRARY_PATH'] = original
        io = {'stderr': subprocess.DEVNULL} if quiet else {}
        if quiet and os.name == 'nt':
            io['creationflags'] = subprocess.CREATE_NO_WINDOW
        client_log = work / CLIENT_LOG_FILE
        logging_args = ['-E', str(client_log), '-o', 'LogLevel=INFO'] if quiet else []
        if before_connect is not None:
            before_connect()
        try:
            if runner is None:
                subprocess.run([ssh, '-T', *logging_args, *ssh_config, *options, '--', host, command], stdin=archive,
                               stdout=receipt, check=True, timeout=timeout, env=environment, **io)
            else:
                runner(command, archive, receipt, timeout)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
            if target == 'windows-amd64' and isinstance(error, subprocess.CalledProcessError) and error.returncode == 1:
                # A PowerShell login shell can collapse the child process's status to 1.
                failures = WINDOWS_FAILURE_RECEIPT.findall(output_tail(receipt))
                if len(failures) == 1 and (stage := int(failures[0])) in REMOTE_FAILURES:
                    raise subprocess.CalledProcessError(stage, error.cmd) from None
            if (quiet and isinstance(error, subprocess.CalledProcessError) and error.returncode in SSH_DISCONNECT_CODES
                    and receipt.seek(0, os.SEEK_END) == 0):
                # Only use client diagnostics, excluding remote stderr.
                try:
                    with client_log.open('rb') as stream:
                        diagnostic = output_tail(stream).rstrip(b'\r\n').rsplit(b'\n', 1)[-1]
                except OSError:
                    diagnostic = b''
                if diagnostic == b'Host key verification failed.':
                    raise SSHConnectionRejected('ssh-host-key', 'OpenSSH rejected the target host key') from None
                if re.fullmatch(rb'[^\r\n]+@[^ \r\n]+: Permission denied \([a-z0-9@.,_-]*\)\.', diagnostic):
                    raise SSHConnectionRejected('ssh-auth', 'OpenSSH rejected non-interactive authentication') from None
            status, stage, message = failure(error)
            if not check_only and status == 'uncertain':
                output = output_tail(receipt)
                # The receiver confirms startup after the installer succeeds. OpenSSH can
                # lose the exit status even after receiving that confirmation.
                lost_exit_status = (isinstance(error, subprocess.TimeoutExpired)
                                    or (isinstance(error, subprocess.CalledProcessError) and error.returncode in SSH_DISCONNECT_CODES))
                if lost_exit_status and confirmed_before_disconnect(output):
                    return output
                raise UnconfirmedInstall(stage, message, last_checkpoint(output), node_receipt(output)[0],
                                         returncode=getattr(error, 'returncode', None),
                                         stderr=getattr(error, 'stderr', None)) from None
            raise
        finally:
            if not quiet:
                # Keep the original stdout available for the receipt parser and CLI diagnostics.
                receipt.seek(0)
                shutil.copyfileobj(receipt, sys.stdout.buffer)
                sys.stdout.flush()
        return output_tail(receipt)
