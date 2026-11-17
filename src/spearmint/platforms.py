"""Native filesystem, process identity and capability adapters."""
import errno
import os
from pathlib import Path
import platform
import shutil
import stat
import time

import psutil

WINDOWS = os.name == "nt"


def current_sid():
    import win32api
    import win32con
    import win32security

    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    try:
        return win32security.GetTokenInformation(token, win32security.TokenUser)[0]
    finally:
        token.Close()


def secure_private(path: Path, mode: int = 0o600) -> None:
    if not WINDOWS:
        path.chmod(mode)
        return
    import win32security as security

    acl = security.ACL()
    flags = security.OBJECT_INHERIT_ACE | security.CONTAINER_INHERIT_ACE if path.is_dir() else 0
    for sid in (current_sid(), security.CreateWellKnownSid(security.WinLocalSystemSid),
                security.CreateWellKnownSid(security.WinBuiltinAdministratorsSid)):
        acl.AddAccessAllowedAceEx(security.ACL_REVISION, flags, 0x1F01FF, sid)
    security.SetNamedSecurityInfo(str(path), security.SE_FILE_OBJECT,
        security.DACL_SECURITY_INFORMATION | security.PROTECTED_DACL_SECURITY_INFORMATION,
        None, None, acl, None)


def check_private(path: Path, mode: int, directory: bool) -> None:
    info = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ValueError(f"Unsafe state path {path}: regular private {'directory' if directory else 'file'} required")
    if not WINDOWS:
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != mode:
            raise ValueError(f"Unsafe state path {path} (expected owner UID {os.getuid()} and mode {mode:04o})")
        return
    import win32security as security

    descriptor = security.GetNamedSecurityInfo(str(path), security.SE_FILE_OBJECT,
        security.OWNER_SECURITY_INFORMATION | security.DACL_SECURITY_INFORMATION)
    owner = security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner())
    identity = security.ConvertSidToStringSid(current_sid())
    allowed = {identity, "S-1-5-18", "S-1-5-32-544"}
    acl = descriptor.GetSecurityDescriptorDacl()
    # Windows assigns Administrators as the default owner for an elevated creator.
    # Administrators already has recovery rights in this DACL, like POSIX root.
    if owner not in {identity, "S-1-5-32-544"} or acl is None or not acl.GetAceCount():
        raise ValueError(f"Unsafe state path {path}: user/Administrators ownership and private ACL required")
    for index in range(acl.GetAceCount()):
        ace = acl.GetAce(index)
        if ace[0][0] != security.ACCESS_ALLOWED_ACE_TYPE or security.ConvertSidToStringSid(ace[2]) not in allowed:
            raise ValueError(f"Unsafe state path {path}: ACL grants another identity access")


def lock_file(fd: int, nonblocking: bool) -> None:
    if not WINDOWS:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblocking else 0))
        return
    import errno
    import msvcrt

    if os.fstat(fd).st_size == 0:
        os.write(fd, b"\0")
    while True:
        os.lseek(fd, 0, os.SEEK_SET)
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            return
        except OSError as error:
            if error.errno not in (errno.EACCES, errno.EDEADLK, errno.EAGAIN):
                raise
            if nonblocking:
                raise BlockingIOError("State is locked") from error
            time.sleep(0.05)


def sync_directory(path: Path) -> None:
    # Windows flushes files with fsync; Python has no portable directory handle fsync there.
    if WINDOWS:
        return
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def replace_file(source, destination) -> None:
    """Windows readers can briefly deny replacement of an otherwise private file."""
    deadline = time.monotonic() + 2
    while True:
        try:
            os.replace(source, destination)
            return
        except PermissionError as error:
            if not WINDOWS or getattr(error, "winerror", None) not in {5, 32, 33} or time.monotonic() >= deadline:
                raise
            time.sleep(0.01)


def read_file(path: Path) -> bytes:
    """Allow a bounded Windows sharing conflict during atomic file publication."""
    deadline = time.monotonic() + 2
    while True:
        try:
            return path.read_bytes()
        except PermissionError as error:
            code = getattr(error, "winerror", None)
            # The CRT used by Path.open can report only EACCES for a native
            # sharing conflict. Never treat failure as missing/stopped state.
            sharing_error = code in {5, 32, 33} or code is None and error.errno == errno.EACCES
            if not WINDOWS or not sharing_error or time.monotonic() >= deadline:
                raise
            time.sleep(0.01)


def boot_id() -> str:
    return str(int(psutil.boot_time()))


def process_start(pid: int) -> str:
    try:
        return str(psutil.Process(pid).create_time())
    except psutil.Error as error:
        raise OSError("Process identity is unavailable") from error


def systemd_available() -> bool:
    backend = os.environ.get("SPEARMINT_PROCESS_BACKEND", "auto")
    if backend not in {"auto", "native", "systemd"}:
        raise ValueError("SPEARMINT_PROCESS_BACKEND must be auto, native or systemd")
    if backend == "native":
        return False
    if backend == "systemd" and platform.system() != "Linux":
        raise ValueError("The systemd backend requires Linux")
    return platform.system() == "Linux" and Path("/run/systemd/system").is_dir() and shutil.which("systemctl") is not None


def capabilities() -> dict:
    return {"os": platform.system(), "architecture": platform.machine(),
            "process_backend": "systemd" if systemd_available() else "native-supervisor",
            "docker": "rootless-unix" if platform.system() == "Linux" else "desktop-local",
            "file_security": "windows-acl" if WINDOWS else "posix-owner-mode"}
