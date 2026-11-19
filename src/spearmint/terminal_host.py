"""Native interactive terminals, isolated from the panel's own console."""
from contextlib import suppress
import os
from pathlib import Path
import shutil
import signal
import struct
import subprocess
import sys
from uuid import uuid4

import psutil

from .platforms import WINDOWS


def login_shell() -> int:
    import fcntl
    import termios

    fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    shell = shutil.which('bash') or '/bin/sh'
    os.execve(shell, [shell, '-i'], {**os.environ, 'TERM': 'xterm-256color', 'COLORTERM': 'truecolor'})
    return 1


class UnixTerminal:
    def __init__(self, columns: int, rows: int):
        self.fd, slave = os.openpty()
        try:
            self.resize(columns, rows)
            launcher = [sys.executable, '--internal-terminal'] if getattr(sys, 'frozen', False) else [sys.executable, '-m', __name__]
            self.process = subprocess.Popen(launcher, stdin=slave, stdout=slave, stderr=slave,
                                            start_new_session=True, cwd=Path.home(), close_fds=True)
        except BaseException:
            os.close(self.fd)
            raise
        finally:
            os.close(slave)

    def read(self) -> bytes:
        return os.read(self.fd, 32768)

    def write(self, data: bytes) -> None:
        while data:
            size = os.write(self.fd, data)
            data = data[size:]

    def resize(self, columns: int, rows: int) -> None:
        import fcntl
        import termios
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack('HHHH', rows, columns, 0, 0))

    def close(self) -> None:
        children = []
        with suppress(psutil.Error):
            children = psutil.Process(self.process.pid).children(recursive=True)
        for child in reversed(children):
            with suppress(psutil.Error):
                child.terminate()
        with suppress(ProcessLookupError):
            os.killpg(self.process.pid, signal.SIGTERM)
        _, pending = psutil.wait_procs(children, timeout=.5)
        for child in pending:
            with suppress(psutil.Error):
                child.kill()
        with suppress(ProcessLookupError):
            os.killpg(self.process.pid, signal.SIGKILL)
        with suppress(subprocess.TimeoutExpired):
            self.process.wait(timeout=2)
        os.close(self.fd)


class WindowsTerminal:
    def __init__(self, columns: int, rows: int):
        import win32api
        import win32con
        import win32job
        from winpty import Backend, PtyProcess

        shell = str(Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/cmd.exe')
        self.process = PtyProcess.spawn([shell, '/d', '/q'], cwd=str(Path.home()), dimensions=(rows, columns), backend=Backend.ConPTY)
        try:
            self.job = win32job.CreateJobObject(None, 'Spearmint-Terminal-' + uuid4().hex)
            limits = win32job.QueryInformationJobObject(self.job, win32job.JobObjectExtendedLimitInformation)
            limits['BasicLimitInformation']['LimitFlags'] = win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            win32job.SetInformationJobObject(self.job, win32job.JobObjectExtendedLimitInformation, limits)
            handle = win32api.OpenProcess(win32con.PROCESS_SET_QUOTA | win32con.PROCESS_TERMINATE, False, self.process.pid)
            try:
                win32job.AssignProcessToJobObject(self.job, handle)
            finally:
                handle.Close()
        except BaseException:
            self.process.close(force=True)
            if hasattr(self, 'job'):
                self.job.Close()
            raise

    def read(self) -> bytes:
        return self.process.read(32768).encode('utf-8')

    def write(self, data: bytes) -> None:
        self.process.write(data.decode('utf-8'))

    def resize(self, columns: int, rows: int) -> None:
        self.process.setwinsize(rows, columns)

    def close(self) -> None:
        import win32job
        try:
            win32job.TerminateJobObject(self.job, 0)
            self.process.close(force=True)
        finally:
            self.job.Close()


def open_terminal(columns: int, rows: int):
    return WindowsTerminal(columns, rows) if WINDOWS else UnixTerminal(columns, rows)


if __name__ == '__main__':
    raise SystemExit(login_shell())
