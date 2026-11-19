"""File operations performed as the terminal's host account."""
from contextlib import suppress
from dataclasses import dataclass
import os
from pathlib import Path
import stat
from tempfile import NamedTemporaryFile

from .peer.protocol import PeerError, parse_b64, wire_b64


FILE_CHUNK = 8192


def path_for(value) -> Path:
    if not isinstance(value, str) or len(value) > 4096 or '\0' in value:
        raise PeerError('INVALID_REQUEST', 'Invalid file path')
    path = Path(value).expanduser() if value else Path.home()
    if not path.is_absolute():
        raise PeerError('INVALID_REQUEST', 'Use an absolute file path')
    return path


def fingerprint(info) -> str:
    # Windows directory enumeration and fstat expose different file identifiers.
    return f'{info.st_size}:{info.st_mtime_ns}'


def directory(path: Path, offset: int) -> dict:
    items = []
    with os.scandir(path) as entries:
        for index, entry in enumerate(entries):
            if index < offset:
                continue
            if len(items) == 100:
                break
            try:
                info = entry.stat()
                items.append({'name': entry.name, 'path': str(Path(entry.path)), 'directory': stat.S_ISDIR(info.st_mode),
                              'size': info.st_size, 'modified': info.st_mtime, 'version': fingerprint(info)})
            except OSError:
                continue
        else:
            index = -1
    parent = str(path.parent) if path.parent != path else None
    return {'path': str(path), 'parent': parent, 'items': items, 'next_offset': index if index >= 0 else None,
            'drives': os.listdrives() if os.name == 'nt' else []}


def read_file(path: Path, offset: int, expected: str | None) -> dict:
    with path.open('rb') as stream:
        info = os.fstat(stream.fileno())
        version = fingerprint(info)
        if not stat.S_ISREG(info.st_mode):
            raise PeerError('FILE_UNAVAILABLE', 'Select a regular file')
        if expected is not None and expected != version:
            raise PeerError('CONFLICT', 'File changed during download. Read it again')
        stream.seek(offset)
        data = stream.read(FILE_CHUNK)
    return {'data': wire_b64(data), 'size': info.st_size, 'version': version, 'offset': offset + len(data)}


@dataclass
class Upload:
    path: Path
    temporary: Path
    expected: str | None
    size: int
    offset: int = 0

    @classmethod
    def create(cls, path: Path, expected, size: int):
        check_destination(path, expected)
        with NamedTemporaryFile(prefix='.spearmint-upload-', dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
        return cls(path, temporary, expected, size)

    def write(self, offset: int, encoded: str) -> dict:
        data = parse_b64(encoded, FILE_CHUNK)
        if offset < self.offset:
            with self.temporary.open('rb') as stream:
                stream.seek(offset)
                if stream.read(len(data)) != data or offset + len(data) > self.offset:
                    raise PeerError('CONFLICT', 'Upload chunk does not match the accepted data')
            return {'offset': self.offset}
        if offset != self.offset or offset + len(data) > self.size:
            raise PeerError('INVALID_REQUEST', 'Unexpected upload offset or size')
        with self.temporary.open('ab') as stream:
            stream.write(data)
        self.offset += len(data)
        return {'offset': self.offset}

    def finish(self) -> dict:
        if self.offset != self.size:
            raise PeerError('CONFLICT', 'Upload is incomplete')
        if self.temporary.exists():
            check_destination(self.path, self.expected)
            if self.path.exists():
                os.chmod(self.temporary, stat.S_IMODE(self.path.stat().st_mode))
            os.replace(self.temporary, self.path)
        return {'path': str(self.path), 'size': self.size}

    def close(self):
        with suppress(OSError):
            self.temporary.unlink(missing_ok=True)


def check_destination(path: Path, expected):
    if path.is_symlink():
        raise PeerError('CONFLICT', 'Choose the destination file instead of its symbolic link')
    current = fingerprint(path.stat()) if path.exists() else None
    if expected != current:
        raise PeerError('CONFLICT', 'Destination changed. Refresh before overwriting')
