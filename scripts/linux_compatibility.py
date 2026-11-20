"""Inspect ELF version requirements without executing target binaries."""
import re
from struct import unpack_from
from typing import BinaryIO


ARM64_GLIBC_BASELINE = (2, 35)


def glibc_requirements(stream: BinaryIO) -> set[tuple[int, ...]]:
    stream.seek(0)
    header = stream.read(64)
    if not header.startswith(b'\x7fELF'):
        return set()
    if len(header) != 64 or header[4:6] != b'\x02\x01':
        raise ValueError('Expected a little-endian ELF64 library')
    offset = unpack_from('<Q', header, 40)[0]
    width, count = unpack_from('<HH', header, 58)
    if not offset or width != 64 or not 0 < count <= 4096:
        raise ValueError('ELF section headers are unavailable for ABI verification')

    def read(at, size):
        stream.seek(at)
        data = stream.read(size)
        if len(data) != size:
            raise ValueError('Truncated ELF version information')
        return data

    sections = read(offset, width * count)
    versions = set()
    for index in range(count):
        section = sections[index * width:(index + 1) * width]
        if unpack_from('<I', section, 4)[0] != 0x6ffffffe:  # SHT_GNU_verneed
            continue
        at, size, link = unpack_from('<QQI', section, 24)
        if size > 1024 * 1024 or link >= count:
            raise ValueError('Invalid ELF version requirement section')
        linked = sections[link * width:(link + 1) * width]
        strings_at, strings_size = unpack_from('<QQ', linked, 24)
        if strings_size > 4 * 1024 * 1024:
            raise ValueError('Oversized ELF version string table')
        strings, needs = read(strings_at, strings_size), read(at, size)
        cursor, visited = 0, set()
        while True:
            if cursor in visited or cursor + 16 > len(needs):
                raise ValueError('Invalid ELF version requirement chain')
            visited.add(cursor)
            _, auxiliary_count, _, auxiliary, following = unpack_from('<HHIII', needs, cursor)
            auxiliary += cursor
            for _ in range(auxiliary_count):
                if auxiliary + 16 > len(needs):
                    raise ValueError('Truncated ELF auxiliary version information')
                _, _, _, name, next_auxiliary = unpack_from('<IHHII', needs, auxiliary)
                if name >= len(strings):
                    raise ValueError('Invalid ELF version name')
                label = strings[name:].split(b'\x00', 1)[0]
                if match := re.fullmatch(rb'GLIBC_([0-9]+(?:\.[0-9]+)+)', label):
                    versions.add(tuple(int(part) for part in match[1].split(b'.')))
                elif label.startswith(b'GLIBC_'):
                    raise ValueError(f'Unsupported glibc ABI requirement: {label.decode(errors="replace")}')
                auxiliary += next_auxiliary
            if not following:
                break
            cursor += following
    return versions


def verify_arm64_glibc(stream: BinaryIO, name: str) -> None:
    versions = glibc_requirements(stream)
    if versions and max(versions) > ARM64_GLIBC_BASELINE:
        required = '.'.join(map(str, max(versions)))
        raise ValueError(f'{name}: requires GLIBC_{required}; ARM64 packages must support Ubuntu 22.04 (glibc 2.35)')

