"""Resolve the executor's trusted native package for the detected platform."""
from hashlib import file_digest, sha256
import json
from pathlib import Path
import re
import tarfile
from tempfile import NamedTemporaryFile
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, build_opener
from zipfile import BadZipFile, ZipFile

from .peer.protocol import PeerError


MAX_ARCHIVE = 300 * 1024 * 1024
MANIFEST = 'spearmint/build-manifest.json'


def inspect_archive(path: Path, platform: str) -> dict:
    if platform.startswith('windows'):
        with ZipFile(path) as archive, archive.open(MANIFEST) as source:
            manifest = json.loads(source.read(32 * 1024))
    else:
        with tarfile.open(path, 'r:gz') as archive:
            with archive.extractfile(MANIFEST) as source:
                manifest = json.loads(source.read(32 * 1024))
    if (f'{manifest["os"]}-{manifest["architecture"]}' != platform
            or not re.fullmatch(r'[a-f0-9]{40}', manifest['commit'])):
        raise ValueError('Wrong native package platform')
    return manifest


def acquire(state, platform: str) -> tuple[Path, dict]:
    root = state.directory / 'seed-packages'
    try:
        with (root / 'index.json').open('rb') as source:
            entry = json.loads(source.read(64 * 1024))[platform]
        name, digest = entry['name'], entry['sha256']
        if (not re.fullmatch(r'[\w.-]{1,180}\.(?:zip|tar\.gz)', name, re.ASCII)
                or not re.fullmatch(r'[a-f0-9]{64}', digest)):
            raise ValueError('Invalid native package settings')
        path = root / name
        if not path.exists():
            url = entry['url']
            if urlsplit(url).scheme != 'https':
                raise ValueError('Native package origin must use HTTPS')
            download = build_opener(ProxyHandler({})).open(url, timeout=12)
            with download, NamedTemporaryFile(dir=root, suffix='.part', delete=False) as output:
                incomplete = Path(output.name)
                try:
                    if urlsplit(download.url).scheme != 'https':
                        raise ValueError('Native package redirects must use HTTPS')
                    checksum = sha256()
                    while block := download.read(1024 * 1024):
                        if output.tell() + len(block) > MAX_ARCHIVE:
                            raise ValueError('Native package is too large')
                        checksum.update(block)
                        output.write(block)
                    if checksum.hexdigest() != digest:
                        raise ValueError('Native package checksum mismatch')
                    output.close()
                    inspect_archive(incomplete, platform)
                    incomplete.replace(path)
                finally:
                    if not output.closed:
                        output.close()
                    incomplete.unlink(missing_ok=True)
        if not 0 < path.stat().st_size <= MAX_ARCHIVE:
            raise ValueError('Invalid native package size')
        with path.open('rb') as source:
            if file_digest(source, 'sha256').hexdigest() != digest:
                raise ValueError('Native package checksum mismatch')
        manifest = inspect_archive(path, platform)
    except (OSError, ValueError, KeyError, TypeError, BadZipFile, tarfile.TarError) as error:
        raise PeerError('SEED_PACKAGE', 'No verified native package is available for the detected platform') from error
    return path, {'name': name, 'sha256': digest, 'commit': manifest['commit'], 'size': path.stat().st_size}
