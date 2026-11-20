"""Keep the verified native archive available until the seeding job finishes."""
from dataclasses import dataclass
from hashlib import file_digest, sha256
import json
import os
from pathlib import Path
import re
from shutil import copyfile
import tarfile
from tempfile import NamedTemporaryFile, TemporaryDirectory
from threading import Lock
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, build_opener
from zipfile import BadZipFile, ZipFile

from . import update_release
from .peer.protocol import PeerError


MAX_ARCHIVE = 300 * 1024 * 1024
MANIFEST = 'spearmint/build-manifest.json'
ARCHIVE_INDEX = 'seed-archives.json'
PLATFORM_LOCKS = {target: Lock() for target in update_release.TARGETS}


@dataclass
class SeedArchive:
    path: Path
    metadata: dict
    directory: TemporaryDirectory | None = None

    def close(self) -> None:
        if self.directory is not None:
            self.directory.cleanup()


def inspect_archive(path: Path, platform: str) -> dict:
    if platform.startswith('windows'):
        with ZipFile(path) as archive, archive.open(MANIFEST) as source:
            manifest = json.loads(source.read(32 * 1024))
    else:
        with tarfile.open(path, 'r:gz') as archive:
            member = archive.getmember(MANIFEST)
            if not member.isfile():
                raise ValueError('Invalid native package manifest')
            with archive.extractfile(member) as source:
                manifest = json.loads(source.read(32 * 1024))
    if (f'{manifest["os"]}-{manifest["architecture"]}' != platform
            or not re.fullmatch(r'[a-f0-9]{40}', manifest['commit'])):
        raise ValueError('Wrong native package platform')
    return manifest


def local_index(root: Path) -> dict:
    with (root / 'index.json').open('rb') as source:
        return json.loads(source.read(64 * 1024))


def prune_local(state, platform: str, *, signed: bool = False) -> None:
    root = state.directory / 'seed-packages'
    if not root.is_dir():
        return
    with PLATFORM_LOCKS[platform]:
        # An offline fallback may finish after a signed download on the same node.
        if not signed:
            updates = state.directory / 'grove-updates'
            try:
                with (updates / ARCHIVE_INDEX).open('rb') as source:
                    signed = any(re.fullmatch(update_release.HASH_PATTERN, digest)
                                 and isinstance(entry, list) and len(entry) == 2 and entry[0] == platform
                                 and (updates / (digest + '.archive')).is_file()
                                 for digest, entry in json.loads(source.read(64 * 1024)).items())
            except (OSError, ValueError, TypeError, AttributeError):
                pass
        try:
            configured = local_index(root)[platform]['name']
        except (OSError, ValueError, KeyError, TypeError):
            configured = None
        if not isinstance(configured, str) or not re.fullmatch(r'[\w.-]{1,180}\.(?:zip|tar\.gz)', configured, re.ASCII):
            configured = None
        extension = r'\.zip' if platform.startswith('windows') else r'\.tar\.gz'
        pattern = re.compile(rf'spearmint-[0-9]+\.[0-9]+\.[0-9]+-{platform}-[a-f0-9]{{8}}{extension}')
        files = [path for path in root.iterdir() if not path.is_symlink() and path.is_file()
                 and (pattern.fullmatch(path.name) or path.name == configured)]
        keep = configured or (max(files, key=lambda path: path.stat().st_mtime).name if files else None)
        for path in files:
            if signed or path.name != keep:
                path.unlink(missing_ok=True)


def pin(state, source: Path, name: str) -> tuple[Path, TemporaryDirectory]:
    directory = TemporaryDirectory(prefix='.seed-archive-', dir=state.directory, ignore_cleanup_errors=True)
    path = Path(directory.name) / name
    try:
        try:
            os.link(source, path)
        except OSError:
            copyfile(source, path)
    except OSError:
        directory.cleanup()
        raise
    return path, directory


def retain(state, source: Path, release: update_release.Release, platform: str) -> SeedArchive:
    name = update_release.archive_name(release.version, release.commit, platform)
    asset = release.packages[platform]
    directory = None
    try:
        path, directory = pin(state, source, name)
        if not update_release.correct_archive(path, asset):
            raise ValueError('Deployment archive does not match the signed release')
        manifest = inspect_archive(path, platform)
        if ((manifest['version'], manifest['commit'], manifest['schema']) != (release.version, release.commit, release.database_schema)
                or manifest.get('format') != update_release.FORMAT or manifest.get('grove_update') != 1):
            raise ValueError('Deployment manifest does not match the signed release')
    except (OSError, ValueError, KeyError, TypeError, BadZipFile, tarfile.TarError) as error:
        if directory is not None:
            directory.cleanup()
        raise PeerError('SEED_PACKAGE_FETCH', 'The acquired native deployment package could not be verified') from error
    return SeedArchive(path, {'name': name, 'sha256': asset.sha256, 'commit': release.commit, 'size': asset.size,
                             'host_services': manifest.get('host_services', 0)}, directory)


def acquire_local(state, platform: str) -> SeedArchive:
    if platform not in PLATFORM_LOCKS:
        raise PeerError('SEED_PACKAGE', 'No verified native package is available for the detected platform')
    with PLATFORM_LOCKS[platform]:
        package = acquire_indexed(state, platform)
    try:
        prune_local(state, platform)
    except OSError:
        # An older file may still be open during cleanup on Windows.
        pass
    return package


def acquire_indexed(state, platform: str) -> SeedArchive:
    root = state.directory / 'seed-packages'
    try:
        entry = local_index(root)[platform]
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
        size = path.stat().st_size
        pinned, directory = pin(state, path, name)
    except (OSError, ValueError, KeyError, TypeError, BadZipFile, tarfile.TarError) as error:
        raise PeerError('SEED_PACKAGE', 'No verified native package is available for the detected platform') from error
    return SeedArchive(pinned, {'name': name, 'sha256': digest, 'commit': manifest['commit'], 'size': size,
                               'host_services': manifest.get('host_services', 0)}, directory)
