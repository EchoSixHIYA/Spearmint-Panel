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
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, build_opener
from zipfile import BadZipFile, ZipFile

from . import update_release
from .peer.protocol import PeerError


MAX_ARCHIVE = 300 * 1024 * 1024
MANIFEST = 'spearmint/build-manifest.json'


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


def retain(state, source: Path, release: update_release.Release, platform: str) -> SeedArchive:
    directory = TemporaryDirectory(prefix='.seed-archive-', dir=state.directory, ignore_cleanup_errors=True)
    name = update_release.archive_name(release.version, release.commit, platform)
    path = Path(directory.name) / name
    asset = release.packages[platform]
    try:
        try:
            os.link(source, path)
        except OSError:
            copyfile(source, path)
        if not update_release.correct_archive(path, asset):
            raise ValueError('Deployment archive does not match the signed release')
        manifest = inspect_archive(path, platform)
        if ((manifest['version'], manifest['commit'], manifest['schema']) != (release.version, release.commit, release.database_schema)
                or manifest.get('format') != update_release.FORMAT or manifest.get('grove_update') != 1):
            raise ValueError('Deployment manifest does not match the signed release')
    except (OSError, ValueError, KeyError, TypeError, BadZipFile, tarfile.TarError) as error:
        directory.cleanup()
        raise PeerError('SEED_PACKAGE_FETCH', 'The acquired native deployment package could not be verified') from error
    return SeedArchive(path, {'name': name, 'sha256': asset.sha256, 'commit': release.commit, 'size': asset.size}, directory)


def acquire_local(state, platform: str) -> SeedArchive:
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
    return SeedArchive(path, {'name': name, 'sha256': digest, 'commit': manifest['commit'], 'size': path.stat().st_size})
