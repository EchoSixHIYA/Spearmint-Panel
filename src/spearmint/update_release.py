"""Acquire native update archives from the official GitHub Releases repository."""
from hashlib import file_digest, sha256
import json
import os
from pathlib import Path
import re
import tarfile
import tempfile
import time
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from zipfile import ZipFile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .package_files import verify_package
from .peer.protocol import parse_b64


REPOSITORY = 'EchoSixHIYA/Spearmint-Panel'
API = f'https://api.github.com/repos/{REPOSITORY}'
TARGETS = ('linux-amd64', 'linux-arm64', 'windows-amd64')
MAX_ARCHIVE = 300 * 1024 * 1024
CHUNK = 96 * 1024
HASH_PATTERN = r'^[a-f0-9]{64}$'
RELEASE_PATTERN = r'^v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.-]+)?$'
FORMAT = 'native-executable-with-runtime-and-web'
INDEX = 'update-index.json'
DOMAIN = b'Spearmint Grove release v1\0'
RELEASE_PUBLIC_KEY = bytes.fromhex('f22a628c5e4045dba679b61c459a3e0c376d17622da4e947fa28df4499a5684c')


class Asset(BaseModel):
    model_config = ConfigDict(strict=True, extra='forbid')

    id: int = Field(gt=0, lt=2**53)
    size: int = Field(gt=0, le=MAX_ARCHIVE)
    sha256: str = Field(pattern=HASH_PATTERN)


class Release(BaseModel):
    model_config = ConfigDict(strict=True, extra='forbid', serialize_by_alias=True)

    sequence: int = Field(gt=0, lt=2**53)
    tag: str = Field(pattern=RELEASE_PATTERN, max_length=64)
    version: str = Field(pattern=r'^[0-9]+\.[0-9]+\.[0-9]+$', max_length=32)
    commit: str = Field(pattern=r'^[a-f0-9]{40}$')
    database_schema: int = Field(alias='schema', ge=1, le=2**31 - 1)
    packages: dict[str, Asset] = Field(min_length=3, max_length=3)
    signature: str = Field(min_length=86, max_length=86)

    @model_validator(mode='after')
    def verify_signature(self):
        if set(self.packages) != set(TARGETS) or self.tag[1:].partition('-')[0] != self.version:
            raise ValueError('Invalid platform set or release tag')
        index = self.model_dump(exclude={'signature'})
        index['packages'] = {name: asset.model_dump(exclude={'id'}) for name, asset in self.packages.items()}
        try:
            key = Ed25519PublicKey.from_public_bytes(RELEASE_PUBLIC_KEY)
            key.verify(parse_b64(self.signature, 64), signed_bytes(index))
        except (InvalidSignature, ValueError) as error:
            raise ValueError('Invalid Spearmint release signature') from error
        return self


def signed_bytes(index: dict) -> bytes:
    return DOMAIN + json.dumps(index, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


class GitHubRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        destination = urlsplit(newurl)
        host = destination.hostname or ''
        if (destination.scheme != 'https' or destination.port not in (None, 443)
                or destination.username or destination.password
                or (host not in {'github.com', 'api.github.com'} and not host.endswith('.githubusercontent.com'))):
            raise ValueError('Invalid GitHub release redirect')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def github(path: str, *, binary: bool = False):
    request = Request(API + path, headers={
        'Accept': 'application/octet-stream' if binary else 'application/vnd.github+json',
        'User-Agent': 'Spearmint-Grove-Updater',
    })
    if not binary:
        request.add_header('Cache-Control', 'no-cache')
    token = os.environ.get('SPEARMINT_GITHUB_TOKEN')
    if token:
        request.add_unredirected_header('Authorization', f'Bearer {token}')
    return build_opener(GitHubRedirect()).open(request, timeout=8)


def json_response(path: str, limit: int, *, binary: bool = False):
    with github(path, binary=binary) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError('GitHub response exceeds size limit')
    return json.loads(data)


def asset_metadata(raw: dict) -> Asset:
    digest = raw['digest']
    if raw['state'] != 'uploaded' or not isinstance(digest, str) or not digest.startswith('sha256:'):
        raise ValueError('Release asset has no GitHub SHA-256 digest')
    return Asset(id=raw['id'], size=raw['size'], sha256=digest[7:])


def archive_name(version: str, commit: str, target: str) -> str:
    suffix = '.zip' if target == 'windows-amd64' else '.tar.gz'
    return f'spearmint-{version}-{target}-{commit[:8]}{suffix}'


def latest_release(*, commit: str | None = None) -> Release | None:
    # The shared GitHub cache can still serve the previous list after publication.
    releases = json_response(f'/releases?per_page=10&_={time.time_ns()}', 1024 * 1024)
    for row in sorted(releases, key=lambda release: release['published_at'] or '', reverse=True):
        if row['draft'] or not row['published_at'] or not re.fullmatch(RELEASE_PATTERN, row['tag_name']):
            continue
        assets = {asset['name']: asset for asset in row['assets']}
        if INDEX not in assets:
            continue
        envelope = read_small_asset(asset_metadata(assets[INDEX]))
        index = envelope['release']
        if index['tag'] != row['tag_name'] or not re.fullmatch(r'[a-f0-9]{40}', index['commit']):
            raise ValueError('Signed update index does not match the release tag')
        if commit is not None and index['commit'] != commit:
            continue
        packages = {}
        for target in TARGETS:
            name = archive_name(index['version'], index['commit'], target)
            asset = asset_metadata(assets[name])
            if asset.model_dump(exclude={'id'}) != index['packages'][target]:
                raise ValueError('GitHub archive differs from the signed update index')
            packages[target] = asset
        return Release.model_validate({**index, 'packages': packages, 'signature': envelope['signature']})
    return None


def read_small_asset(asset: Asset) -> dict:
    if asset.size > 128 * 1024:
        raise ValueError('Unexpected deployment manifest size')
    with github(f'/releases/assets/{asset.id}', binary=True) as response:
        data = response.read(asset.size + 1)
    if len(data) != asset.size or sha256(data).hexdigest() != asset.sha256:
        raise ValueError('GitHub deployment manifest did not match its digest')
    return json.loads(data)


def correct_archive(path: Path, asset: Asset) -> bool:
    if not path.is_file() or path.stat().st_size != asset.size:
        return False
    with path.open('rb') as stream:
        return file_digest(stream, 'sha256').hexdigest() == asset.sha256


def download(asset: Asset, destination: Path) -> None:
    if correct_archive(destination, asset):
        return
    # Validate the ID against the official repository before following the asset redirect.
    expected = asset_metadata(json_response(f'/releases/assets/{asset.id}', 128 * 1024))
    if expected != asset:
        raise ValueError('GitHub asset metadata changed')
    until = time.monotonic() + 600
    with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as stream:
        temporary = Path(stream.name)
    try:
        with github(f'/releases/assets/{asset.id}', binary=True) as response, temporary.open('wb') as stream:
            while block := response.read(256 * 1024):
                if stream.tell() + len(block) > asset.size or time.monotonic() > until:
                    raise ValueError('GitHub update download exceeded its expected size or time')
                stream.write(block)
        if not correct_archive(temporary, asset):
            raise ValueError('GitHub update download did not match its SHA-256')
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)


def extract(archive: Path, folder: Path, release: Release, target: str) -> str:
    asset = release.packages[target]
    if not correct_archive(archive, asset):
        raise ValueError('Update archive did not match the selected SHA-256')
    if target == 'windows-amd64':
        with ZipFile(archive) as package:
            entries = package.infolist()
            if (sum(item.file_size for item in entries) > 4 * MAX_ARCHIVE
                    or any(not item.filename.startswith('spearmint/') or '\\' in item.filename
                           or any(part in {'.', '..'} or ':' in part for part in item.filename.split('/'))
                           for item in entries)):
                raise ValueError('Invalid Windows update archive')
            package.extractall(folder)
    else:
        with tarfile.open(archive, 'r:gz') as package:
            entries = package.getmembers()
            if (sum(item.size for item in entries) > 4 * MAX_ARCHIVE
                    or any(item.name != 'spearmint' and not item.name.startswith('spearmint/') for item in entries)):
                raise ValueError('Invalid Linux update archive')
            package.extractall(folder, members=entries, filter='data')
    bundle = folder / 'spearmint'
    manifest = json.loads((bundle / 'build-manifest.json').read_bytes())
    if (manifest.get('grove_update') != 1 or manifest['format'] != FORMAT
            or (manifest['version'], manifest['commit'], manifest['schema']) != (release.version, release.commit, release.database_schema)
            or f"{manifest['os']}-{manifest['architecture']}" != target):
        raise ValueError('Update package does not match the release, architecture, or database schema')
    verify_package(bundle, bundle, 'spearmint.exe' if target == 'windows-amd64' else 'spearmint')
    with (bundle / 'checksums.json').open('rb') as stream:
        return file_digest(stream, 'sha256').hexdigest()
