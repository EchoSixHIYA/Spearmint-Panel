"""Identify the running backend independently of its web and state directories."""

from importlib.metadata import PackageNotFoundError, version
from hashlib import file_digest, sha256
import json
from pathlib import Path
import re
import sys
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .package_files import CHECKSUMS, read_checksums
from .web_bundle import matches_packaged_web, web_bundle_status


DEPLOYMENT_METHOD = 'grove.deployment.status'
DEPLOYMENT_HOST_METHOD = 'grove.deployment.status.v2'
DEPLOYMENT_WEB_METHOD = 'grove.deployment.status.v3'
DEPLOYMENT_DIRECTORY_METHOD = 'grove.deployment.status.v4'
DEPLOYMENT_PACKAGE_METHOD = 'grove.deployment.status.v5'
DEPLOYMENT_DETAILS_METHOD = 'grove.deployment.status.v6'


class BuildStatus(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    version: str | None = Field(max_length=64, pattern=r'^[a-zA-Z0-9.+-]+$')
    commit: str | None = Field(pattern=r'^[a-f0-9]{40}$')
    runtime: Literal['native', 'python']


class WebStatus(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    status: Literal['ready', 'missing-entry', 'unbuilt', 'missing-assets', 'unreadable']
    build: str | None = Field(max_length=256, pattern=r'^[a-zA-Z0-9_-]+ / [a-zA-Z0-9_-]+$')
    package_match: bool | None = None
    package_web_sha256: str | None = Field(default=None, pattern=r'^[a-f0-9]{64}$')


class DeploymentHost(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    target: Literal['linux-amd64', 'linux-arm64', 'windows-amd64'] | None
    database_schema: int = Field(alias='schema', ge=1, le=2**31 - 1)


class MemberDirectoryStatus(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    sequence: str = Field(pattern=r'^[1-9][0-9]{0,18}$')
    members_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    valid_until: int = Field(gt=0, lt=2**53)


class DeploymentStatus(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    build: BuildStatus
    web: WebStatus
    host: DeploymentHost | None = None
    member_directory: MemberDirectoryStatus | None = None
    package_checksums_sha256: str | None = Field(default=None, pattern=r'^[a-f0-9]{64}$')


def deployment_host(platform: dict, schema: int) -> dict:
    architecture = {'x86_64': 'amd64', 'amd64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}
    target = f"{platform['os'].lower()}-{architecture.get(platform['architecture'].lower(), '')}"
    supported = {'linux-amd64', 'linux-arm64', 'windows-amd64'}
    return {'target': target if target in supported else None, 'schema': schema}


def deployment_web(directory: Path, packaged_web: dict[str, str] | None) -> dict:
    result = web_bundle_status(directory)
    if packaged_web is not None:
        result['package_match'] = matches_packaged_web(directory, packaged_web)
        # Match JavaScript's UTF-16 string ordering for names outside the BMP.
        files = sorted(packaged_web.items(), key=lambda item: item[0].encode('utf-16-be', errors='surrogatepass'))
        raw = json.dumps(files, ensure_ascii=False, separators=(',', ':'))
        try:
            result['package_web_sha256'] = sha256(raw.encode('utf-8')).hexdigest()
        except UnicodeEncodeError:
            pass
    return result


def running_package_digest(executable: Path, embedded_manifest: Path, manifest_bytes: bytes) -> str | None:
    try:
        executable = executable.resolve(strict=True)
        root = executable.parent
        manifest_name = embedded_manifest.resolve(strict=True).relative_to(root).as_posix()
        raw = read_checksums(root / CHECKSUMS)
        checksums = json.loads(raw)
        if not isinstance(checksums, dict) or checksums.get(manifest_name) != sha256(manifest_bytes).hexdigest():
            return None
        with executable.open('rb') as stream:
            if checksums.get(executable.name) == file_digest(stream, 'sha256').hexdigest():
                return sha256(raw).hexdigest()
    except (OSError, ValueError, RuntimeError):
        pass
    return None


def running_build() -> tuple[dict, dict[str, str] | None, str | None]:
    try:
        installed_version = version("spearmint-panel")
    except PackageNotFoundError:
        installed_version = None
    native = getattr(sys, "frozen", False)
    bundled = getattr(sys, "_MEIPASS", None) if native else None
    commit = None
    web_files = None
    package_digest = None
    if bundled:
        manifest_path = Path(bundled) / "build-manifest.json"
        try:
            raw = manifest_path.read_bytes()
            manifest = json.loads(raw)
        except (OSError, ValueError):
            manifest = None
        if installed_version and isinstance(manifest, dict) and manifest.get("version") == installed_version:
            candidate = manifest.get("commit")
            if isinstance(candidate, str) and re.fullmatch(r"[a-f0-9]{40}", candidate):
                commit = candidate
                package_digest = running_package_digest(Path(sys.executable), manifest_path, raw)
                expected = manifest.get("web_files")
                if (isinstance(expected, dict) and "index.html" in expected
                        and all(isinstance(digest, str) and re.fullmatch(r"[a-f0-9]{64}", digest)
                                for digest in expected.values())):
                    web_files = expected
    return {"version": installed_version, "commit": commit, "runtime": "native" if native else "python"}, web_files, package_digest
