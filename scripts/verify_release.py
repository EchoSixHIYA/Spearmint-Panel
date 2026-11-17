"""Verify native release archives without installing or extracting them."""

import argparse
from collections.abc import Callable
from contextlib import closing
import hashlib
import json
from pathlib import Path
import posixpath
import re
import stat
import tarfile
from typing import BinaryIO
import zipfile


TARGETS = ("linux-amd64", "linux-arm64", "windows-amd64")
ROOT = "spearmint/"
METADATA_LIMIT = 1024 * 1024
FORMAT = "native-executable-with-runtime-and-web"


def document(raw: bytes, label: str) -> dict:
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain a JSON object")
    return value


def relative_path(name: str) -> str:
    if not name.startswith(ROOT):
        raise ValueError(f"Unexpected package path: {name}")
    path = name.removeprefix(ROOT)
    if not path or "\\" in path or any(part in ("", ".", "..") or ":" in part for part in path.split("/")):
        raise ValueError(f"Unexpected package path: {name}")
    return path


def verify_executable(stream: BinaryIO, target: str) -> None:
    header = stream.read(64)
    if target == "windows-amd64":
        if len(header) == 64 and header.startswith(b"MZ"):
            offset = int.from_bytes(header[60:64], "little")
            if offset >= len(header):
                stream.seek(offset)
                pe = stream.read(26)
                if pe[:6] == b"PE\x00\x00\x64\x86" and pe[24:26] == b"\x0b\x02":
                    return
    else:
        machine = {"linux-amd64": 62, "linux-arm64": 183}[target]
        if (len(header) == 64 and header.startswith(b"\x7fELF\x02\x01\x01")
                and int.from_bytes(header[16:18], "little") in (2, 3)
                and int.from_bytes(header[18:20], "little") == machine):
            return
    raise ValueError(f"{target}: executable header does not match the requested platform")


def read_entries(entries: list[str], open_entry: Callable[[str], BinaryIO], target: str) -> tuple[dict, dict, dict, str]:
    files, metadata, folded = {}, {}, set()
    checksums_digest = ""
    executable = "spearmint.exe" if target == "windows-amd64" else "spearmint"
    for name in entries:
        path = relative_path(name)
        if path.casefold() in folded:
            raise ValueError(f"Duplicate package path: {name}")
        folded.add(path.casefold())
        with closing(open_entry(name)) as stream:
            if path in ("checksums.json", "build-manifest.json"):
                raw = stream.read(METADATA_LIMIT + 1)
                if len(raw) > METADATA_LIMIT:
                    raise ValueError(f"Package metadata too large: {path}")
                metadata[path] = document(raw, path)
                if path == "build-manifest.json":
                    files[path] = hashlib.sha256(raw).hexdigest()
                else:
                    checksums_digest = hashlib.sha256(raw).hexdigest()
            else:
                if path == executable:
                    verify_executable(stream, target)
                    stream.seek(0)
                files[path] = hashlib.file_digest(stream, "sha256").hexdigest()
    if metadata.keys() != {"checksums.json", "build-manifest.json"}:
        raise ValueError("Package is missing its manifest or file checksums")
    return files, metadata["checksums.json"], metadata["build-manifest.json"], checksums_digest


def contents(archive: Path, target: str) -> tuple[dict, dict, dict, str]:
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as bundle:
            entries = []
            for item in bundle.infolist():
                if stat.S_ISLNK(item.external_attr >> 16):
                    raise ValueError(f"Unexpected ZIP link: {item.filename}")
                if not item.is_dir():
                    entries.append(item.filename)
            return read_entries(entries, bundle.open, target)

    with tarfile.open(archive, "r:gz") as bundle:
        entries = [item for item in bundle if not item.isdir()]
        regular = {item.name for item in entries if item.isfile()}
        executable = next((item for item in entries if item.name == ROOT + "spearmint"), None)
        if executable is not None and (not executable.isfile() or not executable.mode & stat.S_IXUSR):
            raise ValueError(f"{target}: package executable must be a regular file with owner execute permission")
        for item in entries:
            if item.isfile():
                continue
            link_target = posixpath.join(posixpath.dirname(item.name), item.linkname) if item.issym() else item.linkname
            if not (item.issym() or item.islnk()) or posixpath.normpath(link_target) not in regular:
                raise ValueError(f"Unexpected archive member: {item.name}")

        def open_entry(name: str) -> BinaryIO:
            stream = bundle.extractfile(name)
            if stream is None:
                raise ValueError(f"Package entry cannot be read: {name}")
            return stream

        return read_entries([item.name for item in entries], open_entry, target)


def package_names(version: str, commit: str, target: str) -> tuple[str, str, str]:
    base = f"spearmint-{version}-{target}-{commit[:8]}"
    archive = base + (".zip" if target.startswith("windows-") else ".tar.gz")
    return archive, archive + ".sha256", base + ".manifest.json"


def verify_package(directory: Path, version: str, commit: str, target: str) -> tuple[dict, dict]:
    archive_name, checksum_name, manifest_name = package_names(version, commit, target)
    archive = directory / archive_name
    with archive.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if (directory / checksum_name).read_text(encoding="ascii").strip() != f"{digest}  {archive_name}":
        raise ValueError(f"{target}: archive checksum mismatch")
    files, checksums, manifest, checksums_digest = contents(archive, target)
    external_manifest = document((directory / manifest_name).read_bytes(), manifest_name)
    if external_manifest.pop("package_checksums_sha256", checksums_digest) != checksums_digest:
        raise ValueError(f"{target}: packaged checksums.json digest differs from the external manifest")
    if manifest != external_manifest:
        raise ValueError(f"{target}: internal and external manifests differ")
    expected_os, expected_arch = target.split("-")
    expected = {"version": version, "commit": commit, "os": expected_os, "architecture": expected_arch, "format": FORMAT}
    if any(manifest.get(key) != value for key, value in expected.items()):
        raise ValueError(f"{target}: package does not match the requested version, commit and platform")
    schema = manifest.get("schema")
    if type(schema) is not int or schema < 1:
        raise ValueError(f"{target}: invalid database schema")
    if checksums != files:
        changed = sorted(path for path in files.keys() | checksums.keys() if files.get(path) != checksums.get(path))
        raise ValueError(f"{target}: package file checksums differ at {', '.join(changed[:5])}")
    web = {path: digest for path, digest in files.items() if path.startswith("web/")}
    if "web_files" in manifest:
        if manifest["web_files"] != {path.removeprefix("web/"): digest for path, digest in web.items()}:
            raise ValueError(f"{target}: build manifest does not match the packaged Web files")
        if files.get("_internal/build-manifest.json") != files["build-manifest.json"]:
            raise ValueError(f"{target}: embedded build manifest differs from the archive manifest")
    windows = expected_os == "windows"
    executable = "spearmint.exe" if windows else "spearmint"
    launcher = "deployment/start.ps1" if windows else "deployment/spearmint.service"
    installer = "deployment/install-windows.ps1" if windows else "deployment/install-linux.sh"
    if installer not in files:
        raise ValueError(f"{target}: package is missing its native installer: {installer}")
    if ("web/index.html" not in web or not any(path.startswith("web/assets/") and path.endswith(".js") for path in web)
            or not {executable, launcher, "DEPLOYMENT.md", "DEPLOYMENT.en.md"} <= files.keys()):
        raise ValueError(f"{target}: package is missing the panel, Web assets or deployment files")
    return {"target": target, "archive": archive_name, "sha256": digest, "manifest": manifest_name,
            "schema": schema, "files": len(files)}, web


def verify_release(directory: Path, version: str, commit: str, targets: tuple[str, ...]) -> dict:
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise ValueError("Use the complete 40-character Git commit ID")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.+-]*", version):
        raise ValueError("Invalid version")
    if len(set(targets)) != len(targets) or not targets or not set(targets) <= set(TARGETS):
        raise ValueError("Choose distinct supported release platforms")
    expected = {name for target in targets for name in package_names(version, commit, target)}
    if {path.name for path in directory.iterdir()} != expected:
        raise ValueError("Release inputs must contain exactly the expected archives, digests and manifests")
    packages = []
    frontend = None
    for target in targets:
        info, web = verify_package(directory, version, commit, target)
        if packages and info["schema"] != packages[0]["schema"]:
            raise ValueError(f"{target}: database schema differs across packages")
        if frontend is not None and web != frontend:
            raise ValueError(f"{target}: Web assets differ across packages")
        frontend = web
        packages.append(info)
    return {"version": version, "commit": commit, "schema": packages[0]["schema"], "packages": packages, "web": frontend}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--target", action="append", choices=TARGETS,
                        help="Verify only the given platform; defaults to all platforms")
    args = parser.parse_args()
    result = verify_release(args.directory, args.version, args.commit, tuple(args.target or TARGETS))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
