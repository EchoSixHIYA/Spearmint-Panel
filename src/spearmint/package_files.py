"""Check the files of an extracted or installed native package."""

import hashlib
import json
from pathlib import Path
import re
import sys


CHECKSUMS = "checksums.json"
METADATA_LIMIT = 1024 * 1024


def read_checksums(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Missing regular package checksum file: {path}")
    with path.open("rb") as stream:
        data = stream.read(METADATA_LIMIT + 1)
    if len(data) > METADATA_LIMIT:
        raise ValueError("Package checksum file is too large")
    return data


def verify_package(reference: Path, target: Path, executable: str) -> None:
    if target.is_symlink() or target.is_junction() or not target.is_dir():
        raise ValueError(f"Invalid package directory: {target}")
    target = target.resolve(strict=True)
    expected = read_checksums(reference / CHECKSUMS)
    if read_checksums(target / CHECKSUMS) != expected:
        raise ValueError("Installed checksums differ from the extracted package")
    files = json.loads(expected)
    required = {executable, "web/index.html", "build-manifest.json", "_internal/build-manifest.json"}
    if not isinstance(files, dict) or not required <= files.keys():
        raise ValueError("Package checksum file is missing required entries")
    if not any(name.startswith("web/assets/") and name.endswith(".js") for name in files):
        raise ValueError("Package checksum file is missing Web assets")

    seen = set()
    for name, digest in files.items():
        parts = name.split("/")
        if (any(not part or part.endswith((".", " ")) or re.search(r'[<>:"\\|?*\x00-\x1f]', part) for part in parts)
                or name.casefold() in seen or name.casefold() == CHECKSUMS
                or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
            raise ValueError(f"Invalid package checksum entry: {name!r}")
        seen.add(name.casefold())
        path = target.joinpath(*parts)
        try:
            resolved = path.resolve(strict=True)
        except (FileNotFoundError, NotADirectoryError):
            raise ValueError(f"Missing package file: {name}") from None
        if not resolved.is_relative_to(target) or not resolved.is_file():
            raise ValueError(f"Invalid package file: {name}")
        with resolved.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != digest:
                raise ValueError(f"Package file checksum mismatch: {name}")

    def raise_error(error: OSError) -> None:
        raise error

    for directory, subdirectories, filenames in target.walk(on_error=raise_error):
        for name in subdirectories:
            if (directory / name).is_junction():
                raise ValueError(f"Unexpected package directory link: {(directory / name).relative_to(target)}")
        for name in filenames:
            relative = (directory / name).relative_to(target).as_posix()
            if relative != CHECKSUMS and relative not in files:
                raise ValueError(f"Unexpected package file: {relative}")


def verify_command(executable: Path, args: list[str]) -> int:
    if len(args) != 1:
        print("Usage: spearmint --verify-package DIRECTORY", file=sys.stderr)
        return 2
    try:
        verify_package(executable.parent, Path(args[0]), executable.name)
    except (OSError, ValueError, RuntimeError) as error:
        print(f"Package verification failed: {error}", file=sys.stderr)
        return 1
    return 0
