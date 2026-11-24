"""Build a native executable package on the matching platform."""
import filecmp
import hashlib
from importlib.metadata import distribution, version
import json
import os
from pathlib import Path
import platform
import posixpath
import re
import shutil
import subprocess
import sys
import sysconfig
import tarfile
import tempfile
import tomllib
import zipfile

if __package__:
    from .linux_compatibility import LINUX_GLIBC_VERSION, verify_linux_glibc
else:
    from linux_compatibility import LINUX_GLIBC_VERSION, verify_linux_glibc

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "work/tmp/package-build"
DEPLOYMENT_DOCS = {
    "README.md": "DEPLOYMENT.md",
    "README.en.md": "DEPLOYMENT.en.md",
    "LICENSE": "LICENSE",
}
DEPLOYMENT_EXAMPLES = {"deploy/nginx.conf.example": "nginx.conf.example"}


def copy_deployment_docs(bundle: Path, commit: str) -> None:
    repository = "https://github.com/EchoSixHIYA/Spearmint-Panel"
    for source, name in DEPLOYMENT_EXAMPLES.items():
        shutil.copy2(ROOT / source, bundle / "deployment" / name)
    for source, destination in DEPLOYMENT_DOCS.items():
        def resolve_link(match: re.Match[str]) -> str:
            link = match[1]
            path, fragment, anchor = link.partition("#")
            if not path or ":" in path or path.startswith("/"):
                return match[0]
            original = posixpath.normpath(posixpath.join(posixpath.dirname(source), path))
            if not (ROOT / original).is_file():
                raise ValueError(f"Missing deployment documentation link in {source}: {link}")
            if original in DEPLOYMENT_DOCS:
                packaged = DEPLOYMENT_DOCS[original]
            elif original in DEPLOYMENT_EXAMPLES:
                packaged = "deployment/" + DEPLOYMENT_EXAMPLES[original]
            elif original.startswith("deploy/package/"):
                packaged = "deployment/" + original.removeprefix("deploy/package/")
            else:
                return f"]({repository}/blob/{commit}/{original}{fragment}{anchor})"
            if original not in DEPLOYMENT_DOCS and not (bundle / packaged).is_file():
                raise ValueError(f"Missing packaged deployment file: {packaged}")
            local = posixpath.relpath(packaged, posixpath.dirname(destination) or ".")
            return f"]({local}{fragment}{anchor})"

        text = (ROOT / source).read_text(encoding="utf-8")
        path = bundle / destination
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(re.sub(r"\]\(([^()\s]+)\)", resolve_link, text), encoding="utf-8", newline="\n")


def copy_runtime_licenses(bundle: Path) -> None:
    licenses = bundle / "LICENSES"
    licenses.mkdir()
    base = Path(sys.base_prefix)
    for source in (base / "LICENSE.txt", base / "LICENSE", Path(sysconfig.get_path("stdlib")) / "LICENSE.txt"):
        if source.is_file():
            shutil.copyfile(source, licenses / "CPython.txt")
            break
    packager = distribution("PyInstaller")
    for path in packager.files or ():
        if path.name == "COPYING.txt" and path.parent.name == "licenses":
            shutil.copyfile(packager.locate_file(path), licenses / "PyInstaller.txt")
            break


def copy_debian_library_licenses(bundle: Path) -> None:
    query = shutil.which("dpkg-query")
    libraries = {path.name: path for path in (bundle / "_internal").glob("lib*.so*") if path.is_file()}
    if not query or not libraries:
        return

    env = {**os.environ, "LC_ALL": "C", "LANGUAGE": "C"}
    search = subprocess.run([query, "--search", "--", *(f"*/{name}" for name in sorted(libraries))],
                            capture_output=True, text=True, env=env)
    owners: dict[str, set[str]] = {}
    for line in search.stdout.splitlines():
        packages, separator, source_name = line.partition(": ")
        source = Path(source_name)
        bundled = libraries.get(source.name)
        if not separator or not source.is_absolute() or bundled is None or not source.is_file():
            continue
        if not filecmp.cmp(source, bundled, shallow=False):
            continue
        for package in packages.split(", "):
            if re.fullmatch(r"[a-z0-9][a-z0-9+.-]+(?::[a-z0-9-]+)?", package):
                owners.setdefault(package, set()).add(bundled.name)
    if not owners:
        return

    installed = subprocess.run([query, "--show", "--", *sorted(owners)], capture_output=True, text=True, env=env)
    records = []
    for line in installed.stdout.splitlines():
        package, separator, package_version = line.partition("\t")
        source = Path("/usr/share/doc") / package.split(":", 1)[0] / "copyright"
        if not separator or not package_version or package not in owners or not source.is_file():
            continue
        target = bundle / "LICENSES/debian" / f"{package.replace(':', '_')}.txt"
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        records.append({"package": package, "version": package_version, "libraries": sorted(owners[package]),
                        "notice": target.relative_to(bundle).as_posix()})
    if records:
        (bundle / "LICENSES/debian-library-sources.json").write_text(
            json.dumps(sorted(records, key=lambda record: record["package"]), indent=2) + "\n", encoding="utf-8")


def build_package(work: Path, env: dict[str, str]):
    # The build can use dependencies from an existing virtual environment.
    # Both the manifest and the frozen application must use this checkout.
    source = ROOT / "src"
    sys.path.insert(0, str(source))
    from spearmint.state import MIGRATIONS

    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    installed_version = version(project["name"])
    if installed_version != project["version"]:
        raise RuntimeError("Install this checkout in the build environment before packaging")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    system = platform.system().lower()
    arch = {"AMD64": "amd64", "x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine(), platform.machine())
    web = ROOT / "web/dist"
    web_files = {path.relative_to(web).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in sorted(web.rglob("*")) if path.is_file()}
    if "index.html" not in web_files:
        raise RuntimeError("Build the frontend before packaging")
    manifest = {"version": installed_version, "commit": commit, "os": system, "architecture": arch,
                "python": platform.python_version(), "schema": len(MIGRATIONS),
                "format": "native-executable-with-runtime-and-web", "grove_update": 1, "web_files": web_files,
                "host_services": 1 if system == 'linux' else 0, "service_deployment": 2}
    if system == 'linux':
        manifest['glibc_baseline'] = LINUX_GLIBC_VERSION
    manifest_path = work / "build-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    args = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onedir", "--name", "spearmint",
            "--paths", str(source),
            "--distpath", str(work / "dist"), "--workpath", str(work / "pyinstaller"), "--specpath", str(work),
            "--add-data", f"{manifest_path}:.",
            "--collect-all", "uvicorn", "--collect-all", "fido2", "--recursive-copy-metadata", "spearmint-panel"]
    if os.name == "nt":
        args.extend(["--collect-all", "winpty"])
        for name in ("win32api", "win32security", "win32job", "win32process", "win32pipe", "win32file", "win32con", "win32event", "win32service", "win32pdh"):
            args.extend(["--hidden-import", name])
    subprocess.run([*args, str(ROOT / "deploy/frozen-entry.py")], check=True, cwd=ROOT, env=env)
    bundle = work / "dist/spearmint"
    shutil.copytree(web, bundle / "web", dirs_exist_ok=True)
    shutil.copytree(ROOT / "deploy/package", bundle / "deployment", dirs_exist_ok=True)
    copy_deployment_docs(bundle, commit)
    copy_runtime_licenses(bundle)
    if sys.platform == "linux":
        copy_debian_library_licenses(bundle)
    if system == 'linux':
        for path in bundle.rglob('*'):
            if path.is_file():
                with path.open('rb') as stream:
                    verify_linux_glibc(stream, path.relative_to(bundle).as_posix())
    for provenance in (bundle / "_internal").rglob("*.dist-info/direct_url.json"):
        provenance.unlink()
    shutil.copyfile(manifest_path, bundle / "build-manifest.json")
    for path in bundle.rglob("*"):
        if path.suffix in {".py", ".pyc"} and "_internal" not in path.parts:
            raise RuntimeError(f"Unexpected source file in deployment package: {path}")
    checksums = {p.relative_to(bundle).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in sorted(bundle.rglob("*")) if p.is_file()}
    if {path.removeprefix("web/"): digest for path, digest in checksums.items() if path.startswith("web/")} != web_files:
        raise RuntimeError("Frontend files changed while building the native package")
    checksums_path = bundle / "checksums.json"
    checksums_path.write_text(json.dumps(checksums, indent=2) + "\n", encoding="utf-8")
    name = f"spearmint-{manifest['version']}-{system}-{arch}-{commit[:8]}"
    output = WORK / "artifacts"
    output.mkdir(exist_ok=True)
    if os.name == "nt":
        archive = output / (name + ".zip")
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as package:
            for path in sorted(bundle.rglob("*")):
                if path.is_file():
                    package.write(path, "spearmint/" + path.relative_to(bundle).as_posix())
    else:
        archive = output / (name + ".tar.gz")
        with tarfile.open(archive, "w:gz") as package:
            package.add(bundle, arcname="spearmint")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_name(archive.name + ".sha256").write_text(digest + "  " + archive.name + "\n", encoding="ascii")
    external_manifest = {**manifest, "package_checksums_sha256": hashlib.sha256(checksums_path.read_bytes()).hexdigest()}
    (output / (name + ".manifest.json")).write_text(json.dumps(external_manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"archive": str(archive), "sha256": digest, **external_manifest}, indent=2))


def main():
    WORK.mkdir(parents=True, exist_ok=True)
    # Keep the final archives, but remove native objects, extracted runtimes,
    # packager caches and temporary files on both success and failure.
    with tempfile.TemporaryDirectory(prefix="run-", dir=WORK) as directory:
        work = Path(directory)
        temporary = work / "temp"
        temporary.mkdir()
        env = {**os.environ, "PYINSTALLER_CONFIG_DIR": str(work / "cache"),
               "TMPDIR": str(temporary), "TEMP": str(temporary), "TMP": str(temporary),
               "PYTHONDONTWRITEBYTECODE": "1", "PIP_NO_CACHE_DIR": "1"}
        previous = sys.dont_write_bytecode
        sys.dont_write_bytecode = True
        try:
            build_package(work, env)
        finally:
            sys.dont_write_bytecode = previous


if __name__ == "__main__":
    main()
