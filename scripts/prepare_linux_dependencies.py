"""Install locked Linux dependencies, rebuilding Argon2 on the minimum ABI."""
import argparse
from hashlib import file_digest
import os
from pathlib import Path
import platform
import subprocess
import sys
from tempfile import TemporaryDirectory

if __package__:
    from .linux_compatibility import LINUX_GLIBC_VERSION, verify_linux_glibc
else:
    from linux_compatibility import LINUX_GLIBC_VERSION, verify_linux_glibc

ROOT = Path(__file__).resolve().parents[1]
ARGON2_SOURCE_SHA256 = '63505c71542a44b68b1e38060450fb006404170da375feb31af153e7f9c6205d'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wheelhouse', type=Path, required=True)
    parser.add_argument('--argon2-source', type=Path, required=True)
    args = parser.parse_args()
    if sys.prefix == sys.base_prefix:
        parser.error('Create and use the checkout .venv first')
    if platform.libc_ver() != ('glibc', LINUX_GLIBC_VERSION):
        parser.error(f'Build dependencies in the pinned glibc {LINUX_GLIBC_VERSION} environment')
    binding = [line for line in (ROOT / 'requirements.lock').read_text().splitlines()
               if line.startswith('argon2-cffi-bindings==')]
    if binding != ['argon2-cffi-bindings==26.1.0']:
        parser.error('Update the pinned Argon2 source when changing its dependency version')
    with args.argon2_source.open('rb') as stream:
        if file_digest(stream, 'sha256').hexdigest() != ARGON2_SOURCE_SHA256:
            parser.error('Argon2 source digest differs from the pinned 26.1.0 release')
    work = ROOT / 'work/tmp/linux-dependencies'
    work.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(dir=work) as directory:
        scratch = Path(directory)
        env = {**os.environ, 'TMPDIR': str(scratch), 'TEMP': str(scratch), 'TMP': str(scratch),
               'PIP_NO_CACHE_DIR': '1', 'PYTHONDONTWRITEBYTECODE': '1', 'CC': 'gcc'}
        def pip(*arguments):
            subprocess.run([sys.executable, '-B', '-m', 'pip', *arguments], check=True, env=env)
        install = ('install', '--no-cache-dir', '--no-index', '--no-deps', '--no-compile',
                   '--find-links', str(args.wheelhouse.resolve()))
        # The official Argon2 wheel needs glibc 2.26; keep its exact version,
        # rebuilding from the pinned source instead of lowering the dependency.
        binary = scratch / 'binary.lock'
        binary.write_text(''.join(line + '\n' for name in ('requirements.lock', 'requirements-build.lock')
                                 for line in (ROOT / name).read_text().splitlines()
                                 if not line.startswith('argon2-cffi-bindings==')), encoding='utf-8')
        pip(*install, '-r', str(binary), '-r', str(ROOT / 'requirements-linux-build.lock'))
        pip('wheel', '--no-cache-dir', '--no-index', '--no-deps', '--no-build-isolation',
            str(args.argon2_source.resolve()), '--wheel-dir', str(scratch))
        wheel, = scratch.glob('argon2_cffi_bindings-26.1.0-*.whl')
        pip(*install, '--force-reinstall', str(wheel))
        pip('check')
        for path in Path(sys.prefix).rglob('*'):
            if path.is_file():
                with path.open('rb') as stream:
                    verify_linux_glibc(stream, path.relative_to(sys.prefix).as_posix())


if __name__ == '__main__':
    main()
