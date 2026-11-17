"""Entry point compiled into every native deployment package."""
import multiprocessing
import os
from pathlib import Path
import sys


if __name__ == "__main__":
    multiprocessing.freeze_support()
    root = Path(sys.executable).resolve().parent
    os.environ.setdefault("SPEARMINT_WEB_DIR", str(root / "web"))
    if sys.argv[1:2] == ["--internal-supervisor"]:
        from spearmint.native_process import supervise
        raise SystemExit(supervise(*sys.argv[2:]))
    if sys.argv[1:2] == ["--internal-frp-supervisor"]:
        from spearmint.frp_runtime import supervise
        raise SystemExit(supervise(*sys.argv[2:]))
    if sys.argv[1:2] == ["--version"]:
        from importlib.metadata import version
        print("Spearmint " + version("spearmint-panel"))
        raise SystemExit(0)
    if sys.argv[1:2] == ["--verify-package"]:
        from spearmint.package_files import verify_command
        raise SystemExit(verify_command(Path(sys.executable), sys.argv[2:]))
    if sys.argv[1:2] == ["mesh"]:
        sys.argv.pop(1)
        from spearmint.peer.workstation import main
    else:
        from spearmint.cli import main
    raise SystemExit(main())
