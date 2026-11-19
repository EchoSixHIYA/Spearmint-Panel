from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts import build_package


class BuildCleanupTest(unittest.TestCase):
    def run_build(self, fail):
        task = Path(__file__).resolve().parents[1] / "work/tmp/build-cleanup-tests"
        task.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(dir=task) as directory:
            root = Path(directory)
            artifacts = root / "artifacts"
            artifacts.mkdir()
            existing = artifacts / "previous-package.tar.gz"
            existing.write_bytes(b"keep existing verified package")
            observed = []
            previous = sys.dont_write_bytecode

            def packager(work, env):
                observed.append(work)
                self.assertTrue(sys.dont_write_bytecode)
                self.assertEqual(env["PYTHONDONTWRITEBYTECODE"], "1")
                self.assertEqual(env["PIP_NO_CACHE_DIR"], "1")
                for name in ("PYINSTALLER_CONFIG_DIR", "TMPDIR", "TEMP", "TMP"):
                    path = Path(env[name])
                    self.assertTrue(path.is_relative_to(work))
                    path.mkdir(exist_ok=True)
                    (path / "build-cache").write_bytes(b"temporary native objects")
                if fail:
                    raise RuntimeError("packager failed after creating temporary files")
                (artifacts / "new-package.zip").write_bytes(b"final package")

            with patch.object(build_package, "WORK", root), \
                    patch.object(build_package, "build_package", side_effect=packager):
                if fail:
                    with self.assertRaisesRegex(RuntimeError, "packager failed"):
                        build_package.main()
                else:
                    build_package.main()
            self.assertEqual(sys.dont_write_bytecode, previous)
            self.assertEqual(len(observed), 1)
            self.assertFalse(observed[0].exists())
            self.assertEqual(list(root.iterdir()), [artifacts])
            self.assertEqual(existing.read_bytes(), b"keep existing verified package")
            if not fail:
                self.assertEqual((artifacts / "new-package.zip").read_bytes(), b"final package")

    def test_success_keeps_archives_and_removes_build_cache(self):
        self.run_build(fail=False)

    def test_failure_removes_build_cache_and_keeps_existing_archives(self):
        self.run_build(fail=True)


if __name__ == "__main__":
    unittest.main()
