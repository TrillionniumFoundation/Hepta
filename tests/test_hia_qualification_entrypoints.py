"""Start real qualification CLIs without importing the checkout in the child.

Only help and required-argument failures are exercised: these subprocesses do
not execute native qualification, toolchain installation, or performance work.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest



ROOT = Path(__file__).resolve().parents[1]




class QualificationEntrypointTests(unittest.TestCase):
    def run_cli(self, args, cwd, *, pythonpath=""):
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1",
                           PYTHONNOUSERSITE="1")
        if pythonpath is None:
            environment.pop("PYTHONPATH", None)
        else:
            environment["PYTHONPATH"] = pythonpath
        return subprocess.run([sys.executable, *map(str, args)], cwd=cwd,
                              env=environment, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=15)

    def assert_help(self, run):
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn("usage:", run.stdout)
        self.assertNotIn("Traceback", run.stdout + run.stderr)



    def test_local_views_reaches_argparse_from_both_working_directories(self):
        script = ROOT / "tools" / "qualify_llvm_local_views.py"
        with tempfile.TemporaryDirectory(prefix="hepta local views CLI ") as directory:
            for cwd in (ROOT, Path(directory)):
                for pythonpath in (None, ""):
                    with self.subTest(cwd=str(cwd), pythonpath=pythonpath):
                        self.assert_help(self.run_cli([script, "--help"], cwd,
                                                      pythonpath=pythonpath))
                        missing = self.run_cli([script], cwd, pythonpath=pythonpath)
                        self.assertEqual(missing.returncode, 2, missing.stdout + missing.stderr)
                        self.assertIn("required", missing.stderr)
                        self.assertIn("--output", missing.stderr)
                        self.assertNotIn("Traceback", missing.stdout + missing.stderr)
            self.assertEqual(list(Path(directory).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
