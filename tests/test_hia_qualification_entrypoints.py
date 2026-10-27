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

from tools.qualify_hia_unified import qualification_plan


ROOT = Path(__file__).resolve().parents[1]


def planned_producers(output):
    tools = {name: "/unused-entrypoint-probe/" + name for name in (
        "clang", "cc", "rustc", "cargo", "qemu_aarch64", "qemu_riscv64",
        "qemu_system_arm", "linker", "lean", "cxx",
    )}
    return [list(map(str, argv)) for _, argv, evidence in
            qualification_plan(output, python=sys.executable, **tools)
            if evidence is not None]


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

    def test_every_direct_producer_starts_outside_checkout_without_pythonpath(self):
        with tempfile.TemporaryDirectory(prefix="hepta CLI outside checkout ") as directory:
            producers = planned_producers(Path(directory) / "unused-output")
            scripts = sorted({argv[1] for argv in producers if argv[1] != "-m"})
            self.assertTrue(scripts)
            for script in scripts:
                with self.subTest(script=script):
                    self.assert_help(self.run_cli([ROOT / script, "--help"], directory))
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_module_producers_start_from_checkout_without_pythonpath(self):
        with tempfile.TemporaryDirectory() as directory:
            producers = planned_producers(Path(directory) / "unused-output")
            modules = sorted({argv[2] for argv in producers if argv[1] == "-m"})
            self.assertTrue(modules)
            for module in modules:
                with self.subTest(module=module):
                    self.assert_help(self.run_cli(["-m", module, "--help"], ROOT))

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
