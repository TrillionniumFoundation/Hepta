#!/usr/bin/env python3
"""Dry-run Makefile command routing; never execute project validation targets."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
# Keep an independent inventory: choosing Python must not change target scope.
COMMANDS = {
    "check": ("-m unittest discover -s tests -v",),
    "native": (
        "tools/validate.py --output artifacts/native-validation.json",
        "tools/abi_fuzz.py --output artifacts/abi-matrix.json",
    ),
    "bench": (
        "tools/validate.py --bench --output artifacts/native-validation.json",
        "tools/benchmark_suite.py --output artifacts/representative-benchmarks.json",
    ),
    "release": ("tools/release_check.py",),
    "examples": (
        "-m hepta run examples/parser.hepta",
        "-m hepta run examples/ownership.hepta",
        "-m hepta run examples/tasks.hepta",
        "-m hepta run examples/results.hepta",
        "-m hepta run examples/packages/app --locked",
    ),
    "groups": (
        "tools/validate_groups.py --repeats 3 --output evidence/groups/native_validation.json",
    ),
    "formal": ("tools/verify_formal.py",),
    "cross": ("tools/validate_cross.py",),
}


class MakefileInterpreterTests(unittest.TestCase):
    def dry_run(self, targets=(), *, assignment=None, environment=None):
        make = shutil.which("make")
        self.assertIsNotNone(make, "GNU make is required for this isolated dry-run check")
        env = dict(os.environ)
        # Do not inherit unrelated make options or a developer's interpreter.
        for key in ("PYTHON", "MAKEFLAGS", "MFLAGS", "GNUMAKEFLAGS", "MAKEFILES", "MAKELEVEL"):
            env.pop(key, None)
        env.update(environment or {})
        command = [make, "--no-print-directory", "-rR", "-n"]
        if assignment is not None:
            command.append("PYTHON=" + assignment)
        command.extend(targets)
        # Only the Makefile exists here. No compiler source, tests, fixtures or
        # evidence directories are copied, imported, or executed.
        with tempfile.TemporaryDirectory(prefix="hepta-make-dry-run-") as temporary:
            directory = Path(temporary)
            (directory / "Makefile").write_bytes((ROOT / "Makefile").read_bytes())
            result = subprocess.run(command, cwd=directory, env=env,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stderr, "")
            self.assertEqual(sorted(p.name for p in directory.iterdir()), ["Makefile"])
        return result.stdout.splitlines()

    def expected(self, interpreter, targets=None):
        return [interpreter + " " + arguments
                for target in (targets or COMMANDS)
                for arguments in COMMANDS[target]]

    def test_default_target_and_interpreter_are_unchanged(self):
        self.assertEqual(self.dry_run(), self.expected("python", ("check",)))
        self.assertEqual(self.dry_run(COMMANDS), self.expected("python"))

    def test_command_line_selection_reaches_every_target(self):
        selected = "/nonexistent/selected-python3.11"
        self.assertEqual(self.dry_run(COMMANDS, assignment=selected), self.expected(selected))

    def test_environment_selection_reaches_every_target(self):
        selected = "/nonexistent/environment-python3.13"
        self.assertEqual(self.dry_run(COMMANDS, environment={"PYTHON": selected}),
                         self.expected(selected))

    def test_command_line_selection_overrides_environment(self):
        selected = "/nonexistent/command-line-python"
        self.assertEqual(self.dry_run(COMMANDS, assignment=selected,
                                     environment={"PYTHON": "/nonexistent/environment-python"}),
                         self.expected(selected))

    def test_interpreter_options_are_preserved(self):
        selected = "python3.11 -B"
        self.assertEqual(self.dry_run(COMMANDS, assignment=selected), self.expected(selected))


if __name__ == "__main__":
    unittest.main(verbosity=2)
