"""Adversarial Clang wrapper child-process termination regressions (POSIX only).

These tests cover children that remain in the compiler's own process group.
They do not certify a full cgroup, container or detached-daemon sandbox.
"""
from __future__ import annotations

import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time
import unittest

from tools.c2hepta import UnsupportedC, _run_bounded_ast


@unittest.skipUnless(os.name == "posix", "POSIX process-group contract")
class ClangProcessGroupTermination(unittest.TestCase):
    def _check_descendant(self, *, overflow: bool) -> None:
        with tempfile.TemporaryDirectory(prefix="hepta-clang-process-group-") as temp:
            root = Path(temp)
            ready = root / "child-ready"
            release = root / "release"
            survived = root / "child-survived"
            # The shell stays in the same process group as its compiler wrapper.
            # It can write only after the parent was terminated and the fixture
            # releases its barrier. This distinguishes kill(parent) from killpg.
            shell = (
                f"printf ready > {shlex.quote(str(ready))}; "
                f"while [ ! -e {shlex.quote(str(release))} ]; do sleep 0.05; done; "
                f"printf survived > {shlex.quote(str(survived))}"
            )
            wrapper = (
                "import pathlib, subprocess, sys, time\n"
                f"subprocess.Popen(['/bin/sh', '-c', {shell!r}], "
                "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
                "stderr=subprocess.DEVNULL)\n"
                "deadline = time.monotonic() + 3\n"
                f"while not pathlib.Path({str(ready)!r}).exists() and time.monotonic() < deadline:\n"
                "    time.sleep(0.01)\n"
                + (
                    "sys.stdout.buffer.write(b'x' * 131072)\n"
                    "sys.stdout.buffer.flush()\n"
                    "time.sleep(60)\n"
                    if overflow else "time.sleep(60)\n"
                )
            )
            try:
                if overflow:
                    with self.assertRaisesRegex(UnsupportedC, "probe output exceeds"):
                        _run_bounded_ast(
                            [sys.executable, "-c", wrapper],
                            context="probe", max_stdout_bytes=64, timeout=5,
                        )
                else:
                    with self.assertRaises(subprocess.TimeoutExpired):
                        _run_bounded_ast(
                            [sys.executable, "-c", wrapper],
                            context="probe", max_stdout_bytes=64, timeout=3,
                        )
                self.assertTrue(ready.is_file(), "compiler child never initialized")
            finally:
                # Release any leaked child so the regression fails without
                # leaving a waiting shell behind on a broken implementation.
                release.touch()
                time.sleep(0.6)
            self.assertFalse(survived.exists(), "compiler descendant survived termination")

    def test_stdout_overflow_kills_compiler_descendants(self):
        self._check_descendant(overflow=True)

    def test_timeout_kills_compiler_descendants(self):
        self._check_descendant(overflow=False)

    def test_normal_short_output_is_preserved(self):
        result = _run_bounded_ast(
            [sys.executable, "-c", "print('ok')"],
            context="probe", max_stdout_bytes=64, timeout=5,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), b"ok")


if __name__ == "__main__":
    unittest.main()
