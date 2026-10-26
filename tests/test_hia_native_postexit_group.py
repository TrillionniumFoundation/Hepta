"""Linux native DSO fork-after-return cleanup regression for HIA differential.

This test uses actual Clang/GCC native shared libraries and the real
hepta.hia_native_differential worker. It does not run a Hepta compiler
and is not a sandbox or native Core/backend-refinement qualification.
"""
from __future__ import annotations

import json
import os
import platform
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from hepta.hia_native_differential import (
    HIADifferentialRejected, _observe_native, _pin_native_artifact,
)


@unittest.skipUnless(
    platform.system() == "Linux"
    and platform.machine().lower() in {"x86_64", "amd64"}
    and hasattr(os, "memfd_create")
    and (shutil.which("clang") or shutil.which("cc")),
    "Linux x86-64 memfd + native C compiler required; NOT QUALIFIED",
)
class HIANativePostExitGroupTests(unittest.TestCase):
    def _compile(self, directory: Path, source: str) -> Path:
        path = directory / "worker.c"
        library = directory / "worker.so"
        path.write_text(source, encoding="utf-8")
        cc = shutil.which("clang") or shutil.which("cc")
        subprocess.run([cc, "-shared", "-fPIC", "-O0", str(path), "-o", str(library)],
                       check=True, capture_output=True, timeout=30)
        return library

    def _run(self, library: Path, function: str, *, timeout: float = 2.0):
        _, _, fd = _pin_native_artifact(library)
        try:
            return _observe_native(library, function, "i32", [],
                                   timeout=timeout, pinned_fd=fd)
        finally:
            os.close(fd)

    def test_ordinary_worker_and_true_abort_preserve_observations(self):
        with tempfile.TemporaryDirectory() as td:
            library = self._compile(Path(td), """
                #include <stdlib.h>
                int healthy(void) { return 7; }
                int trapping(void) { abort(); }
            """)
            self.assertEqual(self._run(library, "healthy"), ("value", 7))
            self.assertEqual(self._run(library, "trapping"), ("trap", None))

    def test_successful_parent_with_lingering_fork_is_rejected_and_killed(self):
        with tempfile.TemporaryDirectory() as td:
            marker = Path(td) / "fork_survived"
            library = self._compile(Path(td), f"""
                #include <unistd.h>
                #include <fcntl.h>
                #include <sys/types.h>
                int spawn(void) {{
                    pid_t child = fork();
                    if (child < 0) return -1;
                    if (child == 0) {{
                        usleep(800000);
                        int fd = open({json.dumps(str(marker))}, O_WRONLY | O_CREAT | O_EXCL, 0600);
                        if (fd >= 0) {{ write(fd, "x", 1); close(fd); }}
                        _exit(0);
                    }}
                    return 7;
                }}
            """)
            with self.assertRaisesRegex(HIADifferentialRejected,
                                        "surviving in-group descendants"):
                self._run(library, "spawn")
            time.sleep(1.15)
            self.assertFalse(marker.exists(), "native fork escaped post-exit cleanup")

    def test_timeout_terminates_worker_and_its_descendants(self):
        with tempfile.TemporaryDirectory() as td:
            marker = Path(td) / "timeout_survived"
            library = self._compile(Path(td), f"""
                #include <unistd.h>
                #include <fcntl.h>
                #include <sys/types.h>
                int stall(void) {{
                    pid_t child = fork();
                    if (child < 0) return -1;
                    if (child == 0) {{
                        usleep(850000);
                        int fd = open({json.dumps(str(marker))}, O_WRONLY | O_CREAT | O_EXCL, 0600);
                        if (fd >= 0) {{ write(fd, "x", 1); close(fd); }}
                        _exit(0);
                    }}
                    sleep(3);
                    return 7;
                }}
            """)
            with self.assertRaisesRegex(HIADifferentialRejected, "timed out"):
                self._run(library, "stall", timeout=0.35)
            time.sleep(1.1)
            self.assertFalse(marker.exists(), "native fork escaped timeout cleanup")


    def test_direct_worker_reap_wait_has_an_explicit_deadline(self):
        # A native thread stuck in uninterruptible kernel sleep may not
        # reap promptly even after the group receives SIGKILL. Never
        # introduce an unbounded parent wait after the policy deadline.
        with tempfile.TemporaryDirectory() as td:
            library = self._compile(Path(td), """
                int healthy(void) { return 7; }
            """)
            actual_wait = subprocess.Popen.wait
            deadlines = []

            def timed_reap(proc, *args, **kwargs):
                deadlines.append(kwargs.get("timeout"))
                if type(kwargs.get("timeout")) not in (int, float) or not (
                        0 < kwargs["timeout"] <= 2):
                    self.fail("unbounded worker reap may stall the evaluator")
                return actual_wait(proc, *args, **kwargs)

            with patch.object(subprocess.Popen, "wait", timed_reap):
                self.assertEqual(self._run(library, "healthy"), ("value", 7))
            self.assertTrue(deadlines)


if __name__ == "__main__":
    unittest.main()
