"""Kernel pre-dlopen fork/clone/session refusal for HIA finite native oracle.

Actual Linux x86-64 shared objects are compiled and executed via the original
sealed-memfd /proc/self/fd observer. This qualifies only the local native
transport policy, not whole-language safety or compiler/LLVM refinement.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from hepta import hia_native_differential as differential

_SUPPORTED = (platform.system() == "Linux"
              and platform.machine().lower() in {"x86_64", "amd64"}
              and hasattr(os, "memfd_create")
              and shutil.which("clang") is not None
              and hasattr(signal, "SIGSYS"))


@unittest.skipUnless(_SUPPORTED, "requires native Linux x86-64 seccomp and Clang")
class HIANativeSeccompTests(unittest.TestCase):
    def compile(self, root: Path, name: str, source: str) -> Path:
        original = root / (name + ".c")
        library = root / (name + ".so")
        original.write_text(source, encoding="utf-8")
        subprocess.run(["clang", "-O0", "-shared", "-fPIC",
                        str(original), "-o", str(library)],
                       check=True, capture_output=True, timeout=30)
        return library

    def observe(self, library: Path, symbol: str, *, timeout=3.0):
        original, identity, fd = differential._pin_native_artifact(library)
        try:
            differential._check_artifact_unchanged(library, original, identity)
            return differential._observe_native(
                library, symbol, "i32", [], timeout=timeout, pinned_fd=fd)
        finally:
            os.close(fd)

    def test_healthy_return_abort_and_nonfork_timeout_keep_their_semantics(self):
        with tempfile.TemporaryDirectory() as td:
            library = self.compile(Path(td), "healthy", r"""
#include <stdlib.h>
#include <unistd.h>
int healthy(void) { return 7; }
int aborting(void) { abort(); }
int stall(void) { sleep(3); return 7; }
""")
            self.assertEqual(self.observe(library, "healthy"), ("value", 7))
            self.assertEqual(self.observe(library, "aborting"), ("trap", None))
            with self.assertRaisesRegex(differential.HIADifferentialRejected, "timed out"):
                self.observe(library, "stall", timeout=0.2)

    def test_fork_escape_clone3_setsid_and_x32_denied_before_native_effect(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            marker = root / "escaped_session_marker"
            library = self.compile(root, "escapes", r"""
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/types.h>
int fork_escape(void) {
    pid_t p = fork();
    if (p == 0) {
        setsid(); usleep(700000);
        int fd = open(""" + json.dumps(str(marker)) + r""", O_WRONLY|O_CREAT|O_EXCL, 0600);
        if (fd >= 0) { write(fd, "X", 1); close(fd); }
        _exit(0);
    }
    return 7;
}
int clone3_direct(void) { syscall(435, 0, 0); return 7; }
int setsid_direct(void) { setsid(); return 7; }
int x32_fork_direct(void) { syscall(0x40000000UL | 57UL); return 7; }
""")
            for fn in ("fork_escape", "clone3_direct", "setsid_direct", "x32_fork_direct"):
                with self.subTest(fn=fn):
                    with self.assertRaisesRegex(
                            differential.HIADifferentialRejected,
                            "unexpected error/signal " + str(-signal.SIGSYS)):
                        self.observe(library, fn)
            time.sleep(0.85)
            self.assertFalse(marker.exists(), "escaped native fork wrote outside worker group")

    def test_elf_constructor_runs_only_after_seccomp_is_installed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            marker = root / "constructor_escape"
            library = self.compile(root, "initializer", r"""
#include <unistd.h>
#include <fcntl.h>
__attribute__((constructor))
static void escape(void) {
    pid_t p = fork();
    if (p == 0) {
        setsid(); usleep(700000);
        int fd = open(""" + json.dumps(str(marker)) + r""", O_WRONLY|O_CREAT|O_EXCL, 0600);
        if (fd >= 0) close(fd);
        _exit(0);
    }
}
int healthy(void) { return 7; }
""")
            with self.assertRaisesRegex(
                    differential.HIADifferentialRejected,
                    "unexpected error/signal " + str(-signal.SIGSYS)):
                self.observe(library, "healthy")
            time.sleep(0.85)
            self.assertFalse(marker.exists())

    def test_filter_unavailable_fails_closed_not_fallback_to_unrestricted_native(self):
        with tempfile.TemporaryDirectory() as td:
            library = self.compile(Path(td), "require_filter", """
int healthy(void) { return 7; }
""")
            real = differential._WORKER
            self.assertEqual(real.count("_libc.prctl(22, 2,"), 1)
            unsupported = real.replace("_libc.prctl(22, 2,", "_libc.prctl(22, 999,")
            with patch.object(differential, "_WORKER", unsupported):
                with self.assertRaisesRegex(
                        differential.HIADifferentialRejected, "unexpected error/signal"):
                    self.observe(library, "healthy")


if __name__ == "__main__":
    unittest.main()
