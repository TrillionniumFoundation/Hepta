"""Native HIA oracle: self-only tgkill and extended mutation syscall denials.

All actual observations use the existing sealed-memfd and bounded native child.
This does not qualify the compiler's source/Core/LLVM refinement.
"""
from __future__ import annotations

import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import tempfile
import unittest

from hepta import hia_native_differential as differential

_SUPPORTED = (
    platform.system() == "Linux"
    and platform.machine().lower() in {"x86_64", "amd64"}
    and hasattr(os, "memfd_create")
    and hasattr(signal, "SIGSYS")
    and shutil.which("clang") is not None
)


@unittest.skipUnless(_SUPPORTED, "requires Linux x86-64 seccomp + Clang; skip != pass")
class HIANativeSelfSignalTests(unittest.TestCase):
    def build(self, root: Path, source: str) -> Path:
        c_file, so = root / "signal_guard.c", root / "signal_guard.so"
        c_file.write_text(source, encoding="utf-8")
        subprocess.run(
            ["clang", "-O0", "-shared", "-fPIC", str(c_file), "-o", str(so)],
            capture_output=True, check=True, timeout=30
        )
        return so

    def observe(self, so: Path, symbol: str):
        original, identity, fd = differential._pin_native_artifact(so)
        try:
            differential._check_artifact_unchanged(so, original, identity)
            return differential._observe_native(
                so, symbol, "i32", [], timeout=4.0, pinned_fd=fd
            )
        finally:
            os.close(fd)

    def test_only_own_sigabrt_preserves_abort_and_all_zero_or_foreign_signals_reject(self):
        with tempfile.TemporaryDirectory() as td:
            so = self.build(Path(td), r"""
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
int healthy(void) { return 7; }
int aborting(void) { abort(); }
int self_tgkill(void) {
    syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), 0);
    return 7;
}
int external_tgkill(void) {
    syscall(SYS_tgkill, 1, 1, 0);
    return 7;
}
int wrong_tid(void) {
    syscall(SYS_tgkill, getpid(), syscall(SYS_gettid) + 1, 0);
    return 7;
}
""")
            self.assertEqual(self.observe(so, "healthy"), ("value", 7))
            self.assertEqual(self.observe(so, "aborting"), ("trap", None))
            for symbol in ("self_tgkill", "external_tgkill", "wrong_tid"):
                with self.subTest(symbol=symbol):
                    with self.assertRaisesRegex(
                        differential.HIADifferentialRejected,
                        "unexpected error/signal " + str(-signal.SIGSYS),
                    ):
                        self.observe(so, symbol)

    def test_kernel_mutation_syscalls_are_not_available_in_native_oracle(self):
        with tempfile.TemporaryDirectory() as td:
            so = self.build(Path(td), r"""
#include <unistd.h>
#include <sys/syscall.h>
int make_memfd(void) {
    syscall(SYS_memfd_create, "attacker", 0);
    return 7;
}
int filesystem_xattr(void) {
    syscall(190, 1, "user.bad", "payload", 7, 0); /* fsetxattr */
    return 7;
}
int modify_mount(void) {
    syscall(165, (void*)0, (void*)0, (void*)0, 0, (void*)0);
    return 7;
}
int io_uring_after_filter(void) {
    syscall(426, -1, 0, 0, (void*)0, 0, (void*)0);
    return 7;
}
""")
            for symbol in (
                "make_memfd", "filesystem_xattr",
                "modify_mount", "io_uring_after_filter",
            ):
                with self.subTest(symbol=symbol):
                    with self.assertRaisesRegex(
                        differential.HIADifferentialRejected,
                        "unexpected error/signal " + str(-signal.SIGSYS),
                    ):
                        self.observe(so, symbol)

    def test_upstream_read_only_and_stdin_controls_not_rolled_back(self):
        worker = differential._WORKER
        self.assertIn("stdin=subprocess.DEVNULL",
                      __import__("inspect").getsource(differential._observe_native))
        self.assertIn("_WRITE_OPEN_FLAGS = 0x3 | 0x40 | 0x200 | 0x400 | 0x400000", worker)
        self.assertIn("_worker_pid = os.getpid()", worker)
        self.assertIn("_worker_tid = _libc.syscall(186)", worker)
        self.assertIn("(0x15, 1, 0, 6)", worker)
        self.assertLess(worker.index("_worker_pid = os.getpid()"),
                        worker.index("_libc.prctl(22, 2,"))


if __name__ == "__main__":
    unittest.main()
