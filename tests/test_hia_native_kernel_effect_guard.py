"""P7 native oracle: forbid cross-process kernel IPC, scheduler and FD effects.

Runs actual Clang DSOs through the original sealed-memfd seccomp observer.
A shadow policy simulation or source-only string assertion is NOT sufficient.
This finite oracle remains deliberately distinct from a hostile-code sandbox.
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

# Linux x86-64 syscall numbers from asm/unistd_64.h, grouped by side effect.
_SYSV = (29, 30, 31, 64, 65, 66, 67, 68, 69, 70, 71, 220)
_KEYS = (248, 249, 250)
_SCHEDULER = (141, 142, 144, 203, 251, 314)
_FD_DUPLICATION = (32, 33, 72, 292)
_ALL = _SYSV + _KEYS + _SCHEDULER + _FD_DUPLICATION
assert len(_ALL) == len(set(_ALL))


@unittest.skipUnless(
    _SUPPORTED, "requires Linux x86-64, Clang, memfd and actual seccomp"
)
class HIANativeKernelEffectFilterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._temp = tempfile.TemporaryDirectory(prefix="hia-kernel-effects-")
        cls.addClassCleanup(cls._temp.cleanup)
        root = Path(cls._temp.name)
        c_path = root / "probe.c"
        cls.library = root / "probe.so"
        # Every attempted syscall has invalid arguments, avoiding side effects
        # even on a mistakenly unfiltered worker. The return value is always
        # 7, so the only acceptable refusal is kernel SIGSYS before return.
        body = [
            "#include <unistd.h>",
            "#include <fcntl.h>",
            "#include <stdlib.h>",
            "#include <sys/syscall.h>",
            "int healthy(void) { return 7; }",
            "int aborting(void) { abort(); }",
            "int readonly(void) {",
            '  int fd = open("/proc/self/status", O_RDONLY);',
            "  if (fd < 0) return 8;",
            "  char c; int ok = read(fd, &c, 1) == 1;",
            "  close(fd); return ok ? 7 : 9;",
            "}",
        ]
        for nr in _ALL:
            body.append(
                f"int probe_{nr}(void) {{ "
                f"(void)syscall({nr}L, -1L, -1L, -1L, -1L, -1L, -1L); "
                "return 7; }"
            )
        c_path.write_text("\n".join(body) + "\n", encoding="utf-8")
        subprocess.run(
            ["clang", "-O0", "-shared", "-fPIC", str(c_path),
             "-o", str(cls.library)],
            capture_output=True, check=True, timeout=30,
        )

    def observe(self, name):
        original, identity, fd = differential._pin_native_artifact(self.library)
        try:
            differential._check_artifact_unchanged(
                self.library, original, identity
            )
            return differential._observe_native(
                self.library, name, "i32", [], timeout=3.0,
                pinned_fd=fd,
            )
        finally:
            os.close(fd)

    def assert_seccomp_denies(self, numbers):
        for nr in numbers:
            with self.subTest(syscall_number=nr):
                with self.assertRaisesRegex(
                    differential.HIADifferentialRejected,
                    "unexpected error/signal " + str(-signal.SIGSYS),
                ):
                    self.observe(f"probe_{nr}")

    def test_normal_return_readonly_and_abort_still_work(self):
        self.assertEqual(self.observe("healthy"), ("value", 7))
        self.assertEqual(self.observe("readonly"), ("value", 7))
        self.assertEqual(self.observe("aborting"), ("trap", None))

    def test_sysv_ipc_calls_denied(self):
        self.assert_seccomp_denies(_SYSV)

    def test_keyring_operations_denied(self):
        self.assert_seccomp_denies(_KEYS)

    def test_scheduler_and_priority_mutations_denied(self):
        self.assert_seccomp_denies(_SCHEDULER)

    def test_descriptor_dup_and_fcntl_denied(self):
        self.assert_seccomp_denies(_FD_DUPLICATION)


if __name__ == "__main__":
    unittest.main()
