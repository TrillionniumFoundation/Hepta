"""Finite HIA native-worker side-effect refusal, checked with real Clang DSOs.

This is a Linux x86-64 seccomp transport regression, NOT a claim that
arbitrary untrusted C/C++ is safely sandboxed or that LLVM is proved correct.
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
import unittest

from hepta import hia_native_differential as differential

_SUPPORTED = (
    platform.system() == "Linux"
    and platform.machine().lower() in {"x86_64", "amd64"}
    and hasattr(os, "memfd_create")
    and shutil.which("clang") is not None
    and hasattr(signal, "SIGSYS")
)


@unittest.skipUnless(_SUPPORTED, "requires Linux x86-64/Clang/seccomp; skip is NOT a pass")
class HIANativeSideEffectSeccomp(unittest.TestCase):
    def compile(self, root: Path, name: str, code: str) -> Path:
        src = root / (name + ".c")
        so = root / (name + ".so")
        src.write_text(code, encoding="utf-8")
        subprocess.run(
            ["clang", "-O0", "-shared", "-fPIC", str(src), "-o", str(so)],
            capture_output=True, check=True, timeout=30
        )
        return so

    def observe(self, so: Path, symbol: str):
        original, identity, fd = differential._pin_native_artifact(so)
        try:
            differential._check_artifact_unchanged(so, original, identity)
            return differential._observe_native(
                so, symbol, "i32", [], timeout=4, pinned_fd=fd
            )
        finally:
            os.close(fd)

    def assert_syscall_refused(self, so: Path, symbol: str):
        with self.subTest(symbol=symbol):
            with self.assertRaisesRegex(
                differential.HIADifferentialRejected,
                r"unexpected error/signal " + str(-signal.SIGSYS),
            ):
                self.observe(so, symbol)

    def test_read_only_load_self_abort_and_self_tgkill_remain_valid(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            readable = root / "readable"
            readable.write_bytes(b"read-only admission")
            so = self.compile(root, "allowed", r"""
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
int healthy(void) { return 7; }
int read_only(void) {
    int fd = open(""" + json.dumps(str(readable)) + r""", O_RDONLY);
    if (fd < 0) return -1;
    close(fd);
    return 7;
}
int self_tgkill_zero(void) {
    syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), 0);
    return 7;
}
int aborting(void) { abort(); }
""")
            for symbol in ("healthy", "read_only", "self_tgkill_zero"):
                with self.subTest(symbol=symbol):
                    self.assertEqual(self.observe(so, symbol), ("value", 7))
            self.assertEqual(self.observe(so, "aborting"), ("trap", None))
            self.assertEqual(readable.read_bytes(), b"read-only admission")

    def test_write_open_openat_mutation_socket_and_signals_are_sigsys(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            marker = root / "must_not_change"
            marker.write_bytes(b"original")
            so = self.compile(root, "forbidden", r"""
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
int write_open(void) {
    int fd = open(""" + json.dumps(str(marker)) + r""", O_CREAT|O_WRONLY|O_TRUNC, 0600);
    if (fd >= 0) close(fd);
    return 7;
}
int write_openat(void) {
    syscall(SYS_openat, AT_FDCWD, """ + json.dumps(str(marker)) + r""",
            O_CREAT|O_RDWR|O_TRUNC, 0600);
    return 7;
}
int unlink_file(void) {
    unlink(""" + json.dumps(str(marker)) + r""");
    return 7;
}
int socket_create(void) {
    socket(AF_INET, SOCK_STREAM, 0);
    return 7;
}
int foreign_tgkill(void) {
    syscall(SYS_tgkill, 1, 1, 0);
    return 7;
}
int foreign_kill(void) {
    syscall(SYS_kill, 1, 0);
    return 7;
}
int memfd_create_direct(void) {
    syscall(SYS_memfd_create, "unsealed", 0);
    return 7;
}
int openat2_direct(void) {
    syscall(437, AT_FDCWD, "/etc/hosts", 0, 0);
    return 7;
}
int ftruncate_direct(void) {
    syscall(SYS_ftruncate, 1, 0);
    return 7;
}
""")
            for symbol in (
                "write_open", "write_openat", "unlink_file",
                "socket_create", "foreign_tgkill", "foreign_kill",
                "memfd_create_direct", "openat2_direct", "ftruncate_direct",
            ):
                self.assert_syscall_refused(so, symbol)
                self.assertEqual(marker.read_bytes(), b"original")

    def test_pre_dlopen_elf_constructor_must_not_write_before_admission(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            marker = root / "constructor_marker"
            so = self.compile(root, "constructor", r"""
#include <fcntl.h>
#include <unistd.h>
__attribute__((constructor))
static void side_effect(void) {
    int fd = open(""" + json.dumps(str(marker)) + r""",
                  O_CREAT|O_WRONLY|O_TRUNC, 0600);
    if (fd >= 0) close(fd);
}
int healthy(void) { return 7; }
""")
            self.assert_syscall_refused(so, "healthy")
            self.assertFalse(marker.exists())

    def test_filter_is_installed_before_ctypes_loader(self):
        worker = differential._WORKER
        self.assertEqual(worker.count("_libc.prctl(22, 2,"), 1)
        self.assertLess(
            worker.index("_rules.append((0x06, 0, 0, 0x7FFF0000))"),
            worker.index("_libc.prctl(22, 2,")
        )
        self.assertLess(worker.index("_libc.prctl(22, 2,"), worker.index("getattr(ctypes.CDLL(lib), symbol)"))
        self.assertIn("_WRITE_OPEN_FLAGS = 0x400643", worker)
        self.assertIn("(2, 24), (257, 32)", worker)
        self.assertIn("self_pid", worker)
        self.assertIn("self_tid", worker)


if __name__ == "__main__":
    unittest.main()
