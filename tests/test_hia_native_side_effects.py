"""P2 native finite-oracle side-effect refusal using the existing seccomp worker.

Real Clang DSOs exercise the original sealed-memfd _observe_native path.
These tests qualify only the finite transport on Linux x86-64; they do NOT
certify a hostile-code sandbox, HIA source/backend refinement, or C++ ABI.
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

from hepta import hia_native_differential as native

_SUPPORTED = (platform.system() == "Linux"
              and platform.machine().lower() in {"x86_64", "amd64"}
              and hasattr(os, "memfd_create")
              and hasattr(signal, "SIGSYS")
              and shutil.which("clang") is not None)


@unittest.skipUnless(_SUPPORTED, "requires Linux x86-64, native Clang and seccomp")
class NativeSideEffectRejectionTests(unittest.TestCase):
    def build(self, root, name, c):
        source, binary = root / (name + ".c"), root / (name + ".so")
        source.write_text(c, encoding="utf-8")
        subprocess.run(["clang", "-O0", "-fPIC", "-shared", str(source), "-o", str(binary)],
                       check=True, capture_output=True, timeout=30)
        return binary

    def observe(self, path, function):
        original, ident, descriptor = native._pin_native_artifact(path)
        try:
            native._check_artifact_unchanged(path, original, ident)
            return native._observe_native(
                path, function, "i32", [], timeout=3, pinned_fd=descriptor)
        finally:
            os.close(descriptor)

    def assert_sigsys(self, binary, function):
        with self.assertRaisesRegex(
                native.HIADifferentialRejected,
                "unexpected error/signal " + str(-signal.SIGSYS)):
            self.observe(binary, function)

    def test_read_only_dlopen_and_valid_abort_remain_observable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            readme = root / "readable_marker"
            readme.write_bytes(b"X")
            lib = self.build(root, "read_only", r"""
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
int healthy(void) { return 7; }
int aborting(void) { abort(); }
int readonly(void) {
  int fd = open(""" + json.dumps(str(readme)) + r""", O_RDONLY);
  if (fd < 0) return 8;
  char letter = 0;
  int result = read(fd, &letter, 1);
  close(fd);
  return result == 1 && letter == 'X' ? 7 : 9;
}
int readonly_dir(void) {
  int fd = open(""" + json.dumps(str(root)) + r""", O_RDONLY | O_DIRECTORY);
  if (fd < 0) return 8;
  close(fd);
  return 7;
}
""")
            self.assertEqual(self.observe(lib, "healthy"), ("value", 7))
            self.assertEqual(self.observe(lib, "readonly"), ("value", 7))
            self.assertEqual(self.observe(lib, "readonly_dir"), ("value", 7))
            self.assertEqual(self.observe(lib, "aborting"), ("trap", None))

    def test_file_creates_removes_and_openat2_reject_before_side_effect(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            marker, existing = root / "creation_denied", root / "must_stay"
            existing.write_bytes(b"X")
            lib = self.build(root, "mutations", r"""
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
int create_open(void) {
  int fd = open(""" + json.dumps(str(marker)) + r""", O_CREAT|O_EXCL|O_WRONLY, 0600);
  if (fd >= 0) close(fd);
  return 7;
}
int create_openat(void) {
  int fd = openat(AT_FDCWD, """ + json.dumps(str(marker)) + r""", O_CREAT|O_EXCL|O_WRONLY, 0600);
  if (fd >= 0) close(fd);
  return 7;
}
int remove_file(void) { unlink(""" + json.dumps(str(existing)) + r"""); return 7; }
int direct_openat2(void) { syscall(437, AT_FDCWD, 0, 0, 0); return 7; }
int direct_tmpfile(void) {
  syscall(SYS_openat, AT_FDCWD, """ + json.dumps(str(root)) + r""",
          0x410000 | O_RDWR, 0600);
  return 7;
}
""")
            for name in ("create_open", "create_openat", "remove_file",
                         "direct_openat2", "direct_tmpfile"):
                with self.subTest(case=name):
                    self.assert_sigsys(lib, name)
            self.assertFalse(marker.exists())
            self.assertEqual(existing.read_bytes(), b"X")

    def test_network_and_direct_signal_syscalls_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lib = self.build(root, "network", r"""
#include <unistd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
int socket_create(void) { socket(AF_INET, SOCK_DGRAM, 0); return 7; }
int socket_pair(void) { int fds[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, fds); return 7; }
int direct_send(void) { syscall(44, -1, 0, 0, 0, 0, 0); return 7; }
int direct_kill(void) { syscall(62, getppid(), 0); return 7; }
int tgkill_parent(void) { syscall(234, getppid(), getppid(), 0); return 7; }
int tgkill_self_wrong_signal(void) {
  syscall(234, getpid(), syscall(186), 10);
  return 7;
}
""")
            for name in ("socket_create", "socket_pair", "direct_send",
                         "direct_kill", "tgkill_parent", "tgkill_self_wrong_signal"):
                with self.subTest(case=name):
                    self.assert_sigsys(lib, name)

    def test_elf_constructor_file_mutation_rejected_before_function_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            marker = root / "constructor_should_not_create"
            lib = self.build(root, "constructor", r"""
#include <fcntl.h>
#include <unistd.h>
__attribute__((constructor)) static void constructor(void) {
  int fd = open(""" + json.dumps(str(marker)) + r""", O_CREAT|O_EXCL|O_WRONLY, 0600);
  if (fd >= 0) close(fd);
}
int healthy(void) { return 7; }
""")
            self.assert_sigsys(lib, "healthy")
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
