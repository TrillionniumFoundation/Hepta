"""Linux sealed-native artifact replay: byte identity, no-follow and bounded IO.

These are genuine shared-library subprocess controls, NOT a qualification of
the pinned Hepta LLVM or Rust source compiler.
"""
from __future__ import annotations

import os
import errno
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_native_differential import (
    HIADifferentialRejected, _pin_native_artifact,
    _check_artifact_unchanged, _observe_native,
    compare_oracle_with_native,
)


@unittest.skipUnless(platform.system() == "Linux" and hasattr(os, "memfd_create"),
                     "requires actual Linux memfd sealing")
class SealingCompatibilityTests(unittest.TestCase):
    def test_outer_exception_does_not_close_a_successfully_transferred_snapshot(self):
        # A caller can prepare fallback code while handling another failure.
        # sys.exc_info() then describes that outer exception, not a failure of
        # this successful pin operation; the returned descriptor stays owned.
        payload = b"snapshot acquired by an exception handler"
        with tempfile.TemporaryDirectory(prefix="hia-pin-exception-context-") as temporary:
            source = Path(temporary) / "snapshot.bin"
            source.write_bytes(payload)
            try:
                raise ValueError("unrelated caller failure")
            except ValueError:
                original, identity, descriptor = _pin_native_artifact(source)
                try:
                    self.assertEqual(os.pread(descriptor, len(payload), 0), payload)
                    self.assertEqual(original, payload)
                    _check_artifact_unchanged(source, original, identity)
                finally:
                    os.close(descriptor)

    def test_missing_python_constant_names_still_require_actual_kernel_seals(self):
        import fcntl
        payload = b"finite native snapshot bytes\x00\xff"
        with tempfile.TemporaryDirectory(prefix="hia-seal-compat-") as temporary:
            source = Path(temporary) / "snapshot.bin"
            source.write_bytes(payload)
            with patch.dict(fcntl.__dict__):
                for name in ("F_ADD_SEALS", "F_GET_SEALS", "F_SEAL_WRITE", "F_SEAL_GROW",
                             "F_SEAL_SHRINK", "F_SEAL_SEAL"):
                    fcntl.__dict__.pop(name, None)
                original, identity, descriptor = _pin_native_artifact(source)
                try:
                    self.assertEqual(original, payload)
                    self.assertEqual(fcntl.fcntl(descriptor, 1034), 0x000F)
                    self.assertEqual(os.pread(descriptor, len(payload) + 1, 0), payload)
                    for operation in (lambda: os.pwrite(descriptor, b"x", 0),
                                      lambda: os.ftruncate(descriptor, len(payload) - 1),
                                      lambda: os.ftruncate(descriptor, len(payload) + 1),
                                      lambda: fcntl.fcntl(descriptor, 1033, 0x0010)):
                        with self.subTest(operation=operation), self.assertRaises(OSError) as error:
                            operation()
                        self.assertEqual(error.exception.errno, errno.EPERM)
                    self.assertEqual(os.pread(descriptor, len(payload) + 1, 0), payload)
                    _check_artifact_unchanged(source, original, identity)
                finally:
                    os.close(descriptor)

    def test_real_kernel_seal_rejection_closes_fd_and_never_returns_unsealed_snapshot(self):
        import fcntl
        memfd_create = os.memfd_create
        descriptors = []
        def kernel_disallows_sealing(name, flags):
            # This actual kernel memfd starts with F_SEAL_SEAL; adding the
            # required write/grow/shrink seals must receive EPERM from Linux.
            descriptor = memfd_create(name, flags & ~os.MFD_ALLOW_SEALING)
            descriptors.append(descriptor)
            self.assertEqual(fcntl.fcntl(descriptor, 1034), 0x0001)
            return descriptor
        with tempfile.TemporaryDirectory(prefix="hia-seal-rejection-") as temporary:
            source = Path(temporary) / "snapshot.bin"
            source.write_bytes(b"kernel must reject unsealable snapshot")
            with patch("hepta.hia_native_differential.os.memfd_create", side_effect=kernel_disallows_sealing):
                with self.assertRaisesRegex(HIADifferentialRejected, "sealed executable snapshot unavailable") as error:
                    _pin_native_artifact(source)
            self.assertIsInstance(error.exception.__cause__, OSError)
            self.assertEqual(error.exception.__cause__.errno, errno.EPERM)
            self.assertEqual(len(descriptors), 1)
            with self.assertRaises(OSError) as closed:
                os.fstat(descriptors[0])
            self.assertEqual(closed.exception.errno, errno.EBADF)


@unittest.skipUnless(os.name == "posix" and shutil.which("clang") and
                     hasattr(os, "memfd_create"),
                     "requires Linux memfd sealing and native Clang")
class SealedNativeArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(prefix="hia-sealed-native-")
        cls.directory = Path(cls.work.name)
        cls.lib = cls.directory / "control.so"
        cls.old_source = cls.directory / "old.c"
        cls.old_source.write_text(
            '#include <stdint.h>\n'
            'uint32_t checked_add(uint32_t a,uint32_t b){ return a+b; }\n',
            encoding="utf-8")
        cls.new_source = cls.directory / "new.c"
        cls.new_source.write_text(
            '#include <stdint.h>\n'
            'uint32_t checked_add(uint32_t a,uint32_t b){ return 77; }\n',
            encoding="utf-8")
        cls.old_library = cls.directory / "old.so"
        cls.new_library = cls.directory / "new.so"
        for source, target in ((cls.old_source, cls.old_library),
                               (cls.new_source, cls.new_library)):
            subprocess.run(["clang", "-O2", "-shared", "-fPIC", str(source),
                            "-o", str(target)], check=True, timeout=30)
        cls.lib.write_bytes(cls.old_library.read_bytes())

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def setUp(self):
        self.lib.write_bytes(self.old_library.read_bytes())

    def test_native_loader_uses_sealed_original_bytes_after_path_swap(self):
        original, identity, fd = _pin_native_artifact(self.lib)
        try:
            self.assertEqual(
                _observe_native(self.lib, "checked_add", "u32", [5, 9],
                                timeout=2.0, pinned_fd=fd), ("value", 14))
            self.lib.write_bytes(self.new_library.read_bytes())
            self.assertEqual(
                _observe_native(self.lib, "checked_add", "u32", [5, 9],
                                timeout=2.0, pinned_fd=fd), ("value", 14))
            with self.assertRaisesRegex(HIADifferentialRejected, "changed"):
                _check_artifact_unchanged(self.lib, original, identity)
        finally:
            os.close(fd)

    def test_symlink_fifo_and_empty_are_refused_before_execution(self):
        link = self.directory / "swap-link.so"
        if link.exists() or link.is_symlink():
            link.unlink()
        link.symlink_to(self.lib)
        with self.assertRaises(HIADifferentialRejected):
            _pin_native_artifact(link)
        fifo = self.directory / "fake-native.fifo"
        if fifo.exists():
            fifo.unlink()
        os.mkfifo(fifo)
        with self.assertRaises(HIADifferentialRejected):
            _pin_native_artifact(fifo)
        empty = self.directory / "empty.so"
        empty.write_bytes(b"")
        with self.assertRaises(HIADifferentialRejected):
            _pin_native_artifact(empty)

    def test_finished_qualification_rejects_source_path_mutation(self):
        class Oracle:
            return_words = (("checked_add", "u32"),)
            def run(self, function, args, *, max_steps=20000):
                return sum(args)
        from unittest.mock import patch
        from hepta import hia_native_differential as diff
        old_observe = diff._observe_native
        def mutate(*args, **kwargs):
            self.lib.write_bytes(self.new_library.read_bytes())
            return old_observe(*args, **kwargs)
        with patch.object(diff, "_observe_native", side_effect=mutate):
            with self.assertRaisesRegex(HIADifferentialRejected, "changed"):
                compare_oracle_with_native(Oracle(), self.lib,
                                           {"checked_add": [[5, 9]]})
