"""C migration must bound source reads at admission and identity recheck."""
from __future__ import annotations

import hashlib
import ctypes
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import c2hepta


class C2HeptaBoundedSource(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="hepta-c2hepta-bounded-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.source = self.root / "module.c"
        self.output = self.root / "module.hepta"
        self.report = self.root / "migration.json"

    def test_maximum_read_size_and_prefix_is_not_a_source_identity(self):
        # A sparse 32 MiB file represents an untrusted oversized input without
        # allocating it in the test process. The reader may retain <=256001 B.
        with self.source.open("wb") as handle:
            handle.truncate(32 * 1024 * 1024)
        self.assertEqual(len(c2hepta._read_bounded_source(self.source)),
                         c2hepta._MAX_SOURCE_BYTES + 1)
        with patch.object(Path, "read_bytes", side_effect=AssertionError("unbounded source read")):
            result = c2hepta.migrate(self.source, self.output, self.report,
                                     clang="/no/such/clang")
        self.assertEqual(result["status"], "rejected")
        self.assertIn("256 KB", result["reason"])
        self.assertIsNone(result["source_sha256"],
                          "digest of an incomplete prefix must never claim full source identity")
        self.assertFalse(self.output.exists())
        self.assertTrue(self.report.exists())

    def test_exact_boundary_has_full_digest(self):
        data = b" " * c2hepta._MAX_SOURCE_BYTES
        self.source.write_bytes(data)
        with patch.object(Path, "read_bytes", side_effect=AssertionError("unbounded source read")):
            result = c2hepta.migrate(self.source, self.output, self.report,
                                     clang="/no/such/clang")
        self.assertEqual(result["status"], "rejected")
        self.assertIn("clang executable unavailable", result["reason"])
        self.assertEqual(result["source_sha256"], hashlib.sha256(data).hexdigest())

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFO")
    def test_fifo_is_rejected_without_waiting_for_a_writer(self):
        os.mkfifo(self.source)
        with patch.object(Path, "read_bytes", side_effect=AssertionError("unbounded source read")):
            result = c2hepta.migrate(self.source, self.output, self.report)
        self.assertEqual(result["status"], "rejected")
        self.assertIn("regular file", result["reason"])
        self.assertFalse(self.output.exists())
        self.assertTrue(self.report.exists())

    @unittest.skipUnless(shutil.which("clang"), "Clang is needed for actual migration")
    def test_valid_conversion_uses_bounded_read_on_both_paths(self):
        self.source.write_text("int identity(int x) { return x; }\n", encoding="utf-8")
        with patch.object(Path, "read_bytes", side_effect=AssertionError("unbounded source read")):
            result = c2hepta.migrate(self.source, self.output, self.report)
        self.assertEqual(result["status"], "converted", result)
        self.assertTrue(self.output.exists())
        self.assertEqual(result["source_sha256"],
                         hashlib.sha256(self.source.read_bytes()).hexdigest())

    @unittest.skipUnless(shutil.which("clang"), "Clang is needed for source-race probe")
    def test_growth_before_identity_recheck_is_rejected(self):
        self.source.write_text("int identity(int x) { return x; }\n", encoding="utf-8")
        real_hash = c2hepta.function_hash

        def change_source(fn):
            digest = real_hash(fn)
            with self.source.open("wb") as handle:
                handle.truncate(32 * 1024 * 1024)
            return digest

        with patch.object(c2hepta, "function_hash", side_effect=change_source):
            with patch.object(Path, "read_bytes",
                              side_effect=AssertionError("unbounded source recheck")):
                result = c2hepta.migrate(self.source, self.output, self.report)
        self.assertEqual(result["status"], "rejected")
        self.assertIn("source changed during conversion", result["reason"])
        self.assertFalse(self.output.exists())

    def test_guarded_migration_executes_original_and_generated_native_code(self):
        # Exercise the real frontend and Rust compiler after guard admission;
        # checking only emitted source or original C would not test this route.
        from hepta.backend import compile_rust, find_rustc
        from hepta.pipeline import analyze

        self.assertTrue(shutil.which("gcc"), "GCC is required for native comparison")
        source = """int choose(int a, int b) {
            if (a >= b) { return a; } else { return b; }
        }
        int negate(int value) { return -value; }
        unsigned int mix(unsigned int a, unsigned int b) {
            return (a * b) + (a - b);
        }
        """
        self.source.write_text(source, encoding="utf-8")
        rustc = find_rustc()
        migrated = c2hepta.migrate(
            self.source, self.output, self.report, verify_native=True, rustc=rustc)
        self.assertEqual(migrated["status"], "converted", migrated)
        self.assertEqual(migrated["backend_validation"], "passed")
        checked = analyze(self.output.read_text(), str(self.output), rustc=rustc)
        self.assertTrue(checked.report["ok"], checked.report)
        target = compile_rust(checked.rust, rustc=rustc, crate_type="cdylib",
                              output=self.root / "generated.so")
        self.assertTrue(target["ok"], target)
        original = self.root / "original.so"
        built = subprocess.run([
            "gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC",
            str(self.source), "-o", str(original),
        ], capture_output=True, timeout=30)
        self.assertEqual(built.returncode, 0, built.stderr)
        libraries = [ctypes.CDLL(str(original)), ctypes.CDLL(target["artifact"])]
        for library in libraries:
            library.choose.argtypes = [ctypes.c_int32, ctypes.c_int32]
            library.choose.restype = ctypes.c_int32
            library.negate.argtypes = [ctypes.c_int32]
            library.negate.restype = ctypes.c_int32
            library.mix.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
            library.mix.restype = ctypes.c_uint32

        signed = (-2147483647, -17, 0, 19, 2147483647)
        unsigned = (0, 1, 255, 65535, 2**31, 2**32 - 1)
        pairs = 0
        for value in signed:
            self.assertEqual([lib.negate(value) for lib in libraries], [-value] * 2)
            pairs += 1
            for other in signed:
                self.assertEqual([lib.choose(value, other) for lib in libraries],
                                 [max(value, other)] * 2)
                pairs += 1
        for value in unsigned:
            for other in unsigned:
                expected = (value * other + value - other) % 2**32
                self.assertEqual([lib.mix(value, other) for lib in libraries],
                                 [expected] * 2)
                pairs += 1
        self.assertEqual(pairs, 66)

        # Compile and execute a deliberately wrong target to establish that
        # the native comparison can observe a value-changing implementation.
        self.assertIn(".wrapping_mul(", checked.rust)
        wrong = compile_rust(checked.rust.replace(".wrapping_mul(", ".wrapping_add(", 1),
                             rustc=rustc, crate_type="cdylib",
                             output=self.root / "wrong.so")
        self.assertTrue(wrong["ok"], wrong)
        wrong_library = ctypes.CDLL(wrong["artifact"])
        wrong_library.mix.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
        wrong_library.mix.restype = ctypes.c_uint32
        self.assertNotEqual(wrong_library.mix(3, 7), libraries[0].mix(3, 7))


if __name__ == "__main__":
    unittest.main()
