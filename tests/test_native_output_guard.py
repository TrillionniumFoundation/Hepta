"""Real file and Clang output gates for P5/P7 resource-safe native artifacts."""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.native_output_guard import NativeOutputRejected, digest_regular_binary, read_native_artifact


class NativeArtifactBudgetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_exact_size_boundary_and_streamed_compiler_digest(self):
        obj = self.root / "valid.o"
        obj.write_bytes(b"native" * 17)
        self.assertEqual(read_native_artifact(obj, max_bytes=102), obj.read_bytes())
        self.assertEqual(digest_regular_binary(obj, max_bytes=102), sha256(obj.read_bytes()).hexdigest())
        with self.assertRaisesRegex(NativeOutputRejected, "SIZE"):
            read_native_artifact(obj, max_bytes=101)
        with self.assertRaisesRegex(NativeOutputRejected, "SIZE"):
            digest_regular_binary(obj, max_bytes=101)

    def test_path_and_type_rejections(self):
        valid = self.root / "valid.o"
        valid.write_bytes(b"binary")
        symlink = self.root / "alias.o"
        symlink.symlink_to(valid)
        missing = self.root / "missing.o"
        dangling = self.root / "dangling.o"
        dangling.symlink_to(missing)
        empty = self.root / "empty.o"
        empty.touch()
        for path, kind in ((symlink, "PATH"), (dangling, "PATH"),
                           (self.root, "PATH"), (missing, "PATH"),
                           (empty, "SIZE")):
            with self.subTest(path=path):
                with self.assertRaisesRegex(NativeOutputRejected, kind):
                    read_native_artifact(path)
                with self.assertRaisesRegex(NativeOutputRejected, kind):
                    digest_regular_binary(path)

    def test_sparse_oversize_compiler_output_rejected_before_memory_read(self):
        oversized = self.root / "oversized.o"
        with oversized.open("wb") as stream:
            stream.truncate(64 * 1024 * 1024 + 1)
        with self.assertRaisesRegex(NativeOutputRejected, "SIZE"):
            read_native_artifact(oversized)
        with self.assertRaisesRegex(NativeOutputRejected, "SIZE"):
            digest_regular_binary(oversized, max_bytes=64 * 1024 * 1024)

    def test_named_pipe_cannot_block_guard(self):
        import os
        if not hasattr(os, "mkfifo"):
            self.skipTest("POSIX FIFO only")
        fifo = self.root / "stdout.fifo"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(NativeOutputRejected, "PATH"):
            read_native_artifact(fifo)

    def test_size_budget_validation_precedes_file_access(self):
        for budget in (False, True, 0, -1, 1.5, "100", 2**64):
            with self.subTest(budget=budget):
                with self.assertRaisesRegex(NativeOutputRejected, "BUDGET"):
                    read_native_artifact(self.root / "missing", max_bytes=budget)

    @unittest.skipUnless(shutil.which("clang"), "Real Clang required")
    def test_real_cross_target_objects_stay_bounded(self):
        source = self.root / "cross.ll"
        source.write_text("define i32 @hepta_guard(i32 %x) {\nentry:\n %v = add i32 %x, 1\n ret i32 %v\n}\n")
        for target, signature in (
            ("x86_64-unknown-linux-gnu", b"\x7fELF"),
            ("aarch64-unknown-linux-gnu", b"\x7fELF"),
            ("x86_64-pc-windows-msvc", b"\x64\x86"),
            ("x86_64-apple-darwin", b"\xcf\xfa\xed\xfe"),
            ("aarch64-apple-darwin", b"\xcf\xfa\xed\xfe"),
        ):
            with self.subTest(target=target):
                native = self.root / (target + ".o")
                run = subprocess.run(["clang", "--target=" + target, "-x", "ir", "-O3",
                                      "-c", str(source), "-o", str(native)],
                                     capture_output=True, text=True, timeout=20)
                self.assertEqual(run.returncode, 0, run.stderr)
                actual = read_native_artifact(native)
                self.assertTrue(actual.startswith(signature))
                self.assertEqual(digest_regular_binary(native), sha256(actual).hexdigest())
                with self.assertRaisesRegex(NativeOutputRejected, "SIZE"):
                    read_native_artifact(native, max_bytes=len(actual) - 1)

    @unittest.skipUnless(shutil.which("clang"), "Real Clang required")
    def test_real_clang_object_is_accepted(self):
        source = self.root / "source.ll"
        source.write_text("define i32 @hepta_guard(i32 %x) {\nentry:\n %v = add i32 %x, 1\n ret i32 %v\n}\n")
        object_file = self.root / "candidate.o"
        run = subprocess.run(["clang", "-x", "ir", "-O3", "-c", str(source),
                              "-o", str(object_file)], capture_output=True,
                             text=True, timeout=20)
        self.assertEqual(run.returncode, 0, run.stderr)
        output = read_native_artifact(object_file)
        self.assertGreater(len(output), 40)
        self.assertEqual(output[:4], b"\x7fELF")
        self.assertEqual(digest_regular_binary(object_file), sha256(output).hexdigest())


if __name__ == "__main__":
    unittest.main()
