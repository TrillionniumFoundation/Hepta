"""Adversarial resource and positive tests for bounded Clang AST capture."""
from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from tools.c2hepta import UnsupportedC, _run_bounded_ast


class BoundedClangAstCapture(unittest.TestCase):
    def test_small_stdout_and_stderr_are_preserved(self):
        completed = _run_bounded_ast([
            sys.executable, "-c",
            "import sys; sys.stdout.write('ok'); sys.stderr.write('warning')",
        ], max_stdout_bytes=2)
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, b"ok")
        self.assertEqual(completed.stderr, b"warning")

    def test_stdout_over_budget_fails_closed(self):
        with self.assertRaisesRegex(UnsupportedC, "E_CAPTURE_OUTPUT_SIZE"):
            _run_bounded_ast([
                sys.executable, "-c",
                "import sys; sys.stdout.buffer.write(b'x' * 4000000)",
            ], max_stdout_bytes=4096)

    def test_stderr_over_budget_is_rejected_without_silent_truncation(self):
        # Preserve the original million-byte adversarial stream, but retain
        # the newer shared capture rule: over-budget diagnostics reject.
        with self.assertRaisesRegex(UnsupportedC, "E_CAPTURE_OUTPUT_SIZE"):
            _run_bounded_ast([
                sys.executable, "-c",
                "import sys; sys.stdout.write('{}'); sys.stderr.write('z' * 1000000)",
            ], max_stdout_bytes=4096)

    def test_timeout_kills_ast_producer(self):
        with self.assertRaisesRegex(UnsupportedC, "E_CAPTURE_TIMEOUT"):
            _run_bounded_ast([
                sys.executable, "-c", "import time; time.sleep(30)",
            ], timeout=0.1)

    def test_real_clang_ast_is_bounded(self):
        self.assertIsNotNone(shutil.which("clang"), "Clang required for migration acceptance")
        with tempfile.TemporaryDirectory(prefix="hepta-ast-limit-") as temp:
            source = Path(temp) / "small.c"
            source.write_text("int increment(int a) { return a + 1; }\n", encoding="utf-8")
            with self.assertRaisesRegex(UnsupportedC, "E_CAPTURE_OUTPUT_SIZE"):
                _run_bounded_ast([
                    "clang", "-x", "c", "-std=c11", "-fsyntax-only",
                    "-Xclang", "-ast-dump=json", str(source),
                ], max_stdout_bytes=1024)


if __name__ == "__main__":
    unittest.main()
