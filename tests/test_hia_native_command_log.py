"""Real bounded command bytes survive success, refusal and capture failure."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

from hepta.clang_capture import CaptureRejected
from hepta.hia_program_llvm import (
    HIAProgramLLVMRejected, _run_logged, build_program_native,
)
from tests.test_hia_program import arithmetic

CLANG = os.environ.get("CLANG", "clang")


class NativeCommandLogTests(unittest.TestCase):
    def test_exact_raw_bytes_and_nonzero_child_result_are_observations(self):
        rows = []
        result = _run_logged([sys.executable, "-c", "import sys;sys.stdout.buffer.write(b'\\x00A\\r\\n');sys.stderr.buffer.write(b'E\\r\\n');sys.exit(7)"],
                             command_log=rows, timeout=5, stdout_limit=64, stderr_limit=64)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual((row["status"], row["returncode"]), ("completed", 7))
        self.assertEqual(bytes.fromhex(row["stdout_hex"]), b"\x00A\r\n")
        self.assertEqual(bytes.fromhex(row["stderr_hex"]), b"E\r\n")
        self.assertTrue(row["stdout_complete"] and row["stderr_complete"])

    def test_real_timeout_retains_available_prefix_and_reraises(self):
        rows = []
        with self.assertRaises(CaptureRejected) as caught:
            _run_logged([sys.executable, "-c", "import sys,time;sys.stdout.buffer.write(b'before-timeout');sys.stdout.flush();time.sleep(5)"],
                        command_log=rows, timeout=1, stdout_limit=64, stderr_limit=64)
        self.assertEqual(caught.exception.code, "E_CAPTURE_TIMEOUT")
        self.assertEqual(rows[0]["status"], "capture_failed")
        self.assertEqual(rows[0]["error"]["code"], "E_CAPTURE_TIMEOUT")
        self.assertEqual(bytes.fromhex(rows[0]["stdout_hex"]), b"before-timeout")
        self.assertEqual(rows[0]["stdout_total_bytes"], 14)

    def test_output_quota_marks_retained_prefix_as_incomplete(self):
        rows = []
        with self.assertRaises(CaptureRejected):
            _run_logged([sys.executable, "-c", "import sys;sys.stdout.buffer.write(b'x'*1024);sys.stdout.flush()"],
                        command_log=rows, timeout=5, stdout_limit=16, stderr_limit=64)
        self.assertEqual(rows[0]["status"], "capture_failed")
        self.assertEqual(bytes.fromhex(rows[0]["stdout_hex"]), b"x" * 16)
        self.assertEqual(rows[0]["stdout_retained_bytes"], 16)
        self.assertGreater(rows[0]["stdout_total_bytes"], 16)
        self.assertFalse(rows[0]["stdout_complete"])

    def test_spawn_failure_keeps_attempt_without_inventing_raw_output(self):
        rows = []
        with self.assertRaises((OSError, CaptureRejected)):
            _run_logged(["/no/such/hepta-test-executable"], command_log=rows, timeout=5)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "capture_failed")
        self.assertIsNone(rows[0]["returncode"])
        self.assertIsNone(rows[0]["stdout_hex"])

    def test_nonplain_log_sink_refuses_before_command_execution(self):
        class ProducerList(list):
            pass
        for value in ({}, (), ProducerList()):
            with self.subTest(value=value), self.assertRaisesRegex(HIAProgramLLVMRejected, "E_HIA_COMMAND_LOG"):
                _run_logged(["/no/such/hepta-test-executable"], command_log=value)


@unittest.skipUnless(shutil.which(CLANG), "actual native Clang required")
class NativeCompilationLogTests(unittest.TestCase):
    def test_actual_compile_records_version_target_and_compiler_original_streams(self):
        with tempfile.TemporaryDirectory() as folder:
            rows = []
            receipt = build_program_native(arithmetic("int.add.wrap", "u32"), Path(folder) / "core.o",
                                           clang=CLANG, kind="object", command_log=rows)
            self.assertTrue(receipt["ok"])
            self.assertEqual(len(rows), 3)
            self.assertEqual(rows[0]["argv"][-1], "--version")
            self.assertEqual(rows[1]["argv"][-1], "-dumpmachine")
            self.assertIn("-x", rows[2]["argv"])
            self.assertIn(b"clang version", bytes.fromhex(rows[0]["stdout_hex"]))
            for row in rows:
                self.assertEqual((row["status"], row["returncode"]), ("completed", 0))
                self.assertTrue(row["stdout_complete"] and row["stderr_complete"])


if __name__ == "__main__":
    unittest.main()
