"""P5 LLVM host and target compile tools share bounded subprocess capture."""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta.clang_capture import CaptureRejected, CaptureResult
from hepta.llvm_ssa_backend import (LLVMSSARejected, SSA_LLVM_IR, _clang_run,
                                    compile_scalar_ssa_llvm)
from hepta.llvm_ssa_target import compile_ssa_target_object


def fixture() -> SSA_LLVM_IR:
    ir = ("define i32 @hepta_test(i32 %x) {\n"
          "entry:\n"
          "  %plus = add i32 %x, 1\n"
          "  ret i32 %plus\n"
          "}\n")
    return SSA_LLVM_IR(
        ir, sha256(ir.encode()).hexdigest(), ("hepta_test",),
        "a"*64, "b"*64)


class CaptureBoundaryTests(unittest.TestCase):
    def test_large_compiler_output_rejected_explicitly(self):
        with patch("hepta.llvm_ssa_backend.run_bounded",
                   side_effect=CaptureRejected("E_CAPTURE_OUTPUT_SIZE", "limit")):
            with self.assertRaisesRegex(LLVMSSARejected, "E_CAPTURE_OUTPUT_SIZE"):
                _clang_run(["clang", "--version"], timeout=10)

    def test_timeout_and_invalid_encoding_rejected(self):
        for error in ("E_CAPTURE_TIMEOUT", "E_CAPTURE_ENCODING"):
            with self.subTest(code=error):
                with patch("hepta.llvm_ssa_backend.run_bounded",
                           side_effect=CaptureRejected(error, "failure")):
                    with self.assertRaisesRegex(LLVMSSARejected, error):
                        _clang_run(["clang", "--version"], timeout=10)

    def test_exact_budgets_are_supplied_to_shared_capture(self):
        with patch("hepta.llvm_ssa_backend.run_bounded",
                   return_value=CaptureResult(0, "clang version test\n", "")) as capture:
            result = _clang_run(["clang", "--version"], timeout=10)
            self.assertEqual(result.returncode, 0)
            capture.assert_called_once_with(
                ["clang", "--version"], timeout=10,
                stdin_limit=0, stdout_limit=64000, stderr_limit=256000)

    @unittest.skipUnless(shutil.which("clang"), "A real Clang compiler is needed")
    def test_host_and_cross_object_real_llvm_compile(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            host_output = root / "host.so"
            host = compile_scalar_ssa_llvm(fixture(), output=host_output)
            self.assertEqual(host["status"], "native_host_compiled_unqualified")
            self.assertGreater(host["artifact_bytes"], 0)
            self.assertFalse(host["claims"]["backend_refinement_proven"])
            cross_output = root / "cross.o"
            cross = compile_ssa_target_object(
                fixture(), target="aarch64-apple-darwin", output=cross_output)
            self.assertEqual(cross["status"], "cross_object_only_not_executed")
            self.assertEqual(cross["object_format"], "MACHO64")
            self.assertTrue(cross_output.read_bytes().startswith(b"\\xcf\\xfa\\xed\\xfe"))
            self.assertFalse(cross["claims"]["foreign_c_abi_qualified"])

    @unittest.skipUnless(shutil.which("clang"), "Tool identity gate needs a Clang path")
    def test_failed_compiler_capture_never_publishes_output(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for output, operation in [
                (root/"host.so", lambda out: compile_scalar_ssa_llvm(fixture(), output=out)),
                (root/"cross.o", lambda out: compile_ssa_target_object(
                    fixture(), target="x86_64-unknown-linux-gnu", output=out)),
            ]:
                with self.subTest(path=output.name):
                    with patch("hepta.llvm_ssa_backend.run_bounded",
                               side_effect=CaptureRejected("E_CAPTURE_OUTPUT_SIZE", "limit")):
                        with self.assertRaisesRegex(LLVMSSARejected, "E_CAPTURE_OUTPUT_SIZE"):
                            operation(output)
                    self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
