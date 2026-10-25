"""Host-local validation of the fixed LLVM scalar vocabulary and its rejects."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.llvm_ir_profile import LLVMProfileRejected, validate_scalar_llvm_profile

HEADER = """; Hepta strict scalar SSA/PHI native-LLVM pilot, not whole-language qualified.
declare void @abort() noreturn
declare { i32, i1 } @llvm.sadd.with.overflow.i32(i32, i32)
declare { i32, i1 } @llvm.ssub.with.overflow.i32(i32, i32)
declare { i32, i1 } @llvm.smul.with.overflow.i32(i32, i32)
"""
VALID = HEADER + """
define i32 @sum(i32 %r_x_0) {
b0000:
  %r_x_1 = add i32 0, %r_x_0
  %t1 = call { i32, i1 } @llvm.sadd.with.overflow.i32(i32 %r_x_1, i32 2)
  %t2 = extractvalue { i32, i1 } %t1, 0
  %t3 = extractvalue { i32, i1 } %t1, 1
  br i1 %t3, label %bad_3, label %cont_3
bad_3:
  call void @abort()
  unreachable
cont_3:
  ret i32 %t2
}
"""


class ProfileTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("clang"), "actual Clang required")
    def test_approved_llvm_native_object_compiles(self):
        validate_scalar_llvm_profile(VALID, ("sum",))
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "approved.ll"
            obj = Path(td) / "approved.o"
            src.write_text(VALID)
            run = subprocess.run(["clang", "-x", "ir", "-O2", "-c", str(src), "-o", str(obj)],
                                 capture_output=True, text=True, timeout=30)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertGreater(obj.stat().st_size, 0)

    def test_hidden_calls_and_memory_operations_rejected(self):
        inserts = (
            "  %t99 = call i32 @puts(ptr null)",
            '  call void asm sideeffect "", ""()',
            "  %r_p_0 = alloca i32",
            "  store i32 4, ptr null",
            "  %t99 = load i32, ptr null",
            "  call void @llvm.memcpy.p0.p0.i64(ptr null, ptr null, i64 4, i1 false)",
        )
        for inject in inserts:
            with self.subTest(instruction=inject):
                tampered = VALID.replace("  ret i32 %t2", inject + "\n  ret i32 %t2")
                with self.assertRaisesRegex(LLVMProfileRejected, "INSTRUCTION"):
                    validate_scalar_llvm_profile(tampered, ("sum",))

    def test_extra_declaration_or_definition_rejected(self):
        examples = (
            VALID.replace("define i32 @sum", "declare i32 @puts(ptr)\ndefine i32 @sum"),
            VALID + "define i32 @extra(i32 %r_x_0) {\nb0000:\n  ret i32 1\n}\n",
            VALID.replace("define i32 @sum", "define i32 @abort"),
            VALID + "!llvm.module.flags = !{!0}\n",
        )
        for tampered in examples:
            with self.subTest(tampered=tampered[-80:]):
                with self.assertRaises(LLVMProfileRejected):
                    validate_scalar_llvm_profile(tampered, ("sum",))

    def test_cfg_fail_closed_and_phi_position(self):
        examples = (
            VALID.replace("label %bad_3", "label %bad_404"),
            VALID.replace("  unreachable\ncont_3:", "cont_3:"),
            VALID.replace("  ret i32 %t2", "  ret i32 %t2\n  %r_x_9 = add i32 0, 9"),
            VALID.replace("  ret i32 %t2",
                          "  %r_x_9 = add i32 0, 9\n"
                          "  %r_y_0 = phi i32 [ %r_x_9, %cont_3 ]\n  ret i32 %t2"),
        )
        for text in examples:
            with self.subTest(source=text[-100:]):
                with self.assertRaises(LLVMProfileRejected):
                    validate_scalar_llvm_profile(text, ("sum",))

    def test_phis_and_loop_branches_allowed(self):
        text = HEADER + """
define i32 @phi(i32 %r_x_0) {
b0000:
  br i1 true, label %b0001, label %b0002
b0001:
  %r_x_1 = add i32 0, 1
  br label %b0003
b0002:
  %r_x_2 = add i32 0, 2
  br label %b0003
b0003:
  %r_x_3 = phi i32 [ %r_x_1, %b0001 ], [ %r_x_2, %b0002 ]
  ret i32 %r_x_3
}
"""
        validate_scalar_llvm_profile(text, ("phi",))

    def test_size_format_and_symbol_identity(self):
        cases = [
            (VALID + "\x00", ("sum",)),
            (VALID.replace("\n", "\r\n"), ("sum",)),
            (VALID, ("other",)),
            (VALID, ("sum", "sum")),
            (VALID, ("abort",)),
            (VALID, ("sum", "alpha")),
        ]
        for content, names in cases:
            with self.subTest(names=names):
                with self.assertRaises(LLVMProfileRejected):
                    validate_scalar_llvm_profile(content, names)


if __name__ == "__main__":
    unittest.main()
