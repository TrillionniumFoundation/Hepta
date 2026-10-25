"""P5 native LLVM containment: a new SHA cannot turn hostile IR into authority."""
from __future__ import annotations

import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from hepta.llvm_ir_profile import (
    HEADER, DECLARATIONS, MIXED_PROFILE, SIGNED_PROFILE, UNSIGNED_MARKER,
    LLVMProfileRejected, validate_scalar_llvm_profile,
)


def fixture(*, unsigned=False, payload=None):
    pre = [HEADER]
    if unsigned:
        pre.append(UNSIGNED_MARKER)
    pre.extend(DECLARATIONS)
    pre.append("")
    body = payload or [
        "define i32 @f(i32 %r_a_0) {",
        "b0000:",
        "  %r_v_0 = add i32 0, %r_a_0",
        "  ret i32 %r_v_0",
        "}", "",
    ]
    return "\n".join(pre + body) + "\n"


class LLVMIRProfileTests(unittest.TestCase):
    def test_signed_and_unsigned_profile(self):
        for unsigned, profile in ((False, SIGNED_PROFILE), (True, MIXED_PROFILE)):
            with self.subTest(profile=profile):
                validate_scalar_llvm_profile(fixture(unsigned=unsigned), ("f",), profile)
        for profile in (SIGNED_PROFILE, MIXED_PROFILE):
            with self.assertRaisesRegex(LLVMProfileRejected, "HEADER"):
                validate_scalar_llvm_profile(fixture(unsigned=True), ("f",), SIGNED_PROFILE)

    def test_real_clang_object_positive(self):
        import shutil
        if not shutil.which("clang"):
            self.skipTest("Clang unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            source, obj = path / "module.ll", path / "module.o"
            source.write_text(fixture())
            result = subprocess.run(["clang", "-x", "ir", "-O2", "-c", str(source), "-o", str(obj)],
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertGreater(obj.stat().st_size, 0)

    def test_clang_malicious_rehashed_operations_denied(self):
        base = fixture()
        attacks = {
            "external call": "  call i32 @puts(ptr null)",
            "arbitrary load": "  %t9 = load i32, ptr null",
            "arbitrary store": "  store i32 7, ptr null",
            "alloca": "  %t9 = alloca i32",
            "inline asm": '  call void asm sideeffect "", ""()',
            "global": "@external = global i32 0",
            "raw declaration": "declare i32 @puts(ptr)",
            "metadata": "!1 = !{i32 1}",
            "rehashed different definition": "define i32 @g(i32 %r_a_0) {",
        }
        for name, attack in attacks.items():
            with self.subTest(name=name):
                if name == "rehashed different definition":
                    text = base.replace("define i32 @f(", attack.replace("%r_a_0) {", ""))
                else:
                    text = base.replace("  ret i32 %r_v_0", attack + "\n  ret i32 %r_v_0")
                with self.assertRaises(LLVMProfileRejected):
                    validate_scalar_llvm_profile(text, ("f",), SIGNED_PROFILE)

    def test_signed_profile_rejects_unsigned_op(self):
        lines = ["define i32 @f(i32 %r_a_0, i32 %r_b_0) {", "b0000:",
                 "  %t1 = icmp ult i32 %r_a_0, %r_b_0", "  ret i32 %r_a_0", "}", ""]
        with self.assertRaisesRegex(LLVMProfileRejected, "SIGNED"):
            validate_scalar_llvm_profile(fixture(payload=lines), ("f",), SIGNED_PROFILE)

    def test_control_flow_and_phi_negative(self):
        base = fixture()
        mutants = [
            base.replace("b0000:", "b0000:\nb0000:"),
            base.replace("  ret i32 %r_v_0", "  br label %b0099"),
            base.replace("  ret i32 %r_v_0", "  %r_v_1 = phi i32 [ %r_v_0, %b0000 ]\n  ret i32 %r_v_1"),
            base.replace("  ret i32 %r_v_0", "  call void @abort()\n  ret i32 %r_v_0"),
            base.replace("  ret i32 %r_v_0", "  ret i32 %r_v_0\n  %t3 = add i32 0, 1"),
            base + "@new_global = global i32 7\n",
        ]
        for mutant in mutants:
            with self.subTest(mutant=mutant[:90]):
                with self.assertRaises(LLVMProfileRejected):
                    validate_scalar_llvm_profile(mutant, ("f",), SIGNED_PROFILE)

    def test_valid_loop_phi_and_backward_edge(self):
        body = [
            "define i32 @f(i32 %r_x_0) {", "b0000:", "  br label %b0001",
            "b0001:",
            "  %r_i_1 = phi i32 [ %r_x_0, %b0000 ], [ %r_i_2, %b0002 ]",
            "  %t1 = icmp slt i32 %r_i_1, 10",
            "  br i1 %t1, label %b0002, label %b0003",
            "b0002:", "  %r_i_2 = add i32 0, %r_i_1", "  br label %b0001",
            "b0003:",
            "  ret i32 %r_i_1", "}", "",
        ]
        text = fixture(payload=body)
        validate_scalar_llvm_profile(text, ("f",), SIGNED_PROFILE)
        import shutil
        if shutil.which("clang"):
            with tempfile.TemporaryDirectory() as tmp:
                src, obj = Path(tmp) / "phi.ll", Path(tmp) / "phi.o"
                src.write_text(text)
                ran = subprocess.run(["clang", "-x", "ir", "-O2", "-c", str(src), "-o", str(obj)],
                                     capture_output=True, text=True, timeout=15)
                self.assertEqual(ran.returncode, 0, ran.stderr)
                self.assertGreater(obj.stat().st_size, 0)

    def test_checked_signed_and_unsigned_intrinsic_syntax(self):
        for unsigned, keyword in ((False, "sadd"), (True, "uadd")):
            body = ["define i32 @f(i32 %r_a_0, i32 %r_b_0) {", "b0000:",
                    f"  %t1 = call {{ i32, i1 }} @llvm.{keyword}.with.overflow.i32(i32 %r_a_0, i32 %r_b_0)",
                    "  %t2 = extractvalue { i32, i1 } %t1, 0",
                    "  %t3 = extractvalue { i32, i1 } %t1, 1",
                    "  br i1 %t3, label %bad_3, label %cont_3",
                    "bad_3:", "  call void @abort()", "  unreachable",
                    "cont_3:", "  ret i32 %t2", "}", ""]
            validate_scalar_llvm_profile(fixture(unsigned=unsigned, payload=body), ("f",),
                                         MIXED_PROFILE if unsigned else SIGNED_PROFILE)


if __name__ == "__main__":
    unittest.main()
