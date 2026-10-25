"""A re-hashed LLVM artifact must not authorize unreviewed native effects."""
from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import re
import unittest

from hepta.llvm_ssa_backend import LLVMSSARejected, emit_scalar_ssa_llvm
from hepta.ssa import lower_cfg_scalar_ssa
from tests.test_llvm_ssa_backend import LLVMSSATests


class LLVMSourceBoundaryTests(unittest.TestCase):
    def setUp(self):
        helper = LLVMSSATests("test_true_loop_phi_and_checked_arithmetic_ir")
        graph = helper.fixture()
        self.ir = emit_scalar_ssa_llvm(lower_cfg_scalar_ssa(graph), graph)

    def resigned(self, text):
        return replace(self.ir, text=text, sha256=sha256(text.encode()).hexdigest())

    def test_unchanged_real_ssa_emitter_is_accepted(self):
        self.ir.check_identity()
        self.assertIn(" phi i32 ", self.ir.text)
        self.assertIn("@llvm.sadd.with.overflow.i32", self.ir.text)

    def test_new_declaration_rejected_even_if_sha256_resigned(self):
        injected = self.ir.text.replace(
            "declare void @abort() noreturn",
            "declare i32 @puts(ptr)\ndeclare void @abort() noreturn")
        with self.assertRaisesRegex(LLVMSSARejected, "PROFILE"):
            self.resigned(injected).check_identity()

    def test_external_call_memory_and_inline_asm_rejected(self):
        for evil in ("  %t999 = call i32 @puts(ptr null)",
                     "  store i32 5, ptr null",
                     "  %t999 = alloca i32",
                     "  %t999 = load i32, ptr null",
                     '  call void asm sideeffect "", ""()'):
            with self.subTest(evil=evil):
                # Insert a well-formed line into the first live block.
                changed = re.sub(r"(?m)^(b[0-9]{4}:)$", r"\1\n" + evil, self.ir.text, count=1)
                with self.assertRaisesRegex(LLVMSSARejected, "PROFILE"):
                    self.resigned(changed).check_identity()

    def test_unsafe_module_preamble_rejected(self):
        for prefix in ("@slot = global i32 1\n", "target triple = \"x86_64-pc-linux-gnu\"\n"):
            with self.subTest(prefix=prefix):
                with self.assertRaisesRegex(LLVMSSARejected, "PROFILE"):
                    self.resigned(prefix + self.ir.text).check_identity()

    def test_missing_ssa_evidence_identity_rejected(self):
        with self.assertRaisesRegex(LLVMSSARejected, "IDENTITY"):
            replace(self.ir, verification_sha256="not-a-sha").check_identity()

    def test_changed_phi_target_rejected_without_changing_function_inventory(self):
        match = re.search(r"(?m)^(  br label %)(b[0-9]{4})$", self.ir.text)
        self.assertIsNotNone(match, self.ir.text)
        bad = self.ir.text[:match.start(2)] + "b9999" + self.ir.text[match.end(2):]
        with self.assertRaisesRegex(LLVMSSARejected, "PROFILE"):
            self.resigned(bad).check_identity()


if __name__ == "__main__":
    unittest.main()
