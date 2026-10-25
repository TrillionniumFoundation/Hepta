"""Rehashed LLVM cannot authorize arbitrary native code or false provenance."""
from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from pathlib import Path
import re
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta.cfg import lower_hsir_cfg
from hepta.hsir import lower_checked_program
from hepta.llvm_ssa_backend import (LLVMSSARejected, compile_scalar_ssa_llvm,
                                    emit_scalar_ssa_llvm, require_exact_ssa_origin)
from hepta.llvm_ssa_target import compile_ssa_target_object, _qualified_header
from hepta.pipeline import analyze
from hepta.ssa import lower_cfg_scalar_ssa


def fixture(unsigned=False):
    word = "u32" if unsigned else "i32"
    source = f"""module llvm_origin;
export "C" fn choose(a: {word}, b: {word}) -> {word} effects {{panic}} {{
    if a < b {{ return a + 1; }}
    else {{ return b; }}
}}
"""
    checked = analyze(source, native=False)
    if not checked.report["ok"]:
        raise AssertionError(checked.report)
    cfg = lower_hsir_cfg(lower_checked_program(checked.program, checked.checked))
    ssa = lower_cfg_scalar_ssa(cfg)
    return cfg, ssa, emit_scalar_ssa_llvm(ssa, cfg)


def rehashed(ir, text):
    return replace(ir, text=text, sha256=sha256(text.encode()).hexdigest())


class LLVMOriginBoundaryTests(unittest.TestCase):
    def test_rehashed_calls_memory_global_and_asm_rejected_before_compiler(self):
        for unsigned in (False, True):
            _, _, ir = fixture(unsigned)
            cases = (
                ir.text.replace("declare void @abort()", "declare void @foreign()\ndeclare void @abort()"),
                ir.text.replace("  call void @abort()", "  store i32 1, ptr null\n  call void @abort()"),
                ir.text.replace("  call void @abort()", "  call void @foreign()\n  call void @abort()"),
                ir.text.replace("  call void @abort()", '  call void asm sideeffect "", ""()\n  call void @abort()'),
                ir.text + "@foreign_state = global i32 0\n",
            )
            for index, text in enumerate(cases):
                with self.subTest(unsigned=unsigned, case=index):
                    candidate = rehashed(ir, text)
                    with patch("hepta.llvm_ssa_backend._clang_run") as native:
                        with self.assertRaisesRegex(LLVMSSARejected, "PROFILE"):
                            compile_scalar_ssa_llvm(candidate, output="never-created.so")
                        native.assert_not_called()
                    with patch("hepta.llvm_ssa_target._clang_run") as native:
                        with self.assertRaisesRegex(LLVMSSARejected, "PROFILE"):
                            compile_ssa_target_object(candidate, target="x86_64-unknown-linux-gnu",
                                                      output="never-created.o")
                        native.assert_not_called()

    def test_textually_valid_semantic_and_sign_changes_fail_origin(self):
        for unsigned in (False, True):
            cfg, ssa, ir = fixture(unsigned)
            changed = re.sub(r"(?m)^  ret i32 [^\n]+$", "  ret i32 12345", ir.text, count=1)
            cases = [rehashed(ir, changed)]
            if unsigned:
                cases.append(rehashed(ir, ir.text.replace("icmp ult", "icmp slt")))
                cases.append(rehashed(ir, ir.text.replace(
                    "= call { i32, i1 } @llvm.uadd", "= call { i32, i1 } @llvm.sadd")))
            for candidate in cases:
                candidate.check_identity()  # Vocabulary is valid; semantics changed.
                with patch("hepta.llvm_ssa_backend._clang_run") as native:
                    with self.assertRaisesRegex(LLVMSSARejected, "ORIGIN"):
                        compile_scalar_ssa_llvm(candidate, output="never-created.so", ssa=ssa, cfg=cfg)
                    native.assert_not_called()
                with patch("hepta.llvm_ssa_target._clang_run") as native:
                    with self.assertRaisesRegex(LLVMSSARejected, "ORIGIN"):
                        compile_ssa_target_object(candidate, target="x86_64-unknown-linux-gnu",
                                                  output="never-created.o", ssa=ssa, cfg=cfg)
                    native.assert_not_called()

    def test_optional_origin_mode_is_explicit_and_partial_origin_is_rejected(self):
        cfg, ssa, ir = fixture(True)
        self.assertFalse(require_exact_ssa_origin(ir))
        self.assertTrue(require_exact_ssa_origin(ir, ssa=ssa, cfg=cfg))
        for kwargs in ({"ssa": ssa}, {"cfg": cfg}, {"ssa": "not SSA", "cfg": cfg}):
            with self.subTest(kwargs=tuple(kwargs)):
                with self.assertRaisesRegex(LLVMSSARejected, "ORIGIN"):
                    require_exact_ssa_origin(ir, **kwargs)
        with self.assertRaisesRegex(LLVMSSARejected, "IDENTITY"):
            replace(ir, source_ssa_sha256="unknown").check_identity()

    @unittest.skipUnless(shutil.which("clang"), "Native Clang is required")
    def test_real_i32_u32_origin_bound_host_and_target_objects(self):
        with tempfile.TemporaryDirectory(prefix="hepta-origin-") as directory:
            root = Path(directory)
            for unsigned in (False, True):
                cfg, ssa, ir = fixture(unsigned)
                host = compile_scalar_ssa_llvm(ir, output=root / f"{unsigned}.so", ssa=ssa, cfg=cfg)
                self.assertTrue(host["claims"]["ssa_cfg_origin_rechecked"])
                self.assertFalse(host["claims"]["backend_refinement_proven"])
                for target in ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu",
                               "x86_64-pc-windows-msvc", "x86_64-apple-darwin",
                               "aarch64-apple-darwin"):
                    with self.subTest(unsigned=unsigned, target=target):
                        output = root / f"{unsigned}-{target}.o"
                        receipt = compile_ssa_target_object(ir, target=target, output=output,
                                                            ssa=ssa, cfg=cfg)
                        self.assertTrue(receipt["claims"]["ssa_cfg_origin_rechecked"])
                        self.assertFalse(receipt["claims"]["target_program_executed"])
                        original = output.read_bytes()
                        self.assertTrue(_qualified_header(original, target))
                        if "linux" in target:
                            for offset, width in ((6, 1), (20, 4)):
                                invalid = bytearray(original)
                                invalid[offset:offset + width] = bytes(width)
                                self.assertFalse(_qualified_header(bytes(invalid), target))

    def test_unknown_or_malformed_object_inputs_fail_closed(self):
        for data, target in ((None, "x86_64-unknown-linux-gnu"), (b"", "unknown"),
                             (b"", []), ("ELF", "x86_64-unknown-linux-gnu")):
            self.assertFalse(_qualified_header(data, target))


if __name__ == "__main__":
    unittest.main()
