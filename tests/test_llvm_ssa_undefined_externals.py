"""P3/P5: native cross-object undefined imports must stay within abort profile."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.llvm_ssa_backend import LLVMSSARejected, emit_scalar_ssa_llvm
from hepta.llvm_ssa_target import (
    _qualified_header, _undefined_externals, compile_ssa_target_object, _TARGETS,
)
from hepta.ssa import lower_cfg_scalar_ssa
from tests.test_llvm_ssa_backend import LLVMSSATests


_HEADER = """; Hepta strict scalar SSA/PHI native-LLVM pilot, not whole-language qualified.
declare void @abort() noreturn
declare { i32, i1 } @llvm.sadd.with.overflow.i32(i32, i32)
declare { i32, i1 } @llvm.ssub.with.overflow.i32(i32, i32)
declare { i32, i1 } @llvm.smul.with.overflow.i32(i32, i32)

"""
_BODY = """define i32 @sum(i32 %r_x_0) {
b0000:
  %t1 = call { i32, i1 } @llvm.sadd.with.overflow.i32(i32 %r_x_0, i32 2)
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


@unittest.skipUnless(shutil.which("clang"), "native Clang required")
class LLVMObjectImportsTests(unittest.TestCase):
    def test_real_clang_five_target_defined_and_unknown_imports(self):
        normal = _HEADER + _BODY
        mutated = normal.replace("declare void @abort() noreturn",
                                 "declare i32 @puts(ptr)\ndeclare void @abort() noreturn")
        mutated = mutated.replace("  ret i32 %t2",
                                  "  %t4 = call i32 @puts(ptr null)\n  ret i32 %t2")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for target in _TARGETS:
                for code, expected in ((normal, {"abort"}), (mutated, {"abort", "puts"})):
                    with self.subTest(target=target, expected=expected):
                        source, obj = root / "case.ll", root / "case.o"
                        source.write_text(code)
                        run = subprocess.run(
                            ["clang", "--target=" + target, "-x", "ir", "-O3",
                             "-c", str(source), "-o", str(obj)],
                            capture_output=True, text=True, timeout=40)
                        self.assertEqual(run.returncode, 0, run.stderr)
                        data = obj.read_bytes()
                        self.assertTrue(_qualified_header(data, target))
                        self.assertEqual(_undefined_externals(data, target), expected)

    def test_compiler_published_object_has_no_unapproved_dependencies(self):
        helper = LLVMSSATests("test_true_loop_phi_and_checked_arithmetic_ir")
        cfg = helper.fixture()
        ir = emit_scalar_ssa_llvm(lower_cfg_scalar_ssa(cfg), cfg)
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "candidate.o"
            result = compile_ssa_target_object(
                ir, target="x86_64-unknown-linux-gnu", output=output)
            self.assertTrue(result["claims"]["undefined_external_inventory_checked"])
            self.assertFalse(set(result["undefined_external_dependencies"]) - {"abort"})
            self.assertFalse(result["claims"]["foreign_c_abi_qualified"])


if __name__ == "__main__":
    unittest.main()
