"""P2/P4/P5: one C++ source -> checked Hepta -> C and direct LLVM native ABIs.

The supported subset covers defined, bounded i32 inputs. Finite tests do not
prove C++ ABI preservation, universal equivalence or language soundness.
"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from hepta.cpp2hepta import migrate_cpp
from hepta.pipeline import analyze
from hepta.hsir import lower_checked_program
from hepta.cfg import lower_hsir_cfg
from hepta.ssa import lower_cfg_scalar_ssa
from hepta.ssa_verify import verify_scalar_ssa
from hepta.llvm_ssa_backend import emit_scalar_ssa_llvm, compile_scalar_ssa_llvm


SOURCE = """
int sum_to(int n) noexcept {
    int total = 0;
    int i = 0;
    for (i = 0; i < n; ++i) { total = total + i; }
    return total;
}
int clamp_local(int x) noexcept {
    int y = x;
    if (y < 0) { y = 0; }
    return y;
}
"""

WRAPPER = """
int sum_to(int) noexcept;
int clamp_local(int) noexcept;
extern "C" int cpp_sum_to(int n) { return sum_to(n); }
extern "C" int cpp_clamp_local(int x) { return clamp_local(x); }
"""


class StatefulMigrationLLVMTests(unittest.TestCase):
    def test_checked_source_two_backends_against_original_cpp(self):
        with tempfile.TemporaryDirectory(prefix="hepta-p2-p4-p5-") as tmp:
            root = Path(tmp)
            source = root / "original.cc"
            source.write_text(SOURCE, encoding="utf-8")
            hepta = root / "migrated.hepta"
            migrated = migrate_cpp(source, hepta)
            self.assertTrue(migrated["ok"], migrated)
            self.assertEqual(migrated["tier"], "L1")
            self.assertFalse(migrated["cpp_abi_preserved"])
            self.assertFalse(migrated["behavioral_equivalence_proved"])
            self.assertEqual(migrated["native_validation"], "not_run")
            lowered_source = hepta.read_text(encoding="utf-8")
            self.assertIn("while (i < n)", lowered_source)
            self.assertIn("i = (i + 1);", lowered_source)

            # Reference rustc must really validate before the LLVM path.
            checked = analyze(hepta.read_text(encoding="utf-8"), str(hepta),
                              native=True, rustc=os.environ.get("RUSTC"),
                              crate_type="rlib")
            self.assertTrue(checked.report["ok"], checked.report)
            self.assertEqual(checked.report["checks"]["rust_borrows_types"], "rustc_checked")
            hsir = lower_checked_program(checked.program, checked.checked)
            cfg = lower_hsir_cfg(hsir)
            ssa = lower_cfg_scalar_ssa(cfg)
            verification = verify_scalar_ssa(ssa, cfg).as_dict()
            self.assertTrue(verification["claims"]["single_assignment_checked"])
            self.assertFalse(verification["claims"]["semantic_equivalence_proven"])
            ir = emit_scalar_ssa_llvm(ssa, cfg)
            self.assertEqual(set(ir.functions), {"sum_to", "clamp_local"})

            wrapper = root / "wrapper.cc"
            wrapper.write_text(WRAPPER, encoding="utf-8")
            cpp_so = root / "reference.so"
            original = subprocess.run(
                ["clang++", "-std=c++20", "-O2", "-fPIC", "-shared",
                 str(source), str(wrapper), "-o", str(cpp_so)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(original.returncode, 0, original.stderr + original.stdout)

            c_so = root / "hepta_c.so"
            c_result = subprocess.run(
                [sys.executable, "-m", "hepta", "build", str(hepta),
                 "--backend", "c", "--crate-type", "cdylib", "-o", str(c_so)],
                capture_output=True, text=True, timeout=100)
            self.assertEqual(c_result.returncode, 0, c_result.stderr + c_result.stdout)

            llvm_so = root / "hepta_llvm.so"
            llvm_report = compile_scalar_ssa_llvm(ir, output=llvm_so)
            self.assertEqual(llvm_report["status"], "native_host_compiled_unqualified")
            self.assertFalse(llvm_report["claims"]["backend_refinement_proven"])

            original_lib = ctypes.CDLL(str(cpp_so))
            c_lib = ctypes.CDLL(str(c_so))
            llvm_lib = ctypes.CDLL(str(llvm_so))
            inputs = {
                "sum_to": [(-100,), (-1,), (0,), (1,), (2,), (7,), (16,), (100,), (1000,)],
                "clamp_local": [(-2**31,), (-100,), (-1,), (0,), (1,), (333,), (2**31 - 1,)],
            }
            for name, rows in inputs.items():
                reference = getattr(original_lib, "cpp_" + name)
                c_output = getattr(c_lib, name)
                llvm_output = getattr(llvm_lib, name)
                for fn in (reference, c_output, llvm_output):
                    fn.argtypes = [ctypes.c_int32]
                    fn.restype = ctypes.c_int32
                for args in rows:
                    with self.subTest(name=name, args=args):
                        expected = reference(*args)
                        self.assertEqual(c_output(*args), expected)
                        self.assertEqual(llvm_output(*args), expected)

            # A compiled, intentionally incorrect C++ original must be caught.
            mutant = root / "mutated.cc"
            mutant.write_text(SOURCE.replace("return total;", "return total + 1;", 1))
            mutated_so = root / "mutated.so"
            bad = subprocess.run(
                ["clang++", "-std=c++20", "-O2", "-fPIC", "-shared",
                 str(mutant), str(wrapper), "-o", str(mutated_so)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(bad.returncode, 0, bad.stderr + bad.stdout)
            wrong = ctypes.CDLL(str(mutated_so)).cpp_sum_to
            wrong.argtypes = [ctypes.c_int32]
            wrong.restype = ctypes.c_int32
            self.assertNotEqual(wrong(10), llvm_lib.sum_to(10))
            self.assertNotEqual(wrong(10), c_lib.sum_to(10))


if __name__ == "__main__":
    unittest.main()
