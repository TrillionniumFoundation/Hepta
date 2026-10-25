"""P5: native Rust-checked Hepta source -> canonical HSIR -> SSA -> LLVM.

This is a bounded executable i32 pilot, not an entire-language backend proof.
"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.pipeline import analyze
from hepta.hsir import lower_checked_program
from hepta.cfg import lower_hsir_cfg
from hepta.ssa import lower_cfg_scalar_ssa
from hepta.ssa_verify import verify_scalar_ssa
from hepta.llvm_ssa_backend import emit_scalar_ssa_llvm, compile_scalar_ssa_llvm


_SOURCE = """\
module p5_source_native;
export "C" fn hepta_accumulate(n: i32) -> i32 effects { panic } {
    let mut total: i32 = 0;
    let mut i: i32 = 0;
    while i < n {
        if i < 4 { total = total + i; }
        else { total = total + 1; }
        i = i + 1;
    }
    return total;
}
"""


@unittest.skipUnless(shutil.which("clang"), "Requires native Clang")
class SourceToLLVMSSATests(unittest.TestCase):
    def test_checked_reference_then_direct_llvm_native_execution(self):
        # A real pinned rustc run is required, not a frontend-only substitute.
        checked = analyze(_SOURCE, "p5_source_native.hepta", native=True,
                          rustc=os.environ.get("RUSTC"), crate_type="rlib")
        self.assertTrue(checked.report["ok"], checked.report.get("diagnostics"))
        self.assertEqual(checked.report["checks"]["rust_borrows_types"], "rustc_checked")
        canonical = lower_checked_program(checked.program, checked.checked)
        self.assertEqual(canonical.as_dict()["status"], "checked_frontend_snapshot_not_proved")
        cfg = lower_hsir_cfg(canonical)
        ssa = lower_cfg_scalar_ssa(cfg)
        verified = verify_scalar_ssa(ssa, cfg)
        self.assertTrue(verified.as_dict())
        ir = emit_scalar_ssa_llvm(ssa, cfg)
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "hepta_ssa_integrated.so"
            report = compile_scalar_ssa_llvm(ir, output=output)
            self.assertEqual(report["status"], "native_host_compiled_unqualified")
            self.assertFalse(report["claims"]["backend_refinement_proven"])
            self.assertGreater(output.stat().st_size, 0)
            native = ctypes.CDLL(str(output)).hepta_accumulate
            native.argtypes = [ctypes.c_int32]
            native.restype = ctypes.c_int32
            for n in [-6, 0, 1, 3, 4, 5, 8, 12, 19, 40]:
                with self.subTest(n=n):
                    expected = sum(i if i < 4 else 1 for i in range(max(0, n)))
                    self.assertEqual(native(n), expected)


if __name__ == "__main__":
    unittest.main()
