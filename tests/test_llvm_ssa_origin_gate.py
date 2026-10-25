"""P0/P5: native compilation provenance must be rederived, not rehashed."""
from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from pathlib import Path
import re
import shutil
import tempfile
import unittest

from hepta.llvm_ssa_backend import (
    LLVMSSARejected, compile_scalar_ssa_llvm, emit_scalar_ssa_llvm,
    require_verified_ssa_cfg_origin,
)
from hepta.ssa import lower_cfg_scalar_ssa
from tests.test_ssa_scalar import snapshot, block, n
from tests.test_llvm_ssa_backend import exported


class LLVMSSAOriginGateTests(unittest.TestCase):
    def fixture(self):
        cfg = exported(snapshot([
            block(0, kind="return", value=n("a"))
        ], params=[("a", "i32")], effects=["panic"]))
        ssa = lower_cfg_scalar_ssa(cfg)
        return ssa, cfg, emit_scalar_ssa_llvm(ssa, cfg)

    def test_verified_source_matches_exact_native_ir(self):
        ssa, cfg, ir = self.fixture()
        self.assertTrue(require_verified_ssa_cfg_origin(ir, ssa=ssa, cfg=cfg))
        self.assertFalse(require_verified_ssa_cfg_origin(ir))
        with self.assertRaisesRegex(LLVMSSARejected, "ORIGIN"):
            require_verified_ssa_cfg_origin(ir, ssa=ssa)
        with self.assertRaisesRegex(LLVMSSARejected, "ORIGIN"):
            require_verified_ssa_cfg_origin(ir, cfg=cfg)

    def test_rehashed_well_formed_wrong_code_rejected_before_compiler(self):
        ssa, cfg, ir = self.fixture()
        # Rehashing is trivial: the forged LLVM retains the *same* function
        # name, syntax, SSA origin claim and structural verifier receipt.
        tampered = re.sub(r"(?m)^  ret i32 [^\n]+$", "  ret i32 0", ir.text, count=1)
        self.assertNotEqual(tampered, ir.text)
        forged = replace(ir, text=tampered, sha256=sha256(tampered.encode()).hexdigest())
        forged.check_identity()  # A closed vocabulary alone cannot prove semantics.
        with self.assertRaisesRegex(LLVMSSARejected, "ORIGIN"):
            require_verified_ssa_cfg_origin(forged, ssa=ssa, cfg=cfg)
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "must-not-exist.so"
            with self.assertRaisesRegex(LLVMSSARejected, "ORIGIN"):
                compile_scalar_ssa_llvm(forged, output=destination, ssa=ssa, cfg=cfg)
            self.assertFalse(destination.exists())

    def test_rehashed_arbitrary_memory_operation_rejected_by_profile(self):
        _, _, ir = self.fixture()
        tampered = re.sub(r"(?m)^  ret i32 [^\n]+$",
                          "  %t99 = load i32, ptr null\n  ret i32 %t99",
                          ir.text, count=1)
        self.assertNotEqual(tampered, ir.text)
        forged = replace(ir, text=tampered, sha256=sha256(tampered.encode()).hexdigest())
        with self.assertRaisesRegex(LLVMSSARejected, "PROFILE"):
            forged.check_identity()

    @unittest.skipUnless(shutil.which("clang"), "Clang needed for native receipt")
    def test_strict_receipt_separates_source_checked_from_legacy_api(self):
        ssa, cfg, ir = self.fixture()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            qualified = compile_scalar_ssa_llvm(
                ir, output=root / "strict.so", ssa=ssa, cfg=cfg)
            self.assertTrue(qualified["ssa_cfg_origin_rechecked"])
            self.assertFalse(qualified["claims"]["backend_refinement_proven"])
            legacy = compile_scalar_ssa_llvm(ir, output=root / "legacy.so")
            self.assertFalse(legacy["ssa_cfg_origin_rechecked"])
            self.assertFalse(legacy["claims"]["backend_refinement_proven"])


if __name__ == "__main__":
    unittest.main()
