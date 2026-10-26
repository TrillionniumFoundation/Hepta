"""P1/P5: source-bound ownership/loan abstract verification gates native LLVM."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from hepta.checker import check
from hepta.parser import parse
from hepta.cfg import lower_hsir_cfg
from hepta.hsir import lower_checked_program
from hepta.native_resource_gate import (
    NativeResourceGateRejected, verify_native_scalar_resource_gate,
)
from hepta.ssa import lower_cfg_scalar_ssa
from hepta.llvm_ssa_pipeline import build_llvm_ssa_source


_SOURCE = """\
module native_p1_resource;
export "C" fn sum(n: i32) -> i32 effects { panic } {
    let mut total: i32 = 0;
    let mut i: i32 = 0;
    while i < n {
        total = total + i;
        i = i + 1;
    }
    return total;
}
"""
_UNSIGNED = """\
module native_p1_resource_u32;
export "C" fn f(a: u32, b: u32) -> u32 effects { panic } {
    return a + b;
}
"""
_OWNED = "fn main()->Unit effects {alloc,block,panic} {let b=buffer(4);drop(move b);}"


def snapshots(source):
    program = parse(source, "p1_native_resource.hepta")
    checked = check(program)
    if not checked.ok:
        raise AssertionError([item.to_dict() for item in checked.diagnostics])
    scalar_hsir = lower_checked_program(program, checked)
    cfg = lower_hsir_cfg(scalar_hsir)
    ssa = lower_cfg_scalar_ssa(cfg)
    return program, checked, scalar_hsir, ssa


class NativeResourceGateTests(unittest.TestCase):
    def test_checked_i32_loop_and_unsigned_u32_native_subset(self):
        for source in (_SOURCE, _UNSIGNED):
            with self.subTest(kind=source.splitlines()[0]):
                program, checked, hsir, ssa = snapshots(source)
                result = verify_native_scalar_resource_gate(
                    program, checked, scalar_hsir=hsir, ssa=ssa,
                    project_sha256="2" * 64)
                self.assertEqual(result["schema"], "hepta.llvm-native-resource-origin.v1")
                self.assertEqual(result["scalar_hsir_sha256"], hsir.sha256)
                self.assertEqual(result["ssa_sha256"], ssa.sha256)
                self.assertEqual(result["source_sha256"], hsir.as_dict()["source_sha256"])
                self.assertEqual(result["project_sha256"], "2" * 64)
                self.assertGreater(result["abstract_resource_operations_checked"], 0)
                self.assertTrue(result["claims"]["source_resource_ir_origin_rechecked"])
                self.assertTrue(result["claims"]["independent_abstract_resource_flow_checked"])
                self.assertFalse(result["claims"]["source_to_ir_refinement_proved"])
                self.assertFalse(result["claims"]["native_codegen_uses_resource_ir"])
                self.assertFalse(result["claims"]["whole_language_soundness_proved"])

    def test_stale_scalar_source_or_ssa_is_rejected(self):
        original, check_a, snapshot_a, ssa_a = snapshots(_UNSIGNED)
        altered, check_b, snapshot_b, ssa_b = snapshots(_UNSIGNED.replace("a + b", "a - b"))
        with self.assertRaisesRegex(NativeResourceGateRejected, "RESOURCE_GATE"):
            verify_native_scalar_resource_gate(
                altered, check_b, scalar_hsir=snapshot_a, ssa=ssa_b)
        with self.assertRaisesRegex(NativeResourceGateRejected, "RESOURCE_GATE"):
            verify_native_scalar_resource_gate(
                original, check_a, scalar_hsir=snapshot_a, ssa=ssa_b)

    def test_unsafe_or_owned_profile_never_silently_falls_back(self):
        program = parse(_OWNED, "owner.hepta")
        checked = check(program)
        self.assertTrue(checked.ok)
        # Owned source is outside the reviewed LLVM scalar subset. A
        # checked Resource IR owner alone does not license emitting scalar
        # LLVM with hidden drops or foreign obligations.
        _, _, scalar_hsir, ssa = snapshots(_UNSIGNED)
        with self.assertRaisesRegex(NativeResourceGateRejected, "RESOURCE_GATE"):
            verify_native_scalar_resource_gate(
                program, checked, scalar_hsir=scalar_hsir, ssa=ssa)

    def test_forged_resource_verification_receipt_rejected(self):
        program, checked, hsir, ssa = snapshots(_UNSIGNED)
        with patch("hepta.native_resource_gate.verify_resource_ir",
                   return_value={"ok": True, "status": "resource_cfg_verified",
                                 "ir_sha256": "0" * 64, "owned_types": [],
                                 "external_obligations": {}, "claims": {}}):
            with self.assertRaisesRegex(NativeResourceGateRejected, "RESOURCE_GATE"):
                verify_native_scalar_resource_gate(
                    program, checked, scalar_hsir=hsir, ssa=ssa)

    def test_rust_qualified_source_pipeline_must_hit_gate_before_codegen(self):
        program, checked, _, _ = snapshots(_SOURCE)
        fake_project = SimpleNamespace(
            identity="2" * 64, sources={},
            unchanged=lambda: True)
        analyzed = SimpleNamespace(
            program=program, checked=checked, project=fake_project,
            report={"ok": True, "checks": {"rust_borrows_types": "rustc_checked"}})
        with tempfile.TemporaryDirectory() as root:
            output = Path(root) / "cannot_publish.so"
            with (patch("hepta.llvm_ssa_pipeline.analyze_project", return_value=analyzed),
                  patch("hepta.llvm_ssa_pipeline.verify_native_scalar_resource_gate",
                        side_effect=NativeResourceGateRejected("E_LLVM_RESOURCE_GATE: injected invalid loan")),
                  patch("hepta.llvm_ssa_pipeline.compile_scalar_ssa_llvm") as compiler):
                result = build_llvm_ssa_source(Path(root) / "source.hepta", output)
                self.assertFalse(result["ok"])
                self.assertEqual(result["diagnostics"][0]["code"], "E_LLVM_RESOURCE_GATE")
                self.assertFalse(output.exists())
                compiler.assert_not_called()


if __name__ == "__main__":
    unittest.main()
