"""P1: native scalar LLVM builds must enforce source-bound Resource IR.

A verified JSON resource graph by itself does not authorize native codegen.
Tests cover exact source identity, false/0 proof spoofing, assumed foreign
resources, source mismatch and refusal to publish an artifact on gate failure.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from hepta.checker import check
from hepta.parser import parse
from hepta.semantic_ir import lower_checked_program as canonical_hsir
from hepta.resource_lowering import lower_resource_ir, verify_resource_source_origin
from hepta.resource_ir import verify_resource_ir
from hepta.native_resource_gate import (
    NativeResourceGateRejected, qualify_native_resource_source,
)
from hepta.llvm_ssa_pipeline import build_llvm_ssa_source


_SOURCE = """\
module native_resource_gate;
export "C" fn hepta_guarded(n: i32) -> i32 effects { panic } {
    let mut acc: i32 = 0;
    while acc < n {
        acc = acc + 1;
    }
    return acc;
}
"""


def fixture(source=_SOURCE):
    program = parse(source, "p1_resource_gate.hepta")
    checked = check(program)
    if not checked.ok:
        raise AssertionError([d.to_dict() for d in checked.diagnostics])
    return program, checked, canonical_hsir(program, checked)["sha256"]


class NativeResourceGateTests(unittest.TestCase):
    def test_scalar_loop_resource_graph_mandatory_success(self):
        program, checked, digest = fixture()
        receipt = qualify_native_resource_source(
            program, checked, canonical_hsir_sha256=digest)
        self.assertEqual(receipt["schema"], "hepta.native.resource-gate.v1")
        self.assertEqual(receipt["canonical_hsir_sha256"], digest)
        self.assertEqual(receipt["functions_checked"], 1)
        self.assertTrue(receipt["claims"]["independent_resource_cfg_verified"])
        self.assertTrue(receipt["claims"]["exact_checked_source_resource_graph_rederived"])
        self.assertFalse(receipt["claims"]["source_to_resource_ir_refinement_proved"])
        self.assertFalse(receipt["claims"]["native_codegen_consumes_resource_ir"])
        self.assertFalse(receipt["claims"]["whole_language_memory_safety_proved"])
        self.assertIsNone(receipt["project_sha256"])

    def test_shared_project_sha_changes_canonical_hsir_and_resource_receipts(self):
        program, checked, unbound = fixture()
        project = "f" * 64
        project_bound = canonical_hsir(
            program, checked, project_sha256=project)["sha256"]
        self.assertNotEqual(unbound, project_bound)
        receipt = qualify_native_resource_source(
            program, checked, canonical_hsir_sha256=project_bound,
            project_sha256=project)
        self.assertEqual(receipt["project_sha256"], project)
        self.assertEqual(receipt["canonical_hsir_sha256"], project_bound)
        with self.assertRaisesRegex(NativeResourceGateRejected, "E_NATIVE_RESOURCE_GATE"):
            qualify_native_resource_source(
                program, checked, canonical_hsir_sha256=unbound,
                project_sha256=project)
        with self.assertRaisesRegex(NativeResourceGateRejected, "E_NATIVE_RESOURCE_GATE"):
            qualify_native_resource_source(
                program, checked, canonical_hsir_sha256=project_bound,
                project_sha256="e" * 64)

    def test_source_hsir_mismatch_and_invalid_inputs_reject(self):
        program, checked, digest = fixture()
        for invalid in ("0" * 64, "", digest.upper(), "x" * 64):
            with self.subTest(invalid=invalid[:5]):
                with self.assertRaisesRegex(NativeResourceGateRejected, "E_NATIVE_RESOURCE_GATE"):
                    qualify_native_resource_source(
                        program, checked, canonical_hsir_sha256=invalid)
        with self.assertRaisesRegex(NativeResourceGateRejected, "E_NATIVE_RESOURCE_GATE"):
            qualify_native_resource_source(
                program, checked, canonical_hsir_sha256=digest,
                project_sha256="not-a-hash")
        with self.assertRaisesRegex(NativeResourceGateRejected, "E_NATIVE_RESOURCE_GATE"):
            qualify_native_resource_source(
                program, SimpleNamespace(ok=1),
                canonical_hsir_sha256=digest)

    def test_stale_program_cannot_keep_valid_old_origin(self):
        old, checked, digest = fixture()
        changed, next_checked, changed_digest = fixture(
            _SOURCE.replace("acc = acc + 1", "acc = acc + 2"))
        self.assertNotEqual(digest, changed_digest)
        with self.assertRaisesRegex(NativeResourceGateRejected, "E_NATIVE_RESOURCE_GATE"):
            qualify_native_resource_source(
                changed, next_checked, canonical_hsir_sha256=digest)
        self.assertEqual(
            qualify_native_resource_source(
                old, checked, canonical_hsir_sha256=digest)["canonical_hsir_sha256"],
            digest)

    def test_forged_resource_proof_scope_rejected(self):
        program, checked, digest = fixture()
        good = verify_resource_ir(lower_resource_ir(program, checked))
        self.assertTrue(good["ok"])
        forged = deepcopy(good)
        forged["claims"]["source_to_ir_refinement_proved"] = True
        with patch("hepta.native_resource_gate.verify_resource_ir", return_value=forged):
            with self.assertRaisesRegex(NativeResourceGateRejected, "E_NATIVE_RESOURCE_GATE"):
                qualify_native_resource_source(
                    program, checked, canonical_hsir_sha256=digest)
        forged = deepcopy(good)
        forged["claims"]["whole_language_soundness_proved"] = 0
        with patch("hepta.native_resource_gate.verify_resource_ir", return_value=forged):
            with self.assertRaisesRegex(NativeResourceGateRejected, "E_NATIVE_RESOURCE_GATE"):
                qualify_native_resource_source(
                    program, checked, canonical_hsir_sha256=digest)

    def test_malformed_resource_function_inventory_is_controlled_rejection(self):
        program, checked, digest = fixture()
        original = verify_resource_ir(lower_resource_ir(program, checked))
        self.assertTrue(original["ok"])
        for inventory in ([None], [{"function": 7}], [{"function": None}],
                          [{"function": "unlisted"}], [{}]):
            with self.subTest(inventory=inventory):
                invalid = deepcopy(original)
                invalid["functions"] = inventory
                with patch("hepta.native_resource_gate.verify_resource_ir",
                           return_value=invalid):
                    with self.assertRaisesRegex(NativeResourceGateRejected,
                                               "E_NATIVE_RESOURCE_GATE"):
                        qualify_native_resource_source(
                            program, checked, canonical_hsir_sha256=digest)

    def test_foreign_obligations_cannot_be_hidden(self):
        program, checked, digest = fixture()
        graph = lower_resource_ir(program, checked)
        source_receipt = verify_resource_source_origin(program, checked, graph)
        forged = deepcopy(graph)
        forged["obligations"] = {
            "foreign:f": {"function": "f", "status": "assumed_not_verified",
                          "requirements": ["abi", "aliasing", "effects", "lifetime", "ownership"]}}
        with (patch("hepta.native_resource_gate.lower_resource_ir", return_value=forged),
              patch("hepta.native_resource_gate.verify_resource_source_origin",
                    return_value=source_receipt)):
            with self.assertRaisesRegex(NativeResourceGateRejected, "E_NATIVE_RESOURCE_GATE"):
                qualify_native_resource_source(
                    program, checked, canonical_hsir_sha256=digest)

    def test_forged_origin_receipt_rejected(self):
        program, checked, digest = fixture()
        graph = lower_resource_ir(program, checked)
        source = verify_resource_source_origin(program, checked, graph)
        altered = deepcopy(source)
        altered["canonical_hsir_sha256"] = "0" * 64
        with patch("hepta.native_resource_gate.verify_resource_source_origin", return_value=altered):
            with self.assertRaisesRegex(NativeResourceGateRejected, "E_NATIVE_RESOURCE_GATE"):
                qualify_native_resource_source(
                    program, checked, canonical_hsir_sha256=digest)

    def test_compiler_must_fail_without_resource_gate_before_native_compiler(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "native.hepta"
            source.write_text(_SOURCE, encoding="utf-8")
            target = root / "must-not-be-published.so"
            program, checked, _ = fixture()
            project = SimpleNamespace(
                entry=source, sources={str(source): "pinned-source"}, identity="9" * 64,
                unchanged=lambda: True)
            analysis = SimpleNamespace(
                program=program, checked=checked, project=project,
                report={"ok": True, "checks": {"rust_borrows_types": "rustc_checked"},
                        "source_sha256": "a" * 64, "compiler_sha256": "b" * 64})
            with (patch("hepta.llvm_ssa_pipeline.analyze_project", return_value=analysis),
                  patch("hepta.llvm_ssa_pipeline.qualify_native_resource_source",
                        side_effect=NativeResourceGateRejected(
                            "E_NATIVE_RESOURCE_GATE: deliberately refused")) as resource,
                  patch("hepta.llvm_ssa_pipeline.compile_scalar_ssa_llvm") as native):
                result = build_llvm_ssa_source(source, target)
            self.assertFalse(result["ok"], result)
            self.assertEqual(result["diagnostics"][0]["code"], "E_NATIVE_RESOURCE_GATE")
            self.assertFalse(result["claims"]["native_artifact_compiled"])
            self.assertFalse(target.exists())
            resource.assert_called_once()
            native.assert_not_called()


if __name__ == "__main__":
    unittest.main()
