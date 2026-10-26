"""Mandatory Resource IR gate for the strict source-facing scalar LLVM compiler.

These tests do not claim general source->IR refinement, native equivalence,
foreign-memory safety or GPU/production qualification.
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
from hepta.resource_ir import verify_resource_ir
from hepta.resource_lowering import lower_resource_ir
from hepta.native_resource_gate import NativeResourceGateRejected, qualify_native_resource_source
from hepta.llvm_ssa_pipeline import build_llvm_ssa_source


_SOURCE = """\
module resource_gate;
export "C" fn checked_counter(n: i32) -> i32 effects { panic } {
    let mut x: i32 = 0;
    while x < n { x = x + 1; }
    return x;
}
"""


def fixture(text=_SOURCE):
    program = parse(text, "resource_gate.hepta")
    checked = check(program)
    if not checked.ok:
        raise AssertionError([x.to_dict() for x in checked.diagnostics])
    return program, checked, canonical_hsir(program, checked)["sha256"]


class NativeResourceGateTests(unittest.TestCase):
    def test_checked_scalar_loop_has_complete_owner_graph(self):
        program, checked, digest = fixture()
        qualified = qualify_native_resource_source(
            program, checked, canonical_hsir_sha256=digest,
            project_sha256="f" * 64)
        self.assertEqual(qualified["schema"], "hepta.native.resource-gate.v1")
        self.assertEqual(qualified["functions_checked"], 1)
        self.assertEqual(qualified["canonical_hsir_sha256"], digest)
        self.assertEqual(qualified["project_sha256"], "f" * 64)
        self.assertTrue(qualified["claims"]["independent_resource_cfg_verified"])
        self.assertTrue(qualified["claims"]["exact_checked_source_resource_graph_rederived"])
        self.assertFalse(qualified["claims"]["native_codegen_consumes_resource_ir"])
        self.assertFalse(qualified["claims"]["whole_language_memory_safety_proved"])

    def test_rehashed_stale_source_and_unchecked_frontend_rejected(self):
        program, checked, digest = fixture()
        changed, changed_checked, newer = fixture(_SOURCE.replace("x = x + 1", "x = x + 2"))
        self.assertNotEqual(digest, newer)
        for invalid in ("0" * 64, digest.upper(), "xyz"):
            with self.subTest(invalid=invalid[:8]):
                with self.assertRaisesRegex(NativeResourceGateRejected, "E_NATIVE_RESOURCE_GATE"):
                    qualify_native_resource_source(
                        program, checked, canonical_hsir_sha256=invalid)
        with self.assertRaisesRegex(NativeResourceGateRejected, "E_NATIVE_RESOURCE_GATE"):
            qualify_native_resource_source(changed, changed_checked, canonical_hsir_sha256=digest)
        with self.assertRaisesRegex(NativeResourceGateRejected, "E_NATIVE_RESOURCE_GATE"):
            qualify_native_resource_source(program, SimpleNamespace(ok=1),
                                          canonical_hsir_sha256=digest)
        with self.assertRaisesRegex(NativeResourceGateRejected, "E_NATIVE_RESOURCE_GATE"):
            qualify_native_resource_source(program, checked, canonical_hsir_sha256=digest,
                                          project_sha256="unbound")

    def test_forged_data_only_graph_or_claims_do_not_authorize_native(self):
        program, checked, digest = fixture()
        verified = verify_resource_ir(lower_resource_ir(program, checked))
        self.assertTrue(verified["ok"])
        for label, mutation in {
            "fake_proof": lambda value: value["claims"].update(source_to_ir_refinement_proved=True),
            "bool_as_zero": lambda value: value["claims"].update(whole_language_soundness_proved=0),
            "wrong_source_graph": lambda value: value.update(ir_sha256="0" * 64),
            "foreign_claim": lambda value: value.update(external_obligations={"foreign": "untrusted"}),
            "wrong_functions": lambda value: value.update(functions=[{"function": "unlisted"}]),
        }.items():
            with self.subTest(label=label):
                forged = deepcopy(verified)
                mutation(forged)
                with patch("hepta.native_resource_gate.verify_resource_ir", return_value=forged):
                    with self.assertRaisesRegex(NativeResourceGateRejected, "E_NATIVE_RESOURCE_GATE"):
                        qualify_native_resource_source(program, checked,
                                                       canonical_hsir_sha256=digest)

    def test_native_pipeline_rejects_resealed_resource_receipt_elevation(self):
        with tempfile.TemporaryDirectory() as temporary:
            src = Path(temporary) / "source.hepta"
            dest = Path(temporary) / "no-native-result.so"
            src.write_text(_SOURCE)
            program, checked, digest = fixture()
            project = SimpleNamespace(identity="d" * 64,
                                      sources={str(src): "pinned"},
                                      unchanged=lambda: True)
            analysis = SimpleNamespace(
                program=program, checked=checked, project=project,
                report={"ok": True, "checks": {"rust_borrows_types": "rustc_checked"},
                        "source_sha256": "a" * 64, "compiler_sha256": "b" * 64})
            genuine = qualify_native_resource_source(
                program, checked, canonical_hsir_sha256=digest,
                project_sha256=project.identity)
            for label, mutation in {
                "fake_soundness": lambda v: v["claims"].update(whole_language_memory_safety_proved=True),
                "bool_integer_forgery": lambda v: v["claims"].update(independent_resource_cfg_verified=1),
                "unknown_claim": lambda v: v["claims"].update(foreign_unsafe_proved=True),
                "unbound_graph": lambda v: v.update(resource_ir_sha256="0" * 64),
                "wrong_source": lambda v: v.update(source_sha256="0" * 64),
                "bad_function_count": lambda v: v.update(functions_checked=True),
            }.items():
                with self.subTest(case=label):
                    forged = deepcopy(genuine)
                    mutation(forged)
                    with (patch("hepta.llvm_ssa_pipeline.analyze_project", return_value=analysis),
                          patch("hepta.llvm_ssa_pipeline.qualify_native_resource_source",
                                return_value=forged),
                          patch("hepta.hia_core.qualify_native_resource_source",
                                wraps=qualify_native_resource_source) as replay,
                          patch("hepta.llvm_ssa_pipeline.emit_scalar_ssa_llvm") as emitter,
                          patch("hepta.llvm_ssa_pipeline.compile_scalar_ssa_llvm") as compiler):
                        report = build_llvm_ssa_source(src, dest)
                    self.assertFalse(report["ok"], report)
                    if label == "unbound_graph":
                        # A well-shaped but unrelated graph digest passes the
                        # receipt shape check. The mandatory HIA source replay
                        # independently rederives the graph and rejects the
                        # mismatch before LLVM emission or native compilation.
                        self.assertEqual(report["diagnostics"][0]["code"], "E_HIA_CORE")
                        self.assertIn("resource gate does not replay from checked source",
                                      report["diagnostics"][0]["message"])
                        replay.assert_called_once()
                    else:
                        self.assertEqual(report["diagnostics"][0]["code"], "E_NATIVE_RESOURCE_GATE")
                        replay.assert_not_called()
                    self.assertFalse(report["claims"]["hia_scalar_core_source_replayed"])
                    self.assertFalse(report["claims"]["native_artifact_compiled"])
                    self.assertFalse(dest.exists())
                    emitter.assert_not_called()
                    compiler.assert_not_called()

    def test_noncanonical_source_foreign_obligations_refused(self):
        program, checked, digest = fixture()
        real = canonical_hsir
        for field in ("external_obligations", "foreign_assumptions", "volatile_accesses",
                      "owned_types"):
            with self.subTest(field=field):
                def dishonest(p, c):
                    canonical = real(p, c)
                    canonical[field] = [{"unexpected": "external"}]
                    return canonical
                with patch("hepta.native_resource_gate.canonical_checked_source", side_effect=dishonest):
                    with self.assertRaisesRegex(NativeResourceGateRejected, "E_NATIVE_RESOURCE_GATE"):
                        qualify_native_resource_source(program, checked,
                                                       canonical_hsir_sha256=digest)

    def test_native_compiler_refuses_gate_failure_before_any_codegen(self):
        with tempfile.TemporaryDirectory() as temporary:
            src = Path(temporary) / "source.hepta"
            out = Path(temporary) / "not-written.so"
            src.write_text(_SOURCE)
            program, checked, _ = fixture()
            project = SimpleNamespace(identity="d" * 64,
                                      sources={str(src): "pinned"},
                                      unchanged=lambda: True)
            analysis = SimpleNamespace(
                program=program, checked=checked, project=project,
                report={"ok": True, "checks": {"rust_borrows_types": "rustc_checked"},
                        "source_sha256": "a" * 64, "compiler_sha256": "b" * 64})
            with (patch("hepta.llvm_ssa_pipeline.analyze_project", return_value=analysis),
                  patch("hepta.llvm_ssa_pipeline.qualify_native_resource_source",
                        side_effect=NativeResourceGateRejected(
                            "E_NATIVE_RESOURCE_GATE: deliberate refusal")) as gate,
                  patch("hepta.llvm_ssa_pipeline.compile_scalar_ssa_llvm") as compiler):
                report = build_llvm_ssa_source(src, out)
            self.assertFalse(report["ok"], report)
            self.assertEqual(report["diagnostics"][0]["code"], "E_NATIVE_RESOURCE_GATE")
            self.assertFalse(report["claims"]["native_artifact_compiled"])
            self.assertFalse(out.exists())
            gate.assert_called_once()
            compiler.assert_not_called()


if __name__ == "__main__":
    unittest.main()
