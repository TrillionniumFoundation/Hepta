"""Real checked ownership + typed v1 snapshot + independent resource CFG tests."""
from pathlib import Path
import copy
import hashlib
import unittest

from hepta.hsir_v1_resource import HSIRResourceRejected, checked_resource_snapshot
from hepta.pipeline import analyze, analyze_project, hsir_v1_analysis, hsir_v1_resource_analysis

ROOT = Path(__file__).resolve().parents[1]


class HSIRV1ResourceTests(unittest.TestCase):
    OWNED = """fn main()->Unit effects {alloc,block,panic} {
        let bytes=buffer(8);
        drop(move bytes);
    }"""

    def frontend(self, source=OWNED):
        analysis = analyze(source, "test.hepta", native=False)
        self.assertTrue(analysis.report["ok"], analysis.report)
        return analysis

    def test_real_owned_program_has_matching_graph(self):
        analysis = self.frontend()
        result = hsir_v1_resource_analysis(analysis)
        self.assertTrue(result["ok"], result)
        binding = result["binding"]
        self.assertEqual(binding["schema"], "hepta.hsir-resource.binding.v1")
        self.assertEqual(binding["source_sha256"],
                         hashlib.sha256(self.OWNED.encode()).hexdigest())
        self.assertEqual(binding["hsir_sha256"], hsir_v1_analysis(analysis)["hsir"]["sha256"])
        self.assertTrue(binding["resource_verification"]["ok"])
        self.assertTrue(binding["claims"]["resource_cfg_independently_checked"])
        self.assertFalse(binding["claims"]["source_to_resource_ir_refinement_proved"])
        self.assertFalse(binding["claims"]["native_codegen_uses_this_ir"])
        self.assertEqual(result["status"], "frontend_only")

    def test_real_multi_file_owned_library(self):
        analysis = analyze_project(ROOT / "examples" / "owned" / "main.hepta",
                                   native=False)
        self.assertTrue(analysis.report["ok"], analysis.report)
        result = hsir_v1_resource_analysis(analysis)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["binding"]["project_sha256"], analysis.project.identity)
        self.assertEqual(len(result["binding"]["resource_ir"]["functions"]),
                         len(analysis.program.functions))
        self.assertFalse(result["binding"]["claims"]["foreign_contracts_proved"])

    def test_source_identity_mismatch_refuses_even_hashed_envelope(self):
        analysis = self.frontend()
        envelope = hsir_v1_analysis(analysis)["hsir"]
        analysis.program.source += "\n"
        with self.assertRaisesRegex(HSIRResourceRejected, "IDENTITY"):
            checked_resource_snapshot(analysis, envelope)

    def test_unsafe_proof_claim_cannot_be_forged(self):
        analysis = self.frontend()
        envelope = copy.deepcopy(hsir_v1_analysis(analysis)["hsir"])
        envelope["claims"]["source_to_ir_refinement_proved"] = True
        with self.assertRaisesRegex(HSIRResourceRejected, "ENVELOPE"):
            checked_resource_snapshot(analysis, envelope)

    def test_resealed_effect_changes_cannot_bind_to_same_checked_source(self):
        """A content-valid v1 digest must not authenticate a false effect list."""
        from hepta.hsir_v1 import integrate_v0, verify_v1
        from hepta.semantic_ir import _stable_json
        analysis = self.frontend()
        original = hsir_v1_analysis(analysis)["hsir"]
        legacy = copy.deepcopy(original["opaque_producer_payload"])
        self.assertIn("alloc", legacy["functions"][0]["declared_effects"])
        legacy["functions"][0]["declared_effects"].remove("alloc")
        legacy.pop("sha256")
        legacy["sha256"] = hashlib.sha256(_stable_json(legacy)).hexdigest()
        forged = integrate_v0(legacy, expected_source_sha256=original["producer"]["source_sha256"])
        self.assertTrue(verify_v1(forged)["ok"])
        with self.assertRaisesRegex(HSIRResourceRejected, "SNAPSHOT_MISMATCH"):
            checked_resource_snapshot(analysis, forged)

    def test_resealed_external_obligation_changes_are_not_discarded(self):
        from hepta.hsir_v1 import integrate_v0, verify_v1
        from hepta.semantic_ir import _stable_json
        analysis = self.frontend()
        original = hsir_v1_analysis(analysis)["hsir"]
        legacy = copy.deepcopy(original["opaque_producer_payload"])
        legacy["external_obligations"].append({
            "function": "main", "reasons": ["raw_pointer_signature"],
            "status": "caller_obligation_not_dischargeable_by_hsir"})
        legacy.pop("sha256")
        legacy["sha256"] = hashlib.sha256(_stable_json(legacy)).hexdigest()
        forged = integrate_v0(legacy, expected_source_sha256=original["producer"]["source_sha256"])
        self.assertTrue(verify_v1(forged)["ok"])
        with self.assertRaisesRegex(HSIRResourceRejected, "SNAPSHOT_MISMATCH"):
            checked_resource_snapshot(analysis, forged)

    def test_resealed_return_type_change_rejected(self):
        from hepta.hsir_v1 import integrate_v0, verify_v1
        from hepta.semantic_ir import _stable_json
        analysis = self.frontend()
        original = hsir_v1_analysis(analysis)["hsir"]
        legacy = copy.deepcopy(original["opaque_producer_payload"])
        legacy["functions"][0]["returns"] = "i64"
        legacy.pop("sha256")
        legacy["sha256"] = hashlib.sha256(_stable_json(legacy)).hexdigest()
        forged = integrate_v0(legacy, expected_source_sha256=original["producer"]["source_sha256"])
        self.assertTrue(verify_v1(forged)["ok"])
        with self.assertRaisesRegex(HSIRResourceRejected, "SNAPSHOT_MISMATCH"):
            checked_resource_snapshot(analysis, forged)

    def test_rejected_frontend_never_exposes_binding(self):
        analysis = analyze("fn bad()->i32 effects {} {return false;}", native=False)
        result = hsir_v1_resource_analysis(analysis)
        self.assertFalse(result["ok"])
        self.assertIsNone(result["binding"])

    def test_unsupported_task_contract_does_not_disappear(self):
        source = """fn run()->Unit effects {alloc,block,spawn} resources {
          heap_allocations=0
        } { }"""
        analysis = analyze(source, native=False)
        if analysis.report["ok"]:
            result = hsir_v1_resource_analysis(analysis)
            self.assertFalse(result["ok"])
            self.assertIsNone(result["binding"])


if __name__ == "__main__":
    unittest.main()
