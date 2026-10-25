"""Fail-closed cross-branch HSIR envelope and digest regression tests."""
import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch

MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "tools" / "audit_hsir_wire.py"
spec = importlib.util.spec_from_file_location("audit_hsir_wire", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def signed(fields):
    canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, allow_nan=False).encode("utf-8")
    return {**fields, "sha256": hashlib.sha256(canonical).hexdigest()}


def source_bound():
    return signed({"schema": "hepta.hsir.v0", "profile": "checked_typed_ast_not_verified_mir",
                   "module": "sample", "source_sha256": "a" * 64, "project_sha256": None,
                   "functions": [], "external_obligations": [], "all_expressions_typed": True,
                   "claims": {"native_borrow_validation": False,
                              "translation_correctness_proved": False,
                              "whole_language_soundness_proved": False,
                              "foreign_contracts_proved": False}})


def frozen():
    return signed({"schema": "hepta.hsir.v0", "status": "checked_frontend_snapshot_not_proved",
                   "program": "sample", "source_sha256": "a" * 64,
                   "functions": [], "external_assumptions": [], "typed_expression_count": 0,
                   "claims": {"lifetimes_fully_modeled": False,
                              "pointer_provenance_proved": False,
                              "source_semantics_refined": False,
                              "native_backend_equivalence_proved": False}})


class WireAuditTests(unittest.TestCase):
    def test_detects_exact_schema_collision(self):
        report = module.compare(source_bound(), frozen())
        self.assertTrue(report["same_schema_different_wire_format"])
        self.assertEqual(report["wire_layout_status"], "incompatible_requires_versioned_adapter")
        self.assertFalse(report["safe_to_mix_without_adapter"])

    def test_same_profile_not_semantic_proof(self):
        report = module.compare(source_bound(), source_bound())
        self.assertFalse(report["same_schema_different_wire_format"])
        self.assertFalse(report["automatic_merge_approved"])
        self.assertEqual(report["wire_layout_status"], "same_format_only_not_semantic_equivalence")

    def test_digest_mismatch_rejected(self):
        broken = source_bound()
        broken["source_sha256"] = "b" * 64
        with self.assertRaisesRegex(module.HSIRWireRejected, "DIGEST_MISMATCH"):
            module.fingerprint(broken)

    def test_forged_claim_rejected_even_when_rehashed(self):
        broken = source_bound()
        del broken["sha256"]
        broken["claims"]["translation_correctness_proved"] = True
        with self.assertRaisesRegex(module.HSIRWireRejected, "PROOF_CLAIM"):
            module.fingerprint(signed(broken))

    def test_unknown_evidence_claim_rejected(self):
        broken = frozen()
        del broken["sha256"]
        broken["claims"]["new_proof_claim"] = True
        with self.assertRaisesRegex(module.HSIRWireRejected, "PROOF_CLAIM"):
            module.fingerprint(signed(broken))

    def test_ambiguous_wire_discriminator_rejected(self):
        broken = source_bound()
        del broken["sha256"]
        broken["status"] = "checked_frontend_snapshot_not_proved"
        with self.assertRaisesRegex(module.HSIRWireRejected, "AMBIGUOUS_PROFILE"):
            module.fingerprint(signed(broken))

    def test_duplicate_json_field_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "source.json"
            path.write_text('{"schema":"hepta.hsir.v0","schema":"hepta.hsir.v0"}')
            with self.assertRaisesRegex(module.HSIRWireRejected, "DUPLICATE_KEY"):
                module.load(str(path))

    def test_adversarial_depth_rejected_without_unhandled_exception(self):
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "deep.json"
            path.write_text("[" * 20000 + "0" + "]" * 20000)
            with self.assertRaisesRegex(module.HSIRWireRejected, "E_HSIR_JSON"):
                module.load(str(path))

    def test_pr14_actual_cli_export_envelope(self):
        envelope = {"schema": "hepta.hsir.export.v0", "ok": True,
                    "status": "frontend_only", "hsir": source_bound(),
                    "validation": {"status": "frontend_only"}}
        result = module.fingerprint(envelope)
        self.assertEqual(result["wire_profile"], "source_bound_dict_v0")
        self.assertTrue(result["external_validation_metadata_unbound_to_payload"])
        self.assertFalse(result["checked_native"])

    def test_pr36_actual_cli_reference_validation_is_unbound(self):
        payload = {**frozen(), "reference_validation": {"status": "checked"}}
        result = module.fingerprint(payload)
        self.assertEqual(result["wire_profile"], "frozen_snapshot_v0")
        self.assertTrue(result["external_validation_metadata_unbound_to_payload"])
        self.assertFalse(result["checked_native"])
        payload["reference_validation"] = {"status": "fake_passed", "claims": {"safe": True}}
        self.assertEqual(module.fingerprint(payload)["sha256"], result["sha256"])

    def test_pr14_wrapper_cannot_claim_pr36_payload(self):
        envelope = {"schema": "hepta.hsir.export.v0", "ok": True,
                    "status": "checked", "hsir": frozen(), "validation": {}}
        with self.assertRaisesRegex(module.HSIRWireRejected, "EXPORT_ENVELOPE"):
            module.fingerprint(envelope)

    def test_pr36_invalid_cli_sidecar_shape_rejected(self):
        payload = {**frozen(), "reference_validation": ["checked"]}
        with self.assertRaisesRegex(module.HSIRWireRejected, "SIDECAR_ENVELOPE"):
            module.fingerprint(payload)

    def test_real_cli_collision_reports_exit_three(self):
        with tempfile.TemporaryDirectory() as d:
            a, b, out = [pathlib.Path(d) / x for x in ("a.json", "b.json", "out.json")]
            a.write_text(json.dumps({"schema": "hepta.hsir.export.v0", "ok": True,
                                     "status": "frontend_only", "hsir": source_bound(),
                                     "validation": {"status": "frontend_only"}}))
            b.write_text(json.dumps({**frozen(),
                                     "reference_validation": {"status": "checked"}}))
            code = module.main(["--left", str(a), "--right", str(b), "--output", str(out)])
            self.assertEqual(code, 3)
            self.assertTrue(json.loads(out.read_text())["same_schema_different_wire_format"])
            self.assertEqual(module.main(["--left", str(a), "--right", str(b),
                                          "--output", str(out)]), 2)


if __name__ == "__main__":
    unittest.main()
