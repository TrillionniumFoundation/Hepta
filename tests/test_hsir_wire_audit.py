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

    def test_real_cli_collision_reports_exit_three(self):
        with tempfile.TemporaryDirectory() as d:
            a, b, out = [pathlib.Path(d) / x for x in ("a.json", "b.json", "out.json")]
            a.write_text(json.dumps(source_bound()))
            b.write_text(json.dumps(frozen()))
            code = module.main(["--left", str(a), "--right", str(b), "--output", str(out)])
            self.assertEqual(code, 3)
            self.assertTrue(json.loads(out.read_text())["same_schema_different_wire_format"])
            self.assertEqual(module.main(["--left", str(a), "--right", str(b),
                                          "--output", str(out)]), 2)


if __name__ == "__main__":
    unittest.main()
