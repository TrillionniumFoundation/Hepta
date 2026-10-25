"""Independent v0 producer shape conformance for the HSIR v1 envelope."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("hepta.hsir_v1", ROOT / "hepta" / "hsir_v1.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def signed(value):
    item = copy.deepcopy(value)
    item.pop("sha256", None)
    item["sha256"] = hashlib.sha256(json.dumps(item, sort_keys=True,
        separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()).hexdigest()
    return item


def pr14():
    return signed({
        "schema": "hepta.hsir.v0", "profile": "checked_typed_ast_not_verified_mir",
        "module": "m", "source_sha256": "a" * 64, "project_sha256": "b" * 64,
        "functions": [{"name": "f", "params": [{"name": "p", "mode": "read", "type": "u8"}],
                       "returns": "u64", "return_mode": "value", "return_origin": None,
                       "extern_c": False, "export_c": False,
                       "declared_effects": ["panic"], "inferred_effects": ["panic"],
                       "resources": {}, "body": [{"node": "expr", "op": "int", "type": "u64"}]}],
        "untyped_expressions": [], "all_expressions_typed": True,
        "external_obligations": [{"function": "f", "reasons": ["ffi_effect"],
                                 "status": "caller_obligation_not_dischargeable_by_hsir"}],
        "foreign_assumptions": [{"function": "foreign_fn", "verified": False}],
        "resource_contracts": {},
        "claims": {"native_borrow_validation": False, "translation_correctness_proved": False,
                   "whole_language_soundness_proved": False, "foreign_contracts_proved": False},
    })


def pr36():
    return signed({
        "schema": "hepta.hsir.v0", "status": "checked_frontend_snapshot_not_proved",
        "program": "m", "source_sha256": "a" * 64,
        "functions": [{"name": "f", "param_types": [{"name": "p", "ownership": "read",
                         "type": {"type": "u8", "args": [], "length": None}}],
                       "return_type": {"type": "u64", "args": [], "length": None},
                       "declared_effects": ["panic"], "inferred_transitive_effects": ["panic"],
                       "resource_contract": {}, "abi": "hepta_unstable", "direction": "local",
                       "body": [{"node": "expr", "operation": "int", "result_type": {
                           "type": "u64", "args": [], "length": None}}]}],
        "typed_expression_count": 1, "external_assumptions": [], "resource_contracts": {},
        "claims": {"lifetimes_fully_modeled": False, "pointer_provenance_proved": False,
                   "source_semantics_refined": False, "native_backend_equivalence_proved": False},
    })


class IntegrationEnvelopeTests(unittest.TestCase):
    def test_both_producers_have_distinct_claims_and_lossless_embedded_origins(self):
        a = module.integrate_v0(pr14(), expected_project_sha256="b" * 64)
        b = module.integrate_v0(pr36())
        self.assertNotEqual(a["producer"]["wire_profile"], b["producer"]["wire_profile"])
        self.assertNotEqual(a["sha256"], b["sha256"])
        self.assertEqual(a["opaque_producer_payload"], pr14())
        self.assertEqual(b["opaque_producer_payload"], pr36())
        self.assertTrue(module.verify_v1(a)["ok"])
        self.assertTrue(module.verify_v1(b)["ok"])
        self.assertFalse(module.verify_v1(b)["codegen_qualified"])

    def test_same_source_does_not_imply_equal_type_model(self):
        a, b = module.integrate_v0(pr14()), module.integrate_v0(pr36())
        self.assertEqual(a["producer"]["source_sha256"], b["producer"]["source_sha256"])
        self.assertFalse(a["interface_projection"]["type_cross_profile_equivalence_proved"])
        self.assertEqual(a["interface_projection"]["functions"][0]["return_type"]["representation"],
                         "producer_display_only")
        self.assertEqual(b["interface_projection"]["functions"][0]["return_type"]["representation"],
                         "producer_structural_unverified")

    def test_foreign_obligations_are_not_dropped(self):
        doc = pr14()
        out = module.integrate_v0(doc)
        self.assertEqual(out["unresolved_external"]["source_obligations"], doc["external_obligations"])
        self.assertEqual(out["unresolved_external"]["foreign_assumptions"], doc["foreign_assumptions"])
        self.assertFalse(out["unresolved_external"]["inventory_complete"])

    def test_source_project_mismatch_fails_closed(self):
        with self.assertRaisesRegex(module.HSIRV1Rejected, "SOURCE_IDENTITY"):
            module.integrate_v0(pr14(), expected_source_sha256="f" * 64)
        with self.assertRaisesRegex(module.HSIRV1Rejected, "PROJECT_IDENTITY"):
            module.integrate_v0(pr14(), expected_project_sha256="f" * 64)
        with self.assertRaisesRegex(module.HSIRV1Rejected, "PROJECT_UNAVAILABLE"):
            module.integrate_v0(pr36(), expected_project_sha256="b" * 64)

    def test_legacy_digest_tamper_rejected(self):
        doc = pr14()
        doc["functions"][0]["name"] = "modified"
        with self.assertRaisesRegex(module.HSIRV1Rejected, "LEGACY_HASH_MISMATCH"):
            module.integrate_v0(doc)

    def test_v1_digest_and_reconstruction_guard(self):
        out = module.integrate_v0(pr14())
        forged = copy.deepcopy(out)
        forged["claims"]["safe_codegen_without_consumer_refinement"] = True
        with self.assertRaisesRegex(module.HSIRV1Rejected, "HASH_MISMATCH"):
            module.verify_v1(forged)
        forged["sha256"] = module._digest({k: v for k, v in forged.items() if k != "sha256"})
        with self.assertRaisesRegex(module.HSIRV1Rejected, "RECONSTRUCTION_MISMATCH"):
            module.verify_v1(forged)

    def test_forged_proof_claim_rejected_before_projection(self):
        doc = pr36()
        doc["claims"]["pointer_provenance_proved"] = True
        doc = signed(doc)
        with self.assertRaisesRegex(module.HSIRV1Rejected, "PROOF_CLAIMS"):
            module.integrate_v0(doc)

    def test_same_schema_ambiguous_wire_rejected(self):
        doc = pr14()
        doc["status"] = "checked_frontend_snapshot_not_proved"
        doc = signed(doc)
        with self.assertRaisesRegex(module.HSIRV1Rejected, "LEGACY_COLLISION"):
            module.integrate_v0(doc)

    def test_incomplete_expression_types_rejected(self):
        doc = pr14()
        doc["functions"][0]["body"][0]["type"] = None
        doc = signed(doc)
        with self.assertRaisesRegex(module.HSIRV1Rejected, "UNTYPED_EXPRESSION"):
            module.integrate_v0(doc)

    def test_wrong_expression_count_rejected(self):
        doc = pr36()
        doc["typed_expression_count"] = 0
        doc = signed(doc)
        with self.assertRaisesRegex(module.HSIRV1Rejected, "EXPRESSION_COUNT"):
            module.integrate_v0(doc)

    def test_ownership_change_rejected(self):
        doc = pr14()
        doc["functions"][0]["params"][0]["mode"] = "secret_force_copy"
        doc = signed(doc)
        with self.assertRaisesRegex(module.HSIRV1Rejected, "OWNERSHIP"):
            module.integrate_v0(doc)

    def test_deep_and_duplicate_json_refusals(self):
        with self.assertRaisesRegex(module.HSIRV1Rejected, "DUPLICATE_KEY"):
            module.decode_json(b'{"schema":1,"schema":2}')
        with self.assertRaisesRegex(module.HSIRV1Rejected, "JSON"):
            module.decode_json(("[" * 20000 + "0" + "]" * 20000).encode())
        with self.assertRaisesRegex(module.HSIRV1Rejected, "NONFINITE"):
            module.decode_json(b'{"x":NaN}')

    def test_result_is_deterministic(self):
        self.assertEqual(module.integrate_v0(pr14()), module.integrate_v0(copy.deepcopy(pr14())))

    def test_no_non_serializable_fallback(self):
        doc = pr14()
        doc["extras"] = object()
        with self.assertRaisesRegex(module.HSIRV1Rejected, "VALUE"):
            module.integrate_v0(doc)


if __name__ == "__main__":
    unittest.main()
