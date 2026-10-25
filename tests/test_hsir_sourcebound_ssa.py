"""End-to-end PR14 source-bound v0 -> versioned v1 -> real CFG/SSA verifier.

These require the actual full compiler branch; unlike the local finite
differential oracle, they intentionally import production CFG/SSA modules.
"""
import copy
import hashlib
import json
import unittest

from hepta.hsir_scalar_bridge import lower_source_bound_scalar
from hepta.hsir_v1 import integrate_v0
from hepta.hsir_v1_ssa import V1SSARejected, lower_verified_v1_scalar_ssa
from test_hsir_scalar_bridge import sample


def sign(value):
    source = copy.deepcopy(value)
    source.pop("sha256", None)
    source["sha256"] = hashlib.sha256(json.dumps(
        source, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False).encode("utf-8")).hexdigest()
    return source


class SourceBoundSSATests(unittest.TestCase):
    def test_branch_while_phi_and_provenance(self):
        source = sign(sample())
        envelope = integrate_v0(source)
        result = lower_verified_v1_scalar_ssa(envelope)
        payload, derived = lower_source_bound_scalar(source)
        self.assertEqual(result["scalar_mapping_profile"], "source_bound_scalar_structure_v1")
        self.assertEqual(result["source_hsir_v0_sha256"], source["sha256"])
        self.assertEqual(result["source_hsir_v1_sha256"], envelope["sha256"])
        self.assertEqual(result["derived_hsir_sha256"], derived)
        self.assertEqual(result["cfg"]["source_hsir_sha256"], derived)
        self.assertEqual(result["source_sha256"], source["source_sha256"])
        self.assertGreater(sum(f["phi_count"] for f in result["ssa_verification"]["functions"]), 0)
        self.assertFalse(result["claims"]["source_to_ir_semantics_proved"])
        self.assertFalse(result["claims"]["native_codegen_qualified_by_adapter"])

    def test_determinism_across_fresh_identity_equivalents(self):
        first = lower_verified_v1_scalar_ssa(integrate_v0(sign(sample())))
        second = lower_verified_v1_scalar_ssa(integrate_v0(sign(sample())))
        self.assertEqual(first, second)

    def test_sourcebound_read_borrow_refused(self):
        original = sample()
        original["functions"][0]["params"][0]["mode"] = "read"
        with self.assertRaisesRegex(V1SSARejected, "UNSUPPORTED_PRODUCER"):
            lower_verified_v1_scalar_ssa(integrate_v0(sign(original)))

    def test_external_obligations_not_dropped(self):
        original = sample()
        original["external_obligations"] = [{"function": "danger",
            "reasons": ["ffi_effect"], "status": "caller_obligation_not_dischargeable_by_hsir"}]
        with self.assertRaisesRegex(V1SSARejected, "UNSUPPORTED_PRODUCER"):
            lower_verified_v1_scalar_ssa(integrate_v0(sign(original)))

    def test_unproven_short_circuit_rejected(self):
        original = sample()
        expr = original["functions"][0]["body"][1]["data"]["condition"]
        expr["value"] = "&&"
        with self.assertRaisesRegex(V1SSARejected, "UNSUPPORTED_PRODUCER"):
            lower_verified_v1_scalar_ssa(integrate_v0(sign(original)))

    def test_tamper_legacy_after_v1_signing_is_rejected(self):
        env = integrate_v0(sign(sample()))
        env["opaque_producer_payload"]["functions"][0]["name"] = "other"
        with self.assertRaisesRegex(V1SSARejected, "IDENTITY"):
            lower_verified_v1_scalar_ssa(env)


if __name__ == "__main__":
    unittest.main()
