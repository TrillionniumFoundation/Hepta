"""P1 v1 -> checked CFG -> SSA -> independent verification path."""
from pathlib import Path
import copy
import unittest

from hepta.checker import check
from hepta.cfg import lower_hsir_cfg
from hepta.hsir import lower_checked_program
from hepta.hsir_v1 import integrate_v0
from hepta.hsir_v1_ssa import V1SSARejected, lower_verified_v1_scalar_ssa
from hepta.parser import parse
from hepta.ssa import lower_cfg_scalar_ssa
from hepta.ssa_verify import verify_scalar_ssa

from test_hsir_v1 import pr14

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "examples" / "ssa_scalar.hepta"


class HSIRV1ScalarSSATests(unittest.TestCase):
    def fixture(self):
        program = parse(SOURCE.read_text(), str(SOURCE))
        checked = check(program)
        self.assertTrue(checked.ok)
        original = lower_checked_program(program, checked)
        envelope = integrate_v0(original.as_dict())
        return original, envelope

    def test_real_checked_source_matches_original_ssa(self):
        original, envelope = self.fixture()
        actual = lower_verified_v1_scalar_ssa(envelope)
        cfg = lower_hsir_cfg(original)
        ssa = lower_cfg_scalar_ssa(cfg)
        verified = verify_scalar_ssa(ssa, cfg)
        self.assertEqual(actual["schema"], "hepta.ssa.integration.v1")
        self.assertEqual(actual["cfg"], cfg.as_dict())
        self.assertEqual(actual["ssa"], ssa.as_dict())
        self.assertEqual(actual["ssa_verification"], verified.as_dict())
        self.assertEqual(actual["source_hsir_v1_sha256"], envelope["sha256"])
        self.assertFalse(actual["claims"]["native_codegen_qualified_by_adapter"])
        self.assertFalse(actual["claims"]["source_to_ir_semantics_proved"])
        self.assertTrue(actual["claims"]["structural_ssa_verified"])

    def test_source_loop_phi_and_determinism(self):
        _, envelope = self.fixture()
        one = lower_verified_v1_scalar_ssa(envelope)
        two = lower_verified_v1_scalar_ssa(copy.deepcopy(envelope))
        self.assertEqual(one["sha256"], two["sha256"])
        self.assertGreater(sum(f["phi_count"] for f in one["ssa_verification"]["functions"]), 0)

    def test_pr14_incompatible_type_body_fails_closed(self):
        envelope = integrate_v0(pr14())
        with self.assertRaisesRegex(V1SSARejected, "UNSUPPORTED_PRODUCER"):
            lower_verified_v1_scalar_ssa(envelope)

    def test_tampered_v1_claim_even_rehashed_rejected(self):
        _, envelope = self.fixture()
        envelope["claims"]["source_to_ir_refinement_proved"] = True
        with self.assertRaisesRegex(V1SSARejected, "IDENTITY"):
            lower_verified_v1_scalar_ssa(envelope)

    def test_other_producer_fixture_is_not_marked_codegen_safe(self):
        _, envelope = self.fixture()
        output = lower_verified_v1_scalar_ssa(envelope)
        self.assertFalse(output["claims"]["memory_safety_proved"])
        self.assertFalse(output["claims"]["foreign_contracts_proved"])


if __name__ == "__main__":
    unittest.main()
