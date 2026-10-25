"""SSA verifier positive and adversarial falsification controls."""
from __future__ import annotations

import json
from hashlib import sha256
import unittest

from hepta.ssa import SSASnapshot, lower_cfg_scalar_ssa
from hepta.ssa_verify import SSAVerificationRejected, verify_scalar_ssa
from tests.test_ssa_scalar import snapshot, block, let, assign, i, n, expr


def encoded(payload):
    s = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return SSASnapshot("hepta.ssa.scalar.v0", s, sha256(s.encode()).hexdigest())


class SSAVerificationTests(unittest.TestCase):
    def fixture(self):
        cfg = snapshot([
            block(0, [let("x", i(0))], kind="branch", condition=n("b", "bool"),
                  **{"then": "b0001", "else": "b0002"}),
            block(1, [assign("x", i(2))], kind="goto", target="b0003"),
            block(2, [assign("x", i(3))], kind="goto", target="b0003"),
            block(3, kind="return", value=n("x"))], params=[("b", "bool")])
        return cfg, lower_cfg_scalar_ssa(cfg)

    def test_valid_diamond_and_loop(self):
        cfg, ssa = self.fixture()
        left = verify_scalar_ssa(ssa, cfg)
        right = verify_scalar_ssa(ssa, cfg)
        self.assertEqual(left.sha256, right.sha256)
        result = left.as_dict()
        self.assertEqual(result["schema"], "hepta.ssa.verify.v0")
        self.assertTrue(result["claims"]["ssa_edge_uses_checked"])
        self.assertFalse(result["claims"]["semantic_equivalence_proven"])
        self.assertEqual(result["functions"][0]["phi_count"], 1)
        cfg = snapshot([
            block(0, [let("x", i(0))], kind="goto", target="b0001"),
            block(1, kind="branch", condition=expr("binary", "<", "bool", n("x"), n("n")),
                  **{"then": "b0002", "else": "b0003"}),
            block(2, [assign("x", expr("binary", "+", "i32", n("x"), i(1)))],
                  kind="goto", target="b0001"),
            block(3, kind="return", value=n("x"))], params=[("n", "i32")], effects=["panic"])
        self.assertEqual(verify_scalar_ssa(lower_cfg_scalar_ssa(cfg), cfg).as_dict()["functions"][0]["phi_count"], 1)

    def test_hash_identity_and_input_mismatch(self):
        cfg, ssa = self.fixture()
        bad = SSASnapshot(ssa.schema, ssa.canonical_json, "0" * 64)
        with self.assertRaisesRegex(SSAVerificationRejected, "HASH"):
            verify_scalar_ssa(bad, cfg)
        x = ssa.as_dict()
        x.pop("sha256")
        x["source_cfg_sha256"] = "0" * 64
        with self.assertRaisesRegex(SSAVerificationRejected, "INPUT"):
            verify_scalar_ssa(encoded(x), cfg)

    def test_wrong_predecessor_or_non_dominating_phi_input(self):
        cfg, ssa = self.fixture()
        x = ssa.as_dict()
        x.pop("sha256")
        x["functions"][0]["blocks"][3]["phis"][0]["incoming"][0]["from"] = "b0000"
        with self.assertRaisesRegex(SSAVerificationRejected, "PHI"):
            verify_scalar_ssa(encoded(x), cfg)
        x = ssa.as_dict()
        x.pop("sha256")
        phi = x["functions"][0]["blocks"][3]["phis"][0]
        phi["incoming"][0]["ssa_ref"] = phi["incoming"][1]["ssa_ref"]
        with self.assertRaisesRegex(SSAVerificationRejected, "DOMINANCE"):
            verify_scalar_ssa(encoded(x), cfg)

    def test_missing_name_ref_and_wrong_original_expression(self):
        cfg, ssa = self.fixture()
        x = ssa.as_dict()
        x.pop("sha256")
        x["functions"][0]["blocks"][3]["terminator"]["value"].pop("ssa_ref")
        with self.assertRaisesRegex(SSAVerificationRejected, "USE"):
            verify_scalar_ssa(encoded(x), cfg)
        x = ssa.as_dict()
        x.pop("sha256")
        x["functions"][0]["blocks"][1]["instructions"][0]["ssa_value"]["value"] = 123
        with self.assertRaisesRegex(SSAVerificationRejected, "ORIGIN"):
            verify_scalar_ssa(encoded(x), cfg)

    def test_duplicate_definition_wrong_count(self):
        cfg, ssa = self.fixture()
        x = ssa.as_dict()
        x.pop("sha256")
        x["functions"][0]["blocks"][2]["instructions"][0]["definition"]["ssa_name"] = \
            x["functions"][0]["blocks"][1]["instructions"][0]["definition"]["ssa_name"]
        with self.assertRaisesRegex(SSAVerificationRejected, "DEF"):
            verify_scalar_ssa(encoded(x), cfg)
        x = ssa.as_dict()
        x.pop("sha256")
        x["functions"][0]["definitions"] += 1
        with self.assertRaisesRegex(SSAVerificationRejected, "COUNT"):
            verify_scalar_ssa(encoded(x), cfg)


if __name__ == "__main__":
    unittest.main()
