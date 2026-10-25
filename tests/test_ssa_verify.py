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

    def test_rehashed_old_still_dominating_local_version_rejected(self):
        cfg = snapshot([
            block(0, [let("x", i(4)), assign("x", i(7))],
                  kind="return", value=n("x"))])
        ssa = lower_cfg_scalar_ssa(cfg)
        self.assertTrue(verify_scalar_ssa(ssa, cfg).as_dict()["functions"][0][
            "latest_source_version_reads_verified"])
        forged = ssa.as_dict()
        forged.pop("sha256")
        item = forged["functions"][0]["blocks"][0]
        # x@0 still dominates this return and occurs before it; the source
        # already performed another assignment, so the correct read is x@1.
        item["terminator"]["value"]["ssa_ref"] = item["instructions"][0][
            "definition"]["ssa_name"]
        with self.assertRaisesRegex(SSAVerificationRejected, "REACHING"):
            verify_scalar_ssa(encoded(forged), cfg)

    def test_rehashed_old_still_dominating_phi_predecessor_rejected(self):
        cfg, ssa = self.fixture()
        forged = ssa.as_dict()
        forged.pop("sha256")
        first = forged["functions"][0]["blocks"][0]["instructions"][0][
            "definition"]["ssa_name"]
        join_phi = forged["functions"][0]["blocks"][3]["phis"][0]
        # x@0 dominates b0001, but b0001 overwrote x before its PHI edge.
        join_phi["incoming"][0]["ssa_ref"] = first
        with self.assertRaisesRegex(SSAVerificationRejected, "REACHING"):
            verify_scalar_ssa(encoded(forged), cfg)

    def test_rehashed_old_still_dominating_loop_backedge_rejected(self):
        cfg = snapshot([
            block(0, [let("x", i(0))], kind="goto", target="b0001"),
            block(1, kind="branch",
                  condition=expr("binary", "<", "bool", n("x"), n("limit")),
                  **{"then": "b0002", "else": "b0003"}),
            block(2, [assign("x", expr("binary", "+", "i32", n("x"), i(1)))],
                  kind="goto", target="b0001"),
            block(3, kind="return", value=n("x"))],
            params=[("limit", "i32")], effects=["panic"])
        ssa = lower_cfg_scalar_ssa(cfg)
        self.assertTrue(verify_scalar_ssa(ssa, cfg).as_dict())
        forged = ssa.as_dict()
        forged.pop("sha256")
        first = forged["functions"][0]["blocks"][0]["instructions"][0][
            "definition"]["ssa_name"]
        loop_phi = forged["functions"][0]["blocks"][1]["phis"][0]
        backedge = next(edge for edge in loop_phi["incoming"]
                        if edge["from"] == "b0002")
        # x@0 dominates b0002, but the backedge must carry its new x version.
        backedge["ssa_ref"] = first
        with self.assertRaisesRegex(SSAVerificationRejected, "REACHING"):
            verify_scalar_ssa(encoded(forged), cfg)

    def test_rehashed_unused_scalar_retag_rejected_against_source(self):
        cfg = snapshot([
            block(0, [let("unused", i(1))], kind="return", value=i(7))])
        ssa = lower_cfg_scalar_ssa(cfg)
        self.assertTrue(verify_scalar_ssa(ssa, cfg).as_dict())
        forged = ssa.as_dict()
        forged.pop("sha256")
        fn = forged["functions"][0]
        # The source local is i32. Its output is deliberately unused, so
        # a verifier that checks use types but never source types accepts a
        # newly hashed forged u32 SSA definition.
        fn["scalar_types"]["unused"] = "u32"
        fn["blocks"][0]["instructions"][0]["definition"]["type"] = "u32"
        with self.assertRaisesRegex(SSAVerificationRejected, "SOURCE_TYPE"):
            verify_scalar_ssa(encoded(forged), cfg)

    def test_rehashed_bool_as_integer_source_is_not_equivalent(self):
        # In native Python equality, 0 == False and 1 == True.
        # Exact source-origin comparison must preserve JSON scalar type.
        cfg, ssa = self.fixture()
        forged = ssa.as_dict()
        forged.pop("sha256")
        forged["functions"][0]["blocks"][0]["instructions"][0]["ssa_value"]["value"] = False
        with self.assertRaisesRegex(SSAVerificationRejected, "ORIGIN"):
            verify_scalar_ssa(encoded(forged), cfg)
        for integer, boolean in ((0, False), (1, True)):
            with self.subTest(source_value=integer):
                cfg = snapshot([block(0, kind="return", value=i(integer))])
                ssa = lower_cfg_scalar_ssa(cfg)
                forged = ssa.as_dict()
                forged.pop("sha256")
                forged["functions"][0]["blocks"][0]["terminator"]["value"]["value"] = boolean
                with self.assertRaisesRegex(SSAVerificationRejected, "ORIGIN"):
                    verify_scalar_ssa(encoded(forged), cfg)

    def test_resigned_entry_phi_cannot_manufacture_source_value(self):
        cfg = snapshot([block(0, kind="return", value=n("x"))],
                       params=[("x", "i32")])
        payload = lower_cfg_scalar_ssa(cfg).as_dict()
        payload.pop("sha256")
        function = payload["functions"][0]
        first = function["blocks"][0]
        first["phis"] = [{
            "result": {"variable": "x", "ssa_name": "x@1",
                       "type": "i32", "defined_in": "b0000"},
            "incoming": [],
        }]
        first["terminator"]["value"]["ssa_ref"] = "x@1"
        function["definitions"] += 1
        function["phi_count"] += 1
        with self.assertRaisesRegex(SSAVerificationRejected, "PHI"):
            verify_scalar_ssa(encoded(payload), cfg)

    def test_closed_ssa_nested_metadata_and_claim_types(self):
        cfg, original = self.fixture()
        mutations = {
            "unexpected block": lambda f: f["blocks"][0].update(loan_owner="forged"),
            "unexpected instruction": lambda f: f["blocks"][0]["instructions"][0].update(drop_owner=True),
            "unexpected definition": lambda f: f["blocks"][0]["instructions"][0]["definition"].update(ffi=True),
            "unexpected phi": lambda f: f["blocks"][3]["phis"][0].update(proof_status="certified"),
            "unexpected phi edge": lambda f: f["blocks"][3]["phis"][0]["incoming"][0].update(unsafe=True),
            "unexpected function": lambda f: f.update(provenance_proved=True),
        }
        for name, mutate in mutations.items():
            with self.subTest(case=name):
                payload = original.as_dict()
                payload.pop("sha256")
                mutate(payload["functions"][0])
                with self.assertRaisesRegex(SSAVerificationRejected,
                                            "(BLOCKS|INSTRUCTIONS|DEF|PHI|FUNCTIONS)"):
                    verify_scalar_ssa(encoded(payload), cfg)
        for key, value in (("phi_inputs_checked", 1),
                           ("native_backend_refinement_proven", 0)):
            with self.subTest(forged_claim=key):
                payload = original.as_dict()
                payload.pop("sha256")
                payload["claims"][key] = value
                with self.assertRaisesRegex(SSAVerificationRejected, "CLAIMS"):
                    verify_scalar_ssa(encoded(payload), cfg)

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
