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

    def test_effect_resource_contract_tamper_rejected_after_rehash(self):
        cfg = snapshot([block(0, kind="return", value=i(3))],
                       effects=["panic"],
                       resources={"heap_allocations": 0, "may_block": False})
        ssa = lower_cfg_scalar_ssa(cfg)
        verification = verify_scalar_ssa(ssa, cfg).as_dict()
        self.assertTrue(verification["claims"]["effect_resource_metadata_matched_to_cfg"])
        self.assertEqual(len(verification["functions"][0]["source_effect_resource_sha256"]), 64)
        mutations = {
            "drop_contract": lambda f: f.pop("resource_contract"),
            "resource_upgrade": lambda f: f["resource_contract"].update(may_block=True),
            "bool_as_zero": lambda f: f["resource_contract"].update(may_block=0),
            "zero_as_bool": lambda f: f["resource_contract"].update(heap_allocations=False),
            "effect_upgrade": lambda f: f.update(declared_effects=["ffi"]),
            "inferred_elision": lambda f: f.update(inferred_transitive_effects=[]),
            "unreviewed_metadata": lambda f: f.update(verified_unsafe=True),
        }
        for name, mutate in mutations.items():
            with self.subTest(case=name):
                payload = ssa.as_dict()
                payload.pop("sha256")
                mutate(payload["functions"][0])
                with self.assertRaisesRegex(SSAVerificationRejected, "CONTRACT"):
                    verify_scalar_ssa(encoded(payload), cfg)

    def test_resealed_ssa_cannot_elevate_claims_or_hide_fields(self):
        cfg, ssa = self.fixture()
        for name, mutation in {
            "raise_native_proof": lambda x: x["claims"].update(native_backend_refinement_proven=True),
            "hide_false_proof": lambda x: x["claims"].pop("native_backend_refinement_proven"),
            "inject_unknown_claim": lambda x: x["claims"].update(memory_soundness_proved=True),
            "true_as_one": lambda x: x["claims"].update(phi_inputs_checked=1),
            "unknown_top_level": lambda x: x.update(elevated_proof=True),
        }.items():
            with self.subTest(case=name):
                forged = ssa.as_dict()
                forged.pop("sha256")
                mutation(forged)
                with self.assertRaisesRegex(SSAVerificationRejected, "CLAIMS"):
                    verify_scalar_ssa(encoded(forged), cfg)

    def test_resealed_zero_input_entry_phi_cannot_create_a_value(self):
        cfg = snapshot([block(0, kind="return", value=n("x"))],
                       params=[("x", "i32")])
        payload = lower_cfg_scalar_ssa(cfg).as_dict()
        payload.pop("sha256")
        function = payload["functions"][0]
        block0 = function["blocks"][0]
        block0["phis"] = [{
            "result": {"variable": "x", "ssa_name": "x@1",
                       "type": "i32", "defined_in": "b0000"},
            "incoming": [],
        }]
        block0["terminator"]["value"]["ssa_ref"] = "x@1"
        function["definitions"] += 1
        function["phi_count"] += 1
        with self.assertRaisesRegex(SSAVerificationRejected, "PHI"):
            verify_scalar_ssa(encoded(payload), cfg)

    def test_resealed_wrong_dead_local_definition_type_rejected(self):
        cfg = snapshot([block(0, [let("x", i(7))],
                              kind="return", value=i(8))])
        payload = lower_cfg_scalar_ssa(cfg).as_dict()
        payload.pop("sha256")
        function = payload["functions"][0]
        # Both SSA declarations agree with each other, but disagree with
        # the actual checked i32 initializer. x is deliberately never read.
        function["scalar_types"]["x"] = "u64"
        function["blocks"][0]["instructions"][0]["definition"]["type"] = "u64"
        with self.assertRaisesRegex(SSAVerificationRejected, "TYPE"):
            verify_scalar_ssa(encoded(payload), cfg)

    def test_resealed_nested_ssa_metadata_cannot_hide_semantics(self):
        cfg, valid = self.fixture()
        for name, mutate in {
            "block_extra_owner": lambda f: f["blocks"][0].update(loan_owner="forged"),
            "instruction_extra_drop": lambda f: f["blocks"][0]["instructions"][0].update(drop_owner=True),
            "definition_extra_effect": lambda f: f["blocks"][0]["instructions"][0]["definition"].update(ffi=True),
            "phi_extra_contract": lambda f: f["blocks"][3]["phis"][0].update(proof_status="certified"),
            "phi_edge_extra_unsafe": lambda f: f["blocks"][3]["phis"][0]["incoming"][0].update(unsafe=True),
        }.items():
            with self.subTest(case=name):
                payload = valid.as_dict()
                payload.pop("sha256")
                mutate(payload["functions"][0])
                with self.assertRaisesRegex(SSAVerificationRejected,
                                            "(BLOCKS|INSTRUCTIONS|DEF|PHI)"):
                    verify_scalar_ssa(encoded(payload), cfg)

    def test_forged_phi_from_dominating_but_overwritten_value_rejected(self):
        cfg, ssa = self.fixture()
        payload = ssa.as_dict()
        payload.pop("sha256")
        fn = payload["functions"][0]
        stale = fn["blocks"][0]["instructions"][0]["definition"]["ssa_name"]
        # Entry's x@0 dominates both branches but neither branch exits with it.
        for edge in fn["blocks"][3]["phis"][0]["incoming"]:
            edge["ssa_ref"] = stale
        with self.assertRaisesRegex(SSAVerificationRejected, "REACHING"):
            verify_scalar_ssa(encoded(payload), cfg)

    def test_omitted_live_join_phi_cannot_read_prebranch_value(self):
        cfg, ssa = self.fixture()
        payload = ssa.as_dict()
        payload.pop("sha256")
        fn = payload["functions"][0]
        join = fn["blocks"][3]
        join["phis"] = []
        join["terminator"]["value"]["ssa_ref"] = (
            fn["blocks"][0]["instructions"][0]["definition"]["ssa_name"])
        fn["definitions"] -= 1
        fn["phi_count"] -= 1
        # x@0 dominates the join but has been overwritten along BOTH edges.
        with self.assertRaisesRegex(SSAVerificationRejected, "REACHING"):
            verify_scalar_ssa(encoded(payload), cfg)

    def test_same_block_stale_read_after_assignment_rejected(self):
        cfg = snapshot([block(0, [let("x", i(1)), assign("x", i(2))],
                              kind="return", value=n("x"))])
        payload = lower_cfg_scalar_ssa(cfg).as_dict()
        payload.pop("sha256")
        fn = payload["functions"][0]
        previous = fn["blocks"][0]["instructions"][0]["definition"]["ssa_name"]
        fn["blocks"][0]["terminator"]["value"]["ssa_ref"] = previous
        with self.assertRaisesRegex(SSAVerificationRejected, "REACHING"):
            verify_scalar_ssa(encoded(payload), cfg)

    def test_live_join_values_and_dead_divergence_are_distinguished(self):
        cfg, valid = self.fixture()
        self.assertEqual(verify_scalar_ssa(valid, cfg).as_dict()["functions"][0]["phi_count"], 1)

        # Distinct branch writes do not need a PHI when the value is dead
        # after the join. Liveness must not demand redundant PHIs.
        dead = snapshot([
            block(0, [let("x", i(0))], kind="branch", condition=n("b", "bool"),
                  **{"then": "b0001", "else": "b0002"}),
            block(1, [assign("x", i(2))], kind="goto", target="b0003"),
            block(2, [assign("x", i(3))], kind="goto", target="b0003"),
            block(3, kind="return", value=i(8))], params=[("b", "bool")])
        result = verify_scalar_ssa(lower_cfg_scalar_ssa(dead), dead).as_dict()
        self.assertEqual(result["functions"][0]["phi_count"], 0)

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
