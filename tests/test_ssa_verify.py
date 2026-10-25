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
            "allocation_count_boolean": lambda f: f["resource_contract"].update(heap_allocations=False),
            "blocking_integer": lambda f: f["resource_contract"].update(may_block=0),
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

    def test_resealed_entry_phi_cannot_invent_source_value(self):
        cfg = snapshot([block(0, kind="return", value=n("x"))],
                       params=[("x", "i32")])
        forged = lower_cfg_scalar_ssa(cfg).as_dict()
        forged.pop("sha256")
        fn = forged["functions"][0]
        fn["blocks"][0]["phis"] = [{
            "result": {"variable": "x", "ssa_name": "x@1",
                       "type": "i32", "defined_in": "b0000"},
            "incoming": [],
        }]
        fn["blocks"][0]["terminator"]["value"]["ssa_ref"] = "x@1"
        fn["definitions"] += 1
        fn["phi_count"] += 1
        with self.assertRaisesRegex(SSAVerificationRejected, "PHI"):
            verify_scalar_ssa(encoded(forged), cfg)

    def test_resealed_nested_ssa_fields_cannot_hide_effects(self):
        cfg, ssa = self.fixture()
        mutations = {
            "block_owner": ("BLOCKS", lambda f: f["blocks"][0].update(owner="forged")),
            "instruction_effect": ("INSTRUCTIONS", lambda f: f["blocks"][0]["instructions"][0].update(ffi=True)),
            "definition_drop": ("DEF", lambda f: f["blocks"][0]["instructions"][0]["definition"].update(drop=True)),
            "phi_proof": ("PHI", lambda f: f["blocks"][3]["phis"][0].update(proved=True)),
            "phi_edge_unsafe": ("PHI", lambda f: f["blocks"][3]["phis"][0]["incoming"][0].update(unsafe=True)),
        }
        for name, (code, mutation) in mutations.items():
            with self.subTest(name=name):
                forged = ssa.as_dict()
                forged.pop("sha256")
                mutation(forged["functions"][0])
                with self.assertRaisesRegex(SSAVerificationRejected, code):
                    verify_scalar_ssa(encoded(forged), cfg)

    def test_literal_types_and_source_spans_survive_ssa_rehash(self):
        cfg = snapshot([block(0, [let("x", i(0))], kind="return", value=i(0))])
        ssa = lower_cfg_scalar_ssa(cfg)
        self.assertTrue(verify_scalar_ssa(ssa, cfg).as_dict())
        for name, mutation in {
            "initializer_bool_instead_of_zero":
                lambda f: f["blocks"][0]["instructions"][0]["ssa_value"].update(value=False),
            "return_bool_instead_of_zero":
                lambda f: f["blocks"][0]["terminator"]["value"].update(value=False),
            "span_start_bool_instead_of_zero":
                lambda f: f["blocks"][0]["instructions"][0]["span"].update(start=False),
        }.items():
            with self.subTest(case=name):
                forged = ssa.as_dict()
                forged.pop("sha256")
                mutation(forged["functions"][0])
                with self.assertRaisesRegex(SSAVerificationRejected, "ORIGIN"):
                    verify_scalar_ssa(encoded(forged), cfg)

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
