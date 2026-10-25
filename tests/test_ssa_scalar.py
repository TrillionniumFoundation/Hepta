"""Pruned typed scalar SSA and fail-closed profile acceptance tests."""
from __future__ import annotations

import json
from hashlib import sha256
import unittest
from hepta.cfg import CFGSnapshot
from hepta.ssa import SSARejected, lower_cfg_scalar_ssa


def typ(kind):
    return {"type": kind, "args": [], "length": None}


def expr(kind, value, ty, *operands):
    return {"node": "expr", "operation": kind, "value": value,
            "result_type": typ(ty), "operands": list(operands), "type_args": [], "span": None}


def n(name, ty="i32"):
    return expr("name", name, ty)


def i(value):
    return expr("int", value, "i32")


def assign(name, val):
    return {"operation": "assign", "fields": {"target": n(name), "expr": val}, "span": None}


def let(name, val, mutable=True):
    return {"operation": "let", "fields": {"name": name, "type": typ("i32"),
                                           "mutable": mutable, "expr": val}, "span": None}


def block(index, instructions=(), **terminator):
    return {"id": f"b{index:04d}", "instructions": list(instructions), "terminator": terminator}


def snapshot(blocks, params=(), *, effects=()):
    edges = []
    for block in blocks:
        t = block["terminator"]
        k = t["kind"]
        dests = ([t["target"]] if k == "goto" else
                 [t["then"], t["else"]] if k == "branch" else
                 [t["body"], t["exit"]] if k == "range_next" else
                 [a["target"] for a in t["arms"]] if k == "switch" else [])
        edges.extend({"from": block["id"], "to": dest} for dest in dests)
    fn = {"name": "f", "entry": "b0000", "blocks": blocks, "edges": edges,
          "param_types": [{"name": name, "type": typ(ty), "ownership": "value"}
                          for name, ty in params],
          "inferred_transitive_effects": list(effects), "return_type": typ("i32")}
    data = {"schema": "hepta.cfg.v0", "status": "structural_cfg_only_not_proved", "functions": [fn]}
    encoded = json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return CFGSnapshot("hepta.cfg.v0", encoded, sha256(encoded.encode()).hexdigest())


class SSATests(unittest.TestCase):
    def test_diamond_phi(self):
        cfg = snapshot([
            block(0, [let("x", i(0))], kind="branch", condition=n("choose", "bool"),
                  **{"then": "b0001", "else": "b0002"}),
            block(1, [assign("x", i(11))], kind="goto", target="b0003"),
            block(2, [assign("x", i(22))], kind="goto", target="b0003"),
            block(3, kind="return", value=n("x")),
        ], params=[("choose", "bool")])
        result = lower_cfg_scalar_ssa(cfg).as_dict()
        self.assertEqual(result["schema"], "hepta.ssa.scalar.v0")
        fn = result["functions"][0]
        self.assertEqual(fn["phi_count"], 1)
        self.assertEqual(fn["definitions"], 5)
        phi = fn["blocks"][3]["phis"][0]
        self.assertEqual(phi["result"]["variable"], "x")
        self.assertEqual([x["from"] for x in phi["incoming"]], ["b0001", "b0002"])
        self.assertNotEqual(phi["incoming"][0]["ssa_ref"], phi["incoming"][1]["ssa_ref"])
        self.assertEqual(fn["blocks"][3]["terminator"]["value"]["ssa_ref"], phi["result"]["ssa_name"])
        self.assertFalse(result["claims"]["whole_language_ssa_complete"])
        self.assertFalse(result["claims"]["native_backend_refinement_proven"])
        self.assertEqual(lower_cfg_scalar_ssa(cfg).sha256, lower_cfg_scalar_ssa(cfg).sha256)

    def test_while_loop_phi_and_backedge(self):
        cfg = snapshot([
            block(0, [let("x", i(0))], kind="goto", target="b0001"),
            block(1, kind="branch", condition=expr("binary", "<", "bool", n("x"), n("n")),
                  **{"then": "b0002", "else": "b0003"}),
            block(2, [assign("x", expr("binary", "+", "i32", n("x"), i(1)))],
                  kind="goto", target="b0001"),
            block(3, kind="return", value=n("x")),
        ], params=[("n", "i32")], effects=["panic"])
        f = lower_cfg_scalar_ssa(cfg).as_dict()["functions"][0]
        self.assertEqual(f["phi_count"], 1)
        phi = f["blocks"][1]["phis"][0]
        self.assertEqual([x["from"] for x in phi["incoming"]], ["b0000", "b0002"])
        self.assertEqual(f["blocks"][1]["terminator"]["condition"]["operands"][0]["ssa_ref"],
                         phi["result"]["ssa_name"])
        self.assertEqual(f["blocks"][2]["instructions"][0]["ssa_value"]["operands"][0]["ssa_ref"],
                         phi["result"]["ssa_name"])
        self.assertEqual(f["blocks"][3]["terminator"]["value"]["ssa_ref"],
                         phi["result"]["ssa_name"])

    def test_dead_branch_local_does_not_require_invalid_phi(self):
        cfg = snapshot([
            block(0, kind="branch", condition=n("choose", "bool"),
                  **{"then": "b0001", "else": "b0002"}),
            block(1, [let("tmp", i(3), False)], kind="goto", target="b0003"),
            block(2, kind="goto", target="b0003"),
            block(3, kind="return", value=i(8)),
        ], params=[("choose", "bool")])
        fn = lower_cfg_scalar_ssa(cfg).as_dict()["functions"][0]
        self.assertEqual(fn["phi_count"], 0)

    def test_missing_branch_definition_rejects(self):
        cfg = snapshot([
            block(0, kind="branch", condition=n("choose", "bool"),
                  **{"then": "b0001", "else": "b0002"}),
            block(1, [let("x", i(3))], kind="goto", target="b0003"),
            block(2, kind="goto", target="b0003"),
            block(3, kind="return", value=n("x")),
        ], params=[("choose", "bool")])
        with self.assertRaisesRegex(SSARejected, "UNDEFINED"):
            lower_cfg_scalar_ssa(cfg)

    def test_non_scalar_operations_must_fail_closed(self):
        bad = snapshot([
            block(0, [{"operation": "expr",
                       "fields": {"expr": expr("call", "print_i64", "i32", i(4))}}],
                  kind="return", value=i(3))
        ])
        with self.assertRaisesRegex(SSARejected, "UNSUPPORTED"):
            lower_cfg_scalar_ssa(bad)
        bad = snapshot([
            block(0, kind="range_next", name="i", body="b0001", exit="b0002"),
            block(1, kind="goto", target="b0000"),
            block(2, kind="return", value=i(3)),
        ])
        with self.assertRaisesRegex(SSARejected, "UNSUPPORTED"):
            lower_cfg_scalar_ssa(bad)
        unsafe = snapshot([block(0, kind="return", value=i(3))], effects=["unsafe"])
        with self.assertRaisesRegex(SSARejected, "EFFECT"):
            lower_cfg_scalar_ssa(unsafe)

    def test_rehashed_cfg_invalid_types_operators_and_effects_reject_deterministically(self):
        base = snapshot([
            block(0, kind="return", value=expr("binary", "+", "i32", n("a"), n("b")))
        ], params=[("a", "i32"), ("b", "i32")], effects=["panic"])
        clean = json.loads(base.canonical_json)
        import copy
        mutations = {
            "parameter_type_array": lambda d: d["functions"][0]["param_types"][0]["type"].update(type=["i32"]),
            "binary_op_array": lambda d: d["functions"][0]["blocks"][0]["terminator"]["value"].update(value=["+"]),
            "expression_kind_array": lambda d: d["functions"][0]["blocks"][0]["terminator"]["value"].update(operation=["binary"]),
            "effect_list_nested": lambda d: d["functions"][0].update(inferred_transitive_effects=[["panic"]]),
            "effect_string": lambda d: d["functions"][0].update(inferred_transitive_effects="panic"),
            "extra_type_field": lambda d: d["functions"][0]["return_type"].update(unreviewed_ownership=True),
        }
        for case, mutate in mutations.items():
            with self.subTest(case=case):
                changed = copy.deepcopy(clean)
                mutate(changed)
                source = json.dumps(changed, sort_keys=True, separators=(",", ":"))
                rejected = CFGSnapshot("hepta.cfg.v0", source, sha256(source.encode()).hexdigest())
                with self.assertRaises(SSARejected):
                    lower_cfg_scalar_ssa(rejected)

    def test_rehashed_cfg_nan_literal_fails_before_ssa_output(self):
        base = snapshot([block(0, kind="return", value=i(3))])
        corrupted = json.loads(base.canonical_json)
        corrupted["functions"][0]["blocks"][0]["terminator"]["value"] = expr(
            "float", float("nan"), "f64")
        # Python's JSON reader normally admits the nonstandard NaN token.
        source = json.dumps(corrupted, sort_keys=True, separators=(",", ":"))
        self.assertIn("NaN", source)
        forged = CFGSnapshot("hepta.cfg.v0", source, sha256(source.encode()).hexdigest())
        with self.assertRaises(SSARejected):
            lower_cfg_scalar_ssa(forged)

    def test_snapshot_tampering_rejected(self):
        cfg = snapshot([block(0, kind="return", value=i(3))])
        bad = CFGSnapshot(cfg.schema, cfg.canonical_json, "0" * 64)
        with self.assertRaisesRegex(SSARejected, "SHA-256"):
            lower_cfg_scalar_ssa(bad)
        output = lower_cfg_scalar_ssa(cfg)
        forgery = output.as_dict()
        forgery["functions"].clear()
        self.assertEqual(len(output.as_dict()["functions"]), 1)

    def test_immutable_reassignment_rejected(self):
        cfg = snapshot([
            block(0, [let("x", i(3), False), assign("x", i(5))],
                  kind="return", value=n("x"))
        ])
        with self.assertRaisesRegex(SSARejected, "immutable"):
            lower_cfg_scalar_ssa(cfg)

    def test_mismatched_branch_and_return_rejected(self):
        bad = snapshot([block(0, kind="branch", condition=i(3),
                              **{"then": "b0001", "else": "b0002"}),
                        block(1, kind="return", value=i(3)),
                        block(2, kind="return", value=i(3))])
        with self.assertRaisesRegex(SSARejected, "CONDITION"):
            lower_cfg_scalar_ssa(bad)
        bad = snapshot([block(0, kind="return", value=n("p", "bool"))], params=[("p", "bool")])
        with self.assertRaisesRegex(SSARejected, "RETURN"):
            lower_cfg_scalar_ssa(bad)


if __name__ == "__main__":
    unittest.main()
