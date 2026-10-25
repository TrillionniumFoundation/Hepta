"""P1 structural CFG qualification; not SSA or lifetime soundness evidence."""
from __future__ import annotations

from hashlib import sha256
import json
import unittest

from hepta.cfg import CFGRejected, lower_checked_cfg, lower_hsir_cfg
from hepta.checker import check
from hepta.hsir import HSIRSnapshot, lower_checked_program
from hepta.parser import parse


class CFGTests(unittest.TestCase):
    SOURCE = """module cfg_fixture;
pub enum Decision { Left(i32), Right(i32) }
fn pick(value: read Decision) -> i32 effects {} {
    match value {
        Decision::Left(x) => { return x; },
        Decision::Right(y) => { return y; },
    }
}
fn work(n: i32) -> i32 effects { panic } {
    let mut total: i32 = 0;
    for i in 0..4 { total = total + 1; }
    while total < n {
        if n > 10 { return total; }
        total = total + 1;
    }
    return total;
}
"""

    def _checked(self, source=None):
        program = parse(self.SOURCE if source is None else source)
        result = check(program)
        self.assertTrue(result.ok, [d.to_dict() for d in result.diagnostics])
        return program, result

    def test_deterministic_cfg_and_integrity(self):
        program, checked = self._checked()
        left = lower_checked_cfg(program, checked)
        right = lower_checked_cfg(program, checked)
        self.assertEqual(left.sha256, right.sha256)
        cfg = left.as_dict()
        self.assertEqual(cfg["schema"], "hepta.cfg.v0")
        self.assertEqual(len(cfg["functions"]), 2)
        self.assertFalse(cfg["claims"]["ssa_constructed"])
        self.assertFalse(cfg["claims"]["pointer_provenance_proved"])
        self.assertFalse(cfg["claims"]["backend_semantics_refined"])
        self.assertEqual(cfg["source_hsir_sha256"], lower_checked_program(program, checked).sha256)
        self.assertNotEqual(cfg["sha256"], "")
        mutated = left.as_dict()
        mutated["functions"][0]["blocks"][0]["id"] = "forged"
        self.assertNotEqual(mutated, left.as_dict())

    def test_edges_targets_terminators_and_backedge(self):
        program, checked = self._checked()
        for fn in lower_checked_cfg(program, checked).as_dict()["functions"]:
            ids = {b["id"] for b in fn["blocks"]}
            self.assertEqual(fn["entry"], "b0000")
            self.assertEqual(len(ids), len(fn["blocks"]))
            self.assertTrue(all(b["terminator"] is not None for b in fn["blocks"]))
            self.assertTrue(all(e["from"] in ids and e["to"] in ids for e in fn["edges"]))
        work = lower_checked_cfg(program, checked).as_dict()["functions"][1]
        operations = [b["terminator"]["kind"] for b in work["blocks"]]
        self.assertIn("range_next", operations)
        self.assertIn("branch", operations)
        self.assertIn("return", operations)
        self.assertTrue(any(int(e["to"][1:]) <= int(e["from"][1:]) for e in work["edges"]))
        init = [ins for b in work["blocks"] for ins in b["instructions"] if ins["operation"] == "range_init"]
        self.assertEqual(len(init), 1)
        self.assertEqual(init[0]["fields"]["evaluation_order"], ["start", "end"])
        self.assertTrue(init[0]["fields"]["exclusive_end"])

    def test_exhaustive_match_arms_are_distinct_successors(self):
        program, checked = self._checked()
        pick = lower_checked_cfg(program, checked).as_dict()["functions"][0]
        switches = [b["terminator"] for b in pick["blocks"] if b["terminator"]["kind"] == "switch"]
        self.assertEqual(len(switches), 1)
        self.assertEqual(len(switches[0]["arms"]), 2)
        self.assertNotEqual(switches[0]["arms"][0]["target"], switches[0]["arms"][1]["target"])
        self.assertEqual({x["pattern"]["variant"] for x in switches[0]["arms"]}, {"Left", "Right"})

    def test_early_return_retains_unreachable_source(self):
        source = """module dead;
fn f(n: i32) -> i32 effects {} { return n; let z: i32 = n; }
"""
        # Some checker versions reject unreachable code. Both outcomes are
        # acceptable, but silently omitting it from a validated CFG is not.
        program = parse(source)
        checked = check(program)
        if checked.ok:
            cfg = lower_checked_cfg(program, checked).as_dict()["functions"][0]
            self.assertEqual(len(cfg["unreachable_source"]), 1)
            self.assertEqual(cfg["unreachable_source"][0]["statement"]["operation"], "let")
        else:
            self.assertTrue(checked.diagnostics)

    def test_invalid_snapshot_and_unknown_control_are_rejected(self):
        program, checked = self._checked()
        hsir = lower_checked_program(program, checked)
        forged = HSIRSnapshot(hsir.schema, hsir.canonical_json, "0" * 64)
        with self.assertRaisesRegex(CFGRejected, "digest mismatch"):
            lower_hsir_cfg(forged)
        with self.assertRaisesRegex(CFGRejected, "requires HSIR"):
            lower_hsir_cfg(HSIRSnapshot("other.v0", hsir.canonical_json, hsir.sha256))
        payload = json.loads(hsir.canonical_json)
        payload["functions"][1]["body"][0]["operation"] = "goto"
        canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False,
                               allow_nan=False, separators=(",", ":"))
        tampered = HSIRSnapshot(hsir.schema, canonical, sha256(canonical.encode("utf-8")).hexdigest())
        with self.assertRaisesRegex(CFGRejected, "UNSUPPORTED"):
            lower_hsir_cfg(tampered)

    def test_unchecked_input_never_yields_a_cfg(self):
        program = parse("module bad; fn f(n: i32) -> i32 effects {} { return n + 1; }")
        checked = check(program)
        self.assertFalse(checked.ok)
        with self.assertRaises(ValueError):
            lower_checked_cfg(program, checked)

    def test_unsafe_depth_is_explicit(self):
        source = """module unsafe_fixture;
fn f(n: i32) -> i32 effects {} {
    unsafe { let x: i32 = n; return x; }
}
"""
        program, checked = self._checked(source)
        cfg = lower_checked_cfg(program, checked).as_dict()["functions"][0]
        instructions = [i for b in cfg["blocks"] for i in b["instructions"]]
        self.assertEqual([i["unsafe_depth"] for i in instructions if i["operation"] == "let"], [1])
        returns = [b["terminator"] for b in cfg["blocks"] if b["terminator"]["kind"] == "return"]
        self.assertEqual(len(returns), 1)
        self.assertEqual(returns[0]["unsafe_depth"], 1)


if __name__ == "__main__":
    unittest.main()
