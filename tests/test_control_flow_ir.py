"""P1 CFG exporter: shape, determinism, fail-closed boundaries and CLI."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from hepta.checker import check
from hepta.control_flow_ir import lower_control_flow_program
from hepta.parser import parse


class ControlFlowIRTests(unittest.TestCase):
    def lower(self, source: str):
        program = parse(source, "cfg.hepta")
        checked = check(program)
        self.assertTrue(checked.ok, [d.to_dict() for d in checked.diagnostics])
        return lower_control_flow_program(program, checked, project_sha256="fixed-graph")

    @staticmethod
    def blocks(hmir: dict):
        return hmir["functions"][0]["blocks"]

    def assert_graph(self, hmir):
        blocks = self.blocks(hmir)
        ids = {block["id"] for block in blocks}
        self.assertEqual(len(ids), len(blocks))
        for block in blocks:
            self.assertIsNotNone(block["terminator"], block["id"])
            for target in block["terminator"]["targets"]:
                self.assertIn(target["to"], ids)
        self.assertFalse(hmir["claims"]["ssa_constructed"])
        self.assertFalse(hmir["claims"]["translation_correctness_proved"])
        self.assertFalse(hmir["claims"]["independent_borrow_validation"])

    def test_reproducible_and_source_bound(self):
        source = "fn pick(flag: bool) -> i64 effects {} { if flag { return 1; } else { return 2; } }"
        first = self.lower(source)
        self.assertEqual(first, self.lower(source))
        self.assertNotEqual(first["sha256"], self.lower(source.replace("return 2", "return 3"))["sha256"])
        self.assertEqual(first["schema"], "hepta.hmir.cfg.v0")
        self.assertEqual(first["project_sha256"], "fixed-graph")
        self.assert_graph(first)

    def test_if_with_both_arms_return_has_no_fake_join(self):
        hmir = self.lower(
            "fn pick(flag: bool) -> i64 effects {} "
            "{ if flag { return 1; } else { return 2; } }")
        blocks = self.blocks(hmir)
        self.assertEqual(len(blocks), 3)
        self.assertEqual(blocks[0]["terminator"]["operation"], "branch")
        self.assertEqual([b["terminator"]["operation"] for b in blocks[1:]],
                         ["return", "return"])
        self.assert_graph(hmir)

    def test_partial_if_joins_only_continuing_branch(self):
        hmir = self.lower(
            "fn pick(flag: bool) -> i64 effects {} "
            "{ if flag { return 1; } return 0; }")
        blocks = self.blocks(hmir)
        joins = [target for b in blocks for target in b["terminator"]["targets"]
                 if target["role"] == "join"]
        self.assertEqual(len(joins), 1)
        self.assert_graph(hmir)

    def test_while_loop_backedge_and_exit(self):
        hmir = self.lower(
            "fn iterate(n: u64) -> u64 effects {} { "
            "let mut x: u64 = 0; "
            "while x < n { x = wrapping_add(x, 1); } return x; }")
        blocks = self.blocks(hmir)
        self.assertEqual(len(blocks), 4)
        self.assertEqual(sum(t["role"] == "backedge"
                             for b in blocks for t in b["terminator"]["targets"]), 1)
        self.assertEqual(sum(b["terminator"]["operation"] == "branch"
                             for b in blocks), 1)
        self.assert_graph(hmir)

    def test_for_range_preheader_and_backedge(self):
        hmir = self.lower(
            "fn accumulate(n: u64) -> u64 effects {} { "
            "let mut acc: u64 = 0; "
            "for i in 0..n { acc = wrapping_add(acc, i); } return acc; }")
        blocks = self.blocks(hmir)
        self.assertEqual(blocks[0]["instructions"][-1]["operation"], "range_init")
        self.assertEqual(blocks[1]["terminator"]["operation"], "range_branch")
        self.assertIn("range_advance", [instruction["operation"]
                        for instruction in blocks[2]["instructions"]])
        self.assert_graph(hmir)

    def test_exhaustive_enum_switch_has_only_declared_cases(self):
        hmir = self.lower(
            "fn choose(input: Result<u64, u8>) -> u64 effects {} "
            "{ match input { "
            "Result::Ok(value) => { return value; }, "
            "Result::Err(_) => { return 0; }, "
            "} }")
        blocks = self.blocks(hmir)
        switch = blocks[0]["terminator"]
        self.assertEqual(switch["operation"], "switch_enum")
        self.assertEqual({t["role"] for t in switch["targets"]},
                         {"Result::Ok", "Result::Err"})
        self.assert_graph(hmir)

    def test_ownership_sites_are_explicitly_unproved(self):
        source = (
            "fn consume(data: take Buffer<u8>) -> u64 "
            "effects {alloc, block, panic} { "
            "release(move data); return 0; }"
        )
        hmir = self.lower(source)
        blocks = self.blocks(hmir)
        events = [event for block in blocks for inst in block["instructions"]
                  if inst.get("expression") is not None
                  for event in inst["expression"]["ownership_sites"]]
        self.assertIn("move", [event["operation"] for event in events])
        self.assertIn("explicit_release_call", [event["operation"] for event in events])
        self.assertTrue(all(e["proof"] == "syntactic_site_only" for e in events))
        self.assertFalse(hmir["claims"]["automatic_drop_lowering"])
        self.assert_graph(hmir)

    def test_extern_is_never_disguised_as_safe_cfg(self):
        hmir = self.lower(
            'extern "C" fn legacy(p: raw const u8) -> u64 effects {ffi, unsafe};')
        fn = hmir["functions"][0]
        self.assertTrue(fn["extern_c"])
        self.assertIsNone(fn["entry"])
        self.assertEqual(fn["blocks"], [])
        self.assertTrue(hmir["foreign_assumptions"])
        self.assertFalse(hmir["claims"]["pointer_provenance_proved"])

    def test_missing_frontend_evidence_and_rejected_source_fail_closed(self):
        source = "fn f(n: u64) -> u64 effects {} { return n; }"
        program = parse(source, "cfg.hepta")
        checked = check(program)
        checked.expr_types.clear()
        with self.assertRaisesRegex(ValueError, "without frontend type evidence"):
            lower_control_flow_program(program, checked)
        broken = parse("fn f() -> u64 effects {} { return false; }", "bad.hepta")
        rejected = check(broken)
        self.assertFalse(rejected.ok)
        with self.assertRaisesRegex(ValueError, "rejected"):
            lower_control_flow_program(broken, rejected)

    def test_cli_frontend_only_does_not_claim_native_validation(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "main.hepta"
            source.write_text(
                "fn main() -> i32 effects {} { return 0; }",
                encoding="utf-8")
            run = subprocess.run(
                [sys.executable, "-m", "hepta.control_flow_ir",
                 str(source), "--frontend-only"],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            payload = json.loads(run.stdout)
            self.assertEqual(payload["schema"], "hepta.hmir.export.v0")
            self.assertEqual(payload["status"], "frontend_only")
            self.assertTrue(payload["ok"])
            self.assertNotEqual(payload["native_validation"], "passed")
            self.assertFalse(payload["hmir"]["claims"]["native_codegen_validated"])


if __name__ == "__main__":
    unittest.main()
