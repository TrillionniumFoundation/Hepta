"""CFG v0 graph, hash, branch, loop, unsafe and rejection tests."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from hepta.ast import Stmt
from hepta.checker import check
from hepta.flow_ir import FlowLowerError, lower_checked_cfg
from hepta.parser import parse
from hepta.pipeline import analyze, cfg_analysis


class FlowIRTests(unittest.TestCase):
    ADD = "fn add(a: i64, b: i64) -> i64 effects {panic} { return a + b; }"

    def lower(self, source):
        p = parse(source, "flow.hepta")
        checked = check(p)
        self.assertTrue(checked.ok, [d.to_dict() for d in checked.diagnostics])
        return lower_checked_cfg(p, checked)

    def test_determinism_and_source_identity(self):
        a = self.lower(self.ADD)
        self.assertEqual(a, self.lower(self.ADD))
        self.assertEqual(a["schema"], "hepta.cfg.v0")
        self.assertNotEqual(a["sha256"], self.lower(
            self.ADD.replace("a + b", "b + a"))["sha256"])
        self.assertFalse(a["claims"]["machine_lowering_verified"])
        self.assertFalse(a["claims"]["borrow_check_independent"])
        blocks = a["functions"][0]["graph"]["blocks"]
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0]["terminator"]["kind"], "return")

    def test_project_identity_changes_digest(self):
        p = parse(self.ADD)
        c = check(p)
        a = lower_checked_cfg(p, c, project_sha256="a")
        b = lower_checked_cfg(p, c, project_sha256="b")
        self.assertNotEqual(a["sha256"], b["sha256"])

    def test_terminal_if_has_no_spurious_join(self):
        ir = self.lower(
            "fn choose(n: i64) -> i64 effects {} { "
            "if n > 0 { return 1; } else { return 2; } }")
        blocks = ir["functions"][0]["graph"]["blocks"]
        self.assertEqual([b["terminator"]["kind"] for b in blocks],
                         ["branch", "return", "return"])

    def test_if_fallthrough_has_join(self):
        ir = self.lower(
            "fn choose(n: i64) -> i64 effects {} { "
            "let mut v: i64 = 0; if n > 0 { v = 1; } "
            "else { v = 2; } return v; }")
        terms = [b["terminator"]["kind"]
                 for b in ir["functions"][0]["graph"]["blocks"]]
        self.assertEqual(terms.count("return"), 1)
        self.assertEqual(terms.count("branch"), 1)
        self.assertEqual(terms.count("goto"), 2)

    def test_while_has_backedge(self):
        ir = self.lower(
            "fn count(n: i64) -> i64 effects {panic} { "
            "let mut i: i64 = 0; while i < n { i = i + 1; } return i; }")
        terms = [b["terminator"] for b in ir["functions"][0]["graph"]["blocks"]]
        self.assertTrue(any(t["kind"] == "goto" and t["target"] == "bb1"
                            for t in terms))

    def test_for_remains_structured(self):
        ir = self.lower(
            "fn count(n: u64) -> u64 effects {panic} { "
            "let mut total: u64 = 0; for i in 0..n { "
            "total = wrapping_add(total, i); } return total; }")
        terms = [b["terminator"] for b in ir["functions"][0]["graph"]["blocks"]]
        loops = [t for t in terms if t["kind"] == "structured_for_range"]
        self.assertEqual(len(loops), 1)
        self.assertFalse(loops[0]["iteration_semantics_lowered"])

    def test_match_has_dispatch(self):
        ir = self.lower(
            "fn decode(x: Result<i64, u8>) -> i64 effects {} { "
            "match x { Result::Ok(v) => { return v; }, "
            "Result::Err(e) => { return 0; }, } }")
        terms = [b["terminator"] for b in ir["functions"][0]["graph"]["blocks"]]
        match = next(t for t in terms if t["kind"] == "structured_match")
        self.assertEqual([a["variant"] for a in match["arms"]], ["Ok", "Err"])
        self.assertIsNone(match["default"])

    def test_unsafe_scope_visible(self):
        ir = self.lower(
            'extern "C" fn c_add(a: i32, b: i32) -> i32 effects {ffi, unsafe}; '
            'fn call(a: i32, b: i32) -> i32 effects {ffi, unsafe} { '
            'unsafe { return c_add(a, b); } }')
        self.assertTrue(ir["functions"][0]["external"])
        graph = ir["functions"][1]["graph"]
        kinds = [op["kind"] for b in graph["blocks"] for op in b["operations"]]
        self.assertIn("unsafe_enter", kinds)
        self.assertEqual(graph["blocks"][0]["terminator"]["unsafe_depth"], 1)

    def test_bad_program_and_missing_types_refuse(self):
        bad = parse("fn bad() -> i64 effects {} { return false; }")
        check_bad = check(bad)
        self.assertFalse(check_bad.ok)
        with self.assertRaises(FlowLowerError):
            lower_checked_cfg(bad, check_bad)
        p = parse(self.ADD)
        c = check(p)
        self.assertTrue(c.ok)
        c.expr_types.clear()
        with self.assertRaisesRegex(FlowLowerError, "without checked types"):
            lower_checked_cfg(p, c)

    def test_unreachable_statements_refuse(self):
        p = parse(self.ADD)
        c = check(p)
        p.functions[0].body.append(Stmt("unknown", {}))
        with self.assertRaises(FlowLowerError):
            lower_checked_cfg(p, c)

    def test_frontend_only_is_not_native_qualification(self):
        analysis = analyze(self.ADD, "flow.hepta", native=False)
        report = cfg_analysis(analysis)
        self.assertTrue(report["ok"])
        self.assertEqual(report["status"], "frontend_only")
        self.assertFalse(report["cfg"]["claims"]["machine_lowering_verified"])

    def test_failed_validation_has_no_graph(self):
        result = cfg_analysis(analyze(
            "fn bad() -> i64 effects {} { return false; }",
            "flow.hepta", native=False))
        self.assertFalse(result["ok"])
        self.assertIsNone(result["cfg"])

    def test_cli_exports_cfg(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "source.hepta"
            path.write_text(self.ADD)
            p = subprocess.run(
                [sys.executable, "-m", "hepta", "cfg", str(path),
                 "--frontend-only"], capture_output=True, text=True, timeout=20)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            result = json.loads(p.stdout)
            self.assertEqual(result["schema"], "hepta.cfg.export.v0")
            self.assertEqual(result["cfg"]["functions"][0]["graph"]["entry"], "bb0")
            self.assertEqual(result["status"], "frontend_only")


if __name__ == "__main__":
    unittest.main()
