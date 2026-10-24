"""Fail-closed CFG/SSA preview: structure, edges, phi, provenance of claims."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from hepta.checker import check
from hepta.hmir import HMIRUnsupported, lower_checked_cfg, validate_cfg_ssa
from hepta.parser import parse


class HMIRTests(unittest.TestCase):
    def lower(self, source):
        program = parse(source, "sample.hepta")
        checked = check(program)
        self.assertTrue(checked.ok, [d.to_dict() for d in checked.diagnostics])
        return lower_checked_cfg(program, checked)

    def test_deterministic_typed_ssa_and_phi_for_if(self):
        src = ("fn choose(a: i64, b: i64, flag: bool) -> i64 effects {} { "
               "let mut n: i64 = a; if flag { n = b; } else { n = a; } return n; }")
        one = self.lower(src)
        self.assertEqual(one, self.lower(src))
        self.assertEqual(one["schema"], "hepta.hmir.cfg-ssa.v0")
        self.assertFalse(one["claims"]["lowering_semantics_proved"])
        blocks = one["functions"][0]["blocks"]
        self.assertEqual(sum(b["terminator"]["op"] == "branch" for b in blocks), 1)
        phis = [p for b in blocks for p in b["phi"] if p["symbol"] == "n"]
        self.assertEqual(len(phis), 1)
        self.assertEqual(len(phis[0]["inputs"]), 2)
        ending = next(b for b in blocks if b["terminator"]["op"] == "return")
        self.assertEqual(ending["terminator"]["value"]["ssa"], phis[0]["ssa"])

    def test_while_header_phi_backedge_and_exit(self):
        src = ("fn count(limit: i64) -> i64 effects {panic} { "
               "let mut n: i64 = 0; while n < limit { n = n + 1; } return n; }")
        blocks = self.lower(src)["functions"][0]["blocks"]
        header = next(b for b in blocks if b["phi"])
        self.assertEqual(header["terminator"]["op"], "branch")
        self.assertEqual(len(header["predecessors"]), 2)
        self.assertEqual(header["terminator"]["condition"]["args"][0]["ssa"],
                         next(p["ssa"] for p in header["phi"] if p["symbol"] == "n"))
        backedges = [b for b in blocks if b["terminator"] == {"op": "jump", "target": header["id"]}]
        self.assertEqual(len(backedges), 2)

    def test_both_branches_return_without_fake_join(self):
        src = ("fn choice(flag: bool) -> i64 effects {} { "
               "if flag { return 10; } else { return 20; } }")
        blocks = self.lower(src)["functions"][0]["blocks"]
        self.assertEqual(len(blocks), 3)
        self.assertEqual(sum(b["terminator"]["op"] == "return" for b in blocks), 2)

    def test_rejects_borrowed_or_pointer_inputs(self):
        src = "fn readsum(data: read [u64]) -> u64 effects {} { return 0; }"
        with self.assertRaisesRegex(HMIRUnsupported, "by-value scalar"):
            self.lower(src)

    def test_rejects_pure_calls_until_call_effects_are_modeled(self):
        src = ("fn helper() -> i64 effects {} { return 4; } "
               "fn use_helper() -> i64 effects {} { return helper(); }")
        with self.assertRaisesRegex(HMIRUnsupported, "expression call"):
            self.lower(src)

    def test_rejects_nested_lexical_local_until_storage_identity(self):
        src = ("fn choice(flag: bool) -> i64 effects {} { "
               "if flag { let x: i64 = 10; return x; } return 0; }")
        with self.assertRaisesRegex(HMIRUnsupported, "block-scoped locals"):
            self.lower(src)

    def test_rejects_all_writes_to_memory(self):
        src = ("fn change(x: mut [u8]) -> Unit effects {write} { x[0] = 4; }")
        with self.assertRaises(HMIRUnsupported):
            self.lower(src)

    def test_frontend_rejection_cannot_be_lowered(self):
        source = "fn broken() -> i64 effects {} { return true; }"
        p = parse(source, "broken.hepta")
        checked = check(p)
        self.assertFalse(checked.ok)
        with self.assertRaises(ValueError):
            lower_checked_cfg(p, checked)

    def test_validator_catches_corrupt_phi_predecessor(self):
        source = ("fn choose(a: i64, b: i64, flag: bool) -> i64 effects {} { "
                  "let mut n: i64 = a; if flag { n = b; } else { n = a; } return n; }")
        graph = self.lower(source)["functions"][0]
        join = next(b for b in graph["blocks"] if b["phi"])
        join["phi"][0]["inputs"].pop()
        with self.assertRaisesRegex(ValueError, "phi inputs"):
            validate_cfg_ssa(graph)

    def test_validator_catches_non_dominating_ssa_read(self):
        source = ("fn choose(a: i64, b: i64, flag: bool) -> i64 effects {} { "
                  "let mut n: i64 = a; if flag { n = b; } else { n = a; } return n; }")
        graph = self.lower(source)["functions"][0]
        ret = next(b for b in graph["blocks"] if b["terminator"]["op"] == "return")
        branch = next(b for b in graph["blocks"] if any(i["ssa"] == "%v2" for i in b["instructions"]))
        self.assertNotEqual(ret["id"], branch["id"])
        ret["terminator"]["value"]["ssa"] = "%v2"
        with self.assertRaisesRegex(ValueError, "not dominated"):
            validate_cfg_ssa(graph)

    def test_validator_catches_undefined_ssa(self):
        graph = self.lower("fn f(x: i64) -> i64 effects {} { return x; }")["functions"][0]
        graph["blocks"][0]["terminator"]["value"]["ssa"] = "%unknown"
        with self.assertRaisesRegex(ValueError, "missing definition"):
            validate_cfg_ssa(graph)

    def test_cli_frontend_only_never_masquerades_as_native(self):
        src = "fn identity(x: i64) -> i64 effects {} { return x; }"
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "small.hepta"
            path.write_text(src, encoding="utf-8")
            process = subprocess.run([sys.executable, "-m", "hepta", "hmir", str(path), "--frontend-only"],
                                     capture_output=True, text=True, timeout=20)
            self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
            report = json.loads(process.stdout)
            self.assertTrue(report["ok"])
            self.assertEqual(report["status"], "frontend_only")
            self.assertEqual(report["native_validation"], "not_run")
            self.assertFalse(report["hmir"]["claims"]["native_borrow_validation"])

    def test_cli_unsupported_emits_machine_readable_failure(self):
        src = "fn identity(x: read [u64]) -> u64 effects {} { return 0; }"
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "borrow.hepta"
            path.write_text(src, encoding="utf-8")
            process = subprocess.run([sys.executable, "-m", "hepta", "hmir", str(path), "--frontend-only"],
                                     capture_output=True, text=True, timeout=20)
            self.assertNotEqual(process.returncode, 0)
            report = json.loads(process.stdout)
            self.assertFalse(report["ok"])
            self.assertIsNone(report["hmir"])
            self.assertEqual(report["diagnostics"][0]["code"], "E_HMIR_UNSUPPORTED")


if __name__ == "__main__":
    unittest.main()
