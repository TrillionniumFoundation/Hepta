"""Independent proof, original fallback, and real checked-reduction execution."""
from __future__ import annotations

from copy import deepcopy
import ctypes
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

from hepta.hia_guarded_optimization import (
    build_guarded_native, guarded_program, propose_guarded_reduction,
    verify_guarded_optimization,
)
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_program_source import lower_source

ROOT = Path(__file__).resolve().parents[1]


class GuardedInductionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = lower_source((ROOT / "benchmarks/hia_native_ndu/kernel.hepta").read_text())
        cls.proposal = propose_guarded_reduction(cls.base, maximum=32, include_induction=True)

    def test_each_reduction_and_counted_step_has_an_independent_obligation(self):
        report = verify_guarded_optimization(self.base, self.proposal)
        self.assertEqual(report["status"], "verified", report["reason"])
        changes = {(c["block"], c["operation"]) for c in self.proposal["changes"]}
        witnessed = {(r["block"], r["operation"]) for r in report["obligations"]
                     if r["kind"] == "removed_check_cannot_trap" and r["result"] == "unsat"}
        self.assertEqual(changes, witnessed)
        self.assertEqual(len(changes), 3)  # fill index, checked sum, reduction index
        self.assertTrue(report["resource_delta"]["allocation_failure_sequence_preserved"])
        self.assertFalse(report["claims"]["backend_refinement_proved"])

    def test_fast_boundary_fallback_and_allocation_refusal_keep_observables(self):
        candidate = guarded_program(self.base, self.proposal)
        for n in (0, 1, 7, 31, 32, 33, 67):
            for seed in (0, 255, 2**32-1):
                for fail_at in (None, 1):
                    with self.subTest(n=n, seed=seed, fail_at=fail_at):
                        before = execute_program(self.base, "calculate", [n, seed], allocation_fail_at=fail_at)
                        after = execute_program(candidate, "calculate", [n, seed], allocation_fail_at=fail_at)
                        self.assertEqual(before["result"], after["result"])
                        self.assertEqual(before["resources"], after["resources"])

    def test_shape_recognition_cannot_authorize_false_entry_invariant(self):
        raw = self.base.as_dict()
        changed = False
        for block in raw["functions"][0]["blocks"]:
            for op in block["ops"]:
                if not changed and op["op"] == "const" and op["out"][0]["type"] == "usize":
                    op["attrs"]["value"] = 2**64-1
                    changed = True
        base = verify_program(raw)
        proposal = propose_guarded_reduction(base, maximum=32, include_induction=True)
        report = verify_guarded_optimization(base, proposal)
        self.assertEqual(report["status"], "rejected", report)
        self.assertEqual(report["obligations"][-1]["result"], "sat")

    def test_changed_step_and_incomplete_inventory_are_refused(self):
        changed = deepcopy(self.proposal)
        item = changed["changes"][0]
        block = next(b for b in changed["fast_core"]["functions"][0]["blocks"] if b["id"] == item["block"])
        constant = block["ops"][item["operation"]-1]
        self.assertEqual(constant["op"], "const")
        constant["attrs"]["value"] = 2
        self.assertEqual(verify_guarded_optimization(self.base, changed)["status"], "rejected")
        changed = deepcopy(self.proposal)
        changed["changes"].pop(0)
        self.assertEqual(verify_guarded_optimization(self.base, changed)["status"], "rejected")

    def test_cli_publishes_actual_induction_candidate_only_after_proof(self):
        from hepta.cli import main
        with tempfile.TemporaryDirectory() as folder:
            source, output = Path(folder) / "core.json", Path(folder) / "proposal.json"
            source.write_text(json.dumps(self.base.as_dict()))
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                result = main(["hia", "optimize-guarded", str(source), "--maximum", "32",
                               "--include-induction", "--output", str(output)])
            self.assertEqual(result, 0, stream.getvalue())
            receipt = json.loads(stream.getvalue())
            self.assertEqual(receipt["verification"]["status"], "verified")
            self.assertEqual(json.loads(output.read_text()), self.proposal)

    def test_actual_native_guard_and_fallback_match_independent_byte_formula(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "checked.so"
            receipt = build_guarded_native(self.base, self.proposal, path,
                                           clang=os.environ.get("CLANG", "clang"))
            self.assertEqual(receipt["verification"]["candidate_sha256"], receipt["native"]["core_sha256"])
            library = ctypes.CDLL(str(path))
            library.calculate.argtypes = (ctypes.c_size_t, ctypes.c_uint32)
            library.calculate.restype = ctypes.c_uint64
            for n in (0, 1, 31, 32, 33, 257, 1025):
                for seed in (0, 255, 2**32-1):
                    self.assertEqual(library.calculate(n, seed), sum((i+seed) % 256 for i in range(n)))


if __name__ == "__main__":
    unittest.main()
