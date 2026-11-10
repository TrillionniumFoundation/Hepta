"""Actual modular/trap proofs, inventory attacks, chains and loaded native bytes."""
from __future__ import annotations

import copy
import ctypes
import hashlib
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program, HIAProgramTrap
from hepta.hia_optimization import DEFAULT_POLICY, OptimizationRejected, _digest
from hepta.hia_narrowing import (propose_modular_narrowing, verify_modular_narrowing,
    narrowed_program, build_narrowed_native, propose_guarded_narrowing,
    verify_guarded_narrowing, guarded_narrowed_program, build_guarded_narrowed_native)
from tests.test_hia_program import m, f, b, i, c, ret

try:
    import z3
except ImportError:
    z3 = None



def expression(wide="u32", narrow="u8", op="int.add.wrap"):
    return m(f("calculate", [("a", wide), ("z", wide)], [narrow], ["trap"], [
        b("entry", [("a", wide), ("z", wide)], [
            i(op, ["a", "z"], [("wide", wide)]),
            i("int.cast", ["wide"], [("result", narrow)], mode="wrap")], ret("result"))]))


def mutate_replacement(proposal):
    row = proposal["rewrites"][0]
    op = next(o for o in row["replacement"] if o["op"] == "int.add.wrap")
    old = copy.deepcopy(op)
    op["op"] = "int.sub.wrap"
    block = next(b for f in proposal["candidate_core"]["functions"] for b in f["blocks"]
                 if f["name"] == row["function"] and b["id"] == row["block"])
    next(o for o in block["ops"] if o == old)["op"] = "int.sub.wrap"


@unittest.skipUnless(z3 is not None, "pinned Z3 required")
class NarrowingProofTests(unittest.TestCase):
    def test_unsigned_modular_algebra_is_proved_and_matches_interpreter_boundaries(self):
        for wide, narrow in (("u16", "u8"), ("u32", "u8"), ("u64", "u16"), ("usize", "u32")):
            width = {"u16": 16, "u32": 32, "u64": 64, "usize": 64}[wide]
            for operation in ("int.add.wrap", "int.sub.wrap", "int.mul.wrap", "bit.and", "bit.or", "bit.xor"):
                base = expression(wide, narrow, operation)
                proposed = propose_modular_narrowing(base)
                report = verify_modular_narrowing(base, proposed)
                self.assertEqual(report["status"], "verified", (wide, narrow, operation, report["reason"]))
                self.assertTrue(all(o["result"] == "unsat" for o in report["equivalence"]["obligations"]))
                candidate = verify_program(proposed["candidate_core"])
                for a, other in ((0, 0), (1, 255), (255, 257), (2**width - 1, 1),
                                 (2**width - 1, 2**width - 1)):
                    self.assertEqual(execute_program(base, "calculate", [a, other])["result"],
                                     execute_program(candidate, "calculate", [a, other])["result"])

    def test_checked_child_trap_is_retained_before_narrow_arithmetic(self):
        base = expression()
        ops = base["functions"][0]["blocks"][0]["ops"]
        ops[:0] = [i("int.add.checked", ["a", "z"], [("checked", "u32")])]
        ops[1]["args"][0] = "checked"
        proposed = propose_modular_narrowing(base)
        report = verify_modular_narrowing(base, proposed)
        self.assertEqual(report["status"], "verified")
        for program in (base, proposed["candidate_core"]):
            with self.assertRaises(HIAProgramTrap) as caught:
                execute_program(program, "calculate", [2**32 - 1, 1])
            self.assertEqual(caught.exception.code, "overflow")
        forged = copy.deepcopy(proposed)
        forged["candidate_core"]["functions"][0]["blocks"][0]["ops"].pop(0)
        self.assertEqual(verify_modular_narrowing(base, forged)["status"], "rejected")

    def test_checked_truncation_and_signed_roots_do_not_enter_the_profile(self):
        for base in (expression("i32", "u8"), expression()):
            if base["functions"][0]["params"][0]["type"] == "u32":
                base["functions"][0]["blocks"][0]["ops"][-1]["attrs"]["mode"] = "checked"
            with self.assertRaisesRegex(OptimizationRejected, "NO_CANDIDATE"):
                propose_modular_narrowing(base)

    def test_nonmodular_shift_remains_a_wide_leaf(self):
        base = expression()
        ops = base["functions"][0]["blocks"][0]["ops"]
        ops[:0] = [c("shift", "u32", 12), i("int.shr.checked", ["a", "shift"], [("wide_shift", "u32")])]
        ops[2]["args"][0] = "wide_shift"
        proposal = propose_modular_narrowing(base)
        report = verify_modular_narrowing(base, proposal)
        self.assertEqual(report["status"], "verified", report["reason"])
        self.assertEqual(sum(o["op"] == "int.shr.checked"
                             for o in proposal["candidate_core"]["functions"][0]["blocks"][0]["ops"]), 1)
        self.assertEqual(execute_program(proposal["candidate_core"], "calculate", [4096, 7])["result"], 8)

    def test_hostile_algebra_change_gets_a_real_counterexample(self):
        base = expression()
        proposal = propose_modular_narrowing(base)
        mutate_replacement(proposal)
        report = verify_modular_narrowing(base, proposal)
        self.assertEqual(report["status"], "rejected", report["reason"])
        self.assertIn("counterexample", report["equivalence"]["obligations"][-1])
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "never.so"
            with patch("hepta.hia_program_llvm.build_program_native", side_effect=AssertionError("compiled")):
                with self.assertRaises(OptimizationRejected):
                    build_narrowed_native(base, proposal, destination)
            self.assertFalse(destination.exists())

    def test_complete_edit_inventory_rejects_extra_changed_or_missing_work(self):
        base = expression()
        for attack in ("absent", "duplicate", "wrong_index", "extra_change", "unchecked_cast", "effect"):
            proposal = propose_modular_narrowing(base)
            row = proposal["rewrites"][0]
            if attack == "absent":
                proposal["rewrites"] = []
            elif attack == "duplicate":
                proposal["rewrites"].append(copy.deepcopy(row))
            elif attack == "wrong_index":
                row["operation"] = 0
            elif attack == "extra_change":
                proposal["candidate_core"]["functions"][0]["blocks"][0]["ops"][0]["op"] = "int.sub.wrap"
            elif attack == "unchecked_cast":
                row["replacement"][-1]["attrs"]["mode"] = "checked"
            else:
                row["replacement"][0]["op"] = "owner.drop"
            report = verify_modular_narrowing(base, proposal)
            self.assertEqual(report["status"], "rejected", (attack, report))

    def test_fresh_names_do_not_alias_original_or_new_scalar_values(self):
        base = expression()
        block = base["functions"][0]["blocks"][0]
        block["ops"].insert(0, c("hia_narrow_1", "u32", 99))
        proposal = propose_modular_narrowing(base)
        report = verify_modular_narrowing(base, proposal)
        self.assertEqual(report["status"], "verified")
        self.assertNotIn("hia_narrow_1", [o["out"][0]["name"] for o in proposal["rewrites"][0]["replacement"]])

    def test_timeout_unknown_and_finite_limits_cannot_publish(self):
        base = expression()
        proposal = propose_modular_narrowing(base)
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "never.so"
            for settings, status in (({"timeout_ms": 0}, "timeout"),
                                     ({"max_obligations": 0}, "unknown"),
                                     ({"max_scalar_operations": 0}, "unknown")):
                policy = {**DEFAULT_POLICY, **settings}
                self.assertEqual(verify_modular_narrowing(base, proposal, policy)["status"], status)
                with patch("hepta.hia_program_llvm.build_program_native", side_effect=AssertionError("compiled")):
                    with self.assertRaises(OptimizationRejected):
                        build_narrowed_native(base, proposal, destination, policy=policy)
                self.assertFalse(destination.exists())
            with patch.object(z3.Solver, "check", return_value=z3.unknown), \
                    patch.object(z3.Solver, "reason_unknown", return_value="incomplete"):
                self.assertEqual(verify_modular_narrowing(base, proposal)["status"], "unknown")
                with self.assertRaises(OptimizationRejected):
                    build_narrowed_native(base, proposal, destination)
            self.assertFalse(destination.exists())




@unittest.skipUnless(z3 is not None and shutil.which(os.environ.get("CLANG", "clang")),
                     "pinned Z3 and native Clang required")
class NarrowingNativeTests(unittest.TestCase):

    def test_proof_source_drift_during_native_build_withdraws_publication(self):
        import hepta.hia_narrowing as narrowing
        from hepta.hia_program_llvm import build_program_native
        base = expression()
        proposal = propose_modular_narrowing(base)
        real_identity, changed = narrowing.narrowing_checker_identity, False

        def identity():
            return "0" * 64 if changed else real_identity()

        def compiler(program, output, **kwargs):
            nonlocal changed
            result = build_program_native(program, output, **kwargs)
            changed = True
            return result

        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "never.so"
            with patch.object(narrowing, "narrowing_checker_identity", side_effect=identity), \
                    patch("hepta.hia_program_llvm.build_program_native", side_effect=compiler):
                with self.assertRaisesRegex(OptimizationRejected, "STALE"):
                    build_narrowed_native(base, proposal, destination, clang=os.environ.get("CLANG", "clang"))
            self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
