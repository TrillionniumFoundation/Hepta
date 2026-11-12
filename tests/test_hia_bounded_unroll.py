"""All-input loop bounds, first traps, failed guesses and stale evidence."""
from __future__ import annotations

import copy
from unittest.mock import patch
import unittest

from hepta.hia_bounded_unroll import (
    propose_bounded_unroll, validate_bounded_translation, verify_bounded_translation_receipt,
)
from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_runtime import execute_program
from tests.test_hia_program import b, branch, c, f, i, jump, m, ret


def counted(limit=8, *, dynamic=False, division=False):
    params = [("x", "u8")] + ([("n", "u8")] if dynamic else [])
    initial = [c("zero", "u8", 0)] + ([] if dynamic else [c("limit", "u8", limit)])
    body = [c("one", "u8", 1)]
    if division:
        body += [c("den", "u8", 0), i("int.div.checked", ["ba", "den"], [("failed", "u8")])]
    body += [i("int.add.wrap", ["ba", "one"], [("next_a", "u8")]),
             i("int.add.wrap", ["bi", "one"], [("next_i", "u8")])]
    return m(f("calculate", params, ["u8"], ["trap"] if division else [], [
        b("entry", params, initial, jump("head", "x", "zero", "n" if dynamic else "limit")),
        b("head", [("ha", "u8"), ("hi", "u8"), ("hn", "u8")],
          [i("compare.lt", ["hi", "hn"], [("more", "bool")])],
          branch("more", ("body", "ha", "hi", "hn"), ("done", "ha"))),
        b("body", [("ba", "u8"), ("bi", "u8"), ("bn", "u8")], body,
          jump("head", "next_a", "next_i", "bn")),
        b("done", [("answer", "u8")], [], ret("answer")),
    ]))


def candidate(source, maximum=8):
    return propose_bounded_unroll(source, function="calculate", max_backedges=maximum)["program"]


def proof(source, after=None, maximum=8, **kwargs):
    return validate_bounded_translation(source, candidate(source, maximum) if after is None else after,
        function="calculate", max_backedges=maximum, **kwargs)


class BoundedUnrollTests(unittest.TestCase):
    def test_actual_fixed_loop_all_inputs_and_independent_interpreter(self):
        source = counted()
        saved = copy.deepcopy(source)
        proposed = propose_bounded_unroll(source, function="calculate", max_backedges=8)
        self.assertFalse(proposed["authorizes_execution"])
        receipt = proof(source, proposed["program"])
        self.assertEqual(receipt["status"], "proved", receipt)
        self.assertTrue(receipt["claims"]["all_input_bound_proved"])
        self.assertEqual(source, saved)
        for x in range(256):
            self.assertEqual(execute_program(proposed["program"], "calculate", [x])["result"], (x + 8) % 256)

    def test_underestimated_bound_replayed_even_if_candidate_matches_truncation(self):
        receipt = proof(counted(9), maximum=8)
        self.assertEqual(receipt["status"], "disproved", receipt)
        self.assertEqual(receipt["counterexample"]["marker_values"], [True])
        self.assertFalse(receipt["claims"]["all_input_bound_proved"])

    def test_input_dependent_trip_count_cannot_borrow_a_sampled_bound(self):
        receipt = proof(counted(dynamic=True))
        self.assertEqual(receipt["status"], "disproved", receipt)
        self.assertGreater(receipt["counterexample"]["arguments"][1], 8)

    def test_zero_feedback_and_original_first_trap(self):
        for source, maximum in ((counted(0), 0), (counted(8, division=True), 0)):
            receipt = proof(source, maximum=maximum)
            self.assertEqual(receipt["status"], "proved", receipt)
            self.assertTrue(receipt["claims"]["first_trap_code_preserved"])

    def test_original_user_trap_cannot_hide_a_reachable_truncation_marker(self):
        source = counted(dynamic=True)
        source["functions"][0]["effects"] = ["trap"]
        source["functions"][0]["blocks"][-1]["term"] = {"op": "trap", "code": "user"}
        self.assertEqual(proof(source)["status"], "disproved")

    def test_changed_value_rejected_after_independent_bound_success(self):
        source = counted()
        changed = candidate(source)
        for block in changed["functions"][0]["blocks"]:
            for op in block["ops"]:
                if op["op"] == "int.add.wrap":
                    op["op"] = "int.sub.wrap"
                    break
            else:
                continue
            break
        verify_program(changed)
        receipt = proof(source, changed)
        self.assertTrue(receipt["claims"]["all_input_bound_proved"])
        self.assertEqual(receipt["status"], "disproved", receipt)

    def test_changed_first_trap_rejected(self):
        source = counted(8, division=True)
        changed = candidate(source)
        for block in changed["functions"][0]["blocks"]:
            for op in block["ops"]:
                if op["op"] == "int.div.checked":
                    op["op"] = "int.shl.checked"
                    op["args"] = [op["args"][0], op["args"][0]]
        receipt = proof(source, changed)
        self.assertEqual(receipt["status"], "disproved", receipt)

    def test_other_functions_and_exports_must_remain_exact(self):
        source = counted()
        source["functions"].append(f("other", [], ["u8"], [], [b("entry", [], [c("v", "u8", 1)], ret("v"))]))
        changed = candidate(source)
        changed["functions"][1]["blocks"][0]["ops"][0]["attrs"]["value"] = 2
        self.assertIn("unproved function", proof(source, changed)["reason"])
        changed = candidate(source)
        changed["exports"] = ["calculate"]
        self.assertIn("module interface", proof(source, changed)["reason"])

    def test_forged_and_stale_receipts_are_recomputed(self):
        source = counted()
        after = candidate(source)
        receipt = proof(source, after)
        self.assertEqual(verify_bounded_translation_receipt(source, after, receipt,
            function="calculate", max_backedges=8)["status"], "proved")
        receipt["before_sha256"] = "0" * 64
        with self.assertRaises(HIAProgramRejected):
            verify_bounded_translation_receipt(source, after, receipt, function="calculate", max_backedges=8)
        with self.assertRaises(HIAProgramRejected):
            verify_bounded_translation_receipt(counted(9), candidate(counted(9)), {"status": "proved"},
                                              function="calculate", max_backedges=8)

    def test_absent_solver_and_invalid_timeout_never_admit(self):
        with patch("hepta.hia_bounded_unroll._z3_module", side_effect=ImportError("absent")):
            self.assertEqual(proof(counted())["reason"], "solver_unavailable")
        for value in (True, 0, -1, 60001, 2.5):
            self.assertEqual(proof(counted(), timeout_ms=value)["status"], "unknown")

    def test_solver_unknown_never_falls_back_to_finite_samples(self):
        import z3
        class UnknownSolver:
            def __init__(self, **kwargs): pass
            def set(self, **kwargs): pass
            def add(self, *args): pass
            def check(self): return z3.unknown
            def reason_unknown(self): return "forced_timeout"
        with patch.object(z3, "Solver", UnknownSolver):
            receipt = proof(counted())
        self.assertEqual(receipt["status"], "unknown")
        self.assertFalse(receipt["claims"]["all_input_bound_proved"])

    def test_acyclic_and_invalid_budgets_rejected(self):
        acyclic = m(f("calculate", [], [], [], [b("entry", [], [], ret())]))
        with self.assertRaises(HIAProgramRejected):
            candidate(acyclic)
        for value in (True, -1, 33, 1.5, "8"):
            with self.assertRaises(HIAProgramRejected):
                candidate(counted(), value)
        larger = counted()
        larger["functions"][0]["blocks"][2]["term"]["target"] = "bridge"
        larger["functions"][0]["blocks"].append(b("bridge", [("xa", "u8"), ("xi", "u8"), ("xn", "u8")],
            [], jump("head", "xa", "xi", "xn")))
        with self.assertRaisesRegex(HIAProgramRejected, "budget"):
            candidate(larger, 32)

    def test_multiple_feedback_edges_remain_outside_closed_profile(self):
        source = m(f("calculate", [("flag", "bool")], [], [], [
            b("entry", [("flag", "bool")], [], branch("flag", ("left",), ("right",))),
            b("left", [], [], jump("left")), b("right", [], [], jump("right"))]))
        with self.assertRaisesRegex(HIAProgramRejected, "one DFS"):
            candidate(source)

    def test_unbounded_loop_never_authorized(self):
        source = m(f("calculate", [], [], [], [b("entry", [], [], jump("cycle")), b("cycle", [], [], jump("cycle"))]))
        receipt = proof(source)
        self.assertEqual(receipt["status"], "disproved", receipt)


if __name__ == "__main__":
    unittest.main()
