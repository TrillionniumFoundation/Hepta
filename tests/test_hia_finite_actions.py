"""Finite proposals stay separate from proof and preserve the selected Core."""
from __future__ import annotations

import copy
import importlib.util
import unittest

from hepta.hia_finite_actions import propose_candidates
from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_translation_validation import validate_translation
from tests.test_hia_program import b, branch, c, f, i, jump, m, ret


def workload(typ="u64"):
    params = [("x", typ)]
    return m(f("calculate", params, [typ], [], [b("entry", params, [
        c("zero", typ, 0), c("one", typ, 1), c("five", typ, 5), c("seven", typ, 7),
        i("int.add.wrap", ["x", "zero"], [("identity", typ)]),
        i("int.add.wrap", ["five", "seven"], [("folded", typ)]),
        i("int.add.wrap", ["identity", "five"], [("mid", typ)]),
        i("int.add.wrap", ["mid", "seven"], [("value", typ)]),
        i("int.mul.wrap", ["value", "one"], [("out", typ)]),
        i("bit.xor", ["x", "folded"], [("dead", typ)]),
    ], ret("out"))]))


class FiniteActionTests(unittest.TestCase):
    def test_deterministic_unique_candidates_do_not_mutate_input(self):
        program = workload()
        original = copy.deepcopy(program)
        candidates = propose_candidates(program, function="calculate")
        self.assertEqual(program, original)
        self.assertEqual(candidates, propose_candidates(program, function="calculate"))
        self.assertGreaterEqual(len(candidates), 4)
        self.assertLessEqual(len(candidates), 8)
        self.assertEqual(len({c["id"] for c in candidates}), len(candidates))
        before = verify_program(program).sha256
        hashes = [verify_program(c["program"]).sha256 for c in candidates]
        self.assertNotIn(before, hashes)
        self.assertEqual(len(set(hashes)), len(hashes))
        for candidate in candidates:
            self.assertEqual(set(candidate), {"id", "action", "program"})
            self.assertNotIn("proved", candidate)

    def test_bound_is_a_prefix_of_the_frozen_recipe_order(self):
        all_candidates = propose_candidates(workload(), function="calculate")
        self.assertEqual(propose_candidates(workload(), function="calculate", max_candidates=2),
                         all_candidates[:2])
        for cap in (0, -1, 9, True, 2.0):
            with self.subTest(cap=cap), self.assertRaises(HIAProgramRejected):
                propose_candidates(workload(), function="calculate", max_candidates=cap)

    def test_trapping_operations_cannot_be_removed_even_when_result_is_dead(self):
        checked = workload("i8")
        fn = checked["functions"][0]
        fn["effects"] = ["trap"]
        fn["blocks"][0]["ops"][-1] = i("int.add.checked", ["x", "seven"], [("dead", "i8")])
        verify_program(checked)
        with self.assertRaisesRegex(HIAProgramRejected, "total effect-free"):
            propose_candidates(checked, function="calculate")

    def test_cycles_and_unknown_functions_are_rejected(self):
        loop = m(f("calculate", [], [], [], [
            b("entry", [], [], jump("cycle")), b("cycle", [], [], jump("cycle")),
        ]))
        with self.assertRaisesRegex(HIAProgramRejected, "cyclic_cfg"):
            propose_candidates(loop, function="calculate")
        with self.assertRaises(HIAProgramRejected):
            propose_candidates(workload(), function="missing")

    def test_unrelated_functions_and_export_contract_are_unchanged(self):
        document = workload()
        other = f("other", [("a", "u8")], ["u8"], [], [b("entry", [("a", "u8")], [], ret("a"))])
        document["functions"].append(other)
        document["exports"] = ["calculate", "other"]
        for candidate in propose_candidates(document, function="calculate"):
            self.assertEqual(candidate["program"]["exports"], document["exports"])
            self.assertEqual(candidate["program"]["functions"][1], other)

    @unittest.skipUnless(importlib.util.find_spec("z3"), "optional z3-solver is not installed")
    def test_every_recipe_is_independently_proved_at_each_signedness(self):
        for typ in ("u8", "i8", "u64", "i64"):
            document = workload(typ)
            for candidate in propose_candidates(document, function="calculate"):
                with self.subTest(type=typ, action=candidate["action"]):
                    proof = validate_translation(document, candidate["program"], function="calculate")
                    self.assertEqual(proof["status"], "proved", proof)

    @unittest.skipUnless(importlib.util.find_spec("z3"), "optional z3-solver is not installed")
    def test_closed_cfg_edge_uses_are_rewritten_without_changing_phi_values(self):
        params = [("flag", "bool"), ("x", "u8")]
        document = m(f("calculate", params, ["u8"], [], [
            b("entry", params, [c("zero", "u8", 0),
                i("int.add.wrap", ["x", "zero"], [("unchanged", "u8")])],
              branch("flag", ("join", "unchanged"), ("join", "x"))),
            b("join", [("phi", "u8")], [], ret("phi")),
        ]))
        proposals = propose_candidates(document, function="calculate")
        self.assertTrue(proposals)
        for proposal in proposals:
            self.assertEqual(validate_translation(document, proposal["program"], function="calculate")["status"], "proved")

    def test_already_minimal_program_has_no_fake_candidate(self):
        document = m(f("calculate", [("x", "u64")], ["u64"], [], [
            b("entry", [("x", "u64")], [], ret("x"))]))
        self.assertEqual(propose_candidates(document, function="calculate"), [])

    def test_native_summary_retains_asymmetric_outliers_and_rejects_failed_rows(self):
        from tools.qualify_hia_ndu_search import _summary
        rows = [{"status": "observed", "elapsed_ns": value} for value in [100, 100, 1000]]
        summary = _summary(rows, 10)
        self.assertEqual(summary["runtime_ns"], 10)
        self.assertEqual(summary["uncertainty_ns"], 90)
        with self.assertRaises(RuntimeError):
            _summary(rows + [{"status": "failed", "elapsed_ns": 100}], 10)

    def test_all_reference_policies_charge_actual_overhead_against_the_cap(self):
        from tools.qualify_hia_ndu_search import _guard
        observations = {"abstain": {"runtime_ns": 100, "uncertainty_ns": 1},
                        "candidate": {"runtime_ns": 1, "uncertainty_ns": 1}}
        within = _guard("candidate", observations, 1000000, 99, 1, 100)
        self.assertEqual(within["selected_id"], "candidate")
        self.assertTrue(within["within_resource_cap"])
        outside = _guard("candidate", observations, 1000000, 99, 2, 100)
        self.assertEqual(outside["selected_id"], "abstain")
        self.assertFalse(outside["within_resource_cap"])


if __name__ == "__main__":
    unittest.main()
