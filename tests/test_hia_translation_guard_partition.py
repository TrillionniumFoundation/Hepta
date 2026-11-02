"""Exhaustive guard preprocessing keeps both value and first-trap cases."""
from __future__ import annotations

import importlib.util
import unittest

from hepta.hia_translation_validation import (
    _Encoder, _partition_entry_equality, validate_translation,
)
from tests.test_hia_specialization import division, propose


@unittest.skipUnless(importlib.util.find_spec("z3"), "actual Z3 is required")
class GuardPartitionTests(unittest.TestCase):
    def prove(self, before, after, status="proved"):
        receipt = validate_translation(before, after, function="calculate", timeout_ms=10_000)
        self.assertEqual(receipt["status"], status, receipt)
        self.assertEqual(receipt["solver"]["timeout_ms"], 10_000)
        preprocessing = receipt["solver"]["query_preprocessing"]
        self.assertEqual(preprocessing["strategy"], "exhaustive_entry_input_equality_split")
        self.assertEqual(preprocessing["input_assumptions"], [])
        self.assertEqual(preprocessing["partition_count"], 2)
        return receipt

    def test_registered_u32_division_guards_keep_the_original_timeout(self):
        source = division("u32")
        for denominator in (8, 10):
            with self.subTest(denominator=denominator):
                self.prove(source, propose(source, denominator))

    def test_general_query_partition_is_logically_equivalent(self):
        import z3
        source = propose(division("u8"), 10)["functions"][0]
        encoder = _Encoder(z3)
        inputs = [encoder.input(i, p["type"]) for i, p in enumerate(source["params"])]
        x, denominator = inputs
        # Arbitrary uninterpreted predicates ensure this check does not depend
        # on either the division implementation or a hand-picked value set.
        sort = z3.BitVecSort(8, ctx=encoder.context)
        boolean = z3.BoolSort(ctx=encoder.context)
        p, q = [z3.Function(name, sort, sort, boolean) for name in ("p", "q")]
        query = z3.Or(z3.And(denominator == 10, p(x, denominator)),
                      z3.And(denominator != 10, q(x, denominator)), p(denominator, x))
        partitioned, _ = _partition_entry_equality(z3, encoder, inputs, (source,), query)
        solver = z3.Solver(ctx=encoder.context)
        solver.set(timeout=10_000)
        solver.add(query != partitioned)
        self.assertEqual(solver.check(), z3.unsat)

    def test_wrong_value_on_either_guard_arm_is_replayed(self):
        for arm in ("then", "else"):
            source = division("u8")
            candidate = propose(source, 10)
            function = candidate["functions"][0]
            target = function["blocks"][0]["term"][arm]["target"]
            block = next(block for block in function["blocks"] if block["id"] == target)
            block["ops"][-1]["op"] = "int.sub.wrap"
            with self.subTest(arm=arm):
                receipt = self.prove(source, candidate, "disproved")
                example = receipt["counterexample"]
                self.assertEqual(example["arguments"][1] == 10, arm == "then")
                self.assertNotEqual(example["before"], example["after"])

    def test_guard_hit_does_not_hide_an_erased_division_by_zero(self):
        source = division("u32")
        candidate = propose(source, 0)
        function = candidate["functions"][0]
        target = function["blocks"][0]["term"]["then"]["target"]
        block = next(block for block in function["blocks"] if block["id"] == target)
        block["ops"] = []
        block["term"] = {"op": "ret", "values": [block["params"][0]["name"]]}
        receipt = self.prove(source, candidate, "disproved")
        self.assertEqual(receipt["counterexample"]["arguments"][1], 0)
        self.assertEqual(receipt["counterexample"]["before"],
                         {"status": "trapped", "code": "division_by_zero"})

    def test_reversed_equality_and_signed_minimum_are_covered(self):
        source = division("i8")
        candidate = propose(source, -1)
        candidate["functions"][0]["blocks"][0]["ops"][-1]["args"].reverse()
        self.prove(source, candidate)


if __name__ == "__main__":
    unittest.main()
