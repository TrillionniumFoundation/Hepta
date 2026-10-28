"""Guarded proposals preserve the generic path and the existing trap semantics."""
from __future__ import annotations

import copy
import importlib.util
import unittest

from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_runtime import HIAProgramTrap, execute_program
from hepta.hia_specialization import propose_guarded_specializations
from hepta.hia_translation_validation import validate_translation
from tests.test_hia_program import b, branch, c, f, i, jump, m, resource_program, ret


def division(typ="u64"):
    params = [("x", typ), ("denominator", typ)]
    return m(f("calculate", params, [typ], ["trap"], [b("entry", params, [
        i("int.div.checked", ["x", "denominator"], [("quotient", typ)]),
        i("int.rem.checked", ["x", "denominator"], [("remainder", typ)]),
        i("int.add.wrap", ["quotient", "remainder"], [("answer", typ)]),
    ], ret("answer"))]))


def propose(program, value, *, parameter="denominator"):
    return propose_guarded_specializations(program, function="calculate",
        assumptions=[{"parameter": parameter, "value": value}])[0]["program"]


def observe(document, arguments):
    try:
        row = execute_program(document, "calculate", arguments, max_steps=1000)
        return {"status": "returned", "values": row["values"]}
    except HIAProgramTrap as error:
        return {"status": "trapped", "code": error.code}


class GuardedSpecializationTests(unittest.TestCase):
    def test_deterministic_bounded_deduplicated_and_no_input_mutation(self):
        source = division()
        saved = copy.deepcopy(source)
        choices = [{"parameter": "denominator", "value": value} for value in (8, 8, 10)]
        first = propose_guarded_specializations(source, function="calculate", assumptions=choices)
        self.assertEqual(source, saved)
        self.assertEqual(first, propose_guarded_specializations(source, function="calculate", assumptions=choices))
        self.assertEqual(len(first), 2)
        self.assertEqual(propose_guarded_specializations(source, function="calculate", assumptions=choices,
                                                       max_candidates=1), first[:1])
        for row in first:
            self.assertEqual(set(row), {"id", "action", "program"})
            self.assertEqual(row["id"], "s" + verify_program(row["program"]).sha256[:31])
            self.assertNotEqual(verify_program(source).sha256, verify_program(row["program"]).sha256)

    def test_complete_assumption_request_is_checked_even_after_output_cap(self):
        bad_values = [True, 1.5, -1, 1 << 64]
        for value in bad_values:
            with self.subTest(value=value), self.assertRaises(HIAProgramRejected):
                propose_guarded_specializations(division(), function="calculate", max_candidates=1,
                    assumptions=[{"parameter": "denominator", "value": 8},
                                 {"parameter": "denominator", "value": value}])
        for assumptions in ([], [{"parameter": "missing", "value": 8}],
                            [{"parameter": "denominator", "value": 8, "proved": True}],
                            [{"parameter": "denominator", "value": 8}] * 9):
            with self.subTest(assumptions=assumptions), self.assertRaises(HIAProgramRejected):
                propose_guarded_specializations(division(), function="calculate", assumptions=assumptions)

    def test_independent_small_integer_oracle_and_every_generic_denominator(self):
        source = division("u8")
        candidate = propose(source, 8)
        for x in (0, 1, 7, 8, 127, 255):
            for denominator in range(1, 256):
                row = execute_program(candidate, "calculate", [x, denominator])
                self.assertEqual(row["values"], [((x // denominator) + (x % denominator)) & 255])
        self.assertEqual(observe(source, [7, 0]), observe(candidate, [7, 0]))

    def test_guarded_and_generic_paths_preserve_first_trap_and_signed_minimum(self):
        source = division("i8")
        for value in (-1, 0, 8):
            candidate = propose(source, value)
            for args in ((-128, -1), (-128, 0), (-128, 8), (-9, 2), (127, -1), (0, 1)):
                with self.subTest(value=value, arguments=args):
                    self.assertEqual(observe(source, list(args)), observe(candidate, list(args)))

    @unittest.skipUnless(importlib.util.find_spec("z3"), "actual Z3 is required")
    def test_all_input_value_and_first_trap_proof_on_integer_widths(self):
        for typ, value in (("u8", 8), ("i8", -1), ("u32", 8)):
            with self.subTest(type=typ, value=value):
                source = division(typ)
                receipt = validate_translation(source, propose(source, value), function="calculate", timeout_ms=5000)
                self.assertEqual(receipt["status"], "proved", receipt)

    @unittest.skipUnless(importlib.util.find_spec("z3"), "actual Z3 is required")
    def test_wide_total_scalar_specialization_is_independently_proved(self):
        params = [("x", "u64"), ("factor", "u64")]
        source = m(f("calculate", params, ["u64"], [], [b("entry", params, [
            i("bit.xor", ["x", "factor"], [("answer", "u64")]),
        ], ret("answer"))]))
        candidate = propose(source, (1 << 64) - 1, parameter="factor")
        self.assertEqual(validate_translation(source, candidate, function="calculate")["status"], "proved")

    @unittest.skipUnless(importlib.util.find_spec("z3"), "actual Z3 is required")
    def test_removing_guard_is_structurally_valid_but_behaviorally_rejected(self):
        source = division("u8")
        candidate = propose(source, 8)
        candidate["functions"][0]["blocks"][0]["ops"][-1] = c("hia_match_0", "bool", True)
        verify_program(candidate)
        result = validate_translation(source, candidate, function="calculate")
        self.assertEqual(result["status"], "disproved", result)
        self.assertIsNotNone(result["counterexample"])

    @unittest.skipUnless(importlib.util.find_spec("z3"), "actual Z3 is required")
    def test_existing_multiblock_phi_paths_boolean_specialization_and_other_export(self):
        params = [("flag", "bool"), ("x", "u8")]
        source = m(f("calculate", params, ["u8"], [], [
            b("entry", params, [], branch("flag", ("yes", "x"), ("no", "x"))),
            b("yes", [("y", "u8")], [c("one", "u8", 1),
                i("int.add.wrap", ["y", "one"], [("plus", "u8")])], jump("join", "plus")),
            b("no", [("n", "u8")], [], jump("join", "n")),
            b("join", [("answer", "u8")], [], ret("answer")),
        ]))
        other = f("other", [("a", "u8")], ["u8"], [], [b("entry", [("a", "u8")], [], ret("a"))])
        source["functions"].append(other)
        source["exports"] = ["calculate", "other"]
        revised = propose(source, True, parameter="flag")
        self.assertEqual(revised["functions"][1], other)
        self.assertEqual(revised["exports"], source["exports"])
        self.assertEqual(validate_translation(source, revised, function="calculate")["status"], "proved")
        for flag in (True, False):
            for value in (0, 127, 255):
                self.assertEqual(observe(source, [flag, value]), observe(revised, [flag, value]))
        with self.assertRaises(HIAProgramRejected):
            propose(source, 1, parameter="flag")

    def test_resources_calls_and_cycles_remain_outside_the_proposal_profile(self):
        with self.assertRaises(HIAProgramRejected):
            propose_guarded_specializations(resource_program(), function="owned",
                assumptions=[{"parameter": "n", "value": 1}])
        target = f("helper", [("y", "u8")], ["u8"], [], [
            b("entry", [("y", "u8")], [], ret("y"))])
        caller = f("calculate", [("x", "u8")], ["u8"], [], [
            b("entry", [("x", "u8")], [i("call", ["x"], [("answer", "u8")],
                function="helper")], ret("answer"))])
        with self.assertRaises(HIAProgramRejected):
            propose(m(caller, target), 8, parameter="x")
        loop = m(f("calculate", [("x", "u64")], [], [], [
            b("entry", [("x", "u64")], [], jump("cycle")),
            b("cycle", [], [], jump("cycle")),
        ]))
        with self.assertRaisesRegex(HIAProgramRejected, "cyclic_cfg"):
            propose(loop, 8, parameter="x")
        with self.assertRaises(HIAProgramRejected):
            propose_guarded_specializations(division(), function="missing",
                assumptions=[{"parameter": "denominator", "value": 8}])


if __name__ == "__main__":
    unittest.main()
