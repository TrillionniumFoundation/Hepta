"""Independent call-closure proofs must not trust the inlining producer."""
from __future__ import annotations

import copy
import unittest
from unittest.mock import patch

from hepta.hia_program import verify_program
from hepta.hia_scalar_call_validation import inline_scalar_calls, validate_scalar_calls
from hepta.hia_translation_validation import validate_translation
from tests.test_hia_program import b, branch, c, f, i, jump, m, ret


def signed_calls():
    params = [("a", "i8"), ("d", "i8")]
    helper = f("helper", [("x", "i8")], ["i8"], ["trap"], [
        b("entry", [("x", "i8")], [c("zero", "i8", 0),
          i("compare.lt", ["x", "zero"], [("negative", "bool")])],
          branch("negative", ("negative", "x"), ("positive", "x"))),
        b("negative", [("n", "i8")], [], ret("n")),
        b("positive", [("p", "i8")], [i("int.neg.checked", ["p"], [("neg", "i8")])], ret("neg")),
    ])
    caller = f("calculate", params, ["i8"], ["trap"], [b("entry", params, [
        i("int.rem.checked", ["a", "d"], [("r", "i8")]),
        i("call", ["d"], [("negative_abs", "i8")], function="helper"),
        i("int.sub.checked", ["r", "negative_abs"], [("answer", "i8")]),
    ], ret("answer"))])
    document = m(caller, helper)
    document["exports"] = ["calculate"]
    return document


class ScalarCallValidationTests(unittest.TestCase):
    def test_actual_direct_calls_and_inline_proposal_prove_first_traps(self):
        source = signed_calls()
        saved = copy.deepcopy(source)
        flat = inline_scalar_calls(source, function="calculate")
        self.assertEqual(source, saved)
        self.assertFalse(any(op["op"] == "call" for block in flat["functions"][0]["blocks"] for op in block["ops"]))
        proof = validate_scalar_calls(source, flat, function="calculate")
        self.assertEqual(proof["status"], "proved", proof)
        self.assertTrue(proof["claims"]["all_input_return_and_first_trap_equivalence"])
        self.assertFalse(proof["execution_authority"])

    def test_legacy_validator_still_rejects_calls(self):
        source = signed_calls()
        proof = validate_translation(source, source, function="calculate")
        self.assertEqual(proof["status"], "unknown")
        self.assertEqual(proof["reason"], "operation_outside_scalar_profile")

    def test_inliner_is_not_called_by_the_independent_encoder(self):
        source = signed_calls()
        flat = inline_scalar_calls(source, function="calculate")
        with patch("hepta.hia_scalar_call_validation.inline_scalar_calls", side_effect=AssertionError("producer used")):
            proof = validate_scalar_calls(source, flat, function="calculate")
        self.assertEqual(proof["status"], "proved", proof)

    def test_wrong_inline_return_is_replayed_as_a_real_counterexample(self):
        source = signed_calls()
        flat = inline_scalar_calls(source, function="calculate")
        operation = next(op for block in flat["functions"][0]["blocks"] for op in block["ops"]
                         if op["op"] == "int.sub.checked")
        operation["op"] = "int.add.checked"
        verify_program(flat)
        proof = validate_scalar_calls(source, flat, function="calculate")
        self.assertEqual(proof["status"], "disproved", proof)
        self.assertNotEqual(proof["counterexample"]["before"], proof["counterexample"]["after"])

    def test_callee_mutation_is_encoded_from_actual_callee_bytes(self):
        source = signed_calls()
        flat = inline_scalar_calls(source, function="calculate")
        wrong = copy.deepcopy(source)
        wrong["functions"][1]["blocks"][2]["ops"][0] = c("neg", "i8", 0)
        proof = validate_scalar_calls(wrong, flat, function="calculate")
        self.assertEqual(proof["status"], "disproved", proof)

    def test_first_trap_code_and_call_position_are_observations(self):
        helper = f("helper", [("x", "i8")], ["i8"], ["trap"], [b("h", [("x", "i8")],
            [i("int.neg.checked", ["x"], [("r", "i8")])], ret("r"))])
        caller = f("calculate", [("x", "i8")], ["i8"], ["trap"], [b("c", [("x", "i8")], [
            c("zero", "i8", 0), i("int.div.checked", ["x", "zero"], [("q", "i8")]),
            i("call", ["x"], [("r", "i8")], function="helper")], ret("r"))])
        source = m(caller, helper)
        source["exports"] = ["calculate"]
        altered = copy.deepcopy(source)
        ops = altered["functions"][0]["blocks"][0]["ops"]
        ops[1], ops[2] = ops[2], ops[1]
        proof = validate_scalar_calls(source, altered, function="calculate")
        self.assertEqual(proof["status"], "disproved", proof)
        self.assertEqual(proof["counterexample"]["before"], {"status": "trapped", "code": "division_by_zero"})
        self.assertEqual(proof["counterexample"]["after"], {"status": "trapped", "code": "overflow"})

    def test_two_calls_keep_the_call_results_and_live_caller_values(self):
        source = signed_calls()
        block = source["functions"][0]["blocks"][0]
        block["ops"].append(i("call", ["answer"], [("second", "i8")], function="helper"))
        block["ops"].append(i("int.add.checked", ["r", "second"], [("final", "i8")]))
        block["term"] = ret("final")
        flat = inline_scalar_calls(source, function="calculate")
        proof = validate_scalar_calls(source, flat, function="calculate")
        self.assertEqual(proof["status"], "proved", proof)

    def test_unknown_callee_and_recursion_cannot_be_admitted(self):
        source = signed_calls()
        for callee in ("missing", "calculate"):
            wrong = copy.deepcopy(source)
            call = wrong["functions"][0]["blocks"][0]["ops"][1]
            call["attrs"]["function"] = callee
            if callee == "calculate":
                call["args"] = ["a", "d"]
            proof = validate_scalar_calls(wrong, wrong, function="calculate")
            self.assertEqual(proof["status"], "unknown", proof)

    def test_declared_resource_effects_never_enter_scalar_call_profile(self):
        source = signed_calls()
        for fn in source["functions"]:
            fn["effects"] = ["alloc", "trap"]
        proof = validate_scalar_calls(source, source, function="calculate")
        self.assertEqual(proof["status"], "unknown", proof)
        self.assertFalse(proof["claims"]["all_input_return_and_first_trap_equivalence"])

    def test_all_finite_closure_and_expansion_limits_fail_closed(self):
        source = signed_calls()
        for field, value in (("MAX_FUNCTIONS", 1), ("MAX_BLOCKS", 1),
                             ("MAX_OPERATIONS", 1), ("MAX_CALL_EXPANSIONS", 1)):
            with self.subTest(field=field), patch("hepta.hia_scalar_call_validation." + field, value):
                proof = validate_scalar_calls(source, source, function="calculate")
                self.assertEqual(proof["status"], "unknown", proof)
                self.assertFalse(proof["claims"]["all_input_return_and_first_trap_equivalence"])

    def test_solver_unknown_never_becomes_equivalence(self):
        import z3
        source = signed_calls()
        class Unknown:
            def set(self, **kw): pass
            def add(self, *args): pass
            def check(self): return z3.unknown
            def reason_unknown(self): return "test timeout"
        with patch.object(z3, "Solver", return_value=Unknown()):
            proof = validate_scalar_calls(source, source, function="calculate")
        self.assertEqual(proof["status"], "unknown", proof)
        self.assertEqual(proof["reason"], "test timeout")

    def test_invalid_timeout_is_not_repaired_or_clamped(self):
        for value in (True, 0, -1, 10001):
            proof = validate_scalar_calls(signed_calls(), signed_calls(), function="calculate", timeout_ms=value)
            self.assertEqual(proof["status"], "unknown")


if __name__ == "__main__":
    unittest.main()
