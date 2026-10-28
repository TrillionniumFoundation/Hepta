"""Normal return is a separate obligation from behavioral equivalence."""
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

from hepta.hia_program import VerifiedProgram, verify_program
from hepta.hia_scalar_totality import SCHEMA, PROFILE, validate_scalar_totality
from hepta.hia_specialization import propose_guarded_specializations
from hepta.hia_translation_validation import validate_translation
from tests.test_hia_program import arithmetic, b, branch, c, f, i, jump, m, resource_program, ret
from tests.test_hia_translation_validation import constant_operation, explicit_trap


def total_division(typ="u8"):
    params = [("x", typ), ("denominator", typ)]
    return m(f("calculate", params, [typ], ["trap"], [
        b("entry", params, [c("zero", typ, 0),
            i("compare.eq", ["denominator", "zero"], [("is_zero", "bool")])],
          branch("is_zero", ("zero_case", "x"), ("nonzero", "x", "denominator"))),
        b("zero_case", [("z", typ)], [], ret("z")),
        b("nonzero", [("n", typ), ("d", typ)], [
            i("int.div.checked", ["n", "d"], [("q", typ)]),
            i("int.rem.checked", ["n", "d"], [("r", typ)]),
            i("int.add.wrap", ["q", "r"], [("answer", typ)])], ret("answer")),
    ]))


@unittest.skipUnless(importlib.util.find_spec("z3"), "actual Z3 is required")
class ScalarTotalityTests(unittest.TestCase):
    def test_guarded_zero_and_specializations_prove_normal_return(self):
        for typ in ("u8", "u16"):
            source = total_division(typ)
            programs = [source] + [row["program"] for row in propose_guarded_specializations(
                source, function="calculate", assumptions=[{"parameter": "denominator", "value": n}
                                                           for n in (0, 3, 16)])]
            for program in programs:
                with self.subTest(type=typ, canonical=verify_program(program).sha256):
                    result = validate_scalar_totality(program)
                    self.assertEqual(result["status"], "proved", result)
                    self.assertEqual(result["solver"]["result"], "unsat")
                    self.assertTrue(result["claims"]["all_inputs_return_normally_proved"])
                    self.assertFalse(result["claims"]["native_backend_refinement_proved"])

    def test_self_equivalence_cannot_authorize_trapping_division(self):
        source = arithmetic("int.div.checked", "u8")
        self.assertEqual(validate_translation(source, source)["status"], "proved")
        result = validate_scalar_totality(source)
        self.assertEqual(result["status"], "disproved", result)
        self.assertEqual(result["counterexample"]["arguments"][1], 0)
        self.assertEqual(result["counterexample"]["observation"],
                         {"status": "trapped", "code": "division_by_zero"})

    def test_guard_direction_and_guarded_denominator_are_semantically_checked(self):
        wrong_direction = total_division()
        wrong_direction["functions"][0]["blocks"][0]["ops"][1]["op"] = "compare.ne"
        wrong_divisor = total_division()
        block = wrong_divisor["functions"][0]["blocks"][2]
        block["ops"].insert(0, c("bad_zero", "u8", 0))
        block["ops"][1]["args"][1] = "bad_zero"
        for source in (wrong_direction, wrong_divisor):
            result = validate_scalar_totality(source)
            self.assertEqual(result["status"], "disproved", result)

    def test_replayed_first_trap_and_signed_minimum_remain_observable(self):
        params = [("x", "i8")]
        first = m(f("calculate", params, ["i8"], ["trap"], [b("entry", params, [
            c("zero", "i8", 0), c("one", "i8", 1),
            i("int.div.checked", ["x", "zero"], [("q", "i8")]),
            i("int.add.checked", ["x", "one"], [("a", "i8")]),
        ], ret("a"))]))
        cases = [(first, "division_by_zero"),
                 (constant_operation("int.rem.checked", "i8", [-128, -1]), "overflow"),
                 (explicit_trap("u8", "bounds"), "bounds")]
        for source, code in cases:
            result = validate_scalar_totality(source)
            self.assertEqual(result["status"], "disproved", result)
            self.assertEqual(result["counterexample"]["observation"]["code"], code)

    def test_unselected_trap_and_multiple_predecessor_join(self):
        params = [("x", "u8")]
        source = m(f("calculate", params, ["u8"], ["trap"], [
            b("entry", params, [c("one", "u8", 1),
                i("compare.lt", ["x", "one"], [("small", "bool")])],
              branch("small", ("join", "x"), ("middle", "x"))),
            b("middle", [("mx", "u8")], [c("never", "bool", False)],
              branch("never", ("trap",), ("join", "mx"))),
            b("trap", [], [], {"op": "trap", "code": "overflow"}),
            b("join", [("answer", "u8")], [], ret("answer")),
        ]))
        result = validate_scalar_totality(source)
        self.assertEqual(result["status"], "proved", result)

    def test_missing_symbolic_path_and_wrong_replay_stay_unknown(self):
        def incomplete(encoder, fn, *_args):
            return encoder.z.IntVal(-1, encoder.context), [encoder.zero(t) for t in fn["returns"]]
        with patch("hepta.hia_translation_validation._Encoder.function", incomplete):
            result = validate_scalar_totality(total_division())
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["reason"], "incomplete_symbolic_execution")
        for observation in ({"status": "returned", "values": [0]},
                            {"status": "trapped", "code": "overflow"}):
            with patch("hepta.hia_translation_validation._execute_observation", return_value=observation):
                result = validate_scalar_totality(arithmetic("int.div.checked", "u8"))
            self.assertEqual(result["status"], "unknown")
            self.assertEqual(result["reason"], "counterexample_replay_disagrees_with_encoder")

    def test_unknown_solver_error_and_absence_do_not_establish_totality(self):
        import z3
        class Exhausted:
            def __init__(self, **_kwargs):
                pass
            def set(self, **_kwargs):
                pass
            def add(self, *_args):
                pass
            def check(self):
                return z3.unknown
            def reason_unknown(self):
                return "timeout"
        with patch("z3.Solver", Exhausted):
            result = validate_scalar_totality(total_division(), timeout_ms=1)
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["solver"]["reason_unknown"], "timeout")
        with patch("z3.Solver", side_effect=z3.Z3Exception("forced error")):
            error = validate_scalar_totality(total_division())
        self.assertEqual(error["reason"], "solver_error")
        with patch("hepta.hia_translation_validation._z3_module", side_effect=ImportError("absent")):
            absent = validate_scalar_totality(total_division())
        self.assertEqual(absent["reason"], "solver_unavailable")
        for value in (result, error, absent):
            self.assertFalse(value["claims"]["all_inputs_return_normally_proved"])

    def test_parallel_jobs_use_independent_contexts_and_bind_implementations(self):
        programs = [total_division(), arithmetic("int.div.checked", "u16")] * 4
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(validate_scalar_totality, programs))
        self.assertEqual([r["status"] for r in results], ["proved", "disproved"] * 4)
        root = Path(__file__).resolve().parents[1]
        for source, result in zip(programs, results):
            self.assertEqual((result["schema"], result["profile"]), (SCHEMA, PROFILE))
            checked = verify_program(source)
            self.assertEqual((result["program_sha256"], result["input_sha256"]),
                             (checked.sha256, checked.input_sha256))
            for name, file in (("validator", "hia_scalar_totality"), ("encoder", "hia_translation_validation")):
                self.assertEqual(result[name+"_sha256"], sha256((root/"hepta"/(file+".py")).read_bytes()).hexdigest())

    def test_modified_implementation_identity_invalidates_even_unsat(self):
        with patch("hepta.hia_scalar_totality._implementation_digest", side_effect=["a"*64, "b"*64]):
            result = validate_scalar_totality(total_division())
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["reason"], "implementation_changed_during_proof")
        self.assertFalse(result["claims"]["all_inputs_return_normally_proved"])


class ScalarTotalityBoundaryTests(unittest.TestCase):
    def test_invalid_timeout_forged_program_and_missing_export_are_unknown(self):
        for timeout in (0, -1, 60001, True, 1.5, "20"):
            result = validate_scalar_totality(total_division(), timeout_ms=timeout)
            self.assertEqual(result["reason"], "invalid_solver_timeout")
        import json
        invalid = total_division()
        invalid["functions"][0]["blocks"][0]["term"]["cond"] = "undefined"
        result = validate_scalar_totality(VerifiedProgram(json.dumps(invalid).encode()))
        self.assertEqual(result["reason"], "invalid_program")
        private = total_division()
        private["exports"] = []
        self.assertEqual(validate_scalar_totality(private)["reason"], "not_a_public_scalar_entrypoint")
        self.assertEqual(validate_scalar_totality(total_division(), function="missing")["reason"],
                         "missing_or_ambiguous_function")

    def test_loops_calls_and_resources_remain_outside_profile(self):
        loop = m(f("calculate", [], [], [], [
            b("entry", [], [], jump("cycle")), b("cycle", [], [], jump("cycle"))]))
        helper = total_division()["functions"][0]
        caller = f("caller", [("x", "u8"), ("d", "u8")], ["u8"], ["trap"], [
            b("entry", [("x", "u8"), ("d", "u8")], [
                i("call", ["x", "d"], [("result", "u8")], function="calculate")], ret("result"))])
        for source, function, reason in (
                (loop, "calculate", "cyclic_cfg_outside_profile"),
                (resource_program(), "owned", "resource_effects_outside_scalar_profile"),
                (m(helper, caller), "caller", "operation_outside_scalar_profile")):
            result = validate_scalar_totality(source, function=function)
            self.assertEqual(result["status"], "unknown")
            self.assertEqual(result["reason"], reason)


if __name__ == "__main__":
    unittest.main()
