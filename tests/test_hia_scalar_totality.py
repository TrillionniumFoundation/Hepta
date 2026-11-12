"""Normal return is a separate obligation from behavioral equivalence."""
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

from hepta.hia_program import VerifiedProgram, verify_program
from hepta.hia_scalar_totality import SCHEMA, PROFILE, validate_scalar_totality
from hepta.hia_scalar_totality import CALL_SCHEMA, CALL_PROFILE, validate_scalar_call_totality
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


def guarded_call_division(typ="u8"):
    """The helper can trap; only its actual guarded call sites are total."""
    helper = arithmetic("int.div.checked", typ)["functions"][0]
    helper["name"] = "divide"
    source = total_division(typ)
    nonzero = source["functions"][0]["blocks"][2]
    nonzero["ops"] = [i("call", ["n", "d"], [("answer", typ)], function="divide")]
    source["functions"].append(helper)
    source["exports"] = ["calculate"]
    return source


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
            def sexpr(self):
                return "test-unknown"
            def check(self):
                return z3.unknown
            def reason_unknown(self):
                return "timeout"
        with patch("z3.Solver", Exhausted):
            result = validate_scalar_totality(total_division(), timeout_ms=2000)
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


    def test_primitive_proof_requires_pinned_solver_and_actual_library_identity(self):
        import z3
        with patch.object(z3, "get_version_string", return_value="unqualified"):
            result = validate_scalar_totality(total_division())
        self.assertEqual(result["status"], "unknown", result)
        self.assertEqual(result["reason"], "pinned_solver_required")
        self.assertFalse(result["claims"]["all_inputs_return_normally_proved"])
        with patch("hepta.hia_optimization._solver_identity",
                   side_effect=[{"solver": "a"}, {"solver": "b"}]):
            result = validate_scalar_totality(total_division())
        self.assertEqual(result["status"], "unknown", result)
        self.assertEqual(result["reason"], "implementation_changed_during_proof")
        self.assertIsNone(result["counterexample"])

    def test_checker_opcode_and_replay_identity_drift_revokes_unsat_or_sat(self):
        for source in (total_division(), arithmetic("int.div.checked", "u8")):
            with patch("hepta.hia_scalar_totality._primitive_implementation_identity",
                       side_effect=[{"hia_program.py": "a"}, {"hia_program.py": "b"}]):
                result = validate_scalar_totality(source)
            self.assertEqual(result["status"], "unknown", result)
            self.assertEqual(result["reason"], "implementation_changed_during_proof")
            self.assertFalse(result["claims"]["all_inputs_return_normally_proved"])
            self.assertIsNone(result["counterexample"])

    def test_deadline_covers_encoding_and_final_identity_rechecks(self):
        for clock in ([0, 2_000_000_001, 2_000_000_002],
                      [0, 1_000_000, 2_000_000_001]):
            with patch("hepta.hia_scalar_totality.time.monotonic_ns", side_effect=clock):
                result = validate_scalar_totality(total_division())
            self.assertEqual(result["status"], "unknown", result)
            self.assertEqual(result["reason"], "proof_deadline_exhausted")
            self.assertFalse(result["claims"]["all_inputs_return_normally_proved"])
        self.assertEqual(result["solver"]["result"], "unsat")

    def test_encoder_replay_and_missing_final_identity_never_escape_as_proof(self):
        for target, source in (
                ("hepta.hia_translation_validation._Encoder.function", total_division()),
                ("hepta.hia_translation_validation._execute_observation", arithmetic("int.div.checked", "u8"))):
            with patch(target, side_effect=RuntimeError("forced incomplete proof")):
                result = validate_scalar_totality(source)
            self.assertEqual(result["status"], "unknown", result)
            self.assertEqual(result["reason"], "proof_error")
            self.assertFalse(result["claims"]["all_inputs_return_normally_proved"])
            self.assertIsNone(result["counterexample"])
        with patch("hepta.hia_scalar_totality._primitive_implementation_identity",
                   side_effect=[{"source": "a"}, OSError("source disappeared")]):
            result = validate_scalar_totality(total_division())
        self.assertEqual(result["reason"], "implementation_identity_unavailable", result)
        self.assertEqual(result["status"], "unknown")

    def test_primitive_evidence_binds_complete_source_and_query_without_universal_claim(self):
        result = validate_scalar_totality(total_division())
        self.assertEqual(result["status"], "proved", result)
        root = Path(__file__).resolve().parents[1]
        self.assertTrue({"hia_program.py", "hia_opcodes.py", "hia_schema.py",
                         "hia_program_runtime.py", "hia_translation_validation.py"}
                        <= result["implementation"].keys())
        for name, digest in result["implementation"].items():
            self.assertEqual(digest, sha256((root/"hepta"/name).read_bytes()).hexdigest())
        self.assertEqual(len(result["solver"]["query_sha256"]), 64)
        self.assertEqual(len(result["solver"]["identity"]["library_sha256"]), 64)
        self.assertFalse(result["execution_authority"])
        self.assertFalse(result["claims"]["all_programs_of_this_profile_proved"])
        self.assertGreater(result["wall_ns"], 0)


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

    def test_unqualified_primitive_schema_cannot_inherit_legacy_totality(self):
        source = total_division()
        source["schema"] = "hepta.hia.program.v8"
        verify_program(source)
        result = validate_scalar_totality(source)
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["reason"], "core_schema_outside_qualified_v1_v7_profile")


@unittest.skipUnless(importlib.util.find_spec("z3"), "actual Z3 is required")
class ScalarCallTotalityTests(unittest.TestCase):
    def test_guarded_calls_prove_selected_totality_without_claiming_callee_totality(self):
        for typ in ("u8", "u16"):
            source = guarded_call_division(typ)
            result = validate_scalar_call_totality(source, function="calculate")
            self.assertEqual(result["status"], "proved", result)
            self.assertEqual(result["solver"]["result"], "unsat")
            self.assertEqual(result["call_closure"], ["calculate", "divide"])
            self.assertEqual(result["call_expansions"], 2)
            self.assertEqual((result["schema"], result["profile"]), (CALL_SCHEMA, CALL_PROFILE))
            self.assertFalse(result["execution_authority"])
            self.assertFalse(result["claims"]["all_programs_of_this_profile_proved"])
            self.assertFalse(result["claims"]["native_backend_refinement_proved"])
            source["exports"].append("divide")
            non_total = validate_scalar_call_totality(source, function="divide")
            self.assertEqual(non_total["status"], "disproved", non_total)
            self.assertEqual(non_total["counterexample"]["observation"]["code"], "division_by_zero")

    def test_nested_original_callees_are_encoded_without_invoking_the_inliner(self):
        source = guarded_call_division()
        helper = source["functions"][1]
        helper["name"] = "leaf"
        middle = f("divide", [("a", "u8"), ("z", "u8")], ["u8"], ["trap"], [
            b("entry", [("a", "u8"), ("z", "u8")], [
                i("call", ["a", "z"], [("result", "u8")], function="leaf")], ret("result"))])
        source["functions"].append(middle)
        with patch("hepta.hia_scalar_call_validation.inline_scalar_calls",
                   side_effect=AssertionError("producer must not prove its own rewrite")):
            result = validate_scalar_call_totality(source, function="calculate")
        self.assertEqual(result["status"], "proved", result)
        self.assertEqual(result["call_expansions"], 3)
        self.assertEqual(result["call_closure"], ["calculate", "divide", "leaf"])

    def test_zero_guard_does_not_hide_signed_minimum_division_overflow_in_callee(self):
        result = validate_scalar_call_totality(guarded_call_division("i8"), function="calculate")
        self.assertEqual(result["status"], "disproved", result)
        self.assertEqual(result["counterexample"]["arguments"], [-128, -1])
        self.assertEqual(result["counterexample"]["observation"], {"status": "trapped", "code": "overflow"})

    def test_callee_body_change_invalidates_totality_and_replays_real_counterexample(self):
        source = guarded_call_division()
        good = validate_scalar_call_totality(source, function="calculate")
        helper = source["functions"][1]["blocks"][0]
        helper["ops"].insert(0, c("always_zero", "u8", 0))
        helper["ops"][1]["args"][1] = "always_zero"
        bad = validate_scalar_call_totality(source, function="calculate")
        self.assertEqual(bad["status"], "disproved", bad)
        self.assertNotEqual(good["program_sha256"], bad["program_sha256"])
        self.assertNotEqual(bad["counterexample"]["arguments"][1], 0)
        self.assertEqual(bad["counterexample"]["observation"],
                         {"status": "trapped", "code": "division_by_zero"})

    def test_caller_and_callee_first_traps_preserve_execution_order(self):
        helper = arithmetic("int.div.checked", "u8")["functions"][0]
        helper["name"] = "divide"
        for call_first in (False, True):
            overflow = i("int.add.checked", ["maximum", "one"], [("overflow", "u8")])
            call = i("call", ["maximum", "zero"], [("result", "u8")], function="divide")
            caller = f("calculate", [], ["u8"], ["trap"], [b("entry", [], [
                c("maximum", "u8", 255), c("one", "u8", 1), c("zero", "u8", 0),
                *([call, overflow] if call_first else [overflow, call])], ret("result"))])
            source = m(caller, helper)
            source["exports"] = ["calculate"]
            result = validate_scalar_call_totality(source, function="calculate")
            self.assertEqual(result["status"], "disproved", result)
            self.assertEqual(result["counterexample"]["observation"]["code"],
                             "division_by_zero" if call_first else "overflow")

    def test_missing_callee_path_cannot_be_hidden_by_normal_caller_return(self):
        from hepta.hia_scalar_call_validation import _Calls
        original = _Calls.function
        def missing(encoder, fn, *args):
            if fn["name"] == "divide":
                return encoder.z.IntVal(-1, encoder.context), [encoder.zero(t) for t in fn["returns"]]
            return original(encoder, fn, *args)
        with patch.object(_Calls, "function", missing):
            result = validate_scalar_call_totality(guarded_call_division(), function="calculate")
        self.assertEqual(result["status"], "unknown", result)
        self.assertEqual(result["reason"], "incomplete_symbolic_execution")

    def test_counterexample_requires_matching_independent_vm_replay(self):
        source = arithmetic("int.div.checked", "u8")
        for observation in ({"status": "returned", "values": [0]},
                            {"status": "trapped", "code": "overflow"}):
            with patch("hepta.hia_scalar_call_validation._observe", return_value=observation):
                result = validate_scalar_call_totality(source, function="calculate")
            self.assertEqual(result["status"], "unknown", result)
            self.assertEqual(result["reason"], "counterexample_replay_disagrees_with_encoder")

    def test_every_existing_call_closure_limit_remains_enforced(self):
        for field, value in (("MAX_FUNCTIONS", 1), ("MAX_BLOCKS", 1),
                             ("MAX_OPERATIONS", 1), ("MAX_CALL_EXPANSIONS", 1)):
            with self.subTest(field=field), patch("hepta.hia_scalar_call_validation." + field, value):
                result = validate_scalar_call_totality(guarded_call_division(), function="calculate")
                self.assertEqual(result["status"], "unknown", result)
                self.assertFalse(result["claims"]["all_inputs_return_normally_proved"])

    def test_recursion_loops_resources_and_unqualified_schema_stay_unknown(self):
        recursive = guarded_call_division()
        recursive["functions"][1]["blocks"][0]["ops"] = [
            i("call", ["a", "z"], [("r", "u8")], function="divide")]
        loop = m(f("calculate", [], ["u8"], [], [
            b("entry", [], [], jump("cycle")), b("cycle", [], [], jump("cycle"))]))
        resource = guarded_call_division()
        for fn in resource["functions"]:
            fn["effects"].append("alloc")
        schema = guarded_call_division()
        schema["schema"] = "hepta.hia.program.v8"
        for source in (recursive, loop, resource, schema):
            verify_program(source)
            result = validate_scalar_call_totality(source, function="calculate")
            self.assertEqual(result["status"], "unknown", result)
            self.assertFalse(result["claims"]["all_inputs_return_normally_proved"])

    def test_solver_unknown_unavailable_and_version_mismatch_never_prove(self):
        import z3
        class Unknown:
            def set(self, **_kwargs): pass
            def add(self, *_args): pass
            def sexpr(self): return "test-unknown"
            def check(self): return z3.unknown
            def reason_unknown(self): return "timeout"
        with patch.object(z3, "Solver", return_value=Unknown()):
            unknown = validate_scalar_call_totality(guarded_call_division(), function="calculate")
        self.assertEqual(unknown["reason"], "solver_unknown", unknown)
        with patch("hepta.hia_translation_validation._z3_module", side_effect=ImportError("absent")):
            absent = validate_scalar_call_totality(guarded_call_division(), function="calculate")
        self.assertEqual(absent["reason"], "solver_or_implementation_unavailable", absent)
        with patch.object(z3, "get_version_string", return_value="unqualified"):
            version = validate_scalar_call_totality(guarded_call_division(), function="calculate")
        self.assertEqual(version["reason"], "pinned_solver_required", version)
        for result in (unknown, absent, version):
            self.assertEqual(result["status"], "unknown")
            self.assertFalse(result["claims"]["all_inputs_return_normally_proved"])

    def test_implementation_and_loaded_solver_identity_are_rechecked(self):
        with patch("hepta.hia_scalar_totality._call_implementation_identity",
                   side_effect=[{"source": "a"}, {"source": "b"}]):
            source_drift = validate_scalar_call_totality(guarded_call_division(), function="calculate")
        with patch("hepta.hia_optimization._solver_identity",
                   side_effect=[{"solver": "a"}, {"solver": "b"}]):
            solver_drift = validate_scalar_call_totality(guarded_call_division(), function="calculate")
        for result in (source_drift, solver_drift):
            self.assertEqual(result["status"], "unknown", result)
            self.assertEqual(result["reason"], "implementation_changed_during_proof")
            self.assertFalse(result["claims"]["all_inputs_return_normally_proved"])

    def test_whole_proof_deadline_cannot_be_restarted_at_solver_entry(self):
        with patch("hepta.hia_scalar_totality.time.monotonic_ns",
                   side_effect=[0, 10_000_000_001, 10_000_000_002]):
            result = validate_scalar_call_totality(guarded_call_division(), function="calculate")
        self.assertEqual(result["status"], "unknown", result)
        self.assertEqual(result["reason"], "proof_deadline_exhausted")
        self.assertEqual(result["solver"]["result"], "not_run")

    def test_invalid_selection_and_deadlines_do_not_infer_authority(self):
        for timeout in (True, 0, -1, 10001, 1.5, "1000"):
            result = validate_scalar_call_totality(guarded_call_division(), function="calculate", timeout_ms=timeout)
            self.assertEqual(result["reason"], "invalid_solver_timeout")
        for function in (None, "divide", "missing", ["calculate"]):
            result = validate_scalar_call_totality(guarded_call_division(), function=function)
            self.assertEqual(result["status"], "unknown", result)
            self.assertEqual(result["reason"], "not_a_public_scalar_entrypoint")

    def test_parallel_call_proofs_have_independent_contexts_and_exact_source_identity(self):
        programs = [guarded_call_division(), arithmetic("int.div.checked", "u8")] * 2
        def prove(source):
            return validate_scalar_call_totality(source, function="calculate")
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(prove, programs))
        self.assertEqual([r["status"] for r in results], ["proved", "disproved"] * 2, results)
        root = Path(__file__).resolve().parents[1]
        for source, result in zip(programs, results):
            checked = verify_program(source)
            self.assertEqual((result["program_sha256"], result["input_sha256"]),
                             (checked.sha256, checked.input_sha256))
            for name, digest in result["implementation"].items():
                self.assertEqual(digest, sha256((root/"hepta"/name).read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
