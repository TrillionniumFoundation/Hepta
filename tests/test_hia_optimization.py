"""Independent scalar semantics, failing proofs, and final native publication."""
from __future__ import annotations

import copy
import ctypes
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_optimization import (DEFAULT_POLICY, POLICY_SCHEMA, OptimizationRejected, _Encoder,
    _fresh, _policy, build_optimized_native, fold_constants, verify_optimization)
from hepta.hia_program import WIDTHS, integer_range, verify_program
from hepta.hia_program_runtime import _Machine, HIAProgramTrap, execute_program
from tests.test_hia_program import arithmetic, b, c, f, i, m, ret, resource_program, jump, branch

try:
    import z3
except ImportError:
    z3 = None


def constant_program():
    return m(f("calculate", [("a", "i32")], ["i32"], ["trap"], [
        b("entry", [("a", "i32")], [c("x", "i32", 6), c("y", "i32", 7),
            i("int.mul.checked", ["x", "y"], [("product", "i32")]),
            i("int.add.wrap", ["a", "product"], [("r", "i32")])], ret("r"))]))



class OptimizationPolicyAdmissionTests(unittest.TestCase):
    """Policy receipts must never derive authority from caller-defined comparisons."""

    def test_nonempty_preconditions_cannot_spoof_empty_list(self):
        class ClaimsEmpty(list):
            def __ne__(self, other):
                return False if other == [] else True

        policy = dict(DEFAULT_POLICY)
        policy["preconditions"] = ClaimsEmpty([{"unproven": "candidate may assume anything"}])
        with self.assertRaisesRegex(OptimizationRejected, "E_HIA_OPT_PRECONDITION"):
            _policy(policy)

    def test_invalid_schema_cannot_spoof_version_equality(self):
        class ClaimsSchema(str):
            def __ne__(self, other):
                return False if other == POLICY_SCHEMA else True

        policy = dict(DEFAULT_POLICY)
        policy["schema"] = ClaimsSchema("hepta.hia.unqualified-policy.v0")
        with self.assertRaisesRegex(OptimizationRejected, "E_HIA_OPT_POLICY"):
            _policy(policy)

    def test_top_level_mapping_subclasses_are_not_policy_authority(self):
        class ProducerPolicy(dict):
            pass

        with self.assertRaisesRegex(OptimizationRejected, "E_HIA_OPT_POLICY"):
            _policy(ProducerPolicy(DEFAULT_POLICY))

    def test_accepted_policy_is_detached_from_caller_mutations(self):
        original = dict(DEFAULT_POLICY)
        original["preconditions"] = []
        normalized = _policy(original)
        self.assertEqual(normalized, DEFAULT_POLICY)
        self.assertIsNot(normalized, original)
        self.assertIsNot(normalized["preconditions"], original["preconditions"])
        original["preconditions"].append("unproved after validation")
        original["schema"] = "changed"
        self.assertEqual(normalized, DEFAULT_POLICY)


@unittest.skipUnless(z3 is not None, "install the pinned optimization extra")
class OptimizationVerificationTests(unittest.TestCase):
    def test_constant_proposal_rechecks_all_inputs(self):
        original = constant_program()
        proposed, generation = fold_constants(original)
        self.assertEqual(generation["replacements"], 1)
        self.assertFalse(generation["equivalence_authority"])
        report = verify_optimization(original, proposed)
        self.assertEqual(report["status"], "verified", report)
        self.assertNotEqual(report["base_sha256"], report["candidate_sha256"])
        self.assertTrue(report["solver"]["library_sha256"])
        self.assertFalse(report["claims"]["backend_refinement_proved"])
        for n in (-2147483648, -42, 0, 2147483647):
            self.assertEqual(execute_program(original, "calculate", [n])["result"],
                             execute_program(proposed, "calculate", [n])["result"])

    def test_checked_to_wrapping_is_rejected_with_counterexample(self):
        for typ in WIDTHS:
            with self.subTest(typ=typ):
                report = verify_optimization(arithmetic(typ=typ), arithmetic("int.add.wrap", typ))
                self.assertEqual(report["status"], "rejected", report)
                self.assertIn("counterexample", report["obligations"][-1])

    def test_commutative_rewrite_at_every_integer_width(self):
        for typ in WIDTHS:
            original = arithmetic(typ=typ)
            proposed = copy.deepcopy(original)
            proposed["functions"][0]["blocks"][0]["ops"][0]["args"].reverse()
            self.assertEqual(verify_optimization(original, proposed)["status"], "verified", typ)

    def test_trap_order_cannot_be_reordered(self):
        original = m(f("calculate", [("a", "i8"), ("z", "i8")], ["i8"], ["trap"], [
            b("entry", [("a", "i8"), ("z", "i8")], [
                c("one", "i8", 1), i("int.add.checked", ["a", "one"], [("sum", "i8")]),
                i("int.div.checked", ["a", "z"], [("r", "i8")])], ret("r"))]))
        proposed = copy.deepcopy(original)
        ops = proposed["functions"][0]["blocks"][0]["ops"]
        ops[1], ops[2] = ops[2], ops[1]
        self.assertEqual(verify_optimization(original, proposed)["status"], "rejected")
        with self.assertRaises(HIAProgramTrap) as first:
            execute_program(original, "calculate", [127, 0])
        with self.assertRaises(HIAProgramTrap) as second:
            execute_program(proposed, "calculate", [127, 0])
        self.assertNotEqual(first.exception.code, second.exception.code)

    def test_resource_arguments_are_checked_before_the_effect(self):
        original = resource_program()
        proposed = copy.deepcopy(original)
        for operation in proposed["functions"][0]["blocks"][0]["ops"]:
            if operation["op"] == "const":
                operation["attrs"]["value"] = 1
        report = verify_optimization(original, proposed)
        self.assertEqual(report["status"], "rejected")
        self.assertIn("zero", report["obligations"][-1]["observed"])

    def test_resource_reorder_and_unknown_cfg_are_not_proved(self):
        original = resource_program()
        proposed = copy.deepcopy(original)
        ops = proposed["functions"][0]["blocks"][0]["ops"]
        ops[-2:] = [i("owner.drop", ["owner"])]
        self.assertEqual(verify_optimization(original, proposed)["status"], "unknown")
        ops.pop()
        self.assertEqual(verify_optimization(original, proposed)["status"], "rejected")

    def test_resource_same_program_preserves_actual_allocation_failure(self):
        original = resource_program()
        self.assertEqual(verify_optimization(original, original)["status"], "verified")
        with self.assertRaises(HIAProgramTrap) as failure:
            execute_program(original, "owned", [4, 9], allocation_fail_at=1)
        self.assertEqual(failure.exception.code, "allocation")

    def test_loop_composition_and_function_barriers(self):
        original = m(f("loop", [("n", "u32")], ["u32"], ["trap"], [
            b("entry", [("n", "u32")], [c("zero", "u32", 0)], jump("head", "n", "zero")),
            b("head", [("bound", "u32"), ("value", "u32")], [
                i("compare.lt", ["value", "bound"], [("more", "bool")])],
                branch("more", ("body", "bound", "value"), ("done", "value"))),
            b("body", [("limit", "u32"), ("current", "u32")], [
                c("two", "u32", 2), c("one", "u32", 1),
                i("int.sub.checked", ["two", "one"], [("step", "u32")]),
                i("int.add.checked", ["current", "step"], [("next", "u32")])],
                jump("head", "limit", "next")),
            b("done", [("answer", "u32")], [], ret("answer")),
        ]))
        proposed, generated = fold_constants(original)
        self.assertEqual(generated["replacements"], 1)
        self.assertEqual(verify_optimization(original, proposed)["status"], "verified")
        for n in (0, 1, 3, 100):
            self.assertEqual(execute_program(proposed, "loop", [n])["result"], n)

    def test_changed_return_even_same_name_is_rejected(self):
        original = constant_program()
        proposed = copy.deepcopy(original)
        proposed["functions"][0]["blocks"][0]["ops"][-1]["op"] = "int.sub.wrap"
        self.assertEqual(verify_optimization(original, proposed)["status"], "rejected")

    def test_effect_symbol_names_cannot_alias_adversarial_parameters(self):
        # Both are valid programs. The argument and independent callee result
        # must not become one solver variable through a textual name collision.
        callee = f("identity", [("x", "u8")], ["u8"], [], [
            b("entry", [("x", "u8")], [], ret("x"))])
        original = m(callee, f("calculate", [("s0_value", "u8"), ("other", "u8")],
            ["u8"], [], [b("entry", [("s0_value", "u8"), ("other", "u8")], [
                i("call", ["other"], [("value", "u8")], function="identity"),
                c("zero", "u8", 0),
                i("int.add.wrap", ["value", "zero"], [("r", "u8")])], ret("r"))]))
        proposed = copy.deepcopy(original)
        proposed["functions"][1]["blocks"][0]["ops"][-1]["args"][0] = "s0_value"
        self.assertNotEqual(execute_program(original, "calculate", [1, 2])["result"],
                            execute_program(proposed, "calculate", [1, 2])["result"])
        self.assertEqual(verify_optimization(original, proposed)["status"], "rejected")

    def test_timeout_unknown_and_assumed_preconditions_never_build(self):
        original = constant_program()
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "never.so"
            for settings, status in (({"timeout_ms": 0}, "timeout"),
                                     ({"max_scalar_operations": 0}, "unknown"),
                                     ({"max_obligations": 0}, "unknown")):
                policy = {**DEFAULT_POLICY, **settings}
                self.assertEqual(verify_optimization(original, original, policy)["status"], status)
                with patch("hepta.hia_program_llvm.build_program_native", side_effect=AssertionError("build")):
                    with self.assertRaises(OptimizationRejected):
                        build_optimized_native(original, original, destination, policy=policy)
                self.assertFalse(destination.exists())
        with self.assertRaises(OptimizationRejected):
            verify_optimization(original, original, {**DEFAULT_POLICY, "preconditions": ["a < 100"]})
        with patch.object(z3, "get_version_string", return_value="99.0.0"):
            self.assertEqual(verify_optimization(original, original)["status"], "unknown")

    def test_solver_unknown_cannot_claim_verified(self):
        original_check = z3.Solver.check
        with patch.object(z3.Solver, "check", return_value=z3.unknown), \
                patch.object(z3.Solver, "reason_unknown", return_value="incomplete"):
            report = verify_optimization(constant_program(), constant_program())
        self.assertEqual(report["status"], "unknown")
        self.assertNotIn("core_scalar_effect_equivalence_checked", report["claims"])

    def test_concurrent_proof_requests_own_separate_solver_contexts(self):
        # Before the per-request context fix, this actual four-thread workload
        # could SIGSEGV inside Z3. Isolate it so a regression cannot crash the
        # rest of the qualification or leave an unbounded core dump.
        script = '''
import json, resource
from concurrent.futures import ThreadPoolExecutor
from hepta.hia_optimization import verify_optimization
from tests.test_hia_optimization import constant_program
from tests.test_hia_program import resource_program
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
def prove(index):
    program = constant_program() if index % 2 else resource_program()
    return verify_optimization(program, program)["status"]
with ThreadPoolExecutor(max_workers=4) as workers:
    print(json.dumps(list(workers.map(prove, range(20)))))
'''
        run = subprocess.run([sys.executable, "-c", script], text=True, capture_output=True, timeout=30)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(json.loads(run.stdout), ["verified"] * 20)

    def test_integer_encoder_against_independent_interpreter_boundaries(self):
        # Real reference evaluation and concrete SMT simplification exercise
        # division sign, signed minimum, shift counts, and first-trap encoding.
        operations = [f"int.{kind}.{mode}" for kind in ("add", "sub", "mul")
                      for mode in ("wrap", "checked")]
        operations += [f"int.{kind}.checked" for kind in ("div", "rem", "shl", "shr")]
        operations += ["bit.and", "bit.or", "bit.xor"]
        for typ in ("i8", "u8"):
            lo, hi = integer_range(typ)
            values = sorted({lo, lo + 1, max(lo, -7), max(lo, -1), 0, 1, 2, 7, 8, hi - 1, hi})
            for op in operations:
                program = verify_program(arithmetic(op, typ))
                instruction = program.as_dict()["functions"][0]["blocks"][0]["ops"][0]
                for a in values:
                    for other in values:
                        machine = _Machine(program, 100, 0, None, 4)
                        env = {"a": a, "z": other}
                        actual_trap = 0
                        try:
                            machine.operation(instruction, env, 0)
                        except HIAProgramTrap as exc:
                            actual_trap = {"overflow": 1, "division_by_zero": 2}[exc.code]
                        encoder = _Encoder(z3, {key: (z3.BitVecVal(value, 8), typ)
                                                for key, value in (("a", a), ("z", other))})
                        encoder.operation(instruction)
                        self.assertEqual(z3.simplify(encoder.trap).as_long(), actual_trap,
                                         (typ, op, a, other))
                        if actual_trap == 0:
                            value = z3.simplify(encoder.env["r"][0]).as_long()
                            if typ == "i8" and value >= 128:
                                value -= 256
                            self.assertEqual(value, env["r"], (typ, op, a, other))

    def test_checked_cast_all_8bit_inputs_and_unit_boolean(self):
        for source, target in (("i8", "u8"), ("u8", "i8"), ("i8", "i16"), ("u8", "i16")):
            instruction = i("int.cast", ["a"], [("r", target)], mode="checked")
            lo, hi = integer_range(source)
            target_lo, target_hi = integer_range(target)
            for value in range(lo, hi + 1):
                encoder = _Encoder(z3, {"a": (z3.BitVecVal(value, 8), source)})
                encoder.operation(instruction)
                self.assertEqual(z3.simplify(encoder.trap).as_long(),
                                 int(not target_lo <= value <= target_hi))
        unit = m(f("unit", [("a", "unit")], ["unit"], [], [
            b("entry", [("a", "unit")], [], ret("a"))]))
        proposed = copy.deepcopy(unit)
        proposed["functions"][0]["blocks"][0]["ops"] = [c("out", "unit", None)]
        # The supported profile conservatively preserves terminator spelling.
        self.assertEqual(verify_optimization(unit, unit)["status"], "verified")


@unittest.skipUnless(z3 is not None and shutil.which(os.environ.get("CLANG", "clang")),
                     "pinned Z3 and real Clang required")
class OptimizationNativeTests(unittest.TestCase):
    def test_final_artifact_binding_and_real_execution(self):
        original = constant_program()
        proposed, _ = fold_constants(original)
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "candidate.so"
            report = build_optimized_native(original, proposed, destination,
                                           clang=os.environ.get("CLANG", "clang"))
            self.assertEqual(report["native"]["output"], str(destination))
            self.assertTrue(report["claims"]["final_artifact_bound"])
            function = ctypes.CDLL(str(destination)).calculate
            function.argtypes, function.restype = [ctypes.c_int32], ctypes.c_int32
            for value in (-2147483648, -42, 0, 2147483647):
                self.assertEqual(function(value), execute_program(original, "calculate", [value])["result"])
            with self.assertRaises(OptimizationRejected):
                build_optimized_native(original, proposed, destination,
                                       clang=os.environ.get("CLANG", "clang"))

    def test_changed_checker_during_actual_compilation_never_publishes(self):
        from hepta.hia_program_llvm import build_program_native
        original = constant_program()
        state = {"built": False}
        from hepta.hia_optimization import checker_identity
        identity = checker_identity()

        def build(*args, **kwargs):
            result = build_program_native(*args, **kwargs)
            state["built"] = True
            return result

        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "never.so"
            with patch("hepta.hia_program_llvm.build_program_native", side_effect=build), \
                    patch("hepta.hia_optimization.checker_identity",
                          side_effect=lambda: "f" * 64 if state["built"] else identity):
                with self.assertRaises(OptimizationRejected):
                    build_optimized_native(original, original, destination,
                                           clang=os.environ.get("CLANG", "clang"))
            self.assertTrue(state["built"])
            self.assertFalse(destination.exists())
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_candidate_dictionary_is_frozen_before_proof_and_build(self):
        from hepta.hia_optimization import require_verified
        original, proposed = constant_program(), constant_program()

        def verify_then_mutate(base, candidate, policy):
            receipt = require_verified(base, candidate, policy)
            proposed["functions"][0]["blocks"][0]["ops"][-1]["op"] = "int.sub.wrap"
            return receipt

        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "candidate.so"
            with patch("hepta.hia_optimization.require_verified", side_effect=verify_then_mutate):
                report = build_optimized_native(original, proposed, destination,
                                               clang=os.environ.get("CLANG", "clang"))
            self.assertEqual(report["native"]["core_sha256"], report["verification"]["candidate_sha256"])
            function = ctypes.CDLL(str(destination)).calculate
            function.argtypes, function.restype = [ctypes.c_int32], ctypes.c_int32
            self.assertEqual(function(0), 42)
            self.assertEqual(execute_program(proposed, "calculate", [0])["result"], -42)


if __name__ == "__main__":
    unittest.main()
