"""All-input scalar equivalence, trap preservation, and hostile receipts."""
from __future__ import annotations

import copy
import importlib.util
import unittest
from unittest.mock import patch

from hepta.hia_program import HIAProgramRejected, VerifiedProgram, integer_range, verify_program
from hepta.hia_translation_validation import validate_translation, verify_translation_receipt
from tests.test_hia_program import (
    arithmetic, b, branch, c, f, i, jump, m, resource_program, ret,
)


def identity(typ="u32"):
    return m(f("calculate", [("a", typ), ("z", typ)], [typ], ["trap"], [
        b("entry", [("a", typ), ("z", typ)], [], ret("a"))]))


def constant_operation(opcode, typ, operands, *, source_type=None, **attrs):
    src = source_type or typ
    operations = [c(f"arg{idx}", src, value) for idx, value in enumerate(operands)]
    operations.append(i(opcode, [f"arg{idx}" for idx in range(len(operands))], [("r", typ)], **attrs))
    return m(f("calculate", [], [typ], ["trap"], [b("entry", [], operations, ret("r"))]))


def constant_return(typ, value):
    return m(f("calculate", [], [typ], ["trap"], [b("entry", [], [c("r", typ, value)], ret("r"))]))


def explicit_trap(typ, code):
    return m(f("calculate", [], [typ], ["trap"], [b("entry", [], [], {"op": "trap", "code": code})]))


@unittest.skipUnless(importlib.util.find_spec("z3"), "optional z3-solver is not installed")
class ScalarTranslationProofTests(unittest.TestCase):
    def assert_proved(self, before, after, **kwargs):
        receipt = validate_translation(before, after, **kwargs)
        self.assertEqual(receipt["status"], "proved", receipt)
        self.assertEqual(receipt["solver"]["result"], "unsat")
        self.assertTrue(receipt["claims"]["canonical_core_reverified"])
        self.assertTrue(receipt["claims"]["all_input_behavior_equivalence_proved"])
        self.assertFalse(receipt["claims"]["resource_bounds_proved"])
        self.assertFalse(receipt["claims"]["backend_refinement_proved"])
        return receipt

    def test_wrapping_cancellation_all_widths_and_signs(self):
        for typ in ("i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "isize", "usize"):
            before = arithmetic("int.add.wrap", typ)
            block = before["functions"][0]["blocks"][0]
            block["ops"].append(i("int.sub.wrap", ["r", "z"], [("cancel", typ)]))
            block["term"] = ret("cancel")
            with self.subTest(type=typ):
                self.assert_proved(before, identity(typ))

    def test_safe_but_wrong_rewrite_gets_replayed_counterexample(self):
        before = arithmetic("int.add.wrap", "u64")
        after = arithmetic("int.sub.wrap", "u64")
        verify_program(before)
        verify_program(after)
        receipt = validate_translation(before, after)
        self.assertEqual(receipt["status"], "disproved", receipt)
        self.assertEqual(receipt["reason"], "behavioral_counterexample_replayed")
        example = receipt["counterexample"]
        self.assertNotEqual(example["before"], example["after"])
        self.assertEqual(receipt["structural_verification"], {"before": True, "after": True})

    def test_discarded_checked_operation_still_has_observable_trap(self):
        before = arithmetic("int.add.checked", "i8")
        before["functions"][0]["blocks"][0]["term"] = ret("a")
        receipt = validate_translation(before, identity("i8"))
        self.assertEqual(receipt["status"], "disproved", receipt)
        self.assertEqual(receipt["counterexample"]["before"], {"status": "trapped", "code": "overflow"})
        self.assertEqual(receipt["counterexample"]["after"]["status"], "returned")

    def test_first_trap_code_and_operation_order_are_observable(self):
        params = [("a", "i8")]
        division = i("int.div.checked", ["a", "zero"], [("quotient", "i8")])
        addition = i("int.add.checked", ["a", "one"], [("sum", "i8")])
        constants = [c("zero", "i8", 0), c("one", "i8", 1)]
        before = m(f("calculate", params, ["i8"], ["trap"], [
            b("entry", params, constants + [division, addition], ret("a"))]))
        after = m(f("calculate", params, ["i8"], ["trap"], [
            b("entry", params, constants + [addition, division], ret("a"))]))
        receipt = validate_translation(before, after)
        self.assertEqual(receipt["status"], "disproved", receipt)
        self.assertEqual(receipt["counterexample"]["arguments"], [127])
        self.assertEqual(receipt["counterexample"]["before"]["code"], "division_by_zero")
        self.assertEqual(receipt["counterexample"]["after"]["code"], "overflow")

    def test_cfg_phi_and_select_have_identical_all_input_behavior(self):
        params = [("flag", "bool"), ("a", "i64"), ("z", "i64")]
        before = m(f("calculate", params, ["i64"], [], [
            b("entry", params, [], branch("flag", ("join", "a"), ("join", "z"))),
            b("join", [("phi", "i64")], [], ret("phi")),
        ]))
        after = m(f("calculate", params, ["i64"], [], [
            b("entry", params, [i("select", ["flag", "a", "z"], [("r", "i64")])], ret("r")),
        ]))
        self.assert_proved(before, after)

    def test_branch_guard_masks_unexecuted_overflow(self):
        params = [("flag", "bool"), ("a", "i8")]
        before = m(f("calculate", params, ["i8"], ["trap"], [
            b("entry", params, [], branch("flag", ("yes", "a"), ("no", "a"))),
            b("yes", [("ya", "i8")], [c("one", "i8", 1),
                i("int.add.checked", ["ya", "one"], [("sum", "i8")])], ret("sum")),
            b("no", [("na", "i8")], [], ret("na")),
        ]))
        after = copy.deepcopy(before)
        # Hoisting a checked add into entry traps even when flag is false.
        after["functions"][0]["blocks"][0]["ops"] = [c("unused_one", "i8", 1),
            i("int.add.checked", ["a", "unused_one"], [("unused_sum", "i8")])]
        receipt = validate_translation(before, after)
        self.assertEqual(receipt["status"], "disproved", receipt)
        self.assertEqual(receipt["counterexample"]["arguments"], [False, 127])

    def test_precise_signed_unsigned_boundaries_and_casts(self):
        cases = [
            ("int.div.checked", "i8", [-7, 3], -2, None, None, {}),
            ("int.rem.checked", "i8", [-7, 3], -1, None, None, {}),
            ("int.div.checked", "i8", [-128, -1], None, "overflow", None, {}),
            ("int.rem.checked", "i8", [-128, -1], None, "overflow", None, {}),
            ("int.div.checked", "u8", [255, 2], 127, None, None, {}),
            ("int.rem.checked", "u8", [255, 2], 1, None, None, {}),
            ("int.div.checked", "i8", [0, 0], None, "division_by_zero", None, {}),
            ("int.shl.checked", "i8", [1, 7], -128, None, None, {}),
            ("int.shr.checked", "i8", [-8, 2], -2, None, None, {}),
            ("int.shr.checked", "u8", [248, 2], 62, None, None, {}),
            ("int.shl.checked", "i8", [1, -1], None, "overflow", None, {}),
            ("int.shr.checked", "u8", [1, 8], None, "overflow", None, {}),
            ("int.neg.checked", "u8", [0], 0, None, None, {}),
            ("int.neg.checked", "u8", [1], None, "overflow", None, {}),
            ("int.neg.checked", "i64", [-(1 << 63)], None, "overflow", None, {}),
            ("int.cast", "u64", [-1], (1 << 64) - 1, None, "i8", {"mode": "wrap"}),
            ("int.cast", "u64", [-1], None, "overflow", "i8", {"mode": "checked"}),
            ("int.cast", "i64", [(1 << 64) - 1], None, "overflow", "u64", {"mode": "checked"}),
            ("int.cast", "i64", [(1 << 64) - 1], -1, None, "u64", {"mode": "wrap"}),
            ("int.cast", "i16", [255], 255, None, "u8", {"mode": "checked"}),
            ("int.cast", "i8", [255], None, "overflow", "u8", {"mode": "checked"}),
            ("int.cast", "i8", [-129], 127, None, "i16", {"mode": "wrap"}),
        ]
        for op, typ, operands, value, code, source, attrs in cases:
            with self.subTest(op=op, type=typ, operands=operands, attrs=attrs):
                before = constant_operation(op, typ, operands, source_type=source, **attrs)
                after = explicit_trap(typ, code) if code else constant_return(typ, value)
                self.assert_proved(before, after)

    def test_all_checked_arithmetic_extremes(self):
        for typ in ("i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "isize", "usize"):
            lo, hi = integer_range(typ)
            for op, operands, code, expected in [
                ("int.add.checked", [hi, 1], "overflow", None),
                ("int.sub.checked", [lo, 1], "overflow", None),
                ("int.mul.checked", [hi, 2], "overflow", None),
                ("int.mul.checked", [hi, 1], None, hi),
                ("int.add.checked", [lo, 0], None, lo),
            ]:
                with self.subTest(type=typ, op=op, operands=operands):
                    target = explicit_trap(typ, code) if code else constant_return(typ, expected)
                    self.assert_proved(constant_operation(op, typ, operands), target)

    def test_boolean_bitwise_comparison_and_unit_results(self):
        params = [("a", "u32"), ("z", "u32")]
        before = m(f("calculate", params, ["bool", "u32", "unit"], [], [
            b("entry", params, [i("compare.lt", ["a", "z"], [("lt", "bool")]),
                i("bit.xor", ["a", "a"], [("zero", "u32")]), c("nothing", "unit", None)],
              ret("lt", "zero", "nothing")),
        ]))
        after = m(f("calculate", params, ["bool", "u32", "unit"], [], [
            b("entry", params, [i("compare.ge", ["a", "z"], [("ge", "bool")]),
                i("bool.not", ["ge"], [("lt", "bool")]), c("zero", "u32", 0), c("nothing", "unit", None)],
              ret("lt", "zero", "nothing")),
        ]))
        self.assert_proved(before, after)

    def test_signedness_is_not_discarded(self):
        params = [("a", "i8"), ("z", "i8")]
        before = m(f("calculate", params, ["bool"], [], [
            b("entry", params, [i("compare.lt", ["a", "z"], [("r", "bool")])], ret("r"))]))
        after = m(f("calculate", params, ["bool"], [], [
            b("entry", params, [i("int.cast", ["a"], [("ua", "u8")], mode="wrap"),
                i("int.cast", ["z"], [("uz", "u8")], mode="wrap"),
                i("compare.lt", ["ua", "uz"], [("r", "bool")])], ret("r"))]))
        receipt = validate_translation(before, after)
        self.assertEqual(receipt["status"], "disproved", receipt)

    def test_exact_canonical_hash_binding_and_stale_receipt(self):
        before = arithmetic("int.add.wrap")
        receipt = self.assert_proved(before, before)
        self.assertEqual(receipt["before_sha256"], verify_program(before).sha256)
        self.assertEqual(verify_translation_receipt(before, before, receipt)["status"], "proved")
        changed = arithmetic("int.sub.wrap")
        with self.assertRaises(HIAProgramRejected):
            verify_translation_receipt(before, changed, receipt)
        tampered = copy.deepcopy(receipt)
        tampered["before_input_sha256"] = "0" * 64
        with self.assertRaises(HIAProgramRejected):
            verify_translation_receipt(before, before, tampered)

    def test_forged_proved_with_correct_new_hashes_still_rechecks_semantics(self):
        before, wrong = arithmetic("int.add.wrap"), arithmetic("int.sub.wrap")
        forged = self.assert_proved(before, before)
        current = verify_program(wrong)
        forged["after_sha256"] = current.sha256
        forged["after_input_sha256"] = current.input_sha256
        with self.assertRaises(HIAProgramRejected) as caught:
            verify_translation_receipt(before, wrong, forged)
        self.assertEqual(caught.exception.code, "E_HIA_TRANSLATION_UNPROVED")

    def test_solver_unknown_never_becomes_proved(self):
        import z3
        class TimedOutSolver:
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
        with patch("z3.Solver", TimedOutSolver):
            receipt = validate_translation(identity(), identity())
        self.assertEqual(receipt["status"], "unknown")
        self.assertEqual(receipt["solver"]["reason_unknown"], "timeout")
        self.assertFalse(receipt["claims"]["all_input_behavior_equivalence_proved"])

    def test_parallel_proofs_have_independent_solver_contexts(self):
        from concurrent.futures import ThreadPoolExecutor
        pairs = [(identity("u64"), identity("u64")),
                 (arithmetic("int.add.wrap", "i8"), arithmetic("int.sub.wrap", "i8"))] * 4
        with ThreadPoolExecutor(max_workers=4) as workers:
            statuses = list(workers.map(lambda pair: validate_translation(*pair)["status"], pairs))
        self.assertEqual(statuses, ["proved", "disproved"] * 4)

    def test_unreplayable_counterexample_is_unknown(self):
        with patch("hepta.hia_translation_validation._execute_observation", return_value={"status": "returned", "values": [0]}):
            receipt = validate_translation(arithmetic("int.add.wrap"), arithmetic("int.sub.wrap"))
        self.assertEqual(receipt["status"], "unknown")
        self.assertEqual(receipt["reason"], "counterexample_replay_disagrees_with_encoder")

    def test_missing_symbolic_path_cannot_prove_vacuous_equivalence(self):
        def incomplete(encoder, fn, *_args):
            return encoder.z.IntVal(-1, encoder.context), [encoder.zero(t) for t in fn["returns"]]
        with patch("hepta.hia_translation_validation._Encoder.function", incomplete):
            receipt = validate_translation(identity(), identity())
        self.assertEqual(receipt["status"], "unknown")
        self.assertEqual(receipt["reason"], "incomplete_symbolic_execution")


class TranslationBoundaryTests(unittest.TestCase):
    def test_same_loop_is_unknown_not_vacuous_identity_proof(self):
        loop = m(f("forever", [], [], [], [
            b("entry", [], [], jump("loop")), b("loop", [], [], jump("loop")),
        ]))
        receipt = validate_translation(loop, loop)
        self.assertEqual(receipt["status"], "unknown")
        self.assertEqual(receipt["reason"], "cyclic_cfg_outside_profile")

    def test_memory_and_calls_are_structurally_checked_but_not_behavior_proved(self):
        memory = resource_program()
        helper = identity()["functions"][0]
        caller = f("caller", [("x", "u32"), ("y", "u32")], ["u32"], ["trap"], [
            b("entry", [("x", "u32"), ("y", "u32")], [
                i("call", ["x", "y"], [("r", "u32")], function="calculate")], ret("r")),
        ])
        calls = m(helper, caller)
        for doc, name, reason in [(memory, "owned", "resource_effects_outside_scalar_profile"),
                                  (calls, "caller", "operation_outside_scalar_profile")]:
            with self.subTest(function=name):
                receipt = validate_translation(doc, doc, function=name)
                self.assertEqual(receipt["status"], "unknown")
                self.assertEqual(receipt["reason"], reason)
                self.assertEqual(receipt["structural_verification"], {"before": True, "after": True})

    def test_forged_verified_program_is_not_a_structural_authority(self):
        invalid = identity()
        invalid["functions"][0]["blocks"][0]["term"] = ret("undefined")
        import json
        forged = VerifiedProgram(json.dumps(invalid).encode())
        receipt = validate_translation(identity(), forged)
        self.assertEqual(receipt["status"], "unknown")
        self.assertEqual(receipt["reason"], "invalid_after_program")

    def test_optional_solver_absence_and_invalid_timeout_fail_closed(self):
        with patch("hepta.hia_translation_validation._z3_module", side_effect=ImportError("missing")):
            receipt = validate_translation(identity(), identity())
        self.assertEqual(receipt["status"], "unknown")
        self.assertEqual(receipt["reason"], "solver_unavailable")
        for timeout in (0, -1, 60_001, True, 1.5, "20"):
            with self.subTest(timeout=timeout):
                receipt = validate_translation(identity(), identity(), timeout_ms=timeout)
                self.assertEqual(receipt["status"], "unknown")
                self.assertEqual(receipt["reason"], "invalid_solver_timeout")

    def test_signature_and_public_entrypoint_mismatches_fail_closed(self):
        receipt = validate_translation(identity("u32"), identity("i32"))
        self.assertEqual(receipt["status"], "unknown")
        self.assertEqual(receipt["reason"], "signature_mismatch")
        private = identity()
        private["exports"] = []
        receipt = validate_translation(private, private)
        self.assertEqual(receipt["status"], "unknown")
        self.assertEqual(receipt["reason"], "not_a_public_scalar_entrypoint")


if __name__ == "__main__":
    unittest.main()
