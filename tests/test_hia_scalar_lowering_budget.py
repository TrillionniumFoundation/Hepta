"""Bound actual recursive symbolic work before encoding another instruction."""
from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

import z3

from hepta import hia_scalar_lowering_check as check
from hepta.hia_program import verify_program
from hepta.hia_program_llvm import emit_program_llvm
from tests.test_hia_program import b, c, f, i, m, ret


def repeated_adds(name, count, callee=None):
    operations, last = [c("one", "u32", 1)], "value"
    for index in range(count):
        output = "sum" + str(index)
        operations.append(i("int.add.wrap", [last, "one"], [(output, "u32")]))
        last = output
    if callee is not None:
        operations.append(i("call", [last], [("called", "u32")], function=callee))
        last = "called"
    return f(name, [("value", "u32")], ["u32"], [], [
        b("entry", [("value", "u32")], operations, ret(last))])


class ScalarLoweringWorkBudgetTests(unittest.TestCase):
    def test_core_stops_before_encoding_over_budget_block_operations(self):
        program = m(repeated_adds("calculate", 16))
        actual = check._Encoder.operation
        encoded = []

        def operation(encoder, instruction):
            encoded.append(instruction["op"])
            return actual(encoder, instruction)

        with patch.object(check, "MAX_LLVM_STEPS", 4), \
                patch.object(check._Encoder, "operation", operation):
            with self.assertRaisesRegex(check.ScalarLoweringRejected, "Core.*budget"):
                check.verify_scalar_lowering(program)
        self.assertLessEqual(len(encoded), 4, encoded)

    def test_core_recursive_calls_share_the_same_work_budget(self):
        leaf = repeated_adds("leaf", 3)
        parent = f("calculate", [("value", "u32")], ["u32"], [], [
            b("entry", [("value", "u32")], [
                i("call", ["value"], [("first", "u32")], function="leaf"),
                i("call", ["first"], [("second", "u32")], function="leaf"),
            ], ret("second"))])
        program = m(leaf, parent)
        original_operation, original_reference = check._Encoder.operation, check._reference
        encoded, called = [], []

        def operation(encoder, instruction):
            encoded.append(instruction["op"])
            return original_operation(encoder, instruction)

        def reference(*args, **kwargs):
            called.append(args[2]["name"])
            return original_reference(*args, **kwargs)

        with patch.object(check, "MAX_LLVM_STEPS", 8), \
                patch.object(check._Encoder, "operation", operation), \
                patch.object(check, "_reference", reference):
            with self.assertRaisesRegex(check.ScalarLoweringRejected, "Core.*budget"):
                check.verify_scalar_lowering(program, function="calculate")
        # Every nested call and pure operation requires a symbolic step. This
        # counts actual work, without relying on an implementation counter.
        self.assertLessEqual(len(encoded) + len(called) - 1, 8, (encoded, called))

    def test_llvm_child_does_not_start_with_a_fresh_instruction_allowance(self):
        document = verify_program(m(repeated_adds("leaf", 3),
                                    repeated_adds("calculate", 3, "leaf"))).as_dict()
        text = emit_program_llvm(verify_program(document)).text
        context = z3.Context()
        inputs = {"value": check._fresh(z3, "input", "u32", context)}
        original = check._LLVM.assigned
        encoded = []

        def assigned(encoder, expression):
            encoded.append(expression)
            return original(encoder, expression)

        with patch.object(check, "MAX_LLVM_STEPS", 4), \
                patch.object(check._LLVM, "assigned", assigned):
            encoder = check._LLVM(z3, context, text, document["functions"][1],
                                  inputs, 1, document, frozenset({0, 1}))
            with self.assertRaisesRegex(check.ScalarLoweringRejected, "LLVM.*budget"):
                encoder.execute()
        self.assertLessEqual(len(encoded), 4, encoded)

    def test_late_unsat_cannot_grant_a_completed_validation(self):
        program = m(repeated_adds("calculate", 1))
        clock = SimpleNamespace(now=0)
        actual = z3.Solver.check

        def late_unsat(solver, *args, **kwargs):
            result = actual(solver, *args, **kwargs)
            self.assertEqual(result, z3.unsat)
            clock.now = 2_000_000
            return result

        with patch.object(check, "time", SimpleNamespace(monotonic_ns=lambda: clock.now)), \
                patch.object(z3.Solver, "check", late_unsat):
            with self.assertRaisesRegex(check.ScalarLoweringRejected, "deadline"):
                check.verify_scalar_lowering(program, timeout_ms=1)

    def test_encoding_checks_deadline_before_another_operation(self):
        program = m(repeated_adds("calculate", 16))
        clock = SimpleNamespace(now=0)
        actual = check._Encoder.operation
        encoded = []

        def operation(encoder, instruction):
            encoded.append(instruction["op"])
            result = actual(encoder, instruction)
            clock.now = 2_000_000
            return result

        with patch.object(check, "time", SimpleNamespace(monotonic_ns=lambda: clock.now)), \
                patch.object(check._Encoder, "operation", operation):
            with self.assertRaisesRegex(check.ScalarLoweringRejected, "deadline"):
                check.verify_scalar_lowering(program, timeout_ms=1)
        self.assertEqual(len(encoded), 1)


if __name__ == "__main__":
    unittest.main()
