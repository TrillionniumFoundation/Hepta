"""Caller mutation cannot change the scalar invocation after validation.

The thread rendezvous instruments the existing scalar checker only to select
the otherwise timing-dependent mutation window. The real Core verifier,
interpreter, type predicate, allocation and stopped resource ledger all run.
"""
from __future__ import annotations

from threading import Event, Thread
import unittest
from unittest.mock import patch

from hepta.hia_program import HIAProgramRejected, SCHEMA
from hepta import hia_program_runtime as runtime


def _identity(typ="u8"):
    parameter = {"name": "value", "type": typ}
    return {
        "schema": SCHEMA,
        "module": "argument_snapshot",
        "functions": [{
            "name": "identity", "params": [parameter], "returns": [typ],
            "effects": [], "entry": "entry",
            "blocks": [{"id": "entry", "params": [parameter], "ops": [],
                        "term": {"op": "ret", "values": ["value"]}}],
        }],
    }


def _owned_size():
    def operation(op, args, out=()):
        return {"op": op, "args": args, "attrs": {},
                "out": [{"name": name, "type": typ} for name, typ in out]}

    parameter = {"name": "size", "type": "usize"}
    return {
        "schema": SCHEMA,
        "module": "argument_snapshot_resources",
        "functions": [{
            "name": "owned_size", "params": [parameter], "returns": ["usize"],
            "effects": ["alloc", "trap"], "entry": "entry",
            "blocks": [{
                "id": "entry", "params": [parameter],
                "ops": [
                    operation("buffer.new", ["size"], [("owner", "buffer")]),
                    operation("buffer.len", ["owner"], [("length", "usize")]),
                    operation("owner.drop", ["owner"]),
                ],
                "term": {"op": "ret", "values": ["length"]},
            }],
        }],
    }


class ArgumentSnapshotTests(unittest.TestCase):
    def execute_while_mutating(self, program, function, arguments, replacement,
                               **limits):
        validated, changed = Event(), Event()
        original_check = runtime.scalar_value_valid
        first_check = True

        def checked_before_mutation(value, typ):
            nonlocal first_check
            result = original_check(value, typ)
            if first_check:
                first_check = False
                validated.set()
                if not changed.wait(5):
                    raise AssertionError("caller did not mutate its argument list")
            return result

        def mutate_caller_list():
            if validated.wait(5):
                arguments[:] = replacement
                changed.set()

        thread = Thread(target=mutate_caller_list)
        thread.start()
        try:
            with patch.object(runtime, "scalar_value_valid",
                              side_effect=checked_before_mutation):
                return runtime.execute_program(program, function, arguments,
                                               **limits)
        finally:
            validated.set()
            thread.join(5)
            self.assertFalse(thread.is_alive(), "caller mutation thread leaked")
            self.assertTrue(changed.is_set(), "mutation window was not exercised")

    def test_out_of_range_replacement_cannot_escape_typed_return(self):
        arguments = [7]
        report = self.execute_while_mutating(_identity(), "identity", arguments,
                                             [300])
        self.assertEqual(arguments, [300])
        self.assertEqual(report["status"], "returned")
        self.assertEqual(report["result"], 7)

    def test_valid_replacement_is_not_a_different_admitted_invocation(self):
        report = self.execute_while_mutating(_identity(), "identity", [7], [8])
        self.assertEqual(report["result"], 7)

    def test_argument_removal_after_check_does_not_change_arity(self):
        report = self.execute_while_mutating(_identity(), "identity", [7], [])
        self.assertEqual(report["result"], 7)

    def test_allocation_extent_and_cleanup_use_validated_values(self):
        report = self.execute_while_mutating(_owned_size(), "owned_size", [5],
                                             [0], max_heap_bytes=5)
        self.assertEqual(report["result"], 5)
        self.assertEqual(report["resources"]["peak_bytes"], 5)
        self.assertEqual(report["resources"]["allocation_attempts"], 1)
        self.assertEqual(report["resources"]["frees"], 1)
        self.assertEqual(report["resources"]["live_owners"], 0)

    def test_mutation_cannot_turn_heap_stop_into_a_success(self):
        with self.assertRaises(runtime.HIAProgramBudgetExceeded) as caught:
            self.execute_while_mutating(_owned_size(), "owned_size", [5], [0],
                                        max_heap_bytes=4)
        self.assertEqual(caught.exception.code, "heap")
        self.assertEqual(caught.exception.report["status"], "budget_exceeded")
        self.assertEqual(caught.exception.report["resources"]["allocation_attempts"], 0)
        self.assertEqual(caught.exception.report["resources"]["live_owners"], 0)

    def test_mutation_cannot_hide_the_admitted_allocator_failure(self):
        with self.assertRaises(runtime.HIAProgramTrap) as caught:
            self.execute_while_mutating(_owned_size(), "owned_size", [5], [0],
                                        allocation_fail_at=1)
        self.assertEqual(caught.exception.code, "allocation")
        self.assertEqual(caught.exception.report["resources"]["allocation_attempts"], 1)
        self.assertEqual(caught.exception.report["resources"]["allocations"], 0)

    def test_invalid_original_argument_remains_rejected(self):
        with patch.object(runtime._Machine, "invoke") as invoke:
            with self.assertRaises(HIAProgramRejected) as caught:
                self.execute_while_mutating(_identity(), "identity", [300], [7])
        self.assertEqual(caught.exception.code, "E_HIA_INPUT")
        invoke.assert_not_called()

    def test_immutable_tuple_and_exact_scalar_rules_are_preserved(self):
        self.assertEqual(runtime.execute_program(_identity(), "identity", (255,))["result"], 255)
        for arguments in ((True,), (-1,), (256,), ("7",), (7.0,)):
            with self.subTest(arguments=arguments), self.assertRaises(HIAProgramRejected):
                runtime.execute_program(_identity(), "identity", arguments)


if __name__ == "__main__":
    unittest.main()
