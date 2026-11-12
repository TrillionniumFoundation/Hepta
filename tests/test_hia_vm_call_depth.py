"""Exact zero-/one-based HIA VM call-depth budget regression.

The static HIA budget counts the root call as depth one. Its runtime budget
must reject the next call frame *before* running any operation in that frame.
These are real standalone HIA Core verifier and interpreter tests (not mocks).
"""
from __future__ import annotations

import unittest

from hepta.hia_program import verify_program
from hepta.hia_program_runtime import HIAProgramBudgetExceeded, execute_program
from hepta.hia_static_budget import analyze_static_budget
from tests.test_hia_program import b, f, i, m, ret


def sequential_calls():
    inner = f("inner", [("n", "i32")], ["i32"], [], [
        b("inner_entry", [("n", "i32")], [], ret("n")),
    ])
    outer = f("outer", [("x", "i32")], ["i32"], [], [
        b("outer_entry", [("x", "i32")], [
            i("call", ["x"], [("a", "i32")], function="inner"),
            i("call", ["a"], [("z", "i32")], function="inner"),
        ], ret("z")),
    ])
    return m(inner, outer)


def recursively_nested():
    return m(f("again", [("n", "i32")], ["i32"], [], [
        b("entry", [("n", "i32")], [
            i("call", ["n"], [("next", "i32")], function="again"),
        ], ret("next")),
    ]))


class HIAVMCallDepthTests(unittest.TestCase):
    def test_one_root_frame_fits_one_frame_budget(self):
        core = verify_program(sequential_calls())
        report = execute_program(core, "inner", [19], max_call_depth=1)
        self.assertEqual(report["status"], "returned")
        self.assertEqual(report["result"], 19)
        self.assertEqual(report["steps"], 2)  # entry and terminator

    def test_nested_call_refused_before_callee_entered(self):
        core = verify_program(sequential_calls())
        static = {row["function"]: row for row in
                  analyze_static_budget(core)["functions"]}
        self.assertEqual(static["inner"]["max_call_depth"], 1)
        self.assertEqual(static["outer"]["max_call_depth"], 2)
        with self.assertRaises(HIAProgramBudgetExceeded) as caught:
            execute_program(core, "outer", [9], max_call_depth=1)
        self.assertEqual(caught.exception.code, "calls")
        self.assertEqual(caught.exception.report["status"], "budget_exceeded")
        # Only the root-entry tick and the attempted-call instruction tick.
        # The refused callee must execute no entry, body or allocator events.
        self.assertEqual(caught.exception.report["steps"], 2)
        self.assertEqual(caught.exception.report["resources"]["allocation_attempts"], 0)
        self.assertEqual(caught.exception.report["resources"]["live_owners"], 0)

    def test_sequential_sibling_calls_do_not_consume_extra_stack_depth(self):
        core = verify_program(sequential_calls())
        report = execute_program(core, "outer", [27], max_call_depth=2)
        self.assertEqual(report["result"], 27)
        self.assertEqual(report["status"], "returned")

    def test_recursive_call_depth_limit_is_root_inclusive(self):
        core = verify_program(recursively_nested())
        for limit in (1, 2, 3, 5):
            with self.subTest(max_call_depth=limit):
                with self.assertRaises(HIAProgramBudgetExceeded) as caught:
                    execute_program(core, "again", [4], max_call_depth=limit)
                self.assertEqual(caught.exception.code, "calls")
                self.assertEqual(caught.exception.report["status"], "budget_exceeded")
                # Each admitted frame executes one entry tick and one call
                # instruction tick. The (limit + 1)th frame is NOT entered.
                self.assertEqual(caught.exception.report["steps"], 2 * limit)
                self.assertEqual(caught.exception.report["resources"]["live_owners"], 0)


if __name__ == "__main__":
    unittest.main()
