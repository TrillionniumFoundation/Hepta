"""Zero-live-heap proof for verified scalar-only HIA cycles.

The standalone HIA verifier remains the sole source of CFG/opcode authority.
These tests do not infer termination, finite VM ticks or physical RSS.
"""
from __future__ import annotations

import unittest

from hepta.hia_heap_bound import analyze_constant_live_heap
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program, HIAProgramBudgetExceeded
from hepta.hia_static_budget import HIAStaticBudgetRejected, analyze_static_budget
from tests.test_hia_program import b, branch, c, f, i, jump, m, ret


def scalar_loop():
    return m(f("count_down", [("n", "u32")], ["u32"], ["trap"], [
        b("entry", [("n", "u32")], [
            c("one", "u32", 1),
        ], jump("head", "n", "one")),
        b("head", [("remaining", "u32"), ("step", "u32")], [
            c("zero", "u32", 0),
            i("compare.gt", ["remaining", "zero"], [("more", "bool")]),
        ], branch("more", ("body", "remaining", "step"), ("exit", "remaining"))),
        b("body", [("r", "u32"), ("s", "u32")], [
            i("int.sub.checked", ["r", "s"], [("next", "u32")]),
        ], jump("head", "next", "s")),
        b("exit", [("answer", "u32")], [], ret("answer")),
    ]))


class ZeroHeapLoopQualification(unittest.TestCase):
    def test_verified_scalar_backedge_has_zero_heap_but_not_finite_ticks(self):
        core = verify_program(scalar_loop())
        self.assertEqual(analyze_constant_live_heap(core), {"count_down": 0})
        for n in (0, 1, 3, 7, 63):
            with self.subTest(n=n):
                result = execute_program(core, "count_down", [n])
                self.assertEqual(result["result"], 0)
                self.assertEqual(result["resources"]["peak_bytes"], 0)
                self.assertEqual(result["resources"]["live_bytes"], 0)
        with self.assertRaisesRegex(HIAStaticBudgetRejected, "E_HIA_BUDGET_UNBOUNDED"):
            analyze_static_budget(core, max_live_heap_bytes=0)

    def test_arbitrary_scalar_loop_still_has_no_termination_proof(self):
        forever = m(f("forever", [], [], [], [
            b("entry", [], [], jump("loop")),
            b("loop", [], [], jump("loop")),
        ]))
        core = verify_program(forever)
        self.assertEqual(analyze_constant_live_heap(core), {"forever": 0})
        with self.assertRaises(HIAProgramBudgetExceeded) as limited:
            execute_program(core, "forever", [], max_steps=10)
        self.assertEqual(limited.exception.code, "steps")
        self.assertEqual(limited.exception.report["resources"]["peak_bytes"], 0)

    def test_allocating_cycle_still_rejects_even_for_zero_byte_extent(self):
        source = scalar_loop()
        fn = source["functions"][0]
        fn["effects"] = ["alloc", "trap"]
        body = next(block for block in fn["blocks"] if block["id"] == "body")
        body["ops"] = [
            c("empty", "usize", 0),
            i("buffer.try_new", ["empty"], [("owner", "buffer"), ("ok", "bool")]),
            i("owner.drop", ["owner"]),
            *body["ops"],
        ]
        core = verify_program(source)
        with self.assertRaisesRegex(HIAStaticBudgetRejected, "E_HIA_BUDGET_UNBOUNDED"):
            analyze_constant_live_heap(core)

    def test_repeated_scalar_callee_not_silently_treated_as_pure(self):
        program = scalar_loop()
        fn = program["functions"][0]
        fn["effects"] = ["trap"]
        body = next(block for block in fn["blocks"] if block["id"] == "body")
        # A declared call to another function is deliberately excluded from
        # the cycle whitelist; no interprocedural purity is inferred.
        other = f("identity", [("v", "u32")], ["u32"], [], [
            b("only", [("v", "u32")], [], ret("v")),
        ])
        body["ops"].insert(0, i("call", ["r"], [("identity_result", "u32")], function="identity"))
        program["functions"].append(other)
        core = verify_program(program)
        with self.assertRaisesRegex(HIAStaticBudgetRejected, "E_HIA_BUDGET_UNBOUNDED"):
            analyze_constant_live_heap(core)

    def test_noncyclic_existing_owned_budget_is_unchanged(self):
        from tests.test_hia_heap_bound import local_buffers
        core = verify_program(local_buffers())
        self.assertEqual(analyze_constant_live_heap(core), {"finite": 12})


if __name__ == "__main__":
    unittest.main()
