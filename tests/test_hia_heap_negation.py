"""HIA v6: conservative checked-negation SSA intervals for heap admission.

These tests exercise the existing canonical Core, VM and static budget; no
second owner checker, memory optimizer or arbitrary interval assumptions.
"""
from __future__ import annotations

import unittest

from hepta.hia_heap_bound import HIAHeapBoundRejected, analyze_constant_live_heap
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import HIAProgramTrap, execute_program
from hepta.hia_static_budget import analyze_static_budget
from tests.test_hia_program import b, c, f, i, m, ret


def negated_choice(*, potentially_overflowing=False):
    typ = "i8" if potentially_overflowing else "i32"
    small = -(1 << 7) if potentially_overflowing else -7
    large = -7 if potentially_overflowing else -12
    return m(f("bounded_negative", [("choose", "bool")], ["usize"], ["alloc", "trap"], [
        b("entry", [("choose", "bool")], [
            c("small", typ, small),
            c("large", typ, large),
            i("select", ["choose", "small", "large"], [("negative", typ)]),
            i("int.neg.checked", ["negative"], [("positive", typ)]),
            i("int.cast", ["positive"], [("extent", "usize")], mode="checked"),
            i("buffer.new", ["extent"], [("owner", "buffer")]),
            i("owner.drop", ["owner"]),
        ], ret("extent")),
    ]))


def negation_of_one(value, typ="i8"):
    return m(f("constant_negative", [], ["usize"], ["alloc", "trap"], [
        b("entry", [], [
            c("input", typ, value),
            i("int.neg.checked", ["input"], [("negated", typ)]),
            i("int.cast", ["negated"], [("extent", "usize")], mode="checked"),
            i("buffer.new", ["extent"], [("owner", "buffer")]),
            i("owner.drop", ["owner"]),
        ], ret("extent")),
    ]))


def unknown_negation():
    return m(f("dynamic_negative", [("value", "i32")], [], ["alloc", "trap"], [
        b("entry", [("value", "i32")], [
            i("int.neg.checked", ["value"], [("negated", "i32")]),
            i("int.cast", ["negated"], [("extent", "usize")], mode="checked"),
            i("buffer.new", ["extent"], [("owner", "buffer")]),
            i("owner.drop", ["owner"]),
        ], ret()),
    ]))


class HIAHeapNegationTests(unittest.TestCase):
    def test_full_nonoverflowing_interval_qualifies_both_real_vm_paths(self):
        core = verify_program(negated_choice())
        bounds = analyze_constant_live_heap(core)
        self.assertEqual(bounds, {"bounded_negative": 12})
        self.assertEqual(analyze_static_budget(core, max_live_heap_bytes=12)
                         ["functions"][0]["max_live_heap_bytes"], 12)
        with self.assertRaisesRegex(ValueError, "E_HIA_BUDGET_EXCEEDED"):
            analyze_static_budget(core, max_live_heap_bytes=11)
        for condition, answer in ((True, 7), (False, 12)):
            with self.subTest(flag=condition):
                observed = execute_program(core, "bounded_negative", [condition])
                self.assertEqual(observed["result"], answer)
                self.assertLessEqual(observed["resources"]["peak_bytes"], bounds["bounded_negative"])

    def test_unsigned_zero_negation_remains_zero_allocation(self):
        core = verify_program(negation_of_one(0, typ="u8"))
        self.assertEqual(analyze_constant_live_heap(core), {"constant_negative": 0})
        observed = execute_program(core, "constant_negative", [])
        self.assertEqual(observed["result"], 0)
        self.assertEqual(observed["resources"]["peak_bytes"], 0)

    def test_min_signed_and_unsigned_nonzero_never_qualify(self):
        for value, typ in ((-128, "i8"), (1, "u8")):
            with self.subTest(type=typ, value=value):
                core = verify_program(negation_of_one(value, typ))
                with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_UNBOUNDED"):
                    analyze_constant_live_heap(core)
                with self.assertRaises(HIAProgramTrap) as trapped:
                    execute_program(core, "constant_negative", [])
                self.assertEqual(trapped.exception.code, "overflow")

    def test_partial_overflow_interval_and_unknown_input_fail_closed(self):
        for source in (negated_choice(potentially_overflowing=True),
                       unknown_negation()):
            core = verify_program(source)
            with self.subTest(entry=core.as_dict()["functions"][0]["name"]):
                with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_UNBOUNDED"):
                    analyze_constant_live_heap(core)
                with self.assertRaisesRegex(ValueError, "E_HIA_BUDGET_UNBOUNDED"):
                    analyze_static_budget(core, max_live_heap_bytes=12)


if __name__ == "__main__":
    unittest.main()
