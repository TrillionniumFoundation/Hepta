"""Conservative requested-live-byte budgets atop the one verified HIA Core."""
from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from hepta.hia_heap_bound import HIAHeapBoundRejected, analyze_constant_live_heap
from hepta.hia_program import verify_program
from tests.test_hia_program import b, branch, c, f, i, jump, m, ret


def local_buffers():
    return m(f("finite", [], ["usize"], ["alloc", "trap"], [
        b("entry", [], [
            c("eight", "usize", 8), c("four", "usize", 4),
            i("buffer.new", ["eight"], [("a", "buffer")]),
            i("buffer.try_new", ["four"], [("z", "buffer"), ("ok", "bool")]),
            i("owner.move", ["a"], [("moved", "buffer")]),
            i("owner.drop", ["z"]), i("owner.drop", ["moved"]),
        ], ret("eight"))]))


def joined_max():
    return m(f("select_heap", [("flag", "bool")], [], ["alloc"], [
        b("entry", [("flag", "bool")], [], branch("flag", ("left",), ("right",))),
        b("left", [], [c("low", "usize", 2),
                         i("buffer.try_new", ["low"], [("a", "buffer"), ("ok_a", "bool")])],
          jump("joined", "a")),
        b("right", [], [c("high", "usize", 9),
                          i("buffer.try_new", ["high"], [("b", "buffer"), ("ok_b", "bool")])],
          jump("joined", "b")),
        b("joined", [("owned", "buffer")], [i("owner.drop", ["owned"])], ret()),
    ]))


def scalar_call():
    child = f("inner", [], ["usize"], ["alloc", "trap"], [
        b("inner_entry", [], [c("n", "usize", 7),
             i("buffer.new", ["n"], [("obj", "buffer")]),
             i("owner.drop", ["obj"])], ret("n"))])
    parent = f("parent", [], ["usize"], ["alloc", "trap"], [
        b("parent_entry", [], [c("size", "usize", 3),
            i("buffer.new", ["size"], [("obj", "buffer")]),
            i("call", [], [("scalar", "usize")], function="inner"),
            i("owner.drop", ["obj"])], ret("scalar"))])
    return m(child, parent)


def unknown_size():
    return m(f("dynamic", [("n", "usize")], ["usize"], ["alloc"], [
        b("entry", [("n", "usize")], [
            i("buffer.try_new", ["n"], [("o", "buffer"), ("ok", "bool")]),
            i("owner.drop", ["o"])], ret("n"))]))


class HIAHeapBoundTests(unittest.TestCase):
    def test_static_owner_move_and_drop_preserve_peak_bytes(self):
        core = verify_program(local_buffers())
        self.assertEqual(analyze_constant_live_heap(core), {"finite": 12})
        self.assertEqual(analyze_constant_live_heap(core), analyze_constant_live_heap(core))

    def test_conditional_phi_owner_sizes_take_safe_maximum(self):
        core = verify_program(joined_max())
        self.assertEqual(analyze_constant_live_heap(core), {"select_heap": 9})

    def test_nested_scalar_only_call_adds_concurrent_live_bytes(self):
        core = verify_program(scalar_call())
        self.assertEqual(analyze_constant_live_heap(core), {"inner": 7, "parent": 10})

    def test_future_core_schema_must_be_audited_before_budget_qualification(self):
        document = local_buffers()
        document["schema"] = "hepta.hia.program.v7"
        accepted_by_future = SimpleNamespace(as_dict=lambda: document)
        with patch("hepta.hia_heap_bound.verify_program", return_value=accepted_by_future):
            with self.assertRaisesRegex(HIAHeapBoundRejected, "unknown HIA executable schema"):
                analyze_constant_live_heap(document)

    def test_unreviewed_future_opcode_cannot_silently_skip_byte_accounting(self):
        # This deliberately stubs a future canonical verifier accepting one
        # additional opcode; today verify_program itself rejects it.
        document = local_buffers()
        document["functions"][0]["blocks"][0]["ops"].insert(
            0, i("buffer.unknown_allocator", out=[]))
        accepted_by_future = SimpleNamespace(as_dict=lambda: document)
        with patch("hepta.hia_heap_bound.verify_program", return_value=accepted_by_future):
            with self.assertRaisesRegex(HIAHeapBoundRejected, "unreviewed opcode"):
                analyze_constant_live_heap(document)

    def test_unknown_dynamic_extents_fail_closed(self):
        core = verify_program(unknown_size())
        with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_UNBOUNDED"):
            analyze_constant_live_heap(core)

    def test_owner_return_boundary_fails_closed(self):
        fn = f("take", [("o", "buffer")], ["buffer"], [],
               [b("entry", [("o", "buffer")], [], ret("o"))])
        core = verify_program(m(fn))
        with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_UNBOUNDED"):
            analyze_constant_live_heap(core)

    def test_missing_policy_does_not_expand_legacy_budget(self):
        from hepta.hia_static_budget import analyze_static_budget
        core = verify_program(local_buffers())
        historical = analyze_static_budget(core)
        self.assertNotIn("max_live_heap_bytes", historical["limits"])
        admitted = analyze_static_budget(core, max_live_heap_bytes=12)
        self.assertEqual(admitted["functions"][0]["max_live_heap_bytes"], 12)
        self.assertTrue(admitted["claims"]["requested_live_payload_bytes_upper_bounded"])
        self.assertFalse(admitted["claims"]["native_cpu_time_or_rss_proved"])
        with self.assertRaisesRegex(ValueError, "E_HIA_BUDGET_EXCEEDED"):
            analyze_static_budget(core, max_live_heap_bytes=11)
        with self.assertRaisesRegex(ValueError, "E_HIA_BUDGET_POLICY"):
            analyze_static_budget(core, max_live_heap_bytes=True)

    def test_dynamic_unknown_never_qualifies_native_budget(self):
        from hepta.hia_static_budget import analyze_static_budget
        core = verify_program(unknown_size())
        with self.assertRaisesRegex(ValueError, "E_HIA_BUDGET_UNBOUNDED"):
            analyze_static_budget(core, max_live_heap_bytes=1 << 20)


if __name__ == "__main__":
    unittest.main()
