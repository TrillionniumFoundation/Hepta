"""Finite live HIA heap-payload proof for balanced block-local allocating loops.

The existing verify_program authority checks the full SSA/CFG/ownership graph;
this analyzer adds only a narrow *peak live bytes* invariant. It must not
claim a bound for total allocations, CPU, VM ticks, process RSS or termination.
"""
from __future__ import annotations

from copy import deepcopy
import unittest

from hepta.hia_heap_bound import (HIAHeapBoundRejected, analyze_constant_live_heap,
                                  qualify_live_heap_budget)
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_static_budget import HIAStaticBudgetRejected, analyze_static_budget
from tests.test_hia_program import b, c, i, jump
from tests.test_hia_zero_heap_loops import scalar_loop


def scoped_loop(*, two_allocations=False, in_entry=False):
    source = scalar_loop()
    fn = source["functions"][0]
    fn["effects"] = ["alloc", "trap"]
    body = next(block for block in fn["blocks"] if block["id"] == "body")
    operations = [
        c("scope_bytes", "usize", 9),
        i("buffer.new", ["scope_bytes"], [("local", "buffer")]),
        i("owner.move", ["local"], [("transferred", "buffer")]),
    ]
    if two_allocations:
        operations.extend([
            c("second_size", "usize", 4),
            i("buffer.new", ["second_size"], [("second_owner", "buffer")]),
            i("owner.drop", ["second_owner"]),
        ])
    operations.append(i("owner.drop", ["transferred"]))
    body["ops"] = operations + body["ops"]
    if in_entry:
        entry = next(block for block in fn["blocks"] if block["id"] == "entry")
        entry["ops"] = [
            c("entry_bytes", "usize", 3),
            i("buffer.new", ["entry_bytes"], [("entry_owner", "buffer")]),
            i("owner.drop", ["entry_owner"]),
        ] + entry["ops"]
    return source


class ScopedAllocatingLoopTests(unittest.TestCase):
    def test_true_native_hia_vm_loop_peak_is_iteration_independent(self):
        verified = verify_program(scoped_loop())
        self.assertEqual(analyze_constant_live_heap(verified), {"count_down": 9})
        for n in (0, 1, 2, 5, 25):
            with self.subTest(iterations=n):
                observed = execute_program(verified, "count_down", [n])
                self.assertEqual(observed["result"], 0)
                self.assertEqual(observed["resources"]["peak_bytes"], 9 if n else 0)
                self.assertEqual(observed["resources"]["live_bytes"], 0)
                self.assertEqual(observed["resources"]["allocations"], n)
        # A finite peak does NOT bound the cumulative number of allocations.
        with self.assertRaisesRegex(HIAStaticBudgetRejected, "E_HIA_BUDGET_UNBOUNDED"):
            analyze_static_budget(verified, max_live_heap_bytes=9)

    def test_strict_live_heap_only_admission_cannot_promote_other_budgets(self):
        verified = verify_program(scoped_loop(two_allocations=True))
        accepted = qualify_live_heap_budget(verified, max_live_heap_bytes=13)
        self.assertEqual(accepted["schema"], "hepta.hia.live-heap-admission.v1")
        self.assertEqual(accepted["program_sha256"], verified.sha256)
        self.assertEqual(accepted["peak_bounds"], {"count_down": 13})
        self.assertEqual(accepted["limit_bytes"], 13)
        self.assertTrue(accepted["claims"]["requested_live_payload_bounded"])
        for claim in ("source_origin_authenticated", "allocator_interactions_bounded",
                      "vm_ticks_bounded", "process_rss_bounded",
                      "native_backend_refinement_proved",
                      "whole_language_soundness_proved"):
            self.assertIs(accepted["claims"][claim], False)
        with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_EXCEEDED"):
            qualify_live_heap_budget(verified, max_live_heap_bytes=12)
        for invalid in (True, False, -1, 13.0, None, (1 << 63), "13"):
            with self.subTest(policy=invalid):
                with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_POLICY"):
                    qualify_live_heap_budget(verified, max_live_heap_bytes=invalid)
        # Snapshot digest is not a self-authenticating compiler proof.
        modified = scoped_loop()
        modified["functions"][0]["blocks"][0]["ops"].append(
            i("forged_heap_effect", [], []))
        from hepta.hia_program import HIAProgramRejected
        with self.assertRaises(HIAProgramRejected):
            qualify_live_heap_budget(modified, max_live_heap_bytes=100)

    def test_two_concurrently_live_block_local_owners_are_summed(self):
        verified = verify_program(scoped_loop(two_allocations=True))
        self.assertEqual(analyze_constant_live_heap(verified), {"count_down": 13})
        for n in (1, 7):
            result = execute_program(verified, "count_down", [n])
            self.assertEqual(result["resources"]["peak_bytes"], 13)
            self.assertEqual(result["resources"]["live_bytes"], 0)
            self.assertEqual(result["resources"]["allocations"], 2 * n)

    def test_independent_scopes_on_distinct_blocks_take_max_not_sum(self):
        verified = verify_program(scoped_loop(in_entry=True))
        self.assertEqual(analyze_constant_live_heap(verified), {"count_down": 9})
        for n, expected in ((0, 3), (1, 9), (10, 9)):
            with self.subTest(iterations=n):
                report = execute_program(verified, "count_down", [n])
                self.assertEqual(report["resources"]["peak_bytes"], expected)
                self.assertEqual(report["resources"]["live_bytes"], 0)

    def test_scoped_fallible_owner_loop_bounds_success_and_allocation_failure(self):
        source = scoped_loop()
        body = next(x for x in source["functions"][0]["blocks"] if x["id"] == "body")
        body["ops"][1] = i("buffer.try_new", ["scope_bytes"],
                            [("local", "buffer"), ("allocated", "bool")])
        verified = verify_program(source)
        self.assertEqual(analyze_constant_live_heap(verified), {"count_down": 9})
        receipt = qualify_live_heap_budget(verified, max_live_heap_bytes=9)
        self.assertEqual(receipt["peak_bounds"], {"count_down": 9})
        self.assertIs(receipt["claims"]["allocator_interactions_bounded"], False)
        with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_EXCEEDED"):
            qualify_live_heap_budget(verified, max_live_heap_bytes=8)
        for n in (0, 1, 3, 7):
            for fail_at in (None, 1, 3, 7):
                with self.subTest(iterations=n, fail_at=fail_at):
                    result = execute_program(verified, "count_down", [n],
                                             allocation_fail_at=fail_at)
                    successful = n - int(fail_at is not None and fail_at <= n)
                    self.assertEqual(result["result"], 0)
                    self.assertEqual(result["resources"]["allocations"], successful)
                    self.assertEqual(result["resources"]["frees"], successful)
                    self.assertEqual(result["resources"]["allocation_attempts"], n)
                    self.assertEqual(result["resources"]["owners_created"], n)
                    self.assertEqual(result["resources"]["owners_dropped"], n)
                    self.assertEqual(result["resources"]["peak_bytes"],
                                     9 if successful else 0)
                    self.assertEqual(result["resources"]["live_bytes"], 0)
                    self.assertEqual(result["resources"]["live_owners"], 0)
        # This is a peak-live proof, not a bound on repeated allocator calls.
        with self.assertRaisesRegex(HIAStaticBudgetRejected, "E_HIA_BUDGET_UNBOUNDED"):
            analyze_static_budget(verified, max_live_heap_bytes=9)

    def test_scoped_try_new_dynamic_bound_is_conservative_on_failure(self):
        source = scoped_loop()
        body = next(x for x in source["functions"][0]["blocks"] if x["id"] == "body")
        body["ops"] = [
            i("int.cast", ["r"], [("small", "u8")], mode="checked"),
            i("int.cast", ["small"], [("size", "usize")], mode="checked"),
            i("buffer.try_new", ["size"],
              [("dynamic_owner", "buffer"), ("allocated", "bool")]),
            i("owner.drop", ["dynamic_owner"]),
            *body["ops"][4:],
        ]
        verified = verify_program(source)
        self.assertEqual(analyze_constant_live_heap(verified), {"count_down": 255})
        for n in (1, 2, 7):
            for fail_at in (None, 1):
                with self.subTest(n=n, fail_at=fail_at):
                    result = execute_program(verified, "count_down", [n],
                                             allocation_fail_at=fail_at)
                    self.assertLessEqual(result["resources"]["peak_bytes"], 255)
                    self.assertEqual(result["resources"]["live_bytes"], 0)
                    self.assertEqual(result["resources"]["live_owners"], 0)

    def test_scoped_try_new_requires_owner_cleanup_before_every_cfg_edge(self):
        from hepta.hia_program import HIAProgramRejected
        source = scoped_loop()
        fn = source["functions"][0]
        body = next(x for x in fn["blocks"] if x["id"] == "body")
        body["ops"] = [
            c("size", "usize", 6),
            i("buffer.try_new", ["size"], [("pending", "buffer"), ("ok", "bool")]),
            *body["ops"][4:],
        ]
        # Without a matching drop, the canonical verifier refuses a normal
        # loop edge before any live-heap analysis may issue a receipt.
        with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_RESOURCE"):
            analyze_constant_live_heap(source)
        body["ops"].insert(2, i("owner.drop", ["pending"]))
        self.assertEqual(analyze_constant_live_heap(verify_program(source)),
                         {"count_down": 6})


    def test_checked_small_cast_bounds_dynamic_loop_even_without_termination(self):
        source = scoped_loop()
        body = next(x for x in source["functions"][0]["blocks"] if x["id"] == "body")
        body["ops"] = [
            i("int.cast", ["r"], [("small", "u8")], mode="checked"),
            i("int.cast", ["small"], [("bounded", "usize")], mode="checked"),
            i("buffer.new", ["bounded"], [("dynamic_owner", "buffer")]),
            i("owner.drop", ["dynamic_owner"]),
            *body["ops"][4:],
        ]
        verified = verify_program(source)
        # The continuing path after a successful checked u8 cast has a
        # machine-type maximum of 255 without assuming n <= 255 at entry.
        self.assertEqual(analyze_constant_live_heap(verified), {"count_down": 255})
        for n in (0, 1, 2, 7, 63, 255):
            with self.subTest(iterations=n):
                observed = execute_program(verified, "count_down", [n])
                self.assertEqual(observed["resources"]["peak_bytes"], n)
                self.assertEqual(observed["resources"]["live_bytes"], 0)
        from hepta.hia_program_runtime import HIAProgramTrap
        with self.assertRaises(HIAProgramTrap):
            execute_program(verified, "count_down", [256])

    def test_full_u32_machine_domain_binds_repeat_allocation_peak(self):
        source = scoped_loop()
        body = next(x for x in source["functions"][0]["blocks"] if x["id"] == "body")
        body["ops"] = [
            i("int.cast", ["r"], [("size", "usize")], mode="checked"),
            i("buffer.new", ["size"], [("dynamic_owner", "buffer")]),
            i("owner.drop", ["dynamic_owner"]),
            *body["ops"][4:],
        ]
        verified = verify_program(source)
        self.assertEqual(analyze_constant_live_heap(verified),
                         {"count_down": (1 << 32) - 1})
        self.assertEqual(execute_program(verified, "count_down", [7])["resources"]["peak_bytes"], 7)

    def test_same_block_checked_constant_arithmetic_qualifies_cyclic_peak(self):
        source = scoped_loop()
        body = next(x for x in source["functions"][0]["blocks"] if x["id"] == "body")
        body["ops"] = [
            c("base_size", "usize", 4),
            c("added_size", "usize", 5),
            i("int.add.checked", ["base_size", "added_size"], [("total", "usize")]),
            i("buffer.new", ["total"], [("local", "buffer")]),
            i("owner.drop", ["local"]),
            *body["ops"][4:],
        ]
        verified = verify_program(source)
        self.assertEqual(analyze_constant_live_heap(verified), {"count_down": 9})
        for n in (0, 1, 3):
            result = execute_program(verified, "count_down", [n])
            self.assertEqual(result["resources"]["peak_bytes"], 9 if n else 0)
            self.assertEqual(result["resources"]["live_bytes"], 0)
            self.assertEqual(result["resources"]["allocations"], n)

    def test_proven_u32_interval_plus_one_qualifies_without_caller_assumptions(self):
        source = scoped_loop()
        body = next(x for x in source["functions"][0]["blocks"] if x["id"] == "body")
        body["ops"] = [
            i("int.cast", ["r"], [("first", "usize")], mode="checked"),
            c("one_more", "usize", 1),
            i("int.add.checked", ["first", "one_more"], [("computed_size", "usize")]),
            i("buffer.new", ["computed_size"], [("dynamic_owner", "buffer")]),
            i("owner.drop", ["dynamic_owner"]),
            *body["ops"][4:],
        ]
        verified = verify_program(source)
        # Full typed u32 input domain is [0, 2**32 - 1], and adding
        # one cannot overflow a checked 64-bit usize.
        self.assertEqual(analyze_constant_live_heap(verified),
                         {"count_down": 1 << 32})
        for n in (0, 1, 2, 7):
            result = execute_program(verified, "count_down", [n])
            self.assertEqual(result["resources"]["peak_bytes"], n + 1 if n else 0)
            self.assertEqual(result["resources"]["live_bytes"], 0)

    def test_proven_exact_wrapping_extent_matches_fixed_width_native_semantics(self):
        source = scoped_loop()
        body = next(x for x in source["functions"][0]["blocks"] if x["id"] == "body")
        body["ops"] = [
            c("max_usize", "usize", (1 << 64) - 1),
            c("increment", "usize", 8),
            i("int.add.wrap", ["max_usize", "increment"], [("computed_size", "usize")]),
            i("buffer.new", ["computed_size"], [("owner", "buffer")]),
            i("owner.drop", ["owner"]),
            *body["ops"][4:],
        ]
        verified = verify_program(source)
        self.assertEqual(analyze_constant_live_heap(verified), {"count_down": 7})
        self.assertEqual(execute_program(verified, "count_down", [3])["resources"]["peak_bytes"], 7)

    def test_partially_overflowing_or_wrapping_interval_stays_unqualified(self):
        for instruction in ("int.add.checked", "int.add.wrap"):
            with self.subTest(instruction=instruction):
                source = scoped_loop()
                body = next(x for x in source["functions"][0]["blocks"] if x["id"] == "body")
                body["ops"] = [
                    i("int.cast", ["r"], [("first", "usize")], mode="checked"),
                    c("large", "usize", (1 << 64) - 1),
                    i(instruction, ["first", "large"], [("unproved", "usize")]),
                    i("buffer.new", ["unproved"], [("owner", "buffer")]),
                    i("owner.drop", ["owner"]),
                    *body["ops"][4:],
                ]
                # Valid HIA program, but this interval partially crosses
                # the machine arithmetic boundary; no narrow peak admitted.
                verified = verify_program(source)
                with self.assertRaisesRegex(HIAStaticBudgetRejected, "E_HIA_BUDGET_UNBOUNDED"):
                    analyze_constant_live_heap(verified)

    def test_owner_transferred_across_block_boundary_remains_unqualified(self):
        source = scoped_loop()
        fn = source["functions"][0]
        body = next(x for x in fn["blocks"] if x["id"] == "body")
        body["ops"] = [
            c("bytes_for_cleanup", "usize", 5),
            i("buffer.new", ["bytes_for_cleanup"], [("pending_owner", "buffer")]),
        ]
        body["term"] = jump("release", "pending_owner", "r", "s")
        release = b("release", [("carried", "buffer"), ("carry_n", "u32"), ("carry_step", "u32")], [
            i("owner.drop", ["carried"]),
            i("int.sub.checked", ["carry_n", "carry_step"], [("next_n", "u32")]),
        ], jump("head", "next_n", "carry_step"))
        fn["blocks"].insert(3, release)
        verified = verify_program(source)
        with self.assertRaisesRegex(HIAStaticBudgetRejected, "E_HIA_BUDGET_UNBOUNDED"):
            analyze_constant_live_heap(verified)

    def test_unknown_opcode_has_no_new_cyclic_resource_authority(self):
        source = scoped_loop()
        body = next(x for x in source["functions"][0]["blocks"] if x["id"] == "body")
        body["ops"].insert(0, i("call", ["r"], [("renamed", "u32")], function="other"))
        # The *canonical* verifier must refuse the missing callee before
        # any derived numeric/resource bound can attempt to handle it.
        from hepta.hia_program import HIAProgramRejected
        with self.assertRaises(HIAProgramRejected):
            analyze_constant_live_heap(source)


if __name__ == "__main__":
    unittest.main()
