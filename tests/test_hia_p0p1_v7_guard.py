"""P0/P1 guarded convergence: bounded v1-v6 proofs never authorize v7.

This is a version boundary test. It does not verify the generalized v7 chain,
native backend refinement, whole-process RSS or source-to-LLVM soundness.
"""
from __future__ import annotations

from copy import deepcopy
import unittest

from hepta.hia_heap_bound import (
    HIAHeapBoundRejected, analyze_constant_live_heap, qualify_live_heap_budget,
)
from hepta.hia_program import verify_program
from hepta.hia_schema import SCHEMA_V6, SCHEMA_V7
from tests.test_hia_scoped_alloc_loops import scoped_loop


class GuardedV7HeapProfileTests(unittest.TestCase):
    def test_verified_v6_scope_retains_a_finite_peak(self):
        source = scoped_loop(two_allocations=True)
        source["schema"] = SCHEMA_V6
        validated = verify_program(source)
        self.assertEqual(analyze_constant_live_heap(validated), {"count_down": 13})
        receipt = qualify_live_heap_budget(validated, max_live_heap_bytes=13)
        self.assertEqual(receipt["program_sha256"], validated.sha256)
        self.assertTrue(receipt["claims"]["requested_live_payload_bounded"])
        self.assertIs(receipt["claims"]["process_rss_bounded"], False)
        self.assertIs(receipt["claims"]["whole_language_soundness_proved"], False)

    def test_byte_identical_operations_do_not_inherit_v7_resource_authority(self):
        source = scoped_loop()
        source["schema"] = SCHEMA_V6
        verified = verify_program(source)
        self.assertEqual(analyze_constant_live_heap(verified), {"count_down": 9})

        # Changing only the schema to v7 yields a separately verified Core
        # but MUST NOT silently import an old-version numeric/heap proof.
        upgraded = deepcopy(source)
        upgraded["schema"] = SCHEMA_V7
        checked_v7 = verify_program(upgraded)
        with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_UNBOUNDED"):
            analyze_constant_live_heap(checked_v7)
        with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_UNBOUNDED"):
            qualify_live_heap_budget(checked_v7, max_live_heap_bytes=9)

    def test_v7_scalar_only_is_also_outside_the_resource_admission_profile(self):
        source = scoped_loop()
        source["schema"] = SCHEMA_V7
        # This is a valid v7 program: the optional analyzer is narrower than
        # the executable ISA, and an unsupported profile is not a Core error.
        checked = verify_program(source)
        self.assertEqual(checked.as_dict()["schema"], SCHEMA_V7)
        with self.assertRaises(HIAHeapBoundRejected):
            analyze_constant_live_heap(checked)


if __name__ == "__main__":
    unittest.main()
