"""P1/P7: v6 fallible cyclic Owner peaks do not authorize v7 resource programs."""
from __future__ import annotations

from copy import deepcopy
import unittest

from hepta.hia_heap_bound import (
    HIAHeapBoundRejected, analyze_constant_live_heap, qualify_live_heap_budget,
)
from hepta.hia_program import verify_program
from hepta.hia_schema import SCHEMA_V6, SCHEMA_V7
from tests.test_hia_program import i
from tests.test_hia_scoped_alloc_loops import scoped_loop


def fallible_cycle(schema):
    program = scoped_loop()
    program["schema"] = schema
    body = next(block for block in program["functions"][0]["blocks"]
                if block["id"] == "body")
    body["ops"][1] = i("buffer.try_new", ["scope_bytes"],
                       [("local", "buffer"), ("allocated", "bool")])
    return program


class V7FallibleHeapVersionGuard(unittest.TestCase):
    def test_v6_strict_scope_can_certify_fallible_payload_only(self):
        verified = verify_program(fallible_cycle(SCHEMA_V6))
        self.assertEqual(analyze_constant_live_heap(verified), {"count_down": 9})
        receipt = qualify_live_heap_budget(verified, max_live_heap_bytes=9)
        self.assertEqual(receipt["program_sha256"], verified.sha256)
        self.assertIs(receipt["claims"]["requested_live_payload_bounded"], True)
        for name in ("native_backend_refinement_proved", "process_rss_bounded",
                     "allocator_interactions_bounded", "whole_language_soundness_proved"):
            self.assertIs(receipt["claims"][name], False)

    def test_equivalent_v7_core_cannot_inherit_v6_fallible_budget(self):
        old = fallible_cycle(SCHEMA_V6)
        current = deepcopy(old)
        current["schema"] = SCHEMA_V7
        verified = verify_program(current)
        self.assertEqual(verified.as_dict()["schema"], SCHEMA_V7)
        with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_UNBOUNDED"):
            analyze_constant_live_heap(verified)
        with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_UNBOUNDED"):
            qualify_live_heap_budget(verified, max_live_heap_bytes=9)


if __name__ == "__main__":
    unittest.main()
