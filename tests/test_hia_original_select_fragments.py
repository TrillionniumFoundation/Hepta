"""Provenance boundaries for a conditional proof of actual C1 output bytes."""
from __future__ import annotations

import copy
import struct
import unittest

from tools.hia_selfhost_select import select_source
from tools.qualify_hia_original_select_fragments import projection_object, select_fragment

# The 35-byte span observed from the exact frozen C1's u8/u32/u64/usize output.
# Tests of this layout are not represented as proof of an actual compiler run;
# the qualification tool separately retains all native compiler observations.
OBSERVED = bytes.fromhex(
    "488b9580ffffff488b8d60fcffff488b8540f9ffff4885d2480f45c148898530f9ffff")


class OriginalSelectFragmentTests(unittest.TestCase):
    def test_source_slot_identity_prevents_neighboring_value_substitution(self):
        source = select_source("u64")
        image = b"\x90" * 19 + OBSERVED + b"\xc3"
        binding = select_fragment(source, image)
        self.assertEqual((binding["start"], binding["end"]), (19, 54))
        self.assertEqual(binding["variables"], ["v6", "v56", "v106", "v107"])
        damaged = bytearray(image)
        struct.pack_into("<i", damaged, 19 + 10, -32 - 16 * 55)
        with self.assertRaisesRegex(ValueError, "different source/result SSA slots"):
            select_fragment(source, bytes(damaged))

    def test_result_slot_and_uniqueness_are_part_of_provenance(self):
        source = select_source("u32")
        damaged = bytearray(OBSERVED)
        struct.pack_into("<i", damaged, 31, -32 - 16 * 108)
        with self.assertRaisesRegex(ValueError, "different source/result SSA slots"):
            select_fragment(source, bytes(damaged))
        with self.assertRaisesRegex(ValueError, "exactly one selection marker"):
            select_fragment(source, OBSERVED + OBSERVED)
        with self.assertRaisesRegex(ValueError, "truncated"):
            select_fragment(source, OBSERVED[3:])

    def test_projection_retains_actual_bytes_and_an_explicit_context_boundary(self):
        for typ in ("u8", "u32", "u64", "usize"):
            with self.subTest(typ=typ):
                binding = select_fragment(select_source(typ), OBSERVED)
                obj, projection = projection_object(binding)
                self.assertIn(OBSERVED, obj)
                self.assertTrue(projection["scaffolding_is_new"])
                self.assertFalse(projection["scaffolding_proves_original_context"])
                self.assertFalse(binding["entire_compiler_output_validated"])
                self.assertFalse(binding["fragment_instructions_reemitted"])

    def test_changed_copied_bytes_are_rejected_before_projection(self):
        binding = copy.deepcopy(select_fragment(select_source("u64"), OBSERVED))
        binding["fragment_hex"] = (OBSERVED[:-1] + b"\0").hex()
        with self.assertRaisesRegex(ValueError, "changed before projection"):
            projection_object(binding)


if __name__ == "__main__":
    unittest.main()
