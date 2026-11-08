"""Counterexamples for common output corruption hidden by equal plan arms."""
from copy import deepcopy
import unittest

from tools.qualify_hia_selfhost_machine_plans import (
    CAPACITY, INVALID, check_hash_observation, check_rejected_source,
)


class MachinePlanEffectOracles(unittest.TestCase):
    def hash_observation(self):
        expected = 0x12345678
        header = {str(offset): expected & 255 if offset == 0 else 0
                  for offset in (0, 8, 16, 24, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 224, 248, 1024)}
        return {"core_u32": expected, "workspace_header": header}, bytes([expected & 255]) + b"\xa5" * (CAPACITY - 1), expected

    def test_invalid_return_does_not_hide_output_damage(self):
        with self.assertRaisesRegex(ValueError, "changed output"):
            check_rejected_source({"core_u32": INVALID, "output_unchanged": False}, "common-write")

    def test_intact_rejection_and_hash_effects_pass(self):
        check_rejected_source({"core_u32": INVALID, "output_unchanged": True}, "intact")
        check_hash_observation(*self.hash_observation())

    def test_matching_return_does_not_hide_wrong_output_byte(self):
        result, output, expected = self.hash_observation()
        with self.assertRaisesRegex(ValueError, "output effects"):
            check_hash_observation(result, bytes([output[0] ^ 1]) + output[1:], expected)

    def test_matching_return_does_not_hide_output_tail_write(self):
        result, output, expected = self.hash_observation()
        with self.assertRaisesRegex(ValueError, "output effects"):
            check_hash_observation(result, output[:-1] + b"\0", expected)

    def test_matching_return_and_output_do_not_hide_workspace_damage(self):
        result, output, expected = self.hash_observation()
        for offset in result["workspace_header"]:
            changed = deepcopy(result)
            changed["workspace_header"][offset] ^= 1
            with self.subTest(offset=offset), self.assertRaisesRegex(ValueError, "workspace header"):
                check_hash_observation(changed, output, expected)

    def test_missing_workspace_observation_is_refused(self):
        result, output, expected = self.hash_observation()
        for offset in result["workspace_header"]:
            changed = deepcopy(result)
            del changed["workspace_header"][offset]
            with self.subTest(offset=offset), self.assertRaisesRegex(ValueError, "workspace header"):
                check_hash_observation(changed, output, expected)

    def test_unexpected_workspace_observation_is_refused(self):
        result, output, expected = self.hash_observation()
        result["workspace_header"]["256"] = 0
        with self.assertRaisesRegex(ValueError, "workspace header"):
            check_hash_observation(result, output, expected)


if __name__ == "__main__":
    unittest.main()
