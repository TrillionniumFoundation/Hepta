"""Bound aggregate Agent JSON preflight work, including repeated references."""
from __future__ import annotations

import json
import unittest
from unittest import mock

import hepta.hia_program_tools as transport


class AgentJSONTotalBudgetTests(unittest.TestCase):
    def test_repeated_string_refuses_before_scanning_every_alias_or_encoding(self):
        shared = "x" * 400
        value = [shared] * 100
        with mock.patch.object(transport, "_bounded_json_string_size",
                               wraps=transport._bounded_json_string_size) as measure:
            with mock.patch.object(
                transport.json.JSONEncoder, "iterencode",
                side_effect=AssertionError("oversized aggregate reached encoder"),
            ) as encode:
                with self.assertRaises(transport.HIAEditRejected):
                    transport.bounded_json_wire(value, 1024)
                encode.assert_not_called()
            # Three copies already exceed 1024 bytes. The other 97 aliases
            # must not each trigger another character scan before refusal.
            self.assertLessEqual(measure.call_count, 3)

    def test_container_keys_values_and_punctuation_all_share_one_budget(self):
        values = (
            ["a" * 30, "b" * 30],
            {"a" * 20: "b" * 20, "c" * 20: "d" * 20},
            [{"key": [True, False, None, 123456789, 1.25]}] * 3,
            ("\x00" * 4, "é中🌍", {False: "false", None: -0.0}),
        )
        for value in values:
            for ensure_ascii in (False, True):
                expected = json.dumps(value, ensure_ascii=ensure_ascii,
                                      sort_keys=False, separators=(",", ":"),
                                      allow_nan=False).encode("utf-8")
                with self.subTest(value=value, ensure_ascii=ensure_ascii):
                    self.assertEqual(
                        transport.bounded_json_wire(value, len(expected),
                                                    ensure_ascii=ensure_ascii,
                                                    sort_keys=False), expected)
                    with mock.patch.object(
                        transport.json.JSONEncoder, "iterencode",
                        side_effect=AssertionError("aggregate limit checked too late"),
                    ) as encode:
                        with self.assertRaises(transport.HIAEditRejected):
                            transport.bounded_json_wire(value, len(expected) - 1,
                                                        ensure_ascii=ensure_ascii,
                                                        sort_keys=False)
                        encode.assert_not_called()

    def test_repeated_noncyclic_containers_remain_valid_at_exact_wire_size(self):
        shared = {"value": [0, "é", False]}
        value = [shared, shared]
        expected = json.dumps(value, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=False).encode("utf-8")
        self.assertEqual(transport.bounded_json_wire(
            value, len(expected), ensure_ascii=False), expected)
        self.assertIs(value[0], value[1])


if __name__ == "__main__":
    unittest.main()
