"""Unicode transport preflight: refuse orphan UTF-16 units before Agent JSON decode.

This is a syntax/resource gate, not a replacement for HIA ownership verification.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from hepta.hia_json_preflight import preflight_hia_json
from hepta.hia_program_tools import HIAEditRejected, decode_json


class HIAUnicodePredecode(unittest.TestCase):
    def test_orphan_surrogates_refuse_without_materializing_json_values(self):
        malformed = (
            r'"\ud800"', r'"\udfff"', r'"\ud83dA"',
            r'"\ud83d\u0041"', r'"\ud83d\n"',
            r'"\ud83d\ud800"', r'"\udbff\ud000"',
            r'["\udc00"]', r'{"\udc00":1}',
        )
        for raw in malformed:
            for wire in (raw, raw.encode("ascii")):
                with self.subTest(wire=repr(wire)):
                    with mock.patch(
                        "hepta.hia_program_tools.json.loads",
                        side_effect=AssertionError("JSON value materialized before refusal"),
                    ) as decoder:
                        with self.assertRaisesRegex(HIAEditRejected, "invalid JSON"):
                            decode_json(wire)
                        decoder.assert_not_called()

    def test_all_2048_isolated_escape_code_units_refuse(self):
        for point in range(0xD800, 0xE000):
            raw = '"\\u%04x"' % point
            with self.subTest(point=hex(point)):
                with self.assertRaises(ValueError):
                    preflight_hia_json(raw, max_nodes=16, max_depth=4)

    def test_valid_adjacent_surrogate_pairs_and_literal_backslash(self):
        for raw, expected in (
            (r'"\ud83d\ude00"', "😀"),
            (r'"\uD83D\uDE00"', "😀"),
            (r'"\udbff\udfff"', "\U0010ffff"),
            (r'"\\uD800"', r"\uD800"),
        ):
            with self.subTest(wire=raw):
                self.assertEqual(decode_json(raw), expected)
                self.assertEqual(decode_json(raw.encode("ascii")), expected)

    def test_duplicate_keys_with_escape_equivalent_to_utf8_refuse(self):
        self.assertEqual(decode_json(r'{"\ud83d\ude00":1}'), {"😀": 1})
        for raw in (
            '{"😀":1,"\\ud83d\\ude00":2}',
            '{"\\ud83d\\ude00":1,"😀":2}',
        ):
            with self.subTest(wire=raw):
                with self.assertRaises(HIAEditRejected):
                    decode_json(raw)

    def test_raw_unpaired_surrogate_refused(self):
        raw = '"' + chr(0xD800) + '"'
        with self.assertRaisesRegex(ValueError, "surrogate"):
            preflight_hia_json(raw, max_nodes=4, max_depth=1)


if __name__ == "__main__":
    unittest.main()
