"""Real bounded Agent JSON encoder preflight regression tests.

This exercises the existing published bounded_json_wire API and ensures an
oversized escaped string is rejected before JSONEncoder materializes it.
"""
from __future__ import annotations

import json
import random
import unittest
from unittest.mock import patch

import hepta.hia_program_tools as wire
from hepta.hia_program_tools import HIAEditRejected, bounded_json_wire


class HIAEscapedWirePreflightTests(unittest.TestCase):
    def test_exact_python_json_encoder_string_lengths(self):
        # Exercise ASCII DEL, short and long control escapes, BMP Unicode,
        # supplementary/surrogate-pair escapes and the strict UTF-8 profile.
        rng = random.Random(8827)
        alphabet = ("a", "\x00", "\n", "\b", "\t", "\f", "\r", "\x1f",
                    "\x7f", '"', "\\", "é", "中", "🌍", "\u2028", "\ud800")
        for ensure_ascii in (True, False):
            for _ in range(350):
                text = "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 25)))
                try:
                    exact = len(json.dumps(text, ensure_ascii=ensure_ascii).encode("utf-8"))
                except UnicodeEncodeError:
                    with self.assertRaises(HIAEditRejected):
                        wire._bounded_json_string_bytes(text, 1024, ensure_ascii)
                else:
                    self.assertEqual(wire._bounded_json_string_bytes(
                        text, 1024, ensure_ascii), exact)

    def test_reject_nul_string_before_encoder_is_constructed(self):
        for content in ({"v": "\x00" * 48},
                        {"\x00" * 48: "v"},
                        {"v": "🌍" * 48}):
            with self.subTest(content=next(iter(content))):
                with patch.object(wire.json, "JSONEncoder",
                                  side_effect=AssertionError("escaped fragment allocated")) as encoder:
                    with self.assertRaises(HIAEditRejected):
                        bounded_json_wire(content, 128, ensure_ascii=True)
                    encoder.assert_not_called()

    def test_nonascii_utf8_fragment_preflight_and_nonfinite_keys(self):
        with patch.object(wire.json, "JSONEncoder",
                          side_effect=AssertionError("fragment allocated")) as encoder:
            with self.assertRaises(HIAEditRejected):
                bounded_json_wire({"v": "🌍" * 48}, 128, ensure_ascii=False)
            encoder.assert_not_called()
        for invalid in ({float("inf"): 1}, {float("nan"): 1}):
            with self.assertRaises(HIAEditRejected):
                bounded_json_wire(invalid, 1024)

    def test_huge_integer_key_or_value_refuses_before_encoder(self):
        enormous = 1 << 10_000
        for value in ({enormous: 1}, {"v": enormous}):
            with patch.object(wire.json, "JSONEncoder",
                              side_effect=AssertionError("unbounded integer allocated")) as encoder:
                with self.assertRaises(HIAEditRejected):
                    bounded_json_wire(value, 128)
                encoder.assert_not_called()

    def test_admitted_wire_bytes_unchanged(self):
        values = ({"v": "\x00\n🌍é\x7f"},
                  ["a", {"escaped": '"\\', "n": None, "yes": True}],
                  {"z": [0, 1, -2, 23], "q": "hello"})
        for ascii_mode in (False, True):
            for value in values:
                with self.subTest(ensure_ascii=ascii_mode, value=value):
                    expected = json.dumps(value, ensure_ascii=ascii_mode,
                                          sort_keys=True, separators=(",", ":"),
                                          allow_nan=False).encode("utf-8")
                    self.assertEqual(bounded_json_wire(
                        value, 4096, ensure_ascii=ascii_mode), expected)


if __name__ == "__main__":
    unittest.main()
