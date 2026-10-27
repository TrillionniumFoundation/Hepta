"""P7: even ASCII-escaped in-memory Agent JSON must reject lone UTF-16 units.

The public bounded encoder must not produce a wire value that the HIA JSON
predecoder inevitably rejects. This is transport validation, not an HIA proof.
"""
from __future__ import annotations

import unittest
from unittest import mock

from hepta.hia_program_tools import (
    HIAEditRejected,
    bounded_json_wire,
    decode_json,
)


class InMemoryAgentSurrogateWireTests(unittest.TestCase):
    def test_every_isolated_surrogate_refused_regardless_of_ascii_setting(self):
        for point in range(0xD800, 0xE000):
            for ensure_ascii in (True, False):
                with self.subTest(point=hex(point), ensure_ascii=ensure_ascii):
                    with self.assertRaisesRegex(
                        HIAEditRejected, "unpaired Unicode surrogate"
                    ):
                        bounded_json_wire(chr(point), 8192,
                                          ensure_ascii=ensure_ascii)

    def test_surrogate_nested_value_and_object_key_refuse_before_encoder(self):
        malformed = (
            {"field": ["valid", chr(0xD800)]},
            {chr(0xDFFF): 1},
        )
        for ensure_ascii in (True, False):
            for payload in malformed:
                with self.subTest(ensure_ascii=ensure_ascii, payload=repr(payload)):
                    with mock.patch(
                        "hepta.hia_program_tools.json.JSONEncoder.iterencode",
                        side_effect=AssertionError("encoder reached before rejection"),
                    ) as encoder:
                        with self.assertRaisesRegex(
                            HIAEditRejected, "unpaired Unicode surrogate"
                        ):
                            bounded_json_wire(payload, 8192,
                                              ensure_ascii=ensure_ascii)
                        encoder.assert_not_called()

    def test_valid_unicode_scalars_and_literal_escape_roundtrip(self):
        value = {"emoji": "😀", "max": "\U0010ffff", "literal": r"\uD800"}
        for ensure_ascii in (True, False):
            with self.subTest(ensure_ascii=ensure_ascii):
                wire = bounded_json_wire(value, 8192,
                                         ensure_ascii=ensure_ascii)
                self.assertEqual(decode_json(wire), value)
                if ensure_ascii:
                    self.assertTrue(wire.isascii())
                else:
                    self.assertIn("😀".encode("utf-8"), wire)


if __name__ == "__main__":
    unittest.main()
