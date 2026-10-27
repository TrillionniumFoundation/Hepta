"""P7: do not emit ambiguous object keys after Python-to-JSON coercion."""
from __future__ import annotations

import json
import unittest
from unittest import mock

from hepta.hia_program_tools import HIAEditRejected, bounded_json_wire, decode_json


class InMemoryJSONKeyCollisionTests(unittest.TestCase):
    def test_numeric_boolean_null_and_float_key_aliases_refuse_before_encoder(self):
        cases = (
            {1: "integer", "1": "string"},
            {True: "boolean", "true": "string"},
            {None: "null", "null": "string"},
            {1.5: "float", "1.5": "string"},
            {-0.0: "negative zero", "-0.0": "string"},
            {1e20: "positive exponent", "1e+20": "string"},
            {1e-7: "negative exponent", "1e-07": "string"},
        )
        for value in cases:
            for sort_keys in (False, True):
                with self.subTest(value=value, sort_keys=sort_keys):
                    with mock.patch(
                        "hepta.hia_program_tools.json.JSONEncoder.iterencode",
                        side_effect=AssertionError("serialized before rejecting collision"),
                    ) as encoder:
                        with self.assertRaisesRegex(
                            HIAEditRejected, "JSON object key collision"
                        ):
                            bounded_json_wire(value, 8192, sort_keys=sort_keys)
                        encoder.assert_not_called()

    def test_nested_collision_is_also_refused_before_encoding(self):
        with mock.patch(
            "hepta.hia_program_tools.json.JSONEncoder.iterencode",
            side_effect=AssertionError("serialized before rejecting nested collision"),
        ) as encoder:
            with self.assertRaisesRegex(HIAEditRejected, "JSON object key collision"):
                bounded_json_wire({"outer": [{2: "numeric", "2": "text"}]},
                                  8192, sort_keys=False)
            encoder.assert_not_called()

    def test_noncolliding_typed_keys_keep_the_existing_json_conversion(self):
        cases = (
            {1: "numeric", "other": "text"},
            {True: "boolean", False: "false"},
            {None: "null", 1.5: "float"},
            {"outer": [0, {3: "three", "four": 4}]},
            {-0.0: "negative zero", 1e20: "large", 1e-7: "small", 5e-324: "subnormal"},
            {-123: "negative", 10**3000: "large admitted integer"},
            {"Ω": "unicode", "\x00": "control", "😀": "non-BMP"},
        )
        for value in cases:
            for sort_keys in (False, True):
                for ensure_ascii in (False, True):
                    with self.subTest(value=value, sort_keys=sort_keys, ensure_ascii=ensure_ascii):
                        try:
                            expected = json.dumps(value, sort_keys=sort_keys, ensure_ascii=ensure_ascii,
                                                  separators=(",", ":"), allow_nan=False).encode("utf-8")
                        except TypeError:
                            # Sorting unlike key types remains an unsupported
                            # operation; preflight must not invent an order.
                            with self.assertRaises(HIAEditRejected):
                                bounded_json_wire(value, 8192, sort_keys=sort_keys,
                                                  ensure_ascii=ensure_ascii)
                        else:
                            wire = bounded_json_wire(value, 8192, sort_keys=sort_keys,
                                                     ensure_ascii=ensure_ascii)
                            self.assertEqual(wire, expected)
                            self.assertEqual(decode_json(wire), json.loads(wire))

    def test_nonfinite_numeric_key_remains_rejected(self):
        for key in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(key=key), mock.patch(
                "hepta.hia_program_tools.json.JSONEncoder.iterencode",
                side_effect=AssertionError("serialized nonfinite numeric key"),
            ) as encoder:
                with self.assertRaises(HIAEditRejected):
                    bounded_json_wire({key: "bad"}, 8192, sort_keys=False)
                encoder.assert_not_called()

    def test_oversized_integer_keys_reject_before_decimal_materialization_or_encoder(self):
        for key in (1 << 65536, -(1 << 65536)):
            with mock.patch(
                "hepta.hia_program_tools.json.JSONEncoder.iterencode",
                side_effect=AssertionError("serialized oversized integer key"),
            ) as encoder:
                with self.assertRaisesRegex(HIAEditRejected, "numeric byte budget"):
                    bounded_json_wire({key: "bad"}, 64, sort_keys=False)
                encoder.assert_not_called()

    def test_key_subclasses_cannot_supply_conversion_hooks(self):
        class CustomInt(int):
            def __repr__(self):
                raise AssertionError("called a user conversion hook")

        class CustomFloat(float):
            def __repr__(self):
                raise AssertionError("called a user conversion hook")

        class CustomString(str):
            def __str__(self):
                raise AssertionError("called a user conversion hook")

        for key in (CustomInt(4), CustomFloat(1.5), CustomString("key")):
            with mock.patch(
                "hepta.hia_program_tools.json.JSONEncoder.iterencode",
                side_effect=AssertionError("serialized a key subclass"),
            ) as encoder:
                with self.assertRaisesRegex(HIAEditRejected, "unsupported JSON object key"):
                    bounded_json_wire({key: "bad"}, 8192, sort_keys=False)
                encoder.assert_not_called()


if __name__ == "__main__":
    unittest.main()
