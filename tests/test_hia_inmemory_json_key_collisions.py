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
            {False: "boolean", "false": "string"},
            {None: "null", "null": "string"},
            {1.5: "float", "1.5": "string"},
            {-0.0: "negative zero", "-0.0": "string"},
            {1e+20: "exponent", "1e+20": "string"},
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
        )
        for value in cases:
            with self.subTest(value=value):
                wire = bounded_json_wire(value, 8192, sort_keys=False)
                self.assertEqual(wire, json.dumps(value, ensure_ascii=True,
                                                 separators=(",", ":"),
                                                 allow_nan=False).encode("utf-8"))
                self.assertEqual(decode_json(wire),
                                 json.loads(wire))

    def test_nonfinite_numeric_key_remains_rejected(self):
        for key in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(key=repr(key)):
                with mock.patch(
                    "hepta.hia_program_tools.json.JSONEncoder.iterencode",
                    side_effect=AssertionError("serialized nonfinite numeric key"),
                ) as encoder:
                    with self.assertRaises(HIAEditRejected):
                        bounded_json_wire({key: "bad"}, 8192, sort_keys=False)
                    encoder.assert_not_called()


if __name__ == "__main__":
    unittest.main()
