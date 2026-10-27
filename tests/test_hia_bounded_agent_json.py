"""P5/P7 in-process Agent JSON byte limits before materialization."""
from __future__ import annotations

import copy
import json
import unittest
from unittest import mock

from hepta.hia_program import verify_program
from hepta.hia_program_tools import (HIAEditRejected, MAX_INPUT_BYTES, PATCH_SCHEMA,
                                     apply_program_patch, bounded_json_wire)
from hepta.hia_edit_query import apply_edit, prepare_edit
from hepta.hia_edit_batch import apply_batch, prepare_batch
from tests.test_hia_edit_query import fixture
from tests.test_hia_edit_batch import loans, selected, swaps


class BoundedAgentJSONTests(unittest.TestCase):
    def test_original_canonical_wire_and_number_identity_remain_exact(self):
        for value in ({"b": [None, True, 0, 1.0], "a": {"txt": "é"}},
                      [1, (2, 3), {"nested": [False, 7]}]):
            with self.subTest(value=value):
                expected = json.dumps(value, sort_keys=True, separators=(",", ":"),
                                      allow_nan=False).encode("utf-8")
                self.assertEqual(bounded_json_wire(value, 16 * 1024), expected)
        self.assertNotEqual(bounded_json_wire({"value": True}, 100),
                            bounded_json_wire({"value": 1}, 100))

    def test_large_string_and_container_refused_before_json_encoder(self):
        cases = ({"big": "x" * 70000}, list(range(70000)))
        for value in cases:
            with self.subTest(kind=type(value)):
                with mock.patch("hepta.hia_program_tools.json.JSONEncoder.iterencode",
                                side_effect=AssertionError("must refuse before encoding")):
                    with self.assertRaises(HIAEditRejected):
                        bounded_json_wire(value, 1024)

    def test_cycle_nan_invalid_objects_and_encoded_escapes_are_rejected(self):
        cycle = {}
        cycle["self"] = cycle
        for value in (cycle, {"foo": object()}, {"x": float("nan")}, {"x": set()}):
            with self.subTest(kind=type(value)), self.assertRaises(HIAEditRejected):
                bounded_json_wire(value, 4096)
        # A string may be shorter than a limit but exceed it after escaping.
        with self.assertRaises(HIAEditRejected):
            bounded_json_wire({"escaped": "\n" * 100}, 100)
        shared = []
        self.assertEqual(bounded_json_wire([shared, shared], 100), b"[[],[]]")

    def test_escaped_json_string_exceeding_budget_is_refused_before_encoder(self):
        # Raw string size may be below the budget even when a single encoded
        # JSONEncoder fragment would be several times larger.
        cases = (
            ({"control": "\x00" * 350}, 1024, True),
            ({"non_ascii": "é" * 300}, 1024, True),
            ({"astral": "🌍" * 150}, 1024, True),
            ({"surrogate": "\ud800" * 200}, 1024, True),
            ({"key\x00" * 300: 1}, 1024, False),
            ({"astral": "🌍" * 300}, 1024, False),
        )
        for value, budget, ascii_mode in cases:
            with self.subTest(ascii_mode=ascii_mode, keys=list(value)):
                with mock.patch("hepta.hia_program_tools.json.JSONEncoder.iterencode",
                                side_effect=AssertionError("encoder must not be called")) as encode:
                    with self.assertRaises(HIAEditRejected):
                        bounded_json_wire(value, budget, ensure_ascii=ascii_mode)
                    encode.assert_not_called()

    def test_string_preflight_matches_encoder_with_ascii_and_unicode(self):
        for ascii_mode in (True, False):
            for string in ("plain", '"back\\\\slash"', "\x00\n\t\b\f\r",
                           "é中🌍", "\u2028", "a" * 1022):
                with self.subTest(ascii_mode=ascii_mode, value=string):
                    value = {"key": string}
                    expected = json.dumps(value, ensure_ascii=ascii_mode, sort_keys=True,
                                          separators=(",", ":"), allow_nan=False).encode("utf-8")
                    self.assertEqual(bounded_json_wire(value, len(expected),
                                                        ensure_ascii=ascii_mode), expected)
                    with self.assertRaises(HIAEditRejected):
                        bounded_json_wire(value, len(expected) - 1,
                                          ensure_ascii=ascii_mode)

    def test_inprocess_patch_is_bounded_without_changing_patch_semantics(self):
        original = fixture()
        snapshot = verify_program(original)
        request = {"schema": PATCH_SCHEMA, "expected_sha256": snapshot.sha256,
                   "edits": [{"action": "replace_operation", "function": "calculate",
                              "block": "entry", "index": 1,
                              "operation": copy.deepcopy(original["functions"][0]["blocks"][0]["ops"][1])}]}
        output, receipt = apply_program_patch(original, request)
        self.assertEqual(output.sha256, snapshot.sha256)
        self.assertEqual(receipt["before_sha256"], snapshot.sha256)
        oversized = copy.deepcopy(request)
        oversized["padding"] = "x" * (MAX_INPUT_BYTES + 1)
        with self.assertRaises(HIAEditRejected):
            apply_program_patch(original, oversized)

    def test_inprocess_query_batch_and_response_limits(self):
        original = fixture()
        query = prepare_edit(original, function="calculate", block="entry",
                             output="y", fields=["op"])
        modified, receipt = apply_edit(original, query, {"op": "int.sub.wrap"})
        self.assertNotEqual(modified.sha256, verify_program(original).sha256)
        self.assertTrue(receipt["edit_query"]["entire_module_reverified"])
        with self.assertRaises(HIAEditRejected):
            apply_edit(original, query, {"op": "X" * 20000})
        forged = copy.deepcopy(query)
        forged["padding"] = "X" * (1024 * 1024 + 1)
        with self.assertRaises(HIAEditRejected):
            apply_edit(original, forged, {"op": "int.sub.wrap"})

        source = loans()
        batch = prepare_batch(source, [selected("reader"), selected("writer")])
        huge = {"edits": swaps()["edits"], "padding": "Z" * (64 * 1024 + 1)}
        with self.assertRaises(HIAEditRejected):
            apply_batch(source, batch, huge)


if __name__ == "__main__":
    unittest.main()
