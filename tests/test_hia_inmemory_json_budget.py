"""Bounded in-memory HIA Core admission before canonical JSON materialization.

Direct dict/list callers must obey the same 8 MiB, node and depth restrictions
as byte/text callers BEFORE the stdlib encoder can allocate oversized output.
"""
from __future__ import annotations

import json
import random
import unittest
from unittest.mock import patch

import hepta.hia_program as core
from hepta.hia_program import HIAProgramRejected


class HIAInMemoryJSONBudgetTests(unittest.TestCase):
    def test_exact_canonical_utf8_size_small_positive_controls(self):
        cases = [
            {}, [], {"x": True, "n": None, "f": False},
            {"unicode": "é🌍中", "escaped": "\x00\n\t\b\f\r\\"},
            ["a", {"b": [1, -2, 0, (1 << 64) - 1]}, "q\u2028z"],
            [{"shared": []}, {"shared": []}],
        ]
        for value in cases:
            with self.subTest(value=value):
                expected = len(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                          ensure_ascii=False, allow_nan=False).encode("utf-8"))
                self.assertEqual(core._structure(value), expected)
                loaded, raw = core._decode(value)
                self.assertEqual(len(raw), expected)
                self.assertEqual(loaded, value)

    def test_randomized_structures_equal_real_canonical_encoder(self):
        rng = random.Random(1729)
        alphabet = ("a", "\\", '"', "\x00", "\x1b", "\t", "\n", "é", "🌍", "中", "\u2028")
        def example(depth=0):
            if depth < 4 and rng.randrange(3):
                if rng.randrange(2):
                    return [example(depth + 1) for _ in range(rng.randrange(4))]
                return {f"k{n}": example(depth + 1) for n in range(rng.randrange(4))}
            return rng.choice([
                rng.randrange(-(1 << 63), 1 << 64),
                True, False, None, "".join(rng.choice(alphabet) for _ in range(rng.randrange(12))),
            ])
        for _ in range(300):
            value = example()
            wire = json.dumps(value, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=False, allow_nan=False).encode("utf-8")
            self.assertEqual(core._structure(value), len(wire))
            self.assertEqual(core._decode(value)[1], wire)

    def test_inprocess_giant_escaped_string_refused_without_dumping(self):
        # 350 NULs need 2,100 JSON string bytes although the host string
        # holds only 350 characters. Detect it before a giant escaped string
        # is ever allocated by the JSON serializer.
        with patch.object(core, "MAX_BYTES", 1024):
            with patch.object(core.json, "dumps",
                              side_effect=AssertionError("serializer must not run")) as dumper:
                with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_LIMIT"):
                    core._decode({"padding": "\x00" * 350})
                dumper.assert_not_called()

    def test_oversized_fanout_refused_before_encoder(self):
        with patch.object(core, "MAX_NODES", 128):
            with patch.object(core.json, "dumps",
                              side_effect=AssertionError("serializer must not run")) as dumper:
                with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_LIMIT"):
                    core._decode([0] * 1000)
                dumper.assert_not_called()

    def test_cycles_bad_keys_surrogates_and_non_json_values_refuse(self):
        circular = []
        circular.append(circular)
        inputs = (circular, {True: 1}, {"bad": object()},
                  {"surrogate": "\ud800"}, {"nonfinite": float("nan")})
        for value in inputs:
            with self.subTest(kind=type(value)):
                with self.assertRaises(HIAProgramRejected):
                    core._decode(value)

    def test_no_copy_or_change_to_actual_valid_core_bytes(self):
        example = {
            "schema": "hepta.hia.program.v1", "module": "memory_budget_test",
            "functions": [{
                "name": "f", "params": [], "returns": ["u8"], "effects": [],
                "entry": "entry", "blocks": [{
                    "id": "entry", "params": [], "ops": [{
                        "op": "const", "args": [],
                        "out": [{"name": "v", "type": "u8"}], "attrs": {"value": 3}}],
                    "term": {"op": "ret", "values": ["v"]},
                }],
            }],
        }
        checked = core.verify_program(example)
        self.assertEqual(checked.canonical_bytes,
                         json.dumps(example, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=False, allow_nan=False).encode("utf-8"))
        self.assertEqual(core.execute_program(checked, "f", [])["result"], 3)


if __name__ == "__main__":
    unittest.main()
