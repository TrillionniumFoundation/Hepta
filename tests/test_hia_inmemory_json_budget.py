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
        for sample in range(300):
            value = example()
            wire = json.dumps(value, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=False, allow_nan=False).encode("utf-8")
            with self.subTest(sample=sample, kind=type(value).__name__):
                self.assertEqual(core._structure(value), len(wire))
                # Top-level str/bytes are serialized JSON inputs, not literal
                # in-memory strings. Exercise both wire forms for every value.
                for source in (wire, wire.decode("utf-8")):
                    loaded, raw = core._decode(source)
                    self.assertEqual(loaded, value)
                    self.assertEqual(raw, wire)
                if type(value) is not str:
                    self.assertEqual(core._decode(value)[1], wire)
                # Preserve every generated value, including scalar strings,
                # through both unambiguous in-memory container entry points.
                for container in ([value], {"value": value}):
                    expected = json.dumps(container, sort_keys=True, separators=(",", ":"),
                                          ensure_ascii=False, allow_nan=False).encode("utf-8")
                    self.assertEqual(core._structure(container), len(expected))
                    loaded, raw = core._decode(container)
                    self.assertEqual(loaded, container)
                    self.assertEqual(raw, expected)

    def test_scalar_wire_keeps_its_json_meaning_not_literal_string(self):
        for source, expected in (("true", True), ("false", False), ("null", None),
                                 ("1", 1), ("-1", -1), ("[]", []), ("{}", {})):
            with self.subTest(source=source):
                for wire in (source, source.encode("utf-8")):
                    loaded, raw = core._decode(wire)
                    self.assertIs(type(loaded), type(expected))
                    self.assertEqual(loaded, expected)
                    self.assertEqual(raw, source.encode("utf-8"))
                # Quoting the source or nesting it is how callers supply the
                # string "true", "null", "1", etc. without changing wire syntax.
                quoted = json.dumps(source).encode("utf-8")
                self.assertEqual(core._decode(quoted), (source, quoted))
                self.assertEqual(core._decode({"value": source})[0], {"value": source})

    def test_bare_string_and_invalid_wire_never_fall_back_to_literal(self):
        # Seed 1729 sample 8 was this valid string *value*, incorrectly passed
        # as unquoted JSON source by the old randomized test. "a" is minimal.
        for value in ("a", "🌍\x00a\u2028é", "", "True", "01", "1.0", "1e0",
                      "NaN", "Infinity", '{"a":1,"a":2}'):
            with self.subTest(value=value):
                for source in (value, value.encode("utf-8")):
                    with self.assertRaises(HIAProgramRejected) as rejected:
                        core._decode(source)
                    self.assertEqual(rejected.exception.code, "E_HIA_FORMAT")
                quoted = json.dumps(value, ensure_ascii=False).encode("utf-8")
                self.assertEqual(core._decode(quoted), (value, quoted))

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
