"""P0: UTF-8 byte admission must not encode the full untrusted text first."""
from __future__ import annotations

import json
import tracemalloc
import unittest
from unittest.mock import patch

from hepta import hia_program
from hepta.hia_program import (
    HIAProgramRejected, MAX_BYTES, _bounded_input_utf8_bytes, _decode, verify_program,
)
from tests.test_hia_program import arithmetic, resource_program


class HIAInputUTF8BudgetTests(unittest.TestCase):
    def test_exact_utf8_size_and_ascii_fast_path(self):
        for source in ("", "{}", "hello\\t", "é" * 4099,
                       "🌊" * 5000, "中" * 8193):
            with self.subTest(source=source[:20]):
                self.assertEqual(_bounded_input_utf8_bytes(source),
                                 len(source.encode("utf-8")))
        self.assertEqual(_bounded_input_utf8_bytes("a" * MAX_BYTES), MAX_BYTES)
        self.assertEqual(_bounded_input_utf8_bytes("🌊" * (MAX_BYTES // 4)), MAX_BYTES)

    def test_above_utf8_budget_rejected_before_json_preflight(self):
        for text in ("A" * (MAX_BYTES + 1),
                     "é" * (MAX_BYTES // 2 + 1),
                     "🌊" * (MAX_BYTES // 4 + 1)):
            with self.subTest(kind=text[0]), patch.object(
                hia_program, "preflight_hia_json",
                side_effect=AssertionError("unbounded input reached syntax parser"),
            ):
                with self.assertRaises(HIAProgramRejected) as caught:
                    _decode(text)
                self.assertEqual(caught.exception.code, "E_HIA_LIMIT")

    def test_large_unicode_utf8_count_has_small_peak_temporary_memory(self):
        # Prefix 8 MiB UTF-8, but only 2 MiB code points.  The old
        # len(text.encode("utf-8")) would allocate an ~8 MiB copy.
        source = "🌊" * (MAX_BYTES // 4)
        tracemalloc.start()
        try:
            self.assertEqual(_bounded_input_utf8_bytes(source), MAX_BYTES)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 512 * 1024)

    def test_invalid_surrogate_still_fails_closed(self):
        with self.assertRaises(HIAProgramRejected) as caught:
            _decode('"' + chr(0xD800) + '"')
        self.assertEqual(caught.exception.code, "E_HIA_FORMAT")

    def test_bytes_text_and_detached_object_canonical_agreement(self):
        obj = {"x": ["海", 42, "🌊"], "z": {"a": True}}
        text = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False)
        control, canonical = _decode(obj)
        for candidate in (text, text.encode("utf-8")):
            self.assertEqual(_decode(candidate), (control, canonical))
        for program in (arithmetic(), resource_program()):
            with self.subTest(program=program["module"]):
                text = json.dumps(program, ensure_ascii=False)
                self.assertEqual(verify_program(text).canonical_bytes,
                                 verify_program(program).canonical_bytes)

    def test_original_mutable_snapshot_remains_independent(self):
        original = {"x": ["first"]}
        result, serialized = _decode(original)
        original["x"][0] = "changed"
        self.assertEqual(result, {"x": ["first"]})
        self.assertEqual(json.loads(serialized), result)


if __name__ == "__main__":
    unittest.main()
