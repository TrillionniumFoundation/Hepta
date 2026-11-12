"""P5 evidence admission: no whole-wire allocation before size limits."""
from __future__ import annotations

import json
import tracemalloc
import unittest

from hepta.hia_bounded_wire import WireBudgetExceeded, checked_utf8_wire
from hepta.hia_full_cost_gate import (
    FullCostRejected, MAX_INPUT_BYTES, _wire as full_cost_wire,
)
from hepta.hia_native_paired_replay import (
    MAX_REPORT_BYTES, NativePairedReplayRejected, _read as native_replay_read,
)
from tools.hia_native_process_observer import (
    MAX_MANIFEST, NativeObservationRejected, _parse as native_registration_parse,
)
from tests.test_hia_full_cost_gate import fixture, wire


class HIAEvidenceIntakeBudgetTests(unittest.TestCase):
    def test_exact_ascii_and_multibyte_utf8_wire_sizes(self):
        for source in ("", "[]", "A", "é" * 4099, "🌊" * 4100, "河" * 3):
            encoded = source.encode("utf-8")
            self.assertEqual(checked_utf8_wire(source, len(encoded)), encoded)
            if encoded:
                with self.assertRaises(WireBudgetExceeded):
                    checked_utf8_wire(source, len(encoded) - 1)

    def test_oversized_text_is_rejected_before_full_copy(self):
        sample = "🌊" * (MAX_REPORT_BYTES // 4 + 1)
        tracemalloc.start()
        try:
            with self.assertRaises(WireBudgetExceeded):
                checked_utf8_wire(sample, MAX_REPORT_BYTES)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 512 * 1024)

    def test_third_party_immutable_text_and_error_domains(self):
        bad = "é" * (MAX_INPUT_BYTES // 2 + 1)
        with self.assertRaisesRegex(FullCostRejected, "byte limit"):
            full_cost_wire(bad)
        with self.assertRaisesRegex(NativeObservationRejected, "byte budget"):
            native_registration_parse(bad)
        massive = "🌊" * (MAX_REPORT_BYTES // 4 + 1)
        with self.assertRaisesRegex(NativePairedReplayRejected, "byte limit"):
            native_replay_read(massive)
        invalid = "x" + chr(0xD800)
        with self.assertRaisesRegex(FullCostRejected, "invalid UTF-8"):
            full_cost_wire(invalid)
        with self.assertRaisesRegex(NativeObservationRejected, "invalid JSON"):
            native_registration_parse(invalid)
        with self.assertRaisesRegex(NativePairedReplayRejected, "invalid UTF-8"):
            native_replay_read(invalid)
        for value in (None, {}, True):
            with self.subTest(value=repr(value)):
                with self.assertRaises(TypeError):
                    checked_utf8_wire(value, 10)

    def test_original_cost_receipt_exactly_unchanged(self):
        source = wire(fixture())
        parsed, digest = full_cost_wire(source)
        reparsed, digest_from_text = full_cost_wire(source.decode("utf-8"))
        self.assertEqual(parsed, reparsed)
        self.assertEqual(digest, digest_from_text)
        self.assertEqual(parsed["schema"], fixture()["schema"])

    def test_no_implicit_authority_even_when_wire_admitted(self):
        from hepta.hia_full_cost_gate import assess_full_cost
        source = json.dumps(fixture(), sort_keys=True, separators=(",", ":"))
        report = assess_full_cost(source)
        self.assertEqual(report["authority"], "DENY_ALL")
        self.assertFalse(report["safety_certificate"])
        self.assertFalse(report["production_activation_allowed"])


if __name__ == "__main__":
    unittest.main()
