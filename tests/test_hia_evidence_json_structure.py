"""P5 native research evidence must have bounded nodes/depth before full decode."""
from __future__ import annotations

from hashlib import sha256
from unittest.mock import patch
import unittest

from hepta.hia_full_cost_gate import FullCostRejected, _wire as cost_wire
from hepta.hia_native_paired_replay import (
    NativePairedReplayRejected, _read as replay_read,
)
from tools.hia_native_process_observer import (
    NativeObservationRejected, _parse as observer_parse,
)
from tests.test_hia_full_cost_gate import fixture, wire


class HIAEvidenceStructureTests(unittest.TestCase):
    def test_small_and_large_node_fanout_rejected_before_json_loads(self):
        # Numeric JSON arrays have no keys; the existing syntax scanner does
        # not call json.loads for any key. Patching json.loads therefore
        # detects accidental *full* decoding before the structural limit.
        medium = "[" + "0," * 65536 + "0]"
        huge = "[" + "0," * 262144 + "0]"
        for consumer, bad, exception in (
            (cost_wire, medium, FullCostRejected),
            (observer_parse, medium, NativeObservationRejected),
            (replay_read, huge, NativePairedReplayRejected),
        ):
            with self.subTest(name=consumer.__name__, source_len=len(bad)):
                with patch("json.loads", side_effect=AssertionError(
                    "complete JSON decoded before node/depth admission"
                )):
                    with self.assertRaises(exception):
                        consumer(bad)

    def test_over_depth_refuses_on_both_immutable_input_forms(self):
        too_deep = "[" * 65 + "0" + "]" * 65
        for consumer, exception in (
            (cost_wire, FullCostRejected),
            (observer_parse, NativeObservationRejected),
            (replay_read, NativePairedReplayRejected),
        ):
            for source in (too_deep, too_deep.encode("utf-8")):
                with self.subTest(consumer=consumer.__name__, mode=type(source).__name__):
                    with self.assertRaises(exception):
                        consumer(source)

    def test_successful_wire_digests_and_values_are_unchanged(self):
        source = wire(fixture())
        for candidate in (source, source.decode("utf-8")):
            parsed, source_digest = cost_wire(candidate)
            self.assertEqual(parsed, fixture())
            self.assertEqual(source_digest, sha256(source).hexdigest())
        simple = '{"x":[3,true,null],"a":"\\u4e2d"}'
        for consumer in (observer_parse, replay_read):
            with self.subTest(consumer=consumer.__name__):
                encoded = simple.encode("utf-8")
                parsed = consumer(simple)
                decoded = consumer(encoded)
                if consumer is observer_parse:
                    self.assertEqual(parsed, decoded)
                    self.assertEqual(parsed[1], sha256(encoded).hexdigest())
                else:
                    self.assertEqual(parsed, decoded)
                    self.assertEqual(parsed["a"], "中")

    def test_duplicate_escape_alias_is_still_rejected(self):
        duplicate = '{"a":0,"\\u0061":1}'
        for consumer, exception in (
            (cost_wire, FullCostRejected),
            (observer_parse, NativeObservationRejected),
            (replay_read, NativePairedReplayRejected),
        ):
            with self.subTest(consumer=consumer.__name__):
                with self.assertRaises(exception):
                    consumer(duplicate)


if __name__ == "__main__":
    unittest.main()
