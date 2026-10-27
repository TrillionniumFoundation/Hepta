"""P7: textual Agent JSON must be bounded before stdlib value allocation."""
from __future__ import annotations

import json
import unittest
from unittest import mock

from hepta.hia_program_tools import (
    HIAEditRejected, MAX_AGENT_JSON_DEPTH, MAX_AGENT_JSON_NODES, decode_json,
)


class TextAgentJSONPredecodeTests(unittest.TestCase):
    def test_valid_utf8_requests_still_decode_without_semantic_reinterpretation(self):
        value = {"schema": "hepta.hia.patch.v1", "names": ["é", "x"], "ok": True,
                 "edits": [{"site": 0, "changes": {"op": "int.add.wrap"}}]}
        wire = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
        self.assertEqual(decode_json(wire), value)
        self.assertEqual(decode_json(wire.encode("utf-8")), value)

    def test_dense_node_fanout_refuses_before_json_loads_materializes_values(self):
        # About 512 KiB of valid JSON can otherwise allocate >262144
        # Python values before a later semantic verifier sees the input.
        raw = "[" + ",".join("0" for _ in range(MAX_AGENT_JSON_NODES)) + "]"
        with mock.patch("hepta.hia_program_tools.json.loads",
                        side_effect=AssertionError("premature JSON materialization")) as load:
            with self.assertRaisesRegex(HIAEditRejected, "node/depth budget"):
                decode_json(raw)
            load.assert_not_called()

    def test_small_deep_payload_refuses_before_json_loads(self):
        good = "[" * MAX_AGENT_JSON_DEPTH + "0" + "]" * MAX_AGENT_JSON_DEPTH
        self.assertEqual(decode_json(good), json.loads(good))
        bad = "[" + good + "]"
        with mock.patch("hepta.hia_program_tools.json.loads",
                        side_effect=AssertionError("premature recursive parser")) as load:
            with self.assertRaisesRegex(HIAEditRejected, "node/depth budget"):
                decode_json(bad.encode("utf-8"))
            load.assert_not_called()

    def test_duplicate_escaped_keys_and_non_utf8_bytes_refuse(self):
        with self.assertRaises(HIAEditRejected):
            decode_json('{"schema": 1, "\\u0073chema": 2}')
        with self.assertRaises(HIAEditRejected):
            decode_json(b'{"source":"\\xff"}\xff')
        with self.assertRaises(HIAEditRejected):
            decode_json('{"amount": 1.25}')  # HIA patch profile is integer-only


if __name__ == "__main__":
    unittest.main()
