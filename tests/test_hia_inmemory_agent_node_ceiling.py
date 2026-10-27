"""P7: in-memory Agent JSON fanout must obey the text decoder node ceiling."""
from __future__ import annotations

import unittest
from unittest import mock

from hepta.hia_program_tools import (
    HIAEditRejected,
    MAX_AGENT_JSON_NODES,
    MAX_INPUT_BYTES,
    bounded_json_wire,
    decode_json,
)


class InMemoryAgentNodeCeilingTests(unittest.TestCase):
    def test_exact_shared_text_and_inmemory_node_boundary(self):
        # Array root is itself one node. This is the largest accepted
        # uniform scalar array under the text decoder's 262144-node cap.
        value = [0] * (MAX_AGENT_JSON_NODES - 1)
        wire = bounded_json_wire(value, MAX_INPUT_BYTES, ensure_ascii=False)
        self.assertEqual(len(decode_json(wire)), len(value))

    def test_dense_inmemory_input_refused_before_json_encoder(self):
        # Previously this 512 KiB wire image fit the 8 MiB byte budget,
        # so the in-memory walker would reach the encoder even though
        # decode_json must subsequently refuse the extra structural node.
        value = [0] * MAX_AGENT_JSON_NODES
        with mock.patch(
            "hepta.hia_program_tools.json.JSONEncoder.iterencode",
            side_effect=AssertionError("encoder ran before Agent node admission"),
        ) as encoder:
            with self.assertRaisesRegex(HIAEditRejected, "queued-node/byte budget"):
                bounded_json_wire(value, MAX_INPUT_BYTES)
            encoder.assert_not_called()

    def test_shared_subtree_expansion_refused_before_encoding(self):
        # Reusing a Python list is not a JSON identity/reference: its
        # elements appear three times in the serialized value tree.
        shared = [0] * 131072
        value = [shared, shared, shared]
        with mock.patch(
            "hepta.hia_program_tools.json.JSONEncoder.iterencode",
            side_effect=AssertionError("encoder ran before pending-node admission"),
        ) as encoder:
            with self.assertRaisesRegex(HIAEditRejected, "node/byte budget"):
                bounded_json_wire(value, MAX_INPUT_BYTES)
            encoder.assert_not_called()

    def test_tighter_caller_byte_node_limit_remains_enforced(self):
        with self.assertRaises(HIAEditRejected):
            bounded_json_wire([0] * 100, 100)
        self.assertEqual(bounded_json_wire([0] * 10, 100), b"[" + b"0," * 9 + b"0]")


if __name__ == "__main__":
    unittest.main()
