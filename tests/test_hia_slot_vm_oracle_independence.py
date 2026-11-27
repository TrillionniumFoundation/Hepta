"""The Slot reference interpreter must not consult an installed native image."""
from __future__ import annotations

import ctypes
import struct
import unittest
from unittest.mock import patch

from hepta.hia_agent_assembly import assemble_program
from hepta.hia_program_runtime import _Owner, _View
from hepta.hia_program_runtime_arithmetic import prepare_arithmetic_runtime
from hepta.hia_slot_operations_native import SOURCE
from hepta.hia_slot_operations_protocol import (
    CLAIM, CLAIMED, INITIALIZE, ISSUED, MODES, OUTPUT_BYTES, REQUEST_BYTES,
    REQUEST_MAGIC, RESULT_MAGIC, STATE_BYTES, STATE_MAGIC,
)
from tests.hia_slot_operations_observer import _VMEntry


class SlotVMOracleIndependenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prepared = prepare_arithmetic_runtime(assemble_program(SOURCE.read_bytes()))

    def setUp(self):
        self.package = self.enterContext(patch(
            'hepta.hia_default_native.default_integer_image',
            side_effect=AssertionError('independent Slot VM consulted a package image')))
        self.mapping = self.enterContext(patch(
            'hepta.hia_slot_operations_native.NativeSlotOperations.__init__',
            side_effect=AssertionError('independent Slot VM mapped a native controller')))
        self.entry = _VMEntry(*self.prepared, _Owner, _View)

    def invoke(self, raw, state):
        source = ctypes.create_string_buffer(raw, REQUEST_BYTES)
        output = ctypes.create_string_buffer(OUTPUT_BYTES)
        code = self.entry(source, REQUEST_BYTES, output, OUTPUT_BYTES, state, STATE_BYTES)
        self.assertEqual(source.raw, raw)
        return code, output.raw

    def test_all_fifteen_initialization_and_claim_routes_remain_interpreted(self):
        identity = (0x123456789ABCDEF, 0xFEDCBA987654321)
        for name, mode in MODES.items():
            with self.subTest(method=name):
                state = ctypes.create_string_buffer(STATE_BYTES)
                raw = struct.pack('<16Q', REQUEST_MAGIC, INITIALIZE, 0, 0, 0,
                                  mode, *identity, *([0] * 8))
                code, output = self.invoke(raw, state)
                self.assertEqual(code, OUTPUT_BYTES)
                words = struct.unpack('<12Q', output)
                state_words = struct.unpack('<24Q', state.raw)
                self.assertEqual(words[:2], (RESULT_MAGIC, 0))
                self.assertGreater(words[2], 0)
                self.assertEqual(words[3:7], (1, ISSUED, mode, 0))
                self.assertEqual(words[8:10], identity)
                self.assertEqual(state_words[:3], (STATE_MAGIC, 1, mode))
                raw = struct.pack('<16Q', REQUEST_MAGIC, CLAIM, 1, words[2], 0,
                                  mode, *identity, *([0] * 8))
                code, claimed = self.invoke(raw, state)
                self.assertEqual(code, OUTPUT_BYTES)
                claimed_words = struct.unpack('<12Q', claimed)
                self.assertEqual(claimed_words[:4], words[:4])
                self.assertEqual(claimed_words[4:7], (CLAIMED, mode, 0))
                self.assertEqual(claimed_words[8:10], identity)
        self.assertEqual(self.entry.entries, 30)
        self.assertEqual(self.entry.events, {'0': 15, '1': 15})
        self.package.assert_not_called()
        self.mapping.assert_not_called()

    def test_invalid_request_keeps_state_untouched_without_native_consultation(self):
        state = ctypes.create_string_buffer(STATE_BYTES)
        code, output = self.invoke(bytes(REQUEST_BYTES), state)
        self.assertEqual(code, 4294967293)
        self.assertEqual(output, bytes(OUTPUT_BYTES))
        self.assertEqual(state.raw, bytes(STATE_BYTES))
        self.package.assert_not_called()
        self.mapping.assert_not_called()


if __name__ == '__main__':
    unittest.main()
