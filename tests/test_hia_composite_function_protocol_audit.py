"""Post-restart reconstruction of seven independent protocol properties.

The original test file and its early raw protocol evidence were lost with the
transient environment. This is a new revision, not a byte-identical restoration
of that file or a replacement for its historical evidence. Actual-image checks
use the presently source-bound complete bundle (recovered admit r3/render r2).
They are development controls, not cold/compiler/whole-language qualification.
"""
from __future__ import annotations

from copy import deepcopy
import ctypes
from hashlib import sha256
import os
import struct
import unittest

from hepta.hia_composite_function_tokens import (
    ObjectTokenDecoder, TokenProtocolError, detached_packet_index)
from hepta.hia_composite_functions_native import (
    ADMIT_MAGIC, ADMIT_RESPONSE_MAGIC, MAGIC, OUTPUT_BYTES, WORKSPACE_BYTES,
    installed_composite_functions)
from hepta.hia_composite_types_native import SESSION_BYTES, installed_composite_types
from hepta.hia_instruction_policy_native import transport


BUNDLE = 'HEPTA_HIA_COMPOSITE_FUNCTIONS_DEVELOPMENT_MANIFEST'
TYPES = 'HEPTA_HIA_COMPOSITE_TYPES_DEVELOPMENT_MANIFEST'
ABI = 0xfffffff1
STATE = 4096
SOURCE_BASE = 65536


def token(kind, value=0):
    return struct.pack('<2Q', kind, value)


def document():
    params = [dict(name='x', type='u8')]
    return dict(schema='hepta.hia.composite.v4', module='protocol_audit', types=[],
        functions=[dict(name='main', params=params, returns=['u8'], effects=[],
            entry='entry', blocks=[dict(id='entry', params=deepcopy(params), ops=[],
                                       term=dict(op='ret', values=['x']))])])


class FunctionTokenProtocolAuditTests(unittest.TestCase):
    def test_first_decoder_error_permanently_rejects_later_valid_chunks(self):
        bad = [b'\0', token(99), token(3, 2), token(0, 1234),
               token(4) + token(4), token(6, 1) + token(1, 1) + b'k']
        for payload in bad:
            with self.subTest(payload=payload.hex()):
                decoder = ObjectTokenDecoder({})
                with self.assertRaises(TokenProtocolError):
                    decoder.feed(payload, final=True)
                self.assertTrue(decoder.failed)
                with self.assertRaisesRegex(TokenProtocolError, 'failed protocol'):
                    decoder.feed(token(4), final=True)
                self.assertFalse(decoder.complete)

    def test_source_reference_aliases_belong_to_the_detached_packet(self):
        caller = {'nested': [{'values': [1, 2], 'text': 'snow \u2603'}]}
        expected = deepcopy(caller)
        wire = transport(caller)
        before = sha256(wire).hexdigest()
        snapshot, index = detached_packet_index(wire)
        caller['nested'][0]['values'][0] = 999
        caller['nested'].append({'values': []})
        self.assertEqual(snapshot, expected)
        self.assertIsNot(snapshot, caller)
        self.assertIsNot(snapshot['nested'], caller['nested'])
        decoder = ObjectTokenDecoder(index)
        result = decoder.feed(token(5, 2) + token(0, 0) + token(0, 0), final=True)
        self.assertEqual(result, [expected, expected])
        self.assertIs(result[0], snapshot)
        self.assertIs(result[0], result[1])
        self.assertEqual(sha256(wire).hexdigest(), before)


class _RawFunctionHarness:
    """Plain entry calls and immutable readback; no MagicMock buffer history."""

    def __init__(self, case, images, types_image, *, initial_document=None):
        self.case, self.images = case, images
        self.types = types_image.session([], recursive_chain=True, partial_records=True)
        self.workspace = ctypes.create_string_buffer(WORKSPACE_BYTES)
        self.output = ctypes.create_string_buffer(OUTPUT_BYTES)
        self.entry_count = 0
        try:
            scalar = self.types.resolve('u8')
            identifier = self.types._ids[id(scalar)]
            self.registry = [['main', [['x', identifier]], [identifier]]]
            self.origins = [['main', [None]]]
            source = document() if initial_document is None else initial_document
            self.wire = self.packet(source)
            _, self.index = detached_packet_index(self.wire)
            self.initial_status, self.initial_frame = self.send(self.wire)
            if self.initial_status == 64:
                self.check_frame(self.initial_frame, action=0)
            self.request = None
            self.command = None
        except BaseException:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        self.workspace = self.output = None
        self.types.close()

    def packet(self, source):
        return transport([source, self.registry, self.origins, 0, 0, False, 0])

    def send(self, wire):
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        self.entry_count += 1
        size = self.images['admit']._entry(source, len(wire), self.output,
            OUTPUT_BYTES, self.workspace, WORKSPACE_BYTES)
        self.case.assertEqual(ctypes.string_at(source, len(wire)), wire)
        return size, struct.unpack_from('<8Q', self.output) if size == 64 else None

    def borrowed_entry(self, kernel, *, capacity=OUTPUT_BYTES):
        before = sha256(memoryview(self.types._state)).hexdigest()
        self.entry_count += 1
        size = self.images[kernel]._entry(self.types._state, SESSION_BYTES,
            self.output, capacity, self.workspace, WORKSPACE_BYTES)
        self.case.assertEqual(sha256(memoryview(self.types._state)).hexdigest(), before,
                              'native function kernel changed its borrowed type state')
        self.case.assertEqual(ctypes.string_at(ctypes.addressof(self.workspace) + SOURCE_BASE,
                                               len(self.wire)), self.wire)
        return size

    def check_frame(self, frame, *, action):
        self.case.assertEqual(frame[0], ADMIT_MAGIC)
        self.case.assertEqual(frame[1], action)
        self.case.assertEqual(frame[2], 0)
        self.case.assertEqual(frame[7], 0)

    def begin_request(self):
        self.case.assertEqual(self.initial_status, 64)
        size = self.borrowed_entry('admit')
        self.case.assertEqual(size, 64)
        frame = struct.unpack_from('<8Q', self.output)
        self.check_frame(frame, action=2)
        self.request = frame[6]
        self.case.assertEqual(self.request, 1)
        return frame

    def request_parameters(self):
        frame = self.begin_request()
        decoder = ObjectTokenDecoder(self.index)
        sequence = 0
        while not decoder.complete:
            size = self.borrowed_entry('render')
            self.case.assertGreaterEqual(size, 64)
            self.case.assertLessEqual(size, OUTPUT_BYTES)
            header = struct.unpack_from('<8Q', self.output)
            self.case.assertEqual(header[:3], (MAGIC, 2, sequence))
            self.case.assertIn(header[3], (0, 1))
            self.case.assertEqual(header[4:7], (frame[4], frame[5], self.request))
            self.case.assertEqual(header[7], size - 64)
            decoder.feed(ctypes.string_at(ctypes.addressof(self.output) + 64, size - 64),
                         final=bool(header[3]))
            sequence += 1
        self.command = decoder.root
        self.case.assertEqual(self.command, [2, document()['functions'][0]['params']])
        return self.command

    def valid_response(self):
        self.case.assertIsNotNone(self.command)
        params = self.types.parameters(self.command[1])
        identifiers = [self.types._ids[id(typ)] for _, typ in params]
        return (struct.pack('<4Q', ADMIT_RESPONSE_MAGIC, self.request, 0, len(identifiers))
                + b''.join(struct.pack('<Q', value) for value in identifiers))

    def assert_poisoned(self):
        self.case.assertNotEqual(struct.unpack_from('<Q', self.workspace, STATE + 96)[0], 0)

    def assert_followup_refused(self, valid_response):
        self.assert_poisoned()
        self.case.assertEqual(self.send(valid_response)[0], ABI)
        self.case.assertEqual(self.borrowed_entry('admit'), ABI)
        self.assert_poisoned()


@unittest.skipUnless(os.environ.get(BUNDLE) and os.environ.get(TYPES),
    'source-bound complete function/type development images required')
class NativeFunctionProtocolAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle = installed_composite_functions(os.environ[BUNDLE])
        cls.types_image = installed_composite_types(os.environ[TYPES])

    def harness(self, **kwargs):
        return _RawFunctionHarness(self, self.bundle.images, self.types_image, **kwargs)

    def test_malformed_response_poison_survives_a_valid_followup(self):
        for kind in ('sequence', 'status', 'zero_identifier', 'truncated'):
            with self.subTest(kind=kind), self.harness() as harness:
                harness.request_parameters()
                correct = harness.valid_response()
                changed = bytearray(correct)
                if kind == 'sequence':
                    struct.pack_into('<Q', changed, 8, harness.request + 1)
                elif kind == 'status':
                    struct.pack_into('<Q', changed, 16, 2)
                elif kind == 'zero_identifier':
                    struct.pack_into('<Q', changed, 32, 0)
                else:
                    changed = changed[:-1]
                self.assertEqual(harness.send(bytes(changed))[0], ABI)
                harness.assert_followup_refused(correct)

    def test_rejected_initializer_poison_prevents_reinitialization(self):
        invalid = document()
        invalid['schema'] = 'hepta.hia.composite.v999'
        with self.harness(initial_document=invalid) as harness:
            self.assertEqual(harness.initial_status, ABI)
            harness.assert_poisoned()
            self.assertEqual(harness.send(harness.packet(document()))[0], ABI)
            self.assertEqual(harness.borrowed_entry('admit'), ABI)
            harness.assert_poisoned()

    def test_response_replay_poison_prevents_the_original_resume(self):
        with self.harness() as harness:
            harness.request_parameters()
            response = harness.valid_response()
            size, frame = harness.send(response)
            self.assertEqual(size, 64)
            harness.check_frame(frame, action=0)
            self.assertEqual(harness.send(response)[0], ABI)
            harness.assert_followup_refused(response)

    def test_in_range_unissued_descriptor_poison_prevents_the_original_resume(self):
        with self.harness() as harness:
            harness.request_parameters()
            response = harness.valid_response()
            self.assertNotIn(144, harness.types._types)
            forged = response[:32] + struct.pack('<Q', 144)
            size, frame = harness.send(forged)
            # The narrow response framing admits a bounded ID. The following
            # actual type-state read must reject an ID never issued there.
            self.assertEqual(size, 64)
            harness.check_frame(frame, action=0)
            self.assertEqual(harness.borrowed_entry('admit'), ABI)
            harness.assert_followup_refused(response)

    def test_renderer_full_buffer_refusal_poison_is_shared_with_admission(self):
        # Establish the exact response in a separate successful native stream,
        # then close that workspace before allocating the negative control.
        with self.harness() as control:
            control.request_parameters()
            response = control.valid_response()
        with self.harness() as harness:
            harness.begin_request()
            self.assertEqual(struct.unpack_from('<Q', harness.workspace, STATE + 96)[0], 0)
            self.assertNotEqual(struct.unpack_from('<Q', harness.workspace, STATE + 32)[0], 0)
            self.assertEqual(struct.unpack_from('<Q', harness.workspace, STATE + 48)[0], 0)
            self.assertEqual(harness.borrowed_entry('render', capacity=63), ABI)
            harness.assert_followup_refused(response)
            self.assertEqual(harness.borrowed_entry('render'), ABI)


if __name__ == '__main__':
    unittest.main()
