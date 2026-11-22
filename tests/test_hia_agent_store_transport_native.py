"""Verify typed Store wire bytes against independent host protocol fixtures."""
import ctypes
import json
import os
import struct
import unittest

from hepta.hia_agent_store_native import _native_row, _parameter_cells, _parameters, _row, StoreProtocolError
from hepta.hia_agent_store_transport_native import selected_store_transport, SELECTOR


@unittest.skipUnless(os.environ.get(SELECTOR), 'requires the bound Store transport image')
class StoreTransportTests(unittest.TestCase):
    def setUp(self):
        self.codec = selected_store_transport()

    def test_command_matches_exact_existing_wire(self):
        for request, kind, target, size in [(1, 21, 0, 0), (2, 27, 1, 42),
                (3, 2, 0, 0), (4, 3, 0, 0), (1 << 38, 27, 3, 1 << 24)]:
            with self.subTest(kind=kind, request=request):
                self.assertEqual(self.codec.command(request, kind, target, size),
                                 struct.pack('<8s5Q', b'HIATCM01', 1, request, kind, target, size))
        self.assertIsNone(self.codec.command(0, 21, 0, 0))

    def test_ack_checks_the_complete_request_order_and_version(self):
        args = (7, 27)
        effects = (0, 13, 1 << 36, 0, (1 << 48) - 1, 8)
        frame = struct.pack('<8s9Q', b'HIATXR01', 1, *args, *effects)
        self.assertEqual(self.codec.acknowledgement(*args, frame), effects)
        for mutated in (frame[:-1], frame+b'\0', b'badMagic'+frame[8:],
                        frame[:8]+struct.pack('<Q', 2)+frame[16:]):
            with self.subTest(header=mutated[:16]):
                self.assertIsNone(self.codec.acknowledgement(*args, mutated))
        self.assertIsNone(self.codec.acknowledgement(8, 27, frame))
        self.assertIsNone(self.codec.acknowledgement(7, 3, frame))

    def test_row_header_bounds_size_not_logical_row_offset(self):
        fields = (2, 3, 110, 1 << 22, 128, 0, 0)
        frame = struct.pack('<8s7Q', b'HIAQRF01', *fields)
        self.assertEqual(self.codec.query_header(3, 128, frame), fields)
        self.assertIsNone(self.codec.query_header(4, 128, frame))
        self.assertIsNone(self.codec.query_header(3, 127, frame))
        dirty = frame[:-8]+struct.pack('<Q', 1)
        self.assertIsNone(self.codec.query_header(3, 128, dirty))

    def test_query_continuation_orders_rows_and_terminal_summary(self):
        def event(kind, row=9, offset=0, payload=b'', **changes):
            state = dict(pending_id=None, pending_size=None, limit=1024,
                         rows=0, unique=False, plan=12, mask=63)
            return self.codec.query_event(kind, row, offset, payload, **{**state, **changes})

        self.assertEqual(event(1, payload=bytes(128)), (1, 0))
        retained = dict(pending_size=20, pending_id=9)
        self.assertEqual(event(2, offset=20, payload=b'abc', **retained), (2, 0))
        self.assertEqual(event(2, row=10, offset=20, payload=b'abc', **retained), (104, 0))
        self.assertEqual(event(2, offset=19, payload=b'abc', **retained), (104, 0))
        self.assertEqual(event(2, offset=20, **retained), (101, 0))
        self.assertEqual(event(2, offset=20, payload=b'abc', limit=22, **retained), (101, 0))
        self.assertEqual(event(3, offset=20, **retained), (3, 0))
        self.assertEqual(event(3, offset=20, unique=True, rows=1, **retained), (102, 0))

        summary = bytes(384) + struct.pack('<4Q', 12, 63, 1 << 37, 1)
        self.assertEqual(event(4, payload=summary, rows=1), (4, 1 << 37))
        self.assertEqual(event(4, payload=summary, rows=2), (103, 0))
        self.assertEqual(event(4, payload=summary, rows=1, plan=11), (103, 0))
        self.assertEqual(event(4, payload=summary, rows=1, mask=31), (103, 0))
        self.assertEqual(event(4, payload=summary, rows=1, **retained), (104, 0))

    def test_native_values_preserve_typed_cells_and_wire_error_order(self):
        cells = [(0, b''), (1, struct.pack('<q', -27)), (2, struct.pack('<d', -1.25)),
                 (3, '中文'.encode()), (4, b'\0\xff')]
        header = struct.pack('<8s3Q', b'HIAROW01', 1, 4, len(cells))
        prefix = len(header) + len(cells) * 24
        directory = bytearray()
        payload = bytearray()
        for kind, value in cells:
            directory.extend(struct.pack('<3Q', kind, prefix + len(payload), len(value)))
            payload.extend(value)
        record = bytearray(header + directory + payload)
        expected = [None, -27, -1.25, '中文', b'\0\xff']
        self.assertEqual(_row(record, 4, 5), expected)
        self.assertEqual(_native_row(self.codec, record, 4, 5), expected)

        wrong_type = bytearray(record)
        struct.pack_into('<Q', wrong_type, 32 + 24 * 4, 11)
        invalid_utf8 = bytearray(wrong_type)
        invalid_utf8[prefix + 16] = 255
        for data, table, columns in [(record[:31], 4, 5), (record[:36], 4, 5),
                                     (record, 5, 5), (record, 4, 4), (record[:-1], 4, 5),
                                     (record + b'x', 4, 5), (wrong_type, 4, 5),
                                     (invalid_utf8, 4, 5)]:
            with self.subTest(table=table, columns=columns, length=len(data)):
                with self.assertRaises((StoreProtocolError, UnicodeDecodeError)) as reference:
                    _row(data, table, columns)
                with self.assertRaises(type(reference.exception)) as native:
                    _native_row(self.codec, data, table, columns)
                self.assertEqual(str(native.exception), str(reference.exception))

    def test_transaction_requires_exact_durable_generation_and_matching_anchor(self):
        transaction = self.codec.transaction
        generation = (1 << 40) + 5
        receipt = (b'HIAWTA01' + bytes(120) +
                   struct.pack('<8s2Q', b'HIAWAK01', 1, generation) + bytes(104))
        self.assertEqual(len(receipt), 256)
        self.assertEqual(transaction(0, 0, 0, 0, generation), (1, generation))
        self.assertEqual(transaction(21, 0, 0, generation - 1, generation), (1, generation))
        self.assertEqual(transaction(21, 0, 0, generation + 1, generation), (2, 0))
        self.assertEqual(transaction(2, 0, 17, generation - 1, generation, receipt), (1, generation))
        self.assertEqual(transaction(2, 0, 0, generation, generation), (1, generation))
        self.assertEqual(transaction(3, 0, 17, generation, generation), (1, generation))
        for kind, count, previous, observed, wire in [
                (2, 1, generation - 1, generation, b''),
                (2, 0, generation, generation, receipt),
                (2, 9, generation - 2, generation, receipt),
                (2, 1, (1 << 64) - 1, 0, receipt),
                (3, 9, generation - 1, generation, receipt)]:
            with self.subTest(kind=kind, previous=previous, observed=observed):
                self.assertEqual(transaction(kind, 0, count, previous, observed, wire), (3, 0))
        self.assertEqual(transaction(2, 9, 17, generation - 1, generation, receipt), (3, 0))
        invalid_anchor = receipt[:128] + b'badmagic' + receipt[136:]
        self.assertEqual(transaction(2, 0, 1, generation - 1, generation, invalid_anchor), (4, 0))

    def test_parameters_match_query_insert_and_update_frames_exactly(self):
        for values in ((), (None, -(1 << 63), 1.5, '汉字\0', b'\xff\0'), (b'', '')):
            cells = tuple(_parameter_cells(values))
            for form in (None, b'HIAINS01', b'HIAUPB01'):
                with self.subTest(values=values, form=form):
                    expected = _parameters(values, 17, form)
                    self.assertEqual(self.codec.parameters(17, form, cells, len(expected)), expected)
                    self.assertIsNone(self.codec.parameters(17, form, cells, len(expected) - 1))
        self.assertIsNone(self.codec.parameters(1, b'badmagic', (), 128))
        self.assertIsNone(self.codec.parameters(1, None, ((1, b'not eight'),), 128))
        self.assertIsNone(self.codec.parameters(1, None, ((5, b''),), 128))

    def test_large_artifact_insert_carries_sealed_input_instead_of_copying_to_state(self):
        metadata = json.dumps({
            "candidate": {}, "codegen": {}, "context": {}, "core_sha256": "a" * 64,
            "foreign_buffer_exports": [], "installation": {},
            "machine_plan": {"block_order": {"entry": [f"block_{index}" for index in range(240)]}},
            "object_artifact": {}, "object_sha256": "b" * 64, "output_kind": "object",
            "signatures": {},
        }, separators=(",", ":"), sort_keys=True)
        values = ("a-" + "1" * 32, "2" * 64, "hia://artifacts/" + "3" * 32,
                  "native", metadata, "4" * 64)
        parameters = _parameters(values, 9, b"HIAINS01")
        state = ctypes.create_string_buffer(2304)
        frame = struct.pack("<8s5Q", b"HIASTUP1", 1, 20, 2, 5, len(parameters)) + parameters
        output = ctypes.create_string_buffer(8160)
        self.assertGreater(len(parameters), len(state) - 192)
        count = self.codec._entry(frame, len(frame), output, len(output), state, len(state))
        self.assertEqual(count, 80)
        self.assertEqual(struct.unpack("<4Q", output.raw[:32]), (7, len(parameters), 48, 0))
        self.assertEqual(struct.unpack("<8s5Q", output.raw[32:80]),
                         (b"HIATCM01", 1, 2, 27, 1, len(parameters)))
        self.assertEqual(state.raw[192:], bytes(len(state) - 192))
