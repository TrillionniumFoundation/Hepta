"""Verify typed Store wire bytes against independent host protocol fixtures."""
import os
import struct
import unittest

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
