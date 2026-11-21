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
