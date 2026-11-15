"""Strict two-ABI executable-header controls; no executable is run."""
from __future__ import annotations
import struct
import unittest

from tools.qualify_hia_selfhost_cli import inspect_executable


def legacy():
    size = 177
    return (b'\x7fELF\x02\x01\x01' + bytes(9)
        + struct.pack('<HHIQQQIHHHHHH', 2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)
        + struct.pack('<II6Q',1,5,0,0x400000,0x400000,size,size,4096)
        + struct.pack('<II6Q',0x6474e551,6,0,0,0,0,0,16) + b'\xc3')


def publication():
    # Independent literal of the published HIADELIV v1 layout. Body bytes
    # are not executed; image/source custody is a separate original gate.
    size = 384
    prefix = (b'\x7fELF\x02\x01\x01' + bytes(9)
        + struct.pack('<HHIQQQIHHHHHH',2,62,1,0x400160,64,0,0,64,56,3,0,0,0)
        + struct.pack('<II6Q',1,5,0,0x400000,0x400000,size,size,4096)
        + struct.pack('<II6Q',0x6474e551,6,0,0,0,0,0,16)
        + struct.pack('<II6Q',4,4,232,0x4000e8,0x4000e8,120,120,4)
        + struct.pack('<III',9,96,1) + b'HIADELIV\0' + bytes(3)
        + struct.pack('<12Q',int.from_bytes(b'HIADCTL1','little'),1,
                      0x400160,0x400170,16,128,96,24,0,0,63,0))
    assert len(prefix) == 352
    return prefix + b'\x90' * 31 + b'\xc3'


class ExecutablePublicationAbiTests(unittest.TestCase):
    def test_original_two_segment_compiler_layout_remains_exact(self):
        raw = legacy()
        result = inspect_executable(raw)
        self.assertEqual(result['entry'], 0x4000b0)
        self.assertEqual(result['program_headers'], ['PT_LOAD_RX', 'PT_GNU_STACK_RW'])
        self.assertEqual(result['bytes'], len(raw))
        self.assertIsNone(result['interpreter'])
        self.assertFalse(result['dynamic_loader'])
        self.assertFalse(result['libc'])

    def test_explicit_three_segment_public_artifact_layout_is_complete(self):
        raw = publication()
        result = inspect_executable(raw)
        self.assertEqual(result['entry'], 0x400160)
        self.assertEqual(result['program_headers'],
                         ['PT_LOAD_RX','PT_GNU_STACK_RW','PT_NOTE_HIADELIV'])
        self.assertEqual(result['private_delivery_entry'], 0x400170)
        self.assertEqual(result['private_delivery_ack_bytes'], 128)
        self.assertEqual(result['private_delivery_prefix_bytes'], 16)
        self.assertEqual(result['bytes'], len(raw))
        self.assertIsNone(result['interpreter'])
        self.assertFalse(result['dynamic_loader'])
        self.assertFalse(result['libc'])

    def test_every_original_header_byte_remains_fail_closed(self):
        raw = legacy()
        for offset in range(176):
            with self.subTest(offset=offset):
                corrupt = bytearray(raw)
                corrupt[offset] ^= 1
                with self.assertRaises(ValueError):
                    inspect_executable(bytes(corrupt))
        for raw in (b'', legacy()[:176], legacy()+b'x'):
            with self.subTest(size=len(raw)):
                with self.assertRaises(ValueError):
                    inspect_executable(raw)

    def test_publication_capability_extent_and_private_entry_are_not_general_elf_acceptance(self):
        raw = publication()
        # Every fixed byte in the new 352-byte header is exact, except the
        # private-entry address which is intentionally an in-range descriptor
        # field. Its invalid boundaries and private ELF entry are tested below.
        variable_private_entry = range(280,288)
        for offset in range(352):
            if offset in variable_private_entry:
                continue
            with self.subTest(offset=offset):
                corrupt = bytearray(raw)
                corrupt[offset] ^= 1
                with self.assertRaises(ValueError):
                    inspect_executable(bytes(corrupt))
        for offset,value in ((24,0x400170),(280,0x400160),(280,0x400180),
                             (280,0),(56,2)):
            with self.subTest(offset=offset,value=value):
                corrupt = bytearray(raw)
                if offset == 56:
                    struct.pack_into('<H',corrupt,offset,value)
                else:
                    struct.pack_into('<Q',corrupt,offset,value)
                with self.assertRaises(ValueError):
                    inspect_executable(bytes(corrupt))
        for corrupt in (raw[:351], raw[:-1], raw+b'x'):
            with self.subTest(size=len(corrupt)):
                with self.assertRaises(ValueError):
                    inspect_executable(corrupt)
