"""Native Core placement/archive/writable checks against independent retained rules."""
from hashlib import sha256
import os
from pathlib import Path
import struct
import subprocess
import unittest

from tests.test_hia_release_member_check import check_packet, pager_fixture
from tools.build_hia_core_edit import ADAPTER_RECORD, EXEC_ARCHIVE_MAGIC, PROGRAMS, check_placement
from tools.generate_hia_native_filter import elf_header


def flat(payload):
    header = bytearray(elf_header())
    struct.pack_into('<2Q', header, 96, len(header) + len(payload), len(header) + len(payload))
    return bytes(header) + payload


def placement_fixture(stub, holes, images, source=b'actual expanded adapter source\n'):
    # This is an independent input fixture for a byte checker, not a claim
    # that a compiler or production release was executed by the fixture.
    body = bytearray(stub)
    for index, image in enumerate(images):
        body.extend(bytes(-len(body) % 8))
        for hole, target in holes:
            if target == index:
                struct.pack_into('<i', body, hole, len(body) - hole - 4)
        body.extend(image)
    binary = flat(body)
    check_placement(binary, stub, holes, images)
    record = ADAPTER_RECORD.pack(sha256(source).digest(), sha256(stub).digest(),
                                 sha256(b'recorded object identity').digest(), len(stub), len(holes))
    record += struct.pack('<' + 'Q' * len(holes), *(hole for hole, _ in holes)) + stub
    targets = struct.pack('<' + 'Q' * len(holes), *(target for _, target in holes))
    return [binary, source, record, targets, *images]


@unittest.skipUnless(os.environ.get('HIA_TEST_RELEASE_STAGE_PLANNER'),
                     'requires the actual source-compiled native HIA checker')
class ReleaseCoreNativeChecks(unittest.TestCase):
    def accepted(self, mode, calls, parts):
        p = subprocess.run([os.environ['HIA_TEST_RELEASE_STAGE_PLANNER'], 'build'],
                           input=check_packet(mode, calls, parts), capture_output=True,
                           env={'PATH': ''}, timeout=60)
        self.assertEqual(p.stderr, b'')
        if p.returncode:
            self.assertEqual(p.stdout, b'')
            return False
        self.assertEqual(p.stdout, struct.pack('<8s3Q', b'HIASTOK1', mode, calls, len(parts[0])))
        return True

    def test_section_order_alignment_repeated_targets_and_overlapping_relocations(self):
        for size in (16, 17, 23, 24, 31, 64):
            for holes in (((1, 0), (9, 1)), ((8, 1), (9, 0)),
                          ((8, 0), (9, 1)), ((8, 1), (8, 0)), ((8, 0), (8, 1))):
                with self.subTest(size=size, holes=holes):
                    parts = placement_fixture(bytes(range(size)), holes, [b'first', b'second-section'])
                    self.assertTrue(self.accepted(7, len(holes), parts))
                    bad = list(parts)
                    value = bytearray(bad[0]); value[176 + 8] ^= 1
                    bad[0] = bytes(value)
                    self.assertFalse(self.accepted(7, len(holes), bad))
        self.assertTrue(self.accepted(7, 0, placement_fixture(b'\xc3', (), ())))
        self.assertTrue(self.accepted(7, 0, placement_fixture(b'\xc3', (), (b'', b'part'))))

    def test_record_source_stub_targets_and_exact_elf_extents_are_bound(self):
        parts = placement_fixture(b'\x90' * 19, ((1, 0), (9, 1)), [b'first', b'second'])
        for index in (0, 1, 2, 3, 4, 5):
            changed = list(parts)
            changed[index] += b'x'
            self.assertFalse(self.accepted(7, 2, changed), index)
        for offset in (0, 32, 96, 104, 112, 120):
            changed = list(parts); record = bytearray(parts[2]); record[offset] ^= 1
            changed[2] = bytes(record)
            self.assertFalse(self.accepted(7, 2, changed), offset)
        changed = list(parts); changed[3] = struct.pack('<2Q', 0, 2)
        self.assertFalse(self.accepted(7, 2, changed))
        changed = list(parts); binary = bytearray(parts[0]); binary[16] ^= 1
        changed[0] = bytes(binary)
        self.assertFalse(self.accepted(7, 2, changed))
        # Object SHA is recorded by the old producer, never an authority check.
        changed = list(parts); record = bytearray(parts[2]); record[64] ^= 1
        changed[2] = bytes(record)
        self.assertTrue(self.accepted(7, 2, changed))
        self.assertFalse(self.accepted(7, 1, parts))

    def test_archive_count_is_exact_and_requires_a_complete_elf_envelope(self):
        for count in (0, 1, 2, 5):
            binary = flat(b'code' + EXEC_ARCHIVE_MAGIC * count + b'payload')
            self.assertTrue(self.accepted(8, count, [binary]))
            self.assertFalse(self.accepted(8, count + 1, [binary]))
            if count:
                self.assertFalse(self.accepted(8, count - 1, [binary]))
            self.assertFalse(self.accepted(8, count, [binary + b'x']))
        binary, _ = pager_fixture(EXEC_ARCHIVE_MAGIC * 2)
        self.assertTrue(self.accepted(8, 2, [binary]))

    def test_writable_tail_keeps_full_geometry_and_rejects_any_nonzero_byte(self):
        binary, _ = pager_fixture()
        self.assertTrue(self.accepted(9, 0, [binary]))
        offset, = struct.unpack_from('<Q', binary, 128)
        for at in (offset, len(binary) - 1):
            changed = bytearray(binary); changed[at] = 1
            self.assertFalse(self.accepted(9, 0, [bytes(changed)]))
        for at in (16, 56, 64, 96, 104, 120, 128, 136, 144, 152, 168, 176):
            changed = bytearray(binary); changed[at] ^= 1
            self.assertFalse(self.accepted(9, 0, [bytes(changed)]), at)
        changed = bytearray(binary); changed[280] ^= 1
        self.assertTrue(self.accepted(9, 0, [bytes(changed)]))
        changed = bytearray(binary)
        struct.pack_into('<Q', changed, 160, len(binary) - offset - 1)
        self.assertFalse(self.accepted(9, 0, [bytes(changed)]))
        struct.pack_into('<Q', changed, 160, len(binary) - offset + 1)
        self.assertTrue(self.accepted(9, 0, [bytes(changed)]))
        self.assertFalse(self.accepted(9, 1, [binary]))
        self.assertFalse(self.accepted(9, 0, [flat(b'code')]))

    @unittest.skipUnless(os.environ.get('HIA_TEST_CORE_REFERENCE_STORE'),
                         'requires retained actual native Core products')
    def test_actual_native_core_archive_counts_and_linked_writable_regions(self):
        store = Path(os.environ['HIA_TEST_CORE_REFERENCE_STORE'])
        counts = {'archive': 0, 'writable': 0}
        for name, _ in PROGRAMS.values():
            path = store / name
            if not path.is_file():
                continue
            raw = path.read_bytes()
            expected = raw.count(EXEC_ARCHIVE_MAGIC)
            self.assertTrue(self.accepted(8, expected, [raw]), name)
            counts['archive'] += 1
            if struct.unpack_from('<H', raw, 56)[0] == 3:
                offset, = struct.unpack_from('<Q', raw, 128)
                self.assertEqual(self.accepted(9, 0, [raw]), not any(raw[offset:]), name)
                counts['writable'] += 1
        # Published Core products are two-PHDR packed launchers; their inner
        # linked images use the same native static linker geometry as this
        # retained source-built pager. Do not pretend its outer wrapper is a
        # three-PHDR writable image.
        linked = (store / 'hia-sqlite-pager').read_bytes()
        self.assertEqual(struct.unpack_from('<H', linked, 56)[0], 3)
        offset, = struct.unpack_from('<Q', linked, 128)
        self.assertEqual(self.accepted(9, 0, [linked]), not any(linked[offset:]))
        counts['writable'] += 1
        self.assertGreater(counts['archive'], 0)
        self.assertGreater(counts['writable'], 0)


if __name__ == '__main__':
    unittest.main()
