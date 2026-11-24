"""Safe proof template and embedded-role table checks against retained byte rules."""
from hashlib import sha256
import os
from pathlib import Path
import struct
import subprocess
import unittest

from tests.test_hia_release_core_checks import flat
from tests.test_hia_release_member_check import binding_source, check_packet
from tools.build_hia_supplied_safe_core_proof import check_placement
from tools.generate_hia_core_admission_cli import STATE_BYTES, ARENA_BYTES
from tools.generate_hia_native_filter import elf_header, template, verify_adapter


def builtin_fixture(images, prefix, absolute):
    binary = bytearray(prefix + b''.join(images))
    struct.pack_into('<2Q', binary, 96, len(binary), len(binary))
    entries = (0, len(images[0]))
    for hole, entry in zip(absolute, entries, strict=True):
        struct.pack_into('<i', binary, hole, len(prefix) + entry - hole - 4)
    binding = (sha256(prefix[176:]).digest(), len(prefix) - 176,
               tuple(hole - 176 for hole in absolute))
    verify_adapter(bytes(binary), b''.join(images), binding, entries=entries)
    return [bytes(binary), prefix, struct.pack('<2Q', *absolute), *images]


def outer_fixture(size=128):
    source = b'source-pinned expanded outer proof adapter\n'
    holes = (10, 30, 40)
    stub = bytearray(b'\x90' * size)
    for hole in holes[:2]:
        stub[hole - 1] = 0xe8
        stub[hole:hole + 4] = bytes(4)
    table = holes[2]
    stub[table:table + 80] = bytes(80)
    images = [bytes((i + 1,)) * extent for i, extent in enumerate((1, 5, 9, 2, 17, 3, 16))]
    starts, body = [], bytearray()
    for image in images:
        body.extend(bytes(-(size + len(body)) % 8))
        starts.append(len(body))
        body.extend(image)
    patched = bytearray(stub)
    for hole, entry in zip(holes[:2], starts[:2], strict=True):
        struct.pack_into('<i', patched, hole, size + entry - hole - 4)
    for i, (offset, image) in enumerate(zip(starts[2:], images[2:], strict=True)):
        struct.pack_into('<2Q', patched, table + 16 * i, size + offset - table, len(image))
    binary = flat(patched + body)
    binding = (sha256(stub).digest(), size, holes)
    check_placement(binary, binding, images)
    return [binary, binding_source(source, stub, holes), source, *images], binding


@unittest.skipUnless(os.environ.get('HIA_TEST_RELEASE_STAGE_PLANNER'),
                     'requires an actual source-compiled native HIA checker')
class ReleaseSafeNativeChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prefix, cls.absolute = template(output_bytes=STATE_BYTES, workspace_bytes=ARENA_BYTES,
                                            formatter=True)

    def accepted(self, mode, calls, parts):
        p = subprocess.run([os.environ['HIA_TEST_RELEASE_STAGE_PLANNER'], 'build'],
                           input=check_packet(mode, calls, parts), capture_output=True,
                           env={'PATH': ''}, timeout=30)
        self.assertEqual(p.stderr, b'')
        if p.returncode:
            self.assertEqual(p.stdout, b'')
            return False
        self.assertEqual(p.stdout, struct.pack('<8s3Q', b'HIASTOK1', mode, calls, len(parts[0])))
        return True

    def test_builtin_real_declared_template_matches_retained_adapter_rule(self):
        self.assertEqual(len(self.prefix), 544)
        self.assertEqual(self.absolute, (338, 393))
        self.assertEqual(sha256(self.prefix[176:]).hexdigest(),
                         'ba7ae50495ce23b706d344c0f59bb607e5169e445b678f1f3778a3ffbb534ff6')
        for first_size, second_size in ((1, 1), (7, 13), (64, 65), (129, 1)):
            parts = builtin_fixture((b'\xc3' * first_size, b'\x90' * second_size),
                                    self.prefix, self.absolute)
            self.assertTrue(self.accepted(11, 2, parts))
            for offset in (16, 337, 338, 392, 393, 543, len(parts[0]) - 1):
                bad = list(parts); raw = bytearray(parts[0]); raw[offset] ^= 1
                bad[0] = bytes(raw)
                self.assertFalse(self.accepted(11, 2, bad), offset)
            for index in (1, 2, 3, 4):
                bad = list(parts); bad[index] += b'x'
                self.assertFalse(self.accepted(11, 2, bad), index)
            self.assertFalse(self.accepted(11, 3, parts))

    def test_outer_seven_sections_and_all_five_role_boundaries_match_old_rule(self):
        for size in (128, 129, 135, 136, 151, 256):
            parts, binding = outer_fixture(size)
            self.assertTrue(self.accepted(10, 3, parts))
            for offset in (176 + binding[2][2] + i * 8 for i in range(10)):
                bad = list(parts); raw = bytearray(parts[0]); raw[offset] ^= 1
                bad[0] = bytes(raw)
                with self.assertRaises(ValueError):
                    check_placement(bad[0], binding, bad[3:])
                self.assertFalse(self.accepted(10, 3, bad), offset)
            for offset in (16, 176 + 9, 176 + 10, 176 + 30, 176 + size - 1,
                           176 + size + ((-size) & 7) + 1, len(parts[0]) - 1):
                bad = list(parts); raw = bytearray(parts[0]); raw[offset] ^= 1
                bad[0] = bytes(raw)
                self.assertFalse(self.accepted(10, 3, bad), offset)
            # The checker consumes the admitted adapter_binding declaration;
            # whole-source syntax is enforced by the source compiler upstream.
            # Corrupt the binding itself instead of unrelated trailing source.
            bad = list(parts); bad[1] = binding_source(parts[2], b'wrong stub', binding[2])
            self.assertFalse(self.accepted(10, 3, bad))
            for index in range(2, 10):
                bad = list(parts); bad[index] += b'x'
                self.assertFalse(self.accepted(10, 3, bad), index)
            self.assertFalse(self.accepted(10, 2, parts))
            self.assertFalse(self.accepted(10, 3, parts[:-1]))


if __name__ == '__main__':
    unittest.main()
