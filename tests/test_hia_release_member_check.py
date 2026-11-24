"""Differential tests for native release ELF and source-bound adapter checks."""
from hashlib import sha256
import os
from pathlib import Path
import struct
import subprocess
import unittest

from hepta.hia_agent_assembly import render_assembly
from tools.build_hia_agent_batch_commit import verify_placement
from tools.build_hia_sqlite_pager import verify_executable
from tools.generate_hia_native_filter import (
    _binding_declaration, elf_header, read_adapter_binding, verify_adapter,
)

ROOT = Path(__file__).resolve().parents[1]


def binding_source(source, stub, holes):
    raw = sha256(source).digest() + sha256(stub).digest()
    raw += struct.pack('<' + 'Q' * (1 + len(holes)), len(stub), *holes)
    words = struct.unpack('<' + 'Q' * (9 + len(holes)), raw)
    return render_assembly({'schema': 'hepta.hia.program.v8', 'module': 'binding_fixture',
                            'functions': [_binding_declaration(words)]}).encode('ascii')


def adapter_fixture(code=b'first-image-body-and-second-entry', entries=(0, 5),
                    instructions=(b'\xe8', b'\xe8'), source=b'fixed adapter source\n', size=64):
    holes = (10, 30)
    stub = bytearray(b'\x90' * size)
    for hole, instruction in zip(holes, instructions, strict=True):
        stub[hole - len(instruction):hole] = instruction
        stub[hole:hole + 4] = bytes(4)
    packer = binding_source(source, stub, holes)
    linked = bytearray(stub)
    for hole, entry in zip(holes, entries, strict=True):
        struct.pack_into('<i', linked, hole, size + entry - hole - 4)
    header = bytearray(elf_header())
    struct.pack_into('<2Q', header, 96, len(header) + size + len(code), len(header) + size + len(code))
    return bytes(header + linked + code), code, packer, source


def instruction_packet(instructions):
    return b''.join(struct.pack('<Q', len(raw)) + raw for raw in instructions)


def check_packet(mode, calls, pieces):
    return (struct.pack('<8s4Q', b'HIASTC01', mode, calls, len(pieces), 0)
            + b''.join(struct.pack('<Q', len(part)) + part for part in pieces))


def adapter_pieces(fixture, entries=(0, 5), instructions=(b'\xe8', b'\xe8')):
    binary, code, packer, source = fixture
    return [binary, code, packer, source, struct.pack('<' + 'Q' * len(entries), *entries),
            instruction_packet(instructions)]


def pager_fixture(image=b'actual-compiled-HIA-image'):
    rx_size, rw_offset, rw_size = 512, 4096, 64
    ident = b'\x7fELF\x02\x01\x01' + bytes(9)
    data = bytearray(ident + struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0x400000 + 232,
                                      64, 0, 0, 64, 56, 3, 0, 0, 0)
                     + struct.pack('<II6Q', 1, 5, 0, 0x400000, 0x400000, rx_size, rx_size, 4096)
                     + struct.pack('<II6Q', 1, 6, rw_offset, 0x400000 + rw_offset,
                                   0x400000 + rw_offset, rw_size, rw_size, 4096)
                     + struct.pack('<II6Q', 0x6474e551, 6, 0, 0, 0, 0, 0, 16))
    data.extend(bytes(rw_offset + rw_size - len(data)))
    data[280:280 + len(image)] = image
    return bytes(data), image


@unittest.skipUnless(os.environ.get('HIA_TEST_RELEASE_STAGE_PLANNER'),
                     'requires the source-compiled native stage planner/checker')
class ReleaseMemberNativeChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.planner = Path(os.environ['HIA_TEST_RELEASE_STAGE_PLANNER']).resolve()

    def invoke(self, mode, calls, pieces, *, accepted=True):
        p = subprocess.run([str(self.planner), 'build'], input=check_packet(mode, calls, pieces),
                           capture_output=True, env={'PATH': ''}, timeout=30)
        self.assertEqual(p.stderr, b'')
        if accepted:
            self.assertEqual(p.returncode, 0)
            self.assertEqual(p.stdout, struct.pack('<8s3Q', b'HIASTOK1', mode, calls, len(pieces[0])))
        else:
            self.assertNotEqual(p.returncode, 0)
            self.assertEqual(p.stdout, b'')

    def assert_adapter_result(self, pieces, *, accepted):
        binary, code, packer, source, raw_entries, raw_instructions = pieces
        entries = struct.unpack('<' + 'Q' * (len(raw_entries) // 8), raw_entries)
        at, instructions = 0, []
        while at < len(raw_instructions):
            n, = struct.unpack_from('<Q', raw_instructions, at)
            at += 8
            instructions.append(raw_instructions[at:at + n])
            at += n
        def original():
            binding = read_adapter_binding(packer, source, calls=len(entries))
            verify_adapter(binary, code, binding, entries=entries, instructions=instructions)
        if accepted:
            original()
        else:
            with self.assertRaises((ValueError, KeyError, struct.error)):
                original()
        self.invoke(2, len(entries), pieces, accepted=accepted)

    def test_source_hash_padding_and_zeroed_relocation_digest_match_original(self):
        for n in (0, 1, 55, 56, 63, 64, 65, 128, 257):
            with self.subTest(source_bytes=n):
                fixture = adapter_fixture(source=bytes((i * 37) & 255 for i in range(n)))
                self.assert_adapter_result(adapter_pieces(fixture), accepted=True)

    def test_changed_envelope_image_opcode_displacement_and_adapter_are_rejected(self):
        original = adapter_pieces(adapter_fixture())
        for offset in (0, 24, 68, 96, 104, 176 + 9, 176 + 10, 176 + 40, len(original[0]) - 1):
            pieces = list(original)
            binary = bytearray(pieces[0])
            binary[offset] ^= 1
            pieces[0] = bytes(binary)
            with self.subTest(binary_offset=offset):
                self.assert_adapter_result(pieces, accepted=False)
        pieces = list(original)
        pieces[3] += b'mutated'
        self.assert_adapter_result(pieces, accepted=False)
        pieces = list(original)
        pieces[2] = pieces[2].replace(b'word0:u64', b'wrong0:u64', 1)
        self.assert_adapter_result(pieces, accepted=False)

    def test_overlapping_relocations_preserve_the_original_clear_order(self):
        holes, size = (10, 13), 64
        stub = bytearray(b'\x90' * size)
        stub[9] = 0xe8
        stub[10:17] = bytes(7)
        source = b'overlapping relocation fixture'
        packer = binding_source(source, stub, holes)
        body = bytearray(stub)
        struct.pack_into('<I', body, 10, 0x00e80000)
        struct.pack_into('<I', body, 13, 256)
        code = b'x'
        header = bytearray(elf_header())
        struct.pack_into('<2Q', header, 96, 176 + size + 1, 176 + size + 1)
        entries = (0x00e80000 - (size - 10 - 4), 256 - (size - 13 - 4))
        fixture = bytes(header + body + code), code, packer, source
        self.assert_adapter_result(adapter_pieces(fixture, entries=entries), accepted=False)

    def test_alignment_placement_and_instruction_bytes_match_original(self):
        parts = {'a': b'abc', 'b': b'next-image'}
        code = parts['a'] + bytes(5) + parts['b']
        binary, _, packer, source = adapter_fixture(code, entries=(0, 8),
                                                   instructions=(b'\xe9', b'\xe8'))
        binding = read_adapter_binding(packer, source, calls=2)
        verify_placement(binary, binding, parts, instructions=(b'\xe9', b'\xe8'))
        pieces = [binary, packer, source, instruction_packet((b'\xe9', b'\xe8')), *parts.values()]
        self.invoke(3, 2, pieces)
        damaged = bytearray(binary)
        damaged[176 + 64 + 3] = 1
        with self.assertRaises(ValueError):
            verify_placement(bytes(damaged), binding, parts, instructions=(b'\xe9', b'\xe8'))
        self.invoke(3, 2, [bytes(damaged), *pieces[1:]], accepted=False)

    def test_private_entry_is_derived_from_the_second_real_displacement(self):
        code = b'first-entry--' + bytes.fromhex('f7c2ff0100007409') + b'private-entry-body'
        fixture = adapter_fixture(code, entries=(0, 13))
        self.assert_adapter_result(adapter_pieces(fixture, entries=(0, 13)), accepted=True)
        self.invoke(4, 2, list(fixture))
        bad_code = code[:13] + b'FAILURE!' + code[21:]
        bad = adapter_fixture(bad_code, entries=(0, 13))
        self.assert_adapter_result(adapter_pieces(bad, entries=(0, 13)), accepted=True)
        self.invoke(4, 2, list(bad), accepted=False)

    def test_private_entry_requires_every_current_bounded_recursion_guard_byte(self):
        guard = bytes.fromhex('f7c2ff0100007409')
        for offset in range(len(guard)):
            changed = bytearray(guard)
            changed[offset] ^= 1
            fixture = adapter_fixture(b'first-entry--' + changed + b'private-entry-body', entries=(0, 13))
            self.assert_adapter_result(adapter_pieces(fixture, entries=(0, 13)), accepted=True)
            with self.subTest(guard_offset=offset):
                self.invoke(4, 2, list(fixture), accepted=False)
        for prefix in (bytes.fromhex('554889e5'), *[guard[:n] for n in range(8)]):
            fixture = adapter_fixture(b'first-entry--' + prefix, entries=(0, 13))
            self.assert_adapter_result(adapter_pieces(fixture, entries=(0, 13)), accepted=True)
            with self.subTest(stale_or_truncated_guard=prefix.hex()):
                self.invoke(4, 2, list(fixture), accepted=False)

    def test_pager_headers_extents_permissions_and_unique_image_match_original(self):
        binary, image = pager_fixture()
        verify_executable(binary, image)
        self.invoke(1, 0, [binary, image])
        for offset in (0, 16, 24, 32, 56, 68, 96, 104, 124, 128, 136, 152, 160, 184):
            damaged = bytearray(binary)
            damaged[offset] ^= 1
            # Some one-bit changes still satisfy the retained relational bound
            # (e.g. a larger RW memory extent). Compare the actual old oracle.
            try:
                verify_executable(bytes(damaged), image)
                accepted = True
            except ValueError:
                accepted = False
            with self.subTest(offset=offset, accepted=accepted):
                self.invoke(1, 0, [bytes(damaged), image], accepted=accepted)
        damaged = bytearray(binary)
        damaged[340:340 + len(image)] = image
        with self.assertRaises(ValueError):
            verify_executable(bytes(damaged), image)
        self.invoke(1, 0, [bytes(damaged), image], accepted=False)

    def test_pager_occurrence_uses_the_original_nonoverlapping_count(self):
        binary, image = pager_fixture(b'AAA')
        binary = bytearray(binary)
        binary[283] = ord('A')
        verify_executable(bytes(binary), image)
        self.invoke(1, 0, [bytes(binary), image])

    def test_bad_checker_shape_fails_before_any_receipt(self):
        pieces = adapter_pieces(adapter_fixture())
        self.invoke(2, 1, pieces, accepted=False)
        self.invoke(3, 2, pieces[:5], accepted=False)
        self.invoke(4, 1, list(adapter_fixture()), accepted=False)
        self.invoke(1, 1, list(pager_fixture()), accepted=False)


@unittest.skipUnless(os.environ.get('HIA_TEST_RELEASE_STAGE_PLANNER')
                     and os.environ.get('HIA_TEST_NATIVE_SOURCE_SEED'),
                     'requires the native checker and source build seed')
class ReleaseMemberRealConsumerChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.test_hia_release_stage_plan import ReleaseStageConsumerTests
        ReleaseStageConsumerTests.setUpClass.__func__(cls)

    from tests.test_hia_release_stage_plan import ReleaseStageConsumerTests as _Consumer
    native = _Consumer.native
    compile = _Consumer.compile
    kit = _Consumer.kit
    invoke = ReleaseMemberNativeChecks.invoke

    def test_source_built_direct_call_member_passes_both_original_and_hia_checks(self):
        from tools.build_hia_direct_call import ROLES
        from tools.build_hia_source_build import _named_source_request
        from tools.build_hia_native_store_release import _member_with_object
        source_path, packer_path, adapter_path, _, _ = ROLES['direct-call']
        owner, _ = self.kit('source_filter_member.hepta',
                            packer_path.removeprefix('examples/hia_bootstrap/'))
        source = (ROOT / source_path).read_bytes()
        wire = _named_source_request({'hia-direct-call.hepta': source}, tag=b'HIAIMG01')
        binary, code = _member_with_object(self.native(owner, 'build', wire))
        packer, adapter = (ROOT / packer_path).read_bytes(), (ROOT / adapter_path).read_bytes()
        binding = read_adapter_binding(packer, adapter, calls=1)
        verify_adapter(binary, code, binding, entries=(0,))
        self.invoke(2, 1, [binary, code, packer, adapter, struct.pack('<Q', 0),
                           instruction_packet((b'\xe8',))])


if __name__ == '__main__':
    unittest.main()
