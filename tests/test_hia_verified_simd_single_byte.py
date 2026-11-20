"""A checked scalar entry for one-byte wide reductions, retaining prior profiles."""
from __future__ import annotations

import ctypes
from hashlib import sha256
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_safe_core_elf import _ELF, SafeCoreELFRejected
from hepta.hia_verified_cpu import VerifiedCPURejected, probe_host_isa
from hepta.hia_verified_kernel import build_verified_kernel
from hepta.hia_verified_kernel_load import load_verified_simd_kernel
from hepta.hia_verified_simd import emit_verified_simd, simd_kernel_program
from hepta.hia_verified_simd_check import (
    BOUNDED_ONE_REDUCTION_PROFILES, VerifiedSIMDRejected, decode_simd,
    validate_verified_simd_artifact,
)
from tests import test_hia_verified_simd as legacy
from tests import test_hia_verified_simd_refined as refined
from tests.test_hia_verified_simd_wide import REQUIREMENTS


OLD_BOUNDED_OBJECTS = {
    ('avx2', 'sum_u8'): 'e2ec45aaeb790081466cbd847a11f6aade5fbc198a808054da70fe346b3e4aa0',
    ('avx2', 'all_zero_u8'): '42416ae2b94d5ff7b7adbcaca1554ff5d5770b70198e7aa014e6f9a1407226b0',
    ('avx512', 'sum_u8'): '6d8b8012fcdc93c60a17a8e4ea1c5208c00a8a8b5ada3041fb2bcf1125e825c2',
    ('avx512', 'all_zero_u8'): 'b8282f63772485fa30f53c0e1aeef5ec7b8ae2df123af6138774ba8484bb45f6',
}


class SingleByteReductionDecoderTests(unittest.TestCase):
    def test_plain_rdi_byte_load_decodes_width_base_and_destination(self):
        for register in range(8):
            raw = bytes((0x48, 0x0f, 0xb6, (register << 3) | 7))
            rows = decode_simd(raw)
            self.assertEqual([(r.op, r.args, r.size) for r in rows], [('load8', (register, 7, 0), 4)])

    def test_no_displacement_form_rejects_other_addressing_and_prefixes(self):
        for raw in ('480fb6', '480fb606', '480fb604', '480fb605', '490fb607',
                    '4a0fb607', '400fb607', '480fb74700', '66480fb607'):
            with self.subTest(raw=raw), self.assertRaises(VerifiedSIMDRejected):
                decode_simd(bytes.fromhex(raw))


@unittest.skipUnless(legacy.AVAILABLE, 'Linux x86-64, GNU ld and pinned Z3 are required')
class SingleByteReductionCheckerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-single-byte-check-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root, cls.cases = Path(cls.temporary.name), {}
        for isa, kind in OLD_BOUNDED_OBJECTS:
            core = simd_kernel_program(kind)
            image = emit_verified_simd(core, isa=isa, reduce_tail='bounded-one')
            obj = cls.root / (isa + '-' + kind + '.o')
            final = obj.with_suffix('.so')
            obj.write_bytes(image.object_bytes)
            subprocess.run(['ld', '-m', 'elf_x86_64', '-shared', '-z', 'defs', '-z', 'noexecstack',
                '-z', 'relro', '-z', 'now', '--hash-style=both', '--build-id=none',
                str(obj), '-lc', '-o', str(final)], check=True, capture_output=True, timeout=30)
            linked = final.read_bytes()
            proof = validate_verified_simd_artifact(core, image.object_bytes, linked)
            cls.cases[isa, kind] = core, image, linked, proof

    def rows(self, key):
        return decode_simd(self.cases[key][1].text_bytes)

    def raw(self, key, row):
        return self.cases[key][1].text_bytes[row.pc:row.pc + row.size]

    def reject(self, key, row, changed, *, obligation=None):
        core, image, linked, _ = self.cases[key]
        self.assertEqual(len(changed), row.size)
        self.assertNotEqual(changed, self.raw(key, row))
        obj, final = bytearray(image.object_bytes), bytearray(linked)
        for data, elf_kind in ((obj, 1), (final, 3)):
            offset = _ELF(bytes(data), elf_kind).section('.text')['offset'] + row.pc
            data[offset:offset + row.size] = changed
        with self.assertRaises(VerifiedSIMDRejected) as caught:
            validate_verified_simd_artifact(core, bytes(obj), bytes(final))
        if obligation:
            self.assertEqual(caught.exception.counterexample['obligation'], obligation)
            self.assertFalse(caught.exception.validation['complete'])
            self.assertEqual(caught.exception.validation['obligations'][-1]['result'], 'sat')

    def test_profiles_keep_original_obligations_and_prove_all_new_entry_effects(self):
        for key, (_, image, _, proof) in self.cases.items():
            with self.subTest(key=key):
                bits = 256 if key[0] == 'avx2' else 512
                self.assertEqual(image.reduce_tail, 'bounded-one')
                self.assertEqual(proof['profile'], BOUNDED_ONE_REDUCTION_PROFILES[bits])
                self.assertEqual(proof['model_counts']['reduce_tail'], 'bounded-one')
                self.assertTrue(proof['claims']['single_byte_entry_effects_checked'])
                self.assertEqual(len(proof['obligations']), 25)
                self.assertEqual([x['result'] for x in proof['obligations']], ['sat'] + ['unsat'] * 24)
                self.assertTrue({'decoded_single_byte_entry_partition', 'single_byte_access_bounds',
                    'single_byte_result_and_register_frame', 'decoded_short_entry_partition',
                    'bounded_word_partition_bounds_and_no_overlap', 'wide_to_narrow_reduction_and_frame'
                    } <= {x['name'] for x in proof['obligations']})
                self.assertFalse(proof['checker']['producer_reemission_used'])
                self.assertEqual(set(proof['required_cpu_features']), REQUIREMENTS[key])

    def test_previous_bounded_objects_and_default_selection_are_unchanged(self):
        for (isa, kind), expected in OLD_BOUNDED_OBJECTS.items():
            core = simd_kernel_program(kind)
            old = emit_verified_simd(core, isa=isa, reduce_tail='bounded')
            self.assertEqual(sha256(old.object_bytes).hexdigest(), expected)
            self.assertEqual(emit_verified_simd(core, isa=isa).object_bytes, old.object_bytes)
            self.assertNotEqual(self.cases[isa, kind][1].object_bytes, old.object_bytes)

    def test_single_entry_guard_requires_exactly_one_admitted_byte(self):
        for key in self.cases:
            rows = self.rows(key)
            index = next(i for i, r in enumerate(rows) if r.op == 'alu_imm' and r.args == ('cmp', 10, 1))
            guard, branch = rows[index:index + 2]
            for value in (0, 2, 16):
                raw = bytearray(self.raw(key, guard)); raw[-1] = value
                self.reject(key, guard, bytes(raw))
            for condition in (0x82, 0x85, 0x86, 0x87):
                raw = bytearray(self.raw(key, branch)); raw[1] = condition
                self.reject(key, branch, bytes(raw))

    def test_single_entry_never_bypasses_range_null_or_wrap_guards(self):
        for key in self.cases:
            rows = self.rows(key)
            load = next(r for r in rows if r.op == 'load8')
            entry = next(i for i, r in enumerate(rows) if r.op == 'alu_imm' and r.args == ('cmp', 10, 1))
            for branch in [r for r in rows[:entry] if r.op == 'jcc']:
                raw = bytearray(self.raw(key, branch))
                raw[-4:] = struct.pack('<i', load.pc - branch.pc - branch.size)
                self.reject(key, branch, bytes(raw))

    def test_wrong_byte_destination_produces_functional_and_frame_counterexamples(self):
        for key in self.cases:
            load = next(r for r in self.rows(key) if r.op == 'load8')
            for register in (1, 3, 5, 6):
                raw = bytearray(self.raw(key, load)); raw[3] = (raw[3] & 0xc7) | (register << 3)
                self.reject(key, load, bytes(raw), obligation='single_byte_result_and_register_frame')

    def test_single_entry_rejects_changed_address_width_and_return_target(self):
        for key in self.cases:
            rows = self.rows(key)
            index = next(i for i, r in enumerate(rows) if r.op == 'load8')
            load, branch = rows[index:index + 2]
            raw = bytearray(self.raw(key, load)); raw[3] = (raw[3] & 0xf8) | 6
            self.reject(key, load, bytes(raw))
            raw = bytearray(self.raw(key, load)); raw[2] = 0xb7
            self.reject(key, load, bytes(raw))
            raw = bytearray(self.raw(key, branch)); raw[-4:] = struct.pack('<i', load.pc - branch.pc - branch.size)
            self.reject(key, branch, bytes(raw))

    def test_final_image_binding_and_independence_still_hold(self):
        with patch('hepta.hia_verified_simd.emit_verified_simd', side_effect=AssertionError('producer used')), \
             patch('hepta.hia_verified_simd_wide.emit_wide_simd', side_effect=AssertionError('producer used')):
            for core, image, linked, _ in self.cases.values():
                proof = validate_verified_simd_artifact(core, image.object_bytes, linked)
                self.assertTrue(proof['ok'] and proof['complete'])
        for key, (core, image, linked, _) in self.cases.items():
            load = next(r for r in self.rows(key) if r.op == 'load8')
            final = bytearray(linked)
            offset = _ELF(linked, 3).section('.text')['offset'] + load.pc
            final[offset + load.size - 1] ^= 8
            with self.assertRaises(SafeCoreELFRejected):
                validate_verified_simd_artifact(core, image.object_bytes, bytes(final))

    def test_nonwide_or_copy_single_byte_selection_is_refused(self):
        for isa, kind in (('sse2', 'sum_u8'), ('sse2', 'all_zero_u8'), ('sse2', 'copy_u8'),
                          ('avx2', 'copy_u8'), ('avx512', 'copy_u8')):
            with self.subTest(isa=isa, kind=kind), self.assertRaises(VerifiedSIMDRejected):
                emit_verified_simd(simd_kernel_program(kind), isa=isa, reduce_tail='bounded-one')


@unittest.skipUnless(legacy.AVAILABLE, 'Linux x86-64, GNU ld and pinned Z3 are required')
class SingleByteReductionNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-single-byte-native-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        features = set(probe_host_isa()['common_features'])
        cls.images, cls.refusals = {}, {}
        for key in OLD_BOUNDED_OBJECTS:
            isa, kind = key
            core = simd_kernel_program(kind)
            image = emit_verified_simd(core, isa=isa, reduce_tail='bounded-one')
            path = cls.root / (isa + '-' + kind + '.so')
            if not REQUIREMENTS[key] <= features:
                try:
                    build_verified_kernel(core, path, strategy='simd', simd_isa=isa,
                                          simd_reduce_tail='bounded-one')
                except VerifiedCPURejected as exc:
                    if path.exists() or 'does not enable' not in str(exc):
                        raise AssertionError('unsupported single-byte image was published') from exc
                    cls.refusals[key] = str(exc)
                else:
                    raise AssertionError('unsupported single-byte image was published')
                continue
            build = build_verified_kernel(core, path, strategy='simd', simd_isa=isa,
                                          simd_reduce_tail='bounded-one')
            loaded = load_verified_simd_kernel(core, image.object_bytes, path.read_bytes())
            cls.images[key] = core, image, path, build, loaded
        print('Single-byte native coverage: ' + str(len(cls.images)) + ' proved/admitted images; ' +
              str(len(cls.refusals)) + ' unsupported images refused')

    def test_every_selected_image_requires_final_proof_and_live_cpu_admission(self):
        self.assertEqual(set(self.images) | set(self.refusals), set(OLD_BOUNDED_OBJECTS))
        for key, (_, image, path, build, loaded) in self.images.items():
            self.assertEqual(build['simd_reduce_tail'], 'bounded-one')
            self.assertEqual(build['validation']['subject']['object_sha256'], sha256(image.object_bytes).hexdigest())
            self.assertEqual(build['validation']['subject']['final_image_sha256'], sha256(path.read_bytes()).hexdigest())
            self.assertTrue(loaded.mapping_admission['sealed_image_and_loaded_symbol_bound'])
            self.assertEqual(build['runtime_solver_calls'], 0)
            self.assertEqual(loaded.function(None, 0, 0), int(key[1] == 'all_zero_u8'))

    def test_all_256_bytes_and_unaligned_addresses_preserve_memory(self):
        for (isa, kind), (_, _, _, _, loaded) in self.images.items():
            for offset in range(32):
                for value in range(256):
                    original = b'L' * offset + bytes((value,)) + b'R' * 33
                    memory = ctypes.create_string_buffer(original)
                    result = loaded.function(ctypes.addressof(memory) + offset, 1, 1)
                    self.assertEqual(result, value if kind == 'sum_u8' else int(value == 0), (isa, kind, offset, value))
                    self.assertEqual(memory.raw[:len(original)], original)

    def test_original_length_offset_and_large_range_controls_on_each_new_image(self):
        refined.VerifiedRefinedNativeTests.test_bounded_reductions_cover_all_short_lengths_offsets_and_large_ranges(self)

    def test_every_short_byte_position_still_contributes_to_both_reductions(self):
        refined.VerifiedRefinedNativeTests.test_every_byte_position_contributes_to_sum_and_zero_in_short_ranges(self)

    def test_both_exact_guard_boundaries_cover_every_length_one_through_4096(self):
        refined.VerifiedRefinedNativeTests.test_bounded_word_reads_respect_start_and_end_guard_pages(self)

    def test_invalid_single_byte_inputs_abort_before_access(self):
        cases = ((0, 1, 1), (0, 0, 1), (1, 0, 1), ((1 << 64) - 1, 1, 1),
                 ((1 << 64) - 1, 2, 2), (1, 0, 2))
        for key, (_, _, path, _, _) in self.images.items():
            for pointer, extent, count in cases:
                code = ('import ctypes,resource;resource.setrlimit(resource.RLIMIT_CORE,(0,0));'
                        'f=ctypes.CDLL(' + repr(str(path)) + ').calculate;'
                        'f.argtypes=[ctypes.c_void_p,ctypes.c_uint64,ctypes.c_uint64];'
                        'f.restype=ctypes.c_uint64;f(' + ','.join(map(str, (pointer, extent, count))) + ')')
                result = subprocess.run([sys.executable, '-c', code], capture_output=True, timeout=10)
                self.assertEqual(result.returncode, -signal.SIGABRT, (key, pointer, extent, count, result.stderr))


if __name__ == '__main__':
    unittest.main()
