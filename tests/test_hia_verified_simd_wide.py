"""Wide native effects after final-ELF proof and fresh ISA admission."""
from __future__ import annotations

import ctypes
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_verified_cpu import VerifiedCPURejected, probe_host_isa
from hepta.hia_verified_kernel import build_verified_kernel
from hepta.hia_verified_kernel_load import load_verified_simd_kernel
from hepta.hia_verified_simd import emit_verified_simd, simd_kernel_program
from hepta.hia_verified_simd_check import VerifiedSIMDRejected
from tests import test_hia_verified_simd as legacy


REQUIREMENTS = {
    ('avx2', 'sum_u8'): {'avx', 'avx2'},
    ('avx2', 'all_zero_u8'): {'avx', 'avx2'},
    ('avx2', 'copy_u8'): {'avx'},
    ('avx512', 'sum_u8'): {'avx', 'avx2', 'avx512f', 'avx512bw'},
    ('avx512', 'all_zero_u8'): {'avx', 'avx2', 'avx512f'},
    ('avx512', 'copy_u8'): {'avx', 'avx512f'},
}


class VerifiedWideNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-verified-wide-native-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.observation = probe_host_isa()
        available = set(cls.observation['common_features'])
        cls.variants, cls.refusals, cls.results = {}, {}, {}
        for (isa, kind), required in REQUIREMENTS.items():
            core = simd_kernel_program(kind)
            tail = 'byte' if kind == 'copy_u8' else None
            image = emit_verified_simd(core, isa=isa, copy_tail=tail)
            path = cls.root / (isa + '-' + kind + '.so')
            if not required <= available:
                try:
                    build_verified_kernel(core, path, strategy='simd', simd_isa=isa,
                                          simd_copy_tail=tail)
                except VerifiedCPURejected as exc:
                    if path.exists() or 'does not enable' not in str(exc):
                        raise AssertionError('unsupported ISA did not fail before publication') from exc
                    cls.refusals[isa, kind] = str(exc)
                else:
                    raise AssertionError('unsupported ISA was published')
                continue
            result = build_verified_kernel(core, path, strategy='simd', simd_isa=isa,
                                           simd_copy_tail=tail)
            cls.results[isa, kind] = result
            cls.variants.setdefault(isa, {})[kind] = (core, image, path, result['validation'])
        print('Wide ISA native coverage: ' + str(len(cls.results)) + ' executed-capable images; ' +
              str(len(cls.refusals)) + ' unsupported images refused before publication')

    def _complete_variants(self):
        for isa in ('avx2', 'avx512'):
            cases = self.variants.get(isa, {})
            if len(cases) == 3:
                yield isa, cases
            else:
                self.assertTrue(any((isa, k) in self.refusals for k in
                                    ('sum_u8', 'all_zero_u8', 'copy_u8')))

    def test_decoded_isa_requirements_are_met_for_every_published_image(self):
        self.assertEqual(len(self.results) + len(self.refusals), 6)
        for (isa, kind), result in self.results.items():
            with self.subTest(isa=isa, kind=kind):
                proof = result['validation']
                self.assertEqual(proof['target_isa'], isa)
                self.assertEqual(set(proof['required_cpu_features']), REQUIREMENTS[isa, kind])
                self.assertEqual(proof['required_xcr0_mask'], 6 if isa == 'avx2' else 0xe6)
                self.assertEqual(proof['model_counts']['vector_width'], 32 if isa == 'avx2' else 64)
                self.assertEqual(proof['model_counts']['superblock_width'], 128 if isa == 'avx2' else 256)
                self.assertEqual(proof['model_counts']['reduction_accumulators'], 0 if kind == 'copy_u8' else 4)
                self.assertEqual(result['runtime_solver_calls'], 0)
                self.assertEqual([o['result'] for o in proof['obligations']],
                                 ['sat'] + ['unsat'] * (11 if kind == 'copy_u8' else 13))

    def test_native_tail_lengths_large_buffers_or_explicit_isa_refusal(self):
        for isa, cases in self._complete_variants():
            with self.subTest(isa=isa):
                self.cases = cases
                legacy.VerifiedSIMDTests.test_native_all_tail_lengths_and_large_buffers(self)

    def test_exact_end_guard_pages_or_explicit_isa_refusal(self):
        for isa, cases in self._complete_variants():
            with self.subTest(isa=isa):
                self.cases = cases
                legacy.VerifiedSIMDTests.test_real_guard_pages_cover_every_vector_tail(self)

    def test_invalid_ranges_abort_before_memory_access_or_explicit_isa_refusal(self):
        for isa, cases in self._complete_variants():
            with self.subTest(isa=isa):
                self.cases = cases
                legacy.VerifiedSIMDTests.test_invalid_native_ranges_abort_before_touching_memory(self)

    def test_sealed_loader_executes_each_admitted_wide_image(self):
        for isa, cases in self.variants.items():
            for kind, (core, image, path, _) in cases.items():
                with self.subTest(isa=isa, kind=kind):
                    handle = load_verified_simd_kernel(core, image.object_bytes, path.read_bytes())
                    self.assertTrue(handle.mapping_admission['sealed_image_and_loaded_symbol_bound'])
                    data = (ctypes.c_uint8 * 257)(*[(i * 71 + 17) % 256 for i in range(257)])
                    if kind == 'copy_u8':
                        target = (ctypes.c_uint8 * 257)()
                        self.assertEqual(handle.function(target, 257, data, 257, 257), 257)
                        self.assertEqual(bytes(target), bytes(data))
                    elif kind == 'sum_u8':
                        self.assertEqual(handle.function(data, 257, 257), sum(data))
                    else:
                        data = (ctypes.c_uint8 * 257)()
                        for position in range(257):
                            data[position] = 128
                            self.assertEqual(handle.function(data, 257, position), 1)
                            self.assertEqual(handle.function(data, 257, position + 1), 0)
                            self.assertEqual(handle.function(data, 257, 257), 0)
                            data[position] = 0

    def test_failed_fresh_cpu_admission_publishes_no_image(self):
        core = simd_kernel_program('sum_u8')
        output = self.root / 'unsupported.so'
        with patch('hepta.hia_verified_cpu.require_host_isa',
                   side_effect=VerifiedCPURejected('CPU or OS not enabled')) as gate:
            with self.assertRaises(VerifiedCPURejected):
                build_verified_kernel(core, output, strategy='simd', simd_isa='avx512')
        self.assertFalse(output.exists())
        self.assertEqual(gate.call_args.args, (['avx', 'avx2', 'avx512bw', 'avx512f'], 0xe6))

    def test_unknown_isa_and_unreviewed_wide_unroll_are_refused(self):
        core = simd_kernel_program('sum_u8')
        for isa in (None, True, 512, 'avx', 'native', 'avx1024'):
            with self.subTest(isa=isa), self.assertRaises(VerifiedSIMDRejected):
                emit_verified_simd(core, isa=isa)
        for isa in ('avx2', 'avx512'):
            with self.subTest(isa=isa), self.assertRaises(VerifiedSIMDRejected):
                emit_verified_simd(core, isa=isa, unroll=1)


if __name__ == '__main__':
    unittest.main()
