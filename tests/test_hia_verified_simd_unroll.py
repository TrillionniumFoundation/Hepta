"""Native byte effects and protected-page bounds of the 64-byte SIMD loop."""
from __future__ import annotations

import ctypes
from pathlib import Path
import tempfile
import unittest

from hepta.hia_verified_kernel import build_verified_kernel
from hepta.hia_verified_simd import emit_verified_simd, simd_kernel_program
from hepta.hia_verified_simd_check import VerifiedSIMDRejected
from tests import test_hia_verified_simd as _legacy


@unittest.skipUnless(_legacy.AVAILABLE, 'Linux x86-64, GNU ld and pinned z3 are required')
class VerifiedSIMDUnrolledNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-verified-simd-unroll-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.cases = {}
        cls.builds = {}
        for kind in ('sum_u8', 'all_zero_u8', 'copy_u8'):
            core = simd_kernel_program(kind)
            library = cls.root / (kind + '.so')
            result = build_verified_kernel(core, library, strategy='simd')
            cls.builds[kind] = result
            cls.cases[kind] = (core, None, library, result['validation'])

    def test_default_build_proves_both_vector_loops_before_publication(self):
        for kind, result in self.builds.items():
            with self.subTest(kind=kind):
                proof = result['validation']
                self.assertTrue(proof['ok'] and proof['complete'])
                self.assertEqual(proof['model_counts']['loop_backedges'], 3)
                self.assertEqual(proof['model_counts']['vector_unroll'], 4)
                self.assertEqual(proof['model_counts']['superblock_width'], 64)
                self.assertEqual(proof['model_counts']['range_admission_sites'], 1)
                self.assertEqual(result['runtime_solver_calls'], 0)
                obligations = 13 if kind == 'all_zero_u8' else 12
                self.assertEqual([o['result'] for o in proof['obligations']], ['sat'] + ['unsat'] * (obligations - 1))
                self.assertEqual(proof['model_counts']['reduction_accumulators'],
                                 4 if kind == 'all_zero_u8' else (0 if kind == 'copy_u8' else 1))

    def test_explicit_legacy_build_remains_independently_checkable(self):
        for kind, (core, _, _, _) in self.cases.items():
            with self.subTest(kind=kind):
                result = build_verified_kernel(core, self.root / (kind + '-legacy.so'),
                                               strategy='simd', simd_unroll=1)
                proof = result['validation']
                self.assertTrue(proof['ok'] and proof['complete'])
                self.assertEqual(proof['model_counts']['loop_backedges'], 2)
                self.assertEqual(len(proof['obligations']), 10)

    def test_unreviewed_unroll_factors_are_refused(self):
        core = self.cases['sum_u8'][0]
        for unroll in (True, False, 0, 2, 3, 8, 4.0, '4', None):
            with self.subTest(unroll=unroll), self.assertRaises(VerifiedSIMDRejected):
                emit_verified_simd(core, unroll=unroll)

    # These reuse the established native regression contract with the newly
    # built 64-byte images, including all lengths 0..128 and 4096 exact-end
    # guard-page placements. They do not inherit legacy mutation fixtures.
    test_native_all_tail_lengths_and_large_buffers = _legacy.VerifiedSIMDTests.test_native_all_tail_lengths_and_large_buffers
    test_invalid_native_ranges_abort_before_touching_memory = _legacy.VerifiedSIMDTests.test_invalid_native_ranges_abort_before_touching_memory
    test_real_guard_pages_cover_every_vector_tail = _legacy.VerifiedSIMDTests.test_real_guard_pages_cover_every_vector_tail

    def test_zero_scan_observes_each_byte_and_respects_count(self):
        library = ctypes.CDLL(str(self.cases['all_zero_u8'][2]))
        scan = library.calculate
        scan.restype = ctypes.c_uint64
        scan.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint64]
        data = (ctypes.c_uint8 * 257)()
        for index in range(257):
            data[index] = 128
            self.assertEqual(scan(data, 257, index), 1)
            self.assertEqual(scan(data, 257, index + 1), 0)
            self.assertEqual(scan(data, 257, 257), 0)
            data[index] = 0


if __name__ == '__main__':
    unittest.main()
