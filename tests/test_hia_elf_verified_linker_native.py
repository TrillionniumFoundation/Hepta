"""Exercise the actual publication routes with a cold HIA linker and no PATH."""
import ctypes
from hashlib import sha256
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from hepta.hia_elf_verified_linker_native import SELECTOR, selected_verified_linker
from hepta.hia_safe_core import build_safe_core
from hepta.hia_verified_kernel import build_verified_kernel
from hepta.hia_verified_scalar import VerifiedScalarRejected, build_verified_scalar
from hepta.hia_verified_simd import simd_kernel_program
from hepta.hia_verified_image import VerifiedImageRejected
from tests.test_hia_program import arithmetic
from tests.test_hia_safe_core import read_byte
from tests.test_hia_verified_scalar import multiply_add


@unittest.skipUnless(os.environ.get(SELECTOR), 'a cold HIA verified linker is required')
class VerifiedLinkerNativeTests(unittest.TestCase):
    def test_checked_scalar_and_simd_routes_publish_verified_dlopen_images(self):
        cases = (
            (build_safe_core, arithmetic('int.add.wrap', 'u32'), {}, 'calculate'),
            (build_safe_core, read_byte(), {'foreign_extent': 8}, 'read_byte'),
            (build_verified_scalar, multiply_add(), {}, 'multiply_add'),
            (build_verified_kernel, simd_kernel_program('copy_u8'),
             {'strategy': 'simd', 'simd_unroll': 1}, 'calculate'),
        )
        with TemporaryDirectory(prefix='hia-verified-linker-') as folder, patch.dict(os.environ, {'PATH': ''}):
            image_digest = selected_verified_linker().image_sha256
            for index, (builder, core, options, export) in enumerate(cases):
                with self.subTest(builder=builder.__name__, export=export):
                    output = Path(folder) / (str(index) + '.so')
                    report = builder(core, output, linker='must-not-execute', **options)
                    tool = report.get('toolchain') or report['compilation']['toolchain']
                    self.assertEqual((tool['mode'], tool['path'], tool['sha256']), ('hia', None, image_digest))
                    self.assertTrue(report['validation']['complete'] and report['validation']['ok'])
                    self.assertEqual(report['artifact_sha256'], sha256(output.read_bytes()).hexdigest())
                    self.assertIsNotNone(getattr(ctypes.CDLL(str(output), mode=os.RTLD_NOW), export))

    def test_malformed_native_candidate_is_not_published_or_relinked(self):
        def malformed(_object, destination):
            destination.write_bytes(b'bad')

        with TemporaryDirectory(prefix='hia-verified-linker-') as folder, patch.dict(os.environ, {'PATH': ''}):
            output = Path(folder) / 'unverified.so'
            with patch('hepta.hia_elf_verified_linker_native.NativeVerifiedLinker.link', side_effect=malformed):
                with self.assertRaises(VerifiedScalarRejected) as caught:
                    build_verified_scalar(multiply_add(), output, linker='must-not-execute')
            self.assertIsInstance(caught.exception.__cause__, VerifiedImageRejected)
            self.assertFalse(output.exists())
