"""Exercise the actual publication routes with a cold HIA linker and no PATH."""
import ctypes
from hashlib import sha256
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from hepta.hia_elf_verified_linker_native import SELECTOR, selected_verified_linker
from hepta.hia_program import verify_program
from hepta.hia_program_native import compile_program_machine, emit_program_machine
from hepta.hia_safe_core import build_safe_core
from hepta.hia_safe_core_elf import bind_final_artifact
from hepta.hia_verified_kernel import build_verified_kernel
from hepta.hia_verified_scalar import VerifiedScalarRejected, build_verified_scalar
from hepta.hia_verified_simd import simd_kernel_program
from hepta.hia_verified_image import VerifiedImageRejected
from tests.test_hia_program import arithmetic
from tests.test_hia_safe_core import read_byte
from tests.test_hia_verified_scalar import multiply_add


STANDALONE = os.environ.get('HEPTA_HIA_VERIFIED_LINKER_EXECUTABLE')


@unittest.skipUnless(STANDALONE, 'an installed standalone HIA verified linker is required')
class StandaloneVerifiedLinkerTests(unittest.TestCase):
    def test_one_object_links_without_host_runtime_and_invalid_wire_emits_nothing(self):
        core = verify_program(arithmetic('int.add.wrap', 'u32'))
        image = emit_program_machine(core)

        def link(raw):
            return subprocess.run([STANDALONE], input=raw, capture_output=True, timeout=20, env={'PATH': ''})

        accepted = link(image.object_bytes)
        self.assertEqual((accepted.returncode, accepted.stderr), (0, b''))
        bound = bind_final_artifact(image.object_bytes, accepted.stdout, 'calculate')
        self.assertEqual(bound['binding']['function_shape'], 'internal_with_wrapper')
        for invalid in (b'', image.object_bytes[:64], image.object_bytes + b'\0'):
            refused = link(invalid)
            self.assertEqual((refused.returncode, refused.stdout, refused.stderr), (2, b'', b''))


@unittest.skipUnless(os.environ.get(SELECTOR), 'a cold HIA verified linker is required')
class VerifiedLinkerNativeTests(unittest.TestCase):
    def test_ordinary_worker_linkage_retains_a_machine_provable_final_image(self):
        core = verify_program(arithmetic('int.add.wrap', 'u32'))
        image = emit_program_machine(core)
        with TemporaryDirectory(prefix='hia-verified-linker-') as folder, patch.dict(os.environ, {'PATH': ''}):
            output = Path(folder) / 'ordinary.so'
            result = compile_program_machine(image, program=core, output=output, linker='ld')
            self.assertEqual(result['toolchain']['sha256'], selected_verified_linker().image_sha256)
            self.assertFalse(result['claims']['external_linker_used'])
            self.assertFalse(result['claims']['backend_refinement_proved'])
            binding = bind_final_artifact(image.object_bytes, output.read_bytes(), 'calculate')
            self.assertEqual(binding['binding']['final_image_sha256'], result['artifact_sha256'])

            def malformed(_object, path):
                path.write_bytes(b'bad')
                return True

            invalid = Path(folder) / 'invalid.so'
            with patch('hepta.hia_elf_verified_linker_native.NativeVerifiedLinker.try_link', side_effect=malformed):
                with self.assertRaisesRegex(ValueError, 'E_HIA_SAFE_CORE_ELF'):
                    compile_program_machine(image, program=core, output=invalid, linker='ld')
            self.assertFalse(invalid.exists())

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
