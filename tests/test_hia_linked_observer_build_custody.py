"""Linked-observer publication controls with explicit non-executing fixtures.

The original linked-observer module retains all real native and independent
loader cases. These tests substitute compilation and invocation only to make
malformed receipts observable at the publication boundary; no fixture is run.
"""
from hashlib import sha256
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import hia_selfhost_linked_observer as builder
from tools import qualify_hia_selfhost as qualification
from tools.generate_hia_linked_observer import reference_object


class _LinkBoundaryReached(Exception):
    pass


class LinkedObserverBuildCustodyTests(unittest.TestCase):
    def exercise(self, directory, changes):
        policy = b'\xc3'
        packer = b'explicit non-executing packer fixture'
        expected = reference_object(policy)
        output = expected + b'\xa5' * ((1 << 20) - len(expected))
        digest = lambda raw: sha256(raw).hexdigest()
        receipt = {
            'status': 'returned', 'abi_status': 0,
            'core_u32': len(expected), 'result_u64': len(expected),
            'format': 'flat-x86-64', 'return_encoding': 'zero-extended-u32',
            'artifact_sha256': digest(packer), 'image_sha256': digest(packer),
            'input_sha256': digest(policy), 'source_sha256': digest(policy),
            'input_bytes': len(policy), 'source_unchanged': True,
            'forbidden_compiler_modules_loaded': [],
            'output_sha256': digest(output),
        }
        receipt.update(changes)

        def compile_fixture(folder, label, compiler, source):
            path = folder / (label + '.image.bin')
            path.write_bytes(policy if label.endswith('-policy') else packer)
            return path, {'scope': 'non-executing compilation fixture'}

        reference = {'before_native_compilation': True,
                     'source_sha256': builder.source_identity(), 'before_B0': False}
        with patch.object(qualification, 'compile_stage', side_effect=compile_fixture), \
                patch.object(qualification, 'invoke', return_value=(receipt, output)), \
                patch.object(builder, 'vm_packer', return_value=(expected, {})), \
                patch.object(builder, '_runtime_interpreter', side_effect=_LinkBoundaryReached), \
                patch.object(qualification, 'observe_native_tool') as link:
            try:
                builder.build(directory, directory / 'non-executed-compiler', reference)
            finally:
                link.assert_not_called()

    def test_inconsistent_native_receipts_refuse_before_object_publication(self):
        cases = (
            {'abi_status': False},
            {'result_u64': (1 << 32) + len(reference_object(b'\xc3'))},
            {'image_sha256': '0' * 64},
            {'source_sha256': '0' * 64},
            {'output_sha256': '0' * 64},
        )
        for changes in cases:
            with self.subTest(changes=changes), tempfile.TemporaryDirectory() as temporary:
                folder = Path(temporary)
                with self.assertRaises(ValueError):
                    self.exercise(folder, changes)
                self.assertFalse((folder / 'linked-observer.o').exists())
                self.assertFalse((folder / 'linked-observer.elf').exists())
                self.assertFalse((folder / 'linked-observer-build.json').exists())

    def test_complete_captured_receipt_reaches_link_boundary_without_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            with self.assertRaises(_LinkBoundaryReached):
                self.exercise(folder, {})
            self.assertEqual((folder / 'linked-observer.o').read_bytes(), reference_object(b'\xc3'))
            self.assertFalse((folder / 'linked-observer.elf').exists())


if __name__ == '__main__':
    unittest.main()
