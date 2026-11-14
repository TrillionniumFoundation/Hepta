"""Native compiler publication refuses malformed and changed call receipts."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools.qualify_hia_selfhost import CAPACITY, compile_stage


class CompileStageCustodyTests(unittest.TestCase):
    def test_complete_integer_receipt_publishes_exact_returned_prefix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = root / 'compiler'
            image.write_bytes(b'captured compiler fixture')
            source = b'captured source fixture'
            result = self.receipt(image, source)
            with patch('tools.qualify_hia_selfhost.invoke', return_value=(result, self.output())):
                produced, receipt = compile_stage(root, 'result', image, source)
            self.assertEqual(produced.read_bytes(), b'code')
            self.assertEqual(receipt['produced_sha256'], sha256(b'code').hexdigest())
            self.assertEqual(receipt['produced_bytes'], 4)

    @staticmethod
    def output():
        # The real observer returns the complete admitted output extent.
        return b'codeunused' + bytes(CAPACITY - len(b'codeunused'))

    @staticmethod
    def receipt(image, source):
        return {'status': 'returned', 'abi_status': 0, 'core_u32': 4,
                'result_u64': 4, 'return_encoding': 'zero-extended-u32',
                'source_unchanged': True, 'forbidden_compiler_modules_loaded': [],
                'source_sha256': sha256(source).hexdigest(),
                'input_sha256': sha256(source).hexdigest(), 'input_bytes': len(source),
                'image_sha256': sha256(image.read_bytes()).hexdigest(),
                'artifact_sha256': sha256(image.read_bytes()).hexdigest(),
                'output_sha256': sha256(CompileStageCustodyTests.output()).hexdigest(),
                'limits': {'output_capacity': CAPACITY, 'workspace_bytes': CAPACITY},
                'format': 'flat-x86-64'}

    def test_refusal_cannot_publish_even_a_partial_image(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = root / 'compiler'
            image.write_bytes(b'captured compiler fixture')
            source = b'captured source fixture'
            base = self.receipt(image, source)
            changes = [('abi_status', False), ('abi_status', 0.0),
                ('core_u32', True), ('core_u32', 4.0), ('core_u32', 0),
                ('core_u32', -1), ('core_u32', CAPACITY + 1),
                ('source_unchanged', 1), ('source_unchanged', False),
                ('forbidden_compiler_modules_loaded', None),
                ('forbidden_compiler_modules_loaded', False),
                ('forbidden_compiler_modules_loaded', ['hepta.hia_program_native']),
                ('input_sha256', '0' * 64), ('input_bytes', 0),
                ('artifact_sha256', '0' * 64), ('format', 'seed-shared')]
            for index, (field, value) in enumerate(changes):
                with self.subTest(field=field, value=value):
                    receipt = deepcopy(base)
                    receipt[field] = value
                    label = 'refusal-' + str(index)
                    with patch('tools.qualify_hia_selfhost.invoke', return_value=(receipt, self.output())):
                        with self.assertRaises(AssertionError):
                            compile_stage(root, label, image, source)
                    self.assertFalse((root / (label + '.image.bin')).exists())
            for field in base:
                receipt = deepcopy(base)
                del receipt[field]
                with patch('tools.qualify_hia_selfhost.invoke', return_value=(receipt, self.output())):
                    with self.assertRaises(AssertionError):
                        compile_stage(root, 'missing', image, source)
                self.assertFalse((root / 'missing.image.bin').exists())

    def test_changed_compiler_after_invocation_cannot_publish(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = root / 'compiler'
            image.write_bytes(b'captured compiler fixture')
            source = b'captured source fixture'
            receipt = self.receipt(image, source)
            def invoke(*args, **kwargs):
                image.write_bytes(b'replaced compiler fixture')
                return receipt, self.output()
            with patch('tools.qualify_hia_selfhost.invoke', side_effect=invoke):
                with self.assertRaises(AssertionError):
                    compile_stage(root, 'changed', image, source)
            self.assertFalse((root / 'changed.image.bin').exists())

    def test_custody_refusal_survives_optimized_python(self):
        root = Path(__file__).resolve().parents[1]
        script = '''
import sys
sys.path.insert(0, sys.argv[1])
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from tests.test_hia_compile_stage_custody import CompileStageCustodyTests
from tools.qualify_hia_selfhost import compile_stage
with TemporaryDirectory() as temporary:
    root = Path(temporary)
    compiler = root / 'compiler'
    compiler.write_bytes(b'fixture')
    receipt = CompileStageCustodyTests.receipt(compiler, b'source')
    receipt['source_unchanged'] = False
    with patch('tools.qualify_hia_selfhost.invoke', return_value=(receipt, CompileStageCustodyTests.output())):
        try:
            compile_stage(root, 'forbidden', compiler, b'source')
        except AssertionError:
            if (root / 'forbidden.image.bin').exists():
                raise SystemExit('refused output was published')
        else:
            raise SystemExit('optimized execution bypassed custody')
'''
        result = subprocess.run([sys.executable, '-I', '-S', '-B', '-O', '-c', script, str(root)],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
