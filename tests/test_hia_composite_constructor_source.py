"""Constructor source reproduction and exact retained-body custody."""
import ast
from hashlib import sha256
import inspect
import json
from pathlib import Path
import tempfile
import unittest

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_composite_constructor_native import SOURCES, NativeCompositeConstructor
from hepta.hia_program_composite import _Elaborator
from tools.generate_hia_composite_constructor import document


class ConstructorSourceTests(unittest.TestCase):
    def test_both_complete_sources_reproduce_below_original_limits(self):
        for kernel, path in SOURCES.items():
            data = document(kernel)
            with self.subTest(kernel=kernel):
                self.assertEqual(render_assembly(data).encode(), path.read_bytes())
                functions = data['functions']
                blocks = [block for fn in functions for block in fn['blocks']]
                self.assertLessEqual(len(path.read_bytes()), 1 << 20)
                self.assertLessEqual(len(functions), 128)
                self.assertLessEqual(len(blocks), 1536)
                self.assertLessEqual(sum(len(b['ops']) for b in blocks), 8192)
                for fn in functions:
                    self.assertLessEqual(len(fn['params']), 16)
                    self.assertLessEqual(len(fn['blocks']), 256)
                    definitions = {p['name'] for p in fn['params']}
                    for block in fn['blocks']:
                        self.assertLessEqual(len(block['params']), 16)
                        definitions.update(p['name'] for p in block['params'])
                        definitions.update(p['name'] for op in block['ops'] for p in op['out'])
                    self.assertLessEqual(len(definitions), 2048)

    def test_retained_constructor_body_exact_and_bundle_indivisible(self):
        source = inspect.getsource(_Elaborator._reference_initialize)
        original = source.replace('def _reference_initialize(', 'def __init__(', 1)
        self.assertEqual(sha256(original.encode()).hexdigest(),
                         '1b94c6d4246baf5e8be8d0e23924181b94a3746807215d4e4cb017e1918f5842')
        with self.assertRaisesRegex(ValueError, 'both HIA kernels'):
            NativeCompositeConstructor({'owner': object()}, types_source_sha256='0'*64)

    def test_complete_cold_gate_precedes_any_artifact_write(self):
        from tools.build_hia_composite_constructor import build
        with tempfile.TemporaryDirectory(prefix='hia-constructor-gate-') as temp:
            root = Path(temp)
            compiler, report = root/'compiler', root/'cold.json'
            compiler.write_bytes(b'development image')
            report.write_text(json.dumps({'status': 'DEVELOPMENT_ONLY'}))
            for existing in (False, True):
                output = root/('existing' if existing else 'absent-parent')/'bundle'
                if existing:
                    output.mkdir(parents=True)
                    (output/'sentinel').write_bytes(b'preserved')
                before = {p.relative_to(root):p.read_bytes() for p in root.rglob('*') if p.is_file()}
                with self.assertRaisesRegex(ValueError, 'completed matching native cold qualification'):
                    build(output, compiler, report)
                after = {p.relative_to(root):p.read_bytes() for p in root.rglob('*') if p.is_file()}
                self.assertEqual(before, after)
                self.assertEqual(output.exists(), existing)
                if not existing:
                    self.assertFalse(output.parent.exists())


if __name__ == '__main__':
    unittest.main()
