"""Clang scalar-migration AST subprocess refusal and exact preprocessor checks."""
import shutil
import sys
import unittest
from hepta.c_migrate import MigrationRejected, _run


class ScalarCBoundedTests(unittest.TestCase):
    def test_actual_clang_model_probe(self):
        clang = shutil.which('clang')
        if clang is None:
            self.skipTest('Clang is required')
        model = _run([clang, '-std=c11', '-dM', '-E', '-x', 'c', '-'], input_text='')
        self.assertIn('__SIZEOF_INT__', model)

    def test_actual_clang_ast_json(self):
        clang = shutil.which('clang')
        if clang is None:
            self.skipTest('Clang is required')
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'example.c'
            p.write_text('int increment(int a) { return a + 1; }')
            ast = _run([clang, '-std=c11', '-fsyntax-only', '-Xclang', '-ast-dump=json', str(p)])
        self.assertIn('FunctionDecl', ast)

    def test_scalar_output_capacity(self):
        with self.assertRaises(MigrationRejected) as caught:
            _run([sys.executable,'-c',"import sys;sys.stdout.buffer.write(b'x'*34000000);sys.stdout.flush()"])
        self.assertEqual(caught.exception.code, 'E_CLANG_SIZE')

    def test_scalar_compiler_error(self):
        with self.assertRaises(MigrationRejected) as caught:
            _run([sys.executable,'-c',"import sys;sys.stderr.write('invalid source');sys.exit(4)"])
        self.assertEqual(caught.exception.code, 'E_CLANG_REJECT')
        self.assertIn('invalid source',str(caught.exception))

if __name__=='__main__': unittest.main()
