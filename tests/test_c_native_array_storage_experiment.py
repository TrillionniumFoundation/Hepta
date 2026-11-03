"""Isolated handwritten C representation experiment; no compiler admission."""
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
EXPERIMENT = ROOT / 'experiments/c_native_array_storage'
CC = shutil.which('gcc')

@unittest.skipUnless(CC, 'native GCC required')
class NativeArrayStorageExperimentTests(unittest.TestCase):
    def compile(self, command):
        return subprocess.run(command, capture_output=True, text=True, timeout=60)

    def test_separate_real_callers_at_o0_o3(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            for opt in ('0', '3'):
                flags = [CC, '-std=c11', '-pedantic-errors', '-Wall', '-Wextra', '-Werror',
                         '-O'+opt, '-fstrict-aliasing', '-fsanitize=undefined',
                         '-fno-sanitize-recover=all', '-I', str(EXPERIMENT)]
                for source in ('storage', 'caller'):
                    result = self.compile(flags + ['-c', str(EXPERIMENT/(source+'.c')), '-o', str(d/(source+'.o'))])
                    self.assertEqual(result.returncode, 0, result.stderr)
                result = self.compile(flags + [str(d/'storage.o'), str(d/'caller.o'), '-o', str(d/'run')])
                self.assertEqual(result.returncode, 0, result.stderr)
                result = subprocess.run([str(d/'run')], capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn('runtime error:', result.stderr)

    def test_wrong_store_and_rebinding_are_observed(self):
        original = (EXPERIMENT/'storage.c').read_text()
        replacements = [
            ('memcpy(&rows[index], &value.payload, sizeof value.payload);',
             '(void)rows; (void)index; (void)value;'),
            ('*slot = replacement;', '(void)slot; (void)replacement;'),
        ]
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            for before, after in replacements:
                self.assertEqual(original.count(before), 1)
                (d/'mutant.c').write_text(original.replace(before, after))
                for opt in ('0', '3'):
                    result = self.compile([CC, '-std=c11', '-pedantic-errors', '-Wall', '-Wextra', '-Werror',
                        '-O'+opt, '-fstrict-aliasing', '-fsanitize=undefined', '-fno-sanitize-recover=all',
                        '-I', str(EXPERIMENT), str(d/'mutant.c'), str(EXPERIMENT/'caller.c'), '-o', str(d/'mutant')])
                    self.assertEqual(result.returncode, 0, result.stderr)
                    result = subprocess.run([str(d/'mutant')], capture_output=True, text=True, timeout=10, cwd=d)
                    self.assertEqual(result.returncode, -signal.SIGABRT, result.stderr)
                    self.assertIn('Assertion', result.stderr)
                    self.assertNotIn('runtime error:', result.stderr)

    def test_const_and_wrapper_misuse_fail_compilation(self):
        cases = {
            'const_store': 'void bad(const NativeRow *p) {RowValue v={{1,2,3}}; row_store(p,0,v);}',
            'const_rebind': 'void bad(const NativeRow **p, NativeRow *q) {row_rebind(p,q);}',
            'wrapper_pointer': 'void bad(RowValue *p) {row_identity(p);}',
            'wrapper_nested': 'void bad(RowValue (*p)[2]) {plane_identity(p);}',
        }
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            for label, source in cases.items():
                with self.subTest(label=label):
                    path = d/(label+'.c')
                    path.write_text('#include "storage.h"\n'+source+'\n')
                    result = self.compile([CC, '-std=c11', '-pedantic-errors', '-Wall', '-Wextra', '-Werror', '-I', str(EXPERIMENT), '-c', str(path), '-o', str(d/(label+'.o'))])
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('const' if label == 'const_store' else 'incompatible', result.stderr)

if __name__ == '__main__':
    unittest.main()
