"""Independent native C-defined-input control for the bounded scalar bridge.

The handwritten C function is not a C2Hepta migration; it is an independent
C11 implementation of the loop/branch fixture used for differential checking.
"""
import ctypes
import json
import pathlib
import shutil
import subprocess
import tempfile
import unittest

from hepta.hsir_scalar_bridge import lower_source_bound_scalar
from test_hsir_scalar_bridge import sample
from test_hsir_scalar_differential import run

C_SOURCE = r'''
#include <stdint.h>
int32_t hepta_control_count(int32_t n) {
    int32_t x = 0;
    while (x < n) {
        if (x < 4) { x = x + 1; }
        else { x = x + 1; }
    }
    return x;
}
'''
WRONG_C_SOURCE = C_SOURCE.replace('if (x < 4) { x = x + 1; }',
                                  'if (x < 4) { x = x + 2; }')


class NativeOracleTests(unittest.TestCase):
    def native(self, compiler, source):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            inp, out = root / 'control.c', root / 'control.so'
            inp.write_text(source)
            p = subprocess.run([compiler, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                                '-shared', '-fPIC', str(inp), '-o', str(out)],
                               capture_output=True, text=True, timeout=30)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertTrue(out.stat().st_size > 0)
            lib = ctypes.CDLL(str(out))
            f = lib.hepta_control_count
            f.argtypes = [ctypes.c_int32]
            f.restype = ctypes.c_int32
            return [f(n) for n in range(-10, 50)]

    def test_independent_native_compilers_match_translated_model(self):
        translated = json.loads(lower_source_bound_scalar(sample())[0])
        expected = [run(translated, n, False) for n in range(-10, 50)]
        seen = 0
        for cc in ('gcc', 'clang'):
            compiler = shutil.which(cc)
            if compiler:
                seen += 1
                with self.subTest(compiler=cc):
                    self.assertEqual(self.native(compiler, C_SOURCE), expected)
        if not seen:
            self.skipTest('no native C compiler available')

    def test_wrong_native_implementation_rejected(self):
        compiler = shutil.which('gcc') or shutil.which('clang')
        if not compiler:
            self.skipTest('no native C compiler available')
        correct = self.native(compiler, C_SOURCE)
        incorrect = self.native(compiler, WRONG_C_SOURCE)
        self.assertNotEqual(correct, incorrect)
        self.assertNotEqual(correct[3 + 10], incorrect[3 + 10])


if __name__ == '__main__':
    unittest.main()
