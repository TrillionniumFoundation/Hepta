"""Clang-AST C++ L1 migration bootstrap evidence. Full rustc and C++ ABI are not qualified."""
import contextlib
import io
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.cpp2hepta import convert_cpp, main
from hepta.c2hepta import MigrationRejected


@unittest.skipUnless(shutil.which('clang++'), 'requires real Clang++ AST')
class Cpp2HeptaTests(unittest.TestCase):
    def _with_source(self, src, callback):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'original.cc'
            path.write_text(src)
            return callback(path)

    def test_actual_clang_ast_value_only_candidates(self):
        source = '''
int add(int a, int b) noexcept { return a + b; }
int triangle(int n) noexcept { int result = 0; for (int i=0; i<n; ++i) { result += i; } return result; }
int clamp_low(int x) noexcept { if (x < 0) return 0; else return x; }
int inferred(int x) noexcept { auto y = x; return y; }
'''
        def check(path):
            actual = convert_cpp(path)
            self.assertEqual(actual.report['tier'], 'L1')
            self.assertFalse(actual.report['cpp_abi_preserved'])
            self.assertFalse(actual.report['semantic_equivalence_proved'])
            self.assertEqual(actual.report['functions'], ['add', 'clamp_low', 'inferred', 'triangle'])
            self.assertIn('export "C" fn add(', actual.source)
            self.assertIn('while (i < n)', actual.source)
            self.assertEqual(actual.source, convert_cpp(path).source)
        self._with_source(source, check)

    def test_reject_unsupported_cplusplus(self):
        samples = [
            'class Thing {public: int f() noexcept {return 1;}};',
            'int *bad(int *p) noexcept {return p;}',
            'int foo(int a) noexcept {return a;} int foo(int a, int b) noexcept{return a+b;}',
            'int x=2; int foo(int a) noexcept{return x+a;}',
            'template <class T> T foo(T v) noexcept{return v;}',
            '#include <stdint.h>\nint foo(int a) noexcept{return a;}',
            'int foo(int a) {return a;}',
        ]
        for candidate in samples:
            with self.subTest(source=candidate):
                self._with_source(candidate, lambda path: self.assertRaises(MigrationRejected, convert_cpp, path))

    def test_cli_no_overwrite_and_no_partial_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            orig = Path(tmp) / 'start.cc'
            out = Path(tmp) / 'translated.hepta'
            orig.write_text('int square(int x) noexcept {return x*x;}')
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main([str(orig), '-o', str(out)]), 0)
                self.assertEqual(main([str(orig), '-o', str(out)]), 1)
            assert out.read_text().startswith('module cpp_migrated;')
            self.assertEqual(len(list(Path(tmp).glob('.cpp2hepta-*'))), 0)


if __name__ == '__main__':
    unittest.main()
