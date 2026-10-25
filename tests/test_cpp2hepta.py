"""Clang-AST C++ L1 migration bootstrap evidence. Full rustc and C++ ABI are not qualified."""
import contextlib
import io
from pathlib import Path
import shutil
import subprocess
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
            'int foo(int a=3) noexcept{return a;}',
            'int foo(int a [[maybe_unused]]) noexcept{return 1;}',
        ]
        for candidate in samples:
            with self.subTest(source=candidate):
                self._with_source(candidate, lambda path: self.assertRaises(MigrationRejected, convert_cpp, path))

    def test_optional_cpp_native_abi_differential_against_hepta(self):
        # A finite C++-versus-Hepta execution comparison, not a general proof.
        try:
            from hepta.ast import HeptaError
            from hepta.backend import find_rustc, compile_rust
            from hepta.pipeline import analyze
        except ModuleNotFoundError:
            self.skipTest('full Hepta frontend not mounted')
        from hepta.cpp_bridge import generate_cpp_bridge
        try:
            rustc = find_rustc()
        except HeptaError:
            self.skipTest('pinned rustc not available')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / 'reference.cc'
            original.write_text('''int add(int a, int b) noexcept { return a + b; }
int triangle(int n) noexcept { int result=0; for(int i=0;i<n;++i) {result+=i;} return result; }
int clamp_low(int x) noexcept { if(x<0) return 0; else return x; }
int inferred(int x) noexcept { auto y=x; return y; }
''')
            migrated = convert_cpp(original)
            bridge = generate_cpp_bridge(original)
            self.assertEqual(migrated.report['tier'], 'L1')
            self.assertFalse(migrated.report['cpp_abi_preserved'])
            self.assertFalse(migrated.report['semantic_equivalence_proved'])
            bridge_file = root / 'bridge.cc'
            bridge_file.write_text(bridge.source)
            cpp_lib = root / 'libreference.so'
            subprocess.run([shutil.which('clang++'), '-std=c++20', '-O2', '-fPIC', '-shared',
                            str(original), str(bridge_file), '-o', str(cpp_lib)],
                           check=True, capture_output=True, timeout=30)
            hepta_file = root / 'converted.hepta'
            hepta_file.write_text(migrated.source)
            checked = analyze(migrated.source, path=str(hepta_file),
                              crate_type='cdylib', rustc=rustc)
            self.assertTrue(checked.report['ok'], checked.report['diagnostics'])
            hepta_lib = root / 'libhepta_converted.so'
            built = compile_rust(checked.rust, crate_type='cdylib', rustc=rustc,
                                 output=hepta_lib)
            self.assertTrue(built['ok'], built['diagnostics'])
            import ctypes
            native = ctypes.CDLL(str(cpp_lib))
            hepta = ctypes.CDLL(str(hepta_lib))
            for name, inputs in {
                'add': [(1, 2), (-9, 10), (2_000_000, -900_000)],
                'triangle': [(0,), (1,), (10,), (50,), (200,)],
                'clamp_low': [(-40,), (0,), (99,)],
                'inferred': [(-100,), (0,), (100,)],
            }.items():
                reference_fn = getattr(native, 'hepta_cxx_' + name)
                hepta_fn = getattr(hepta, name)
                for fn in (reference_fn, hepta_fn):
                    fn.restype = ctypes.c_int32
                    fn.argtypes = [ctypes.c_int32] * len(inputs[0])
                for args in inputs:
                    with self.subTest(name=name, args=args):
                        self.assertEqual(reference_fn(*args), hepta_fn(*args))

    def test_dangling_output_symlink_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'reference.cc'
            source.write_text('int f(int n) noexcept { return n + 1; }')
            target = root / 'alias.hepta'
            redirected = root / 'unintended.hepta'
            target.symlink_to(redirected)
            self.assertEqual(main([str(source), '-o', str(target)]), 1)
            self.assertTrue(target.is_symlink())
            self.assertFalse(redirected.exists())

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
