"""Immediate copy-array rvalue reads preserve order and bounds in native C."""
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import unittest

from hepta.ast import HeptaError
from hepta.backend import emit_rust
from hepta.c_backend import emit_c
from hepta.checker import check
from hepta.parser import parse

CC = os.environ.get('CC') or shutil.which('gcc')
RUSTC = os.environ.get('RUSTC') or shutil.which('rustc')

SUCCESS = '''
struct Matrix { rows: [[i64; 2]; 2] }
struct Cell { x: i64 }
fn next(n: mut i64) -> i64 effects { write, panic } { n = n + 1; return n; }
fn values(n: mut i64) -> [i64; 2] effects { write, panic } {
    return [next(mut n), next(mut n)];
}
fn matrix(n: mut i64) -> Matrix effects { write, panic } {
    return Matrix { rows: [values(mut n), values(mut n)] };
}
fn index() -> usize effects {} { return 1; }
fn position(n: read i64) -> usize effects { panic } { return (n - 1) as usize; }
fn main() -> Unit effects { write, panic, io, alloc, block } {
    let mut n: i64 = 0;
    assert([10,20][index()] == 20);
    assert([false, true][index()]);
    assert([1.5, 2.5][index()] == 2.5);
    assert([Cell { x: 4 }, Cell { x: 9 }][index()].x == 9);
    assert(values(mut n)[position(read n)] == 2);
    assert(n == 2);
    assert(len(values(mut n)) == 2);
    assert(n == 4);
    assert(matrix(mut n).rows[1][0] == 7);
    assert(n == 8);
    assert([[1,2],[3,4]][index()][0] == 3);
    assert(true || values(mut n)[0] == 0);
    assert(!(false && values(mut n)[0] == 0));
    assert(n == 8);
    print_i64(n);
}
'''


def frontend(source):
    p = parse(source)
    c = check(p)
    if not c.ok:
        raise AssertionError([d.to_dict() for d in c.diagnostics])
    return p, c


@unittest.skipUnless(CC, 'GCC required')
class CArrayValueTests(unittest.TestCase):
    def execute(self, source, success=True, expected=''):
        p, c = frontend(source)
        with tempfile.TemporaryDirectory() as td:
            path = Path(td)
            (path / 'program.c').write_text(emit_c(p, c))
            for opt in ('-O0', '-O3'):
                exe = path / 'program'
                result = subprocess.run([CC, '-std=c11', opt, '-fsanitize=undefined',
                    '-fno-sanitize-recover=all', str(path / 'program.c'), '-lm', '-o', str(exe)],
                    capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stderr)
                run = subprocess.run([str(exe)], capture_output=True, text=True, timeout=10)
                self.assertEqual(run.returncode == 0, success, run.stderr)
                if not success:
                    self.assertEqual(run.returncode, -signal.SIGABRT, run.stderr)
                self.assertNotIn('runtime error:', run.stderr)
                self.assertEqual(run.stdout, expected)

    def test_literals_returns_fields_nested_order_and_short_circuit(self):
        self.execute(SUCCESS, expected='8\n')

    def test_resource_gated_temporary_projection_remains_rejected(self):
        p, c = frontend('''fn pair<T>(x: T) -> [T; 2] effects {} { return [x, x]; }
            fn main() -> Unit effects { panic } { assert(pair::<i64>(7)[1] == 7); }''')
        with self.assertRaisesRegex(HeptaError, 'Projection from temporary aggregate'):
            emit_c(p, c)

    def test_dynamic_out_of_bounds_aborts_without_undefined_access(self):
        for ix in ('2', '18446744073709551615'):
            self.execute('''fn bad() -> usize effects {} { return ''' + ix + '''; }
                fn main() -> Unit effects { panic } { let x: i64 = [10,20][bad()]; }''', success=False)

    def test_named_array_mutation_still_uses_original_storage(self):
        self.execute('''fn main() -> Unit effects { write, panic } {
            let mut xs: [i64; 2] = [1,2]; xs[1] = 9; assert(xs[1] == 9);
        }''')

    def test_frontend_still_rejects_temporary_borrows_and_resource_arrays(self):
        for source in [
            'fn use(x: read [i64; 2]) -> Unit effects {} {} fn main() -> Unit effects {} { use(read [1,2]); }',
            'fn main() -> Unit effects { alloc, panic } { let xs: [Buffer<u8>; 1] = [buffer(1)]; }',
        ]:
            with self.subTest(source=source):
                p = parse(source)
                self.assertFalse(check(p).ok)

    @unittest.skipUnless(RUSTC, 'Rust reference compiler unavailable')
    def test_same_source_rust_reference(self):
        p, c = frontend(SUCCESS)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / 'program.rs'
            src.write_text(emit_rust(p, c, crate_type='bin'))
            exe = root / 'reference'
            compile_result = subprocess.run([RUSTC, '--edition=2021', str(src), '-o', str(exe)], capture_output=True, text=True, timeout=60)
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            run = subprocess.run([str(exe)], capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(run.stdout, '8\n')
