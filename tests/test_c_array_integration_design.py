"""Counterexamples and current admission boundaries, not production lowering."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.ast import HeptaError
from hepta.c_backend import emit_c
from hepta.checker import check
from hepta.parser import parse
from hepta.resource_ir import ResourceIRError
from hepta.resource_lowering import lower_resource_ir

ROOT = Path(__file__).resolve().parents[1]

class ArrayIntegrationDesignTests(unittest.TestCase):
    def checked(self, source):
        p = parse(source)
        c = check(p)
        self.assertTrue(c.ok, [d.to_dict() for d in c.diagnostics])
        return p, c

    def test_current_unsafe_escape_is_not_a_lifetime_certificate(self):
        # Static-only witness of an existing unsafe contract. NEVER compile or
        # invoke this function: its returned raw pointer outlives local storage.
        p, c = self.checked('''fn escape()->raw mut [i32;3] effects {unsafe} {
          let mut rows:[[i32;3];2]=[[1,2,3],[4,5,6]];
          unsafe {return ptr_mut(mut rows);}
        }''')
        self.assertIn('__hepta_cb_fn_escape', emit_c(p, c, crate_type='staticlib'))
        with self.assertRaises(ResourceIRError) as error:
            lower_resource_ir(p, c)
        self.assertEqual(error.exception.code, 'E_RIR_LOWER_UNSUPPORTED')
        self.assertIn('raw', str(error.exception))

    def test_generic_profile_retains_independent_raw_pointer_refusal(self):
        p, c = self.checked('''fn id<T>(x:T)->T effects {} {return x;}
        fn read_first(p:raw const [i32;3])->i32 effects {unsafe,panic} {
          unsafe {let row=load(p,0);return id::<i32>(row[0]);}
        }''')
        with self.assertRaises(HeptaError) as error:
            emit_c(p, c, crate_type='staticlib')
        self.assertEqual(error.exception.diagnostic.code, 'E_C_RESOURCE_IR')
        self.assertIn('E_RIR_LOWER_UNSUPPORTED', str(error.exception))
        self.assertIn('raw', str(error.exception))

    @unittest.skipUnless(shutil.which('gcc'), 'native GCC required')
    def test_existing_internal_field_pointer_forwarding(self):
        # Actual existing Hepta lowering, deliberately no extern/export boundary.
        p, c = self.checked('''struct Matrix {rows:[[i32;3];2]}
        fn forward(p:raw mut [i32;3])->raw mut [i32;3] effects {} {return p;}
        fn write_row(p:raw mut [i32;3])->Unit effects {unsafe,write} {
          unsafe {store(forward(p),1,[7,8,9]);}
        }
        fn main()->Unit effects {unsafe,write,panic} {
          let mut m=Matrix {rows:[[1,2,3],[4,5,6]]};
          unsafe {
            let p=ptr_mut(mut m.rows);
            let old=load(p as raw const [i32;3],1);
            write_row(p);
            assert(old[1]==5);
          }
          assert(m.rows[1][1]==8);assert(m.rows[0][1]==2);
        }''')
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            (d/'internal.c').write_text(emit_c(p, c))
            for opt in ('0', '3'):
                result = subprocess.run(['gcc', '-std=c11', '-Wall', '-Wextra', '-Werror=incompatible-pointer-types',
                    '-O'+opt, '-fstrict-aliasing', '-fsanitize=undefined', '-fno-sanitize-recover=all',
                    str(d/'internal.c'), '-lm', '-o', str(d/'run')], capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stderr)
                result = subprocess.run([str(d/'run')], capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn('runtime error:', result.stderr)

    @unittest.skipUnless(shutil.which('gcc'), 'native GCC required')
    def test_live_counterexamples_disprove_copy_bridges(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            for opt in ('0', '3'):
                flags = ['gcc', '-std=c11', '-pedantic-errors', '-Wall', '-Wextra', '-Werror',
                         '-O'+opt, '-fstrict-aliasing', '-fsanitize=undefined', '-fno-sanitize-recover=all']
                for name, path in [
                    ('storage', ROOT/'experiments/c_native_array_storage/storage.c'),
                    ('counterexamples', ROOT/'experiments/c_array_integration/counterexamples.c'),
                ]:
                    result = subprocess.run(flags + ['-c', str(path), '-o', str(d/(name+'.o'))], capture_output=True, text=True, timeout=60)
                    self.assertEqual(result.returncode, 0, result.stderr)
                result = subprocess.run(flags + [str(d/'storage.o'), str(d/'counterexamples.o'), '-o', str(d/'run')], capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stderr)
                result = subprocess.run([str(d/'run')], capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn('runtime error:', result.stderr)

if __name__ == '__main__':
    unittest.main()
