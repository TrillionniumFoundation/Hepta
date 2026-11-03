"""The independent 64-bit C target must not inherit Rust-only range checks."""
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


def main(body):
    return 'fn main()->Unit effects{panic,write}{'+body+'}'


INVALID = {
    'signed_above_max': main('let x:isize=9223372036854775808;'),
    'signed_below_min': main('let x:isize=-9223372036854775809;'),
    'unsigned_above_max': main('let x:usize=18446744073709551616;'),
    'huge_unsigned': main('let x:usize=1208925819614629174706176;'),
    'parameter_inference': 'fn id(x:isize)->isize effects{} {return x;}'+main('let x=id(9223372036854775808);'),
    'return_inference': 'fn bad()->usize effects{} {return 18446744073709551616;}'+main(''),
    'array_element': main('let x:[usize;2]=[0,18446744073709551616];'),
    'struct_field': 'struct Size {n:isize}'+main('let x=Size{n:9223372036854775808};'),
    'enum_payload': 'enum Size {N(usize)}'+main('let x=Size::N(18446744073709551616);'),
    'assignment': main('let mut x:usize=0;x=18446744073709551616;'),
    'binary_operand': main('let x:usize=0;assert(x != 18446744073709551616);'),
    'loop_bound': main('for i in (0 as usize)..18446744073709551616 {}'),
    'unselected_branch': main('if false {let x:isize=9223372036854775808;}'),
    'short_circuit': main('assert(true || (18446744073709551616 == (0 as usize)));'),
    'unused_generic': 'fn bad<T:Copy>(x:T)->usize effects{} {return 18446744073709551616;}'+main(''),
    'cast_does_not_rescue_invalid_operand': main('let x:isize=9223372036854775808;let y=x as u64;'),
}
VALID = '''
struct Bounds {low:isize,high:usize}
enum Size {N(usize)}
fn id<T:Copy>(x:T)->T effects{} {return x;}
fn signed(x:isize)->isize effects{} {return x;}
fn neg(x:isize)->isize effects{panic} {return -x;}
fn main()->Unit effects{panic,write}{
 let lo:isize=-9223372036854775808;
 let hi:isize=9223372036854775807;
 let max:usize=18446744073709551615;
 assert(lo < 0);assert(hi > 0);assert(max > (hi as usize));
 assert(signed(-9223372036854775808)==lo);
 let xs:[isize;2]=[-9223372036854775808,9223372036854775807];
 assert(xs[0]==lo);assert(xs[1]==hi);
 let b=Bounds{low:-9223372036854775808,high:18446744073709551615};
 assert(b.low==lo);assert(b.high==max);
 let e=Size::N(18446744073709551615);
 match e {Size::N(n)=>{assert(n==max);}}
 assert(id::<usize>(18446744073709551615)==max);
 let wide:u64=18446744073709551615;assert((wide as isize)==-1);
 let signed_all:i64=-1;assert((signed_all as usize)==max);
 assert((max as u8)==255);assert((lo as u64)==9223372036854775808);
 assert(wrapping_add(max,1)==0);
}
'''
TRAP = 'fn neg(x:isize)->isize effects{panic}{return -x;}'+main('let x=neg(-9223372036854775808);')


def frontend(source):
    p = parse(source, path='pointer-literals.hepta')
    c = check(p)
    if not c.ok:
        raise AssertionError([d.to_dict() for d in c.diagnostics])
    return p,c


class CPointerLiteralTests(unittest.TestCase):
    def test_target_range_rejected_before_c_emission(self):
        for name,source in INVALID.items():
            with self.subTest(name=name):
                p,c = frontend(source)
                with self.assertRaises(HeptaError) as error:
                    emit_c(p,c)
                self.assertEqual(error.exception.diagnostic.code,'E_C_INTEGER_RANGE')
                self.assertEqual(error.exception.diagnostic.span.path,'pointer-literals.hepta')

    def test_signed_minimum_is_only_exempt_directly_under_negation(self):
        for expression in ('9223372036854775808','-(9223372036854775809)'):
            p,c = frontend(main('let x:isize='+expression+';'))
            with self.assertRaises(HeptaError):
                emit_c(p,c)
        for expression in ('-9223372036854775808','-(9223372036854775808)','--9223372036854775808'):
            p,c = frontend(main('let x:isize='+expression+';'))
            self.assertIn('INTPTR_MIN',emit_c(p,c))

    def test_valid_boundaries_and_intentional_casts_emit(self):
        p,c = frontend(VALID)
        self.assertIn('INTPTR_MIN',emit_c(p,c))
        self.assertIn('18446744073709551615',emit_rust(p,c,crate_type='bin'))

    def native(self, rust):
        for name,source in [('boundaries_and_casts',VALID),('negating_minimum_traps',TRAP)]:
            p,c = frontend(source)
            with self.subTest(name=name), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                src = root / ('program.rs' if rust else 'program.c')
                src.write_text(emit_rust(p,c,crate_type='bin') if rust else emit_c(p,c))
                for opt in ('0','3'):
                    exe = root/'program'
                    command = ([RUSTC,'--edition=2021','-C','opt-level='+opt,'-C','overflow-checks=yes','-C','panic=abort',str(src),'-o',str(exe)] if rust else
                               [CC,'-std=c11','-O'+opt,'-fsanitize=undefined','-fno-sanitize-recover=all',str(src),'-lm','-o',str(exe)])
                    built = subprocess.run(command,capture_output=True,text=True,timeout=60)
                    self.assertEqual(built.returncode,0,built.stderr)
                    run = subprocess.run([str(exe)],capture_output=True,text=True,timeout=10)
                    self.assertEqual(run.returncode,-signal.SIGABRT if name=='negating_minimum_traps' else 0,run.stderr)
                    if not rust:
                        self.assertNotIn('runtime error:',run.stderr)

    @unittest.skipUnless(CC,'native GCC required')
    def test_native_c_boundaries_casts_and_trap_o0_o3(self):
        self.native(False)

    @unittest.skipUnless(RUSTC,'native Rust required')
    def test_native_rust_boundaries_casts_and_trap_o0_o3(self):
        self.native(True)

    @unittest.skipUnless(RUSTC,'native Rust required')
    def test_native_rust_rejects_all_invalid_literals(self):
        for name,source in INVALID.items():
            p,c = frontend(source)
            with self.subTest(name=name), tempfile.TemporaryDirectory() as td:
                src = Path(td)/'program.rs'
                src.write_text(emit_rust(p,c,crate_type='bin'))
                result = subprocess.run([RUSTC,'--edition=2021',str(src),'-o',str(Path(td)/'program')],capture_output=True,text=True,timeout=60)
                self.assertNotEqual(result.returncode,0)
                self.assertIn('literal out of range',result.stderr)


if __name__=='__main__':
    unittest.main()
