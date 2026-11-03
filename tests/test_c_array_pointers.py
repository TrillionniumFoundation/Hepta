"""Internal fixed-array pointer values, with public array ABI kept closed."""
import os
from pathlib import Path
import shutil
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
SOURCE = '''
fn read_row(p: raw const [i32;3], i: usize)->[i32;3] effects {unsafe} {
    unsafe {return load(p,i);}
}
fn replace_row(p: raw mut [i32;3], i: usize, row: [i32;3])->Unit effects {unsafe,write} {
    unsafe {store(p,i,row);}
}
fn main()->Unit effects {unsafe,write,panic} {
    let mut rows:[[i32;3];2]=[[1,2,3],[4,5,6]];
    unsafe {
        let p=ptr_mut(mut rows);
        let original=read_row(p as raw const [i32;3],1);
        replace_row(p,0,[7,8,9]);
        replace_row(p,1,[10,11,12]);
        let first=read_row(p as raw const [i32;3],0);
        let last=read_row(p as raw const [i32;3],1);
        assert(first[0]==7);assert(first[2]==9);
        assert(last[0]==10);assert(last[2]==12);
        assert(original[0]==4);assert(original[2]==6);
    }
    assert(rows[0][1]==8);assert(rows[1][1]==11);
    let cubes:[[[i32;2];2];2]=[[[1,2],[3,4]],[[5,6],[7,8]]];
    unsafe {let p=ptr_read(read cubes);let plane=load(p,1);assert(plane[1][1]==8);}
}
'''


def frontend(source):
    p = parse(source)
    c = check(p)
    if not c.ok:
        raise AssertionError([d.to_dict() for d in c.diagnostics])
    return p, c


class CArrayPointerTests(unittest.TestCase):
    def execute(self, source, *, rust=False):
        p, c = frontend(source)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = root / ('program.rs' if rust else 'program.c')
            path.write_text(emit_rust(p,c,crate_type='bin') if rust else emit_c(p,c))
            for opt in ('0','3'):
                exe = root / 'program'
                command = ([RUSTC, '--edition=2021', '-C', 'opt-level='+opt, '-C', 'overflow-checks=yes', str(path), '-o', str(exe)] if rust else
                    [CC, '-std=c11', '-O'+opt, '-Wall', '-Wextra', '-Werror=incompatible-pointer-types', '-fsanitize=undefined', '-fno-sanitize-recover=all', str(path), '-lm', '-o', str(exe)])
                result = subprocess.run(command,capture_output=True,text=True,timeout=60)
                self.assertEqual(result.returncode,0,result.stderr)
                run = subprocess.run([str(exe)],capture_output=True,text=True,timeout=10)
                self.assertEqual(run.returncode,0,run.stderr)
                self.assertNotIn('runtime error:',run.stderr)

    @unittest.skipUnless(CC,'native GCC required')
    def test_internal_array_pointer_reads_writes_and_copies(self):
        self.execute(SOURCE)

    @unittest.skipUnless(RUSTC,'native Rust required')
    def test_rust_oracle_for_identical_source(self):
        self.execute(SOURCE,rust=True)

    def test_public_array_pointer_abi_stays_rejected(self):
        sources = [
            'extern "C" fn f(p:raw const [i32;3])->i32 effects {ffi};',
            'export "C" fn f(p:raw mut [i32;3])->raw mut [i32;3] effects {} {return p;}',
            'extern "C" fn f(p:raw const raw mut [i32;3])->i32 effects {ffi};',
            'repr(C) struct Holder { p:raw const [i32;3] } extern "C" fn f(p:Holder)->i32 effects {ffi};',
        ]
        for source in sources:
            with self.subTest(source=source):
                p,c = frontend(source)
                with self.assertRaises(HeptaError) as error:
                    emit_c(p,c,crate_type='staticlib')
                self.assertIn('C ABI pointers to arrays',str(error.exception))

    def test_volatile_array_access_stays_rejected(self):
        p = parse('fn f(p:raw const [i32;3])->[i32;3] effects {unsafe,io} {unsafe{return volatile_load(p,0);}}')
        c = check(p)
        self.assertFalse(c.ok)
        self.assertIn('E_VOLATILE_TYPE',[d.code for d in c.diagnostics])

    def test_const_array_pointer_store_stays_rejected(self):
        p = parse('fn f(p:raw const [i32;3])->Unit effects {unsafe,write} {unsafe{store(p,0,[1,2,3]);}}')
        c = check(p)
        self.assertFalse(c.ok)
        self.assertIn('E_READ_ONLY',[d.code for d in c.diagnostics])

    def test_zero_length_array_pointee_stays_rejected(self):
        p,c = frontend('fn f(p:raw const [i32;0])->Unit effects {} {}')
        with self.assertRaises(HeptaError) as error:
            emit_c(p,c,crate_type='staticlib')
        self.assertIn('Zero-length',str(error.exception))
