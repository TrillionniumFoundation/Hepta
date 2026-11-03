"""Call argument evaluation snapshots Copy values and retains earlier loans."""
import json
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
from hepta.resource_ir import ResourceIRError, verify_resource_ir
from hepta.resource_lowering import lower_resource_ir

CC = os.environ.get('CC') or shutil.which('gcc')
RUSTC = os.environ.get('RUSTC') or shutil.which('rustc')
PREFIX = '''
struct Pair {a:i32,b:i32}
fn assign(a:mut i32,b:i32)->Unit effects{write}{a=b;}
fn reverse(a:i32,b:mut i32)->Unit effects{write,panic}{b=a+1;}
fn see(a:read i32,b:i32)->Unit effects{} {}
fn bit(a:mut i32,b:bool)->Unit effects{} {}
fn identity(a:i32)->i32 effects{} {return a;}
fn noop(a:mut i32)->i32 effects{} {return 1;}
fn indexed(a:mut usize,b:read i32)->Unit effects{} {}
fn done(a:i32,b:i32)->Unit effects{} {}
'''
REJECTED = {
    'later_scalar_read': 'let mut x:i32=1;assign(mut x,x);',
    'later_field_read': 'let mut x:Pair=Pair{a:1,b:2};assign(mut x.a,x.a);',
    'conservative_index_alias': 'let mut x:[i32;2]=[1,2];assign(mut x[0],x[1]);',
    'nested_value_read': 'let mut x:i32=1;assign(mut x,identity(x));',
    'nested_mut_borrow_under_shared': 'let mut x:i32=1;see(read x,noop(mut x));',
    'short_circuit_rhs': 'let mut x:i32=1;bit(mut x,false && x==1);',
    'borrowed_index_evaluation': 'let mut i:usize=0;let x:[i32;2]=[1,2];indexed(mut i,read x[i]);',
}
ACCEPTED = {
    'copy_before_mutable_loan': 'let mut x:i32=4;reverse(x,mut x);assert(x==5);',
    'move_copy_before_mutable_loan': 'let mut x:i32=4;reverse(move x,mut x);assert(x==5);',
    'disjoint_fields': 'let mut x:Pair=Pair{a:1,b:2};assign(mut x.a,x.b);assert(x.a==2);',
    'shared_reads': 'let x:i32=1;see(read x,x);',
    'nested_loan_ends': 'let mut x:i32=1;done(noop(mut x),x);',
    'separate_nested_read': 'let mut x:i32=1;let y:i32=2;assign(mut x,identity(y));assert(x==2);',
    'separate_calls_end_loans': 'let mut x:i32=1;assign(mut x,2);assign(mut x,3);assert(x==3);',
}


def frontend(body):
    p = parse(PREFIX+'fn main()->Unit effects{write,panic}{'+body+'}')
    c = check(p)
    if not c.ok:
        raise AssertionError([d.to_dict() for d in c.diagnostics])
    return p,c


class CBorrowOrderTests(unittest.TestCase):
    def test_later_conflicting_access_rejected_by_c_gate(self):
        for name,body in REJECTED.items():
            with self.subTest(name=name):
                p,c = frontend(body)
                with self.assertRaises(HeptaError) as raised:
                    emit_c(p,c)
                self.assertEqual(raised.exception.diagnostic.code,'E_C_BORROW')

    def test_resource_verifier_independently_rejects_later_access(self):
        for name,body in REJECTED.items():
            with self.subTest(name=name):
                p,c = frontend(body)
                with self.assertRaises(ResourceIRError) as raised:
                    lower_resource_ir(p,c)
                self.assertIn('live loan',str(raised.exception))

    def test_copy_snapshot_precedes_later_borrow(self):
        p,c = frontend(ACCEPTED['copy_before_mutable_loan'])
        graph = lower_resource_ir(p,c)
        self.assertTrue(verify_resource_ir(json.loads(json.dumps(graph)))['ok'])
        main = next(f for f in graph['functions'] if f['name']=='main')
        ops = main['blocks'][0]['ops']
        call = next(op for op in ops if op['op']=='call' and op['function']=='reverse')
        borrow = next(op for op in ops if op['op']=='borrow')
        self.assertNotEqual(call['args'][0]['id'],borrow['place']['root'])
        earlier = ops[:ops.index(borrow)]
        self.assertTrue(any(op['op']=='use' and op.get('place',{}).get('root')==borrow['place']['root'] for op in earlier))
        self.assertEqual([op['id'] for op in ops if op['op']=='end_borrow'],[borrow['id']])

    def test_nonconflicting_neighbours_pass_both_gates(self):
        for name,body in ACCEPTED.items():
            with self.subTest(name=name):
                p,c = frontend(body)
                graph = lower_resource_ir(p,c)
                self.assertTrue(verify_resource_ir(json.loads(json.dumps(graph)))['ok'])
                self.assertIn('int main(void)',emit_c(p,c))

    def execute_neighbours(self, *, rust):
        for name,body in ACCEPTED.items():
            p,c = frontend(body)
            with self.subTest(name=name), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                source = root / ('program.rs' if rust else 'program.c')
                source.write_text(emit_rust(p,c,crate_type='bin') if rust else emit_c(p,c))
                for opt in ('0','3'):
                    exe = root / 'program'
                    command = ([RUSTC,'--edition=2021','-C','opt-level='+opt,'-C','overflow-checks=yes',str(source),'-o',str(exe)] if rust else
                        [CC,'-std=c11','-O'+opt,'-fsanitize=undefined','-fno-sanitize-recover=all',str(source),'-lm','-o',str(exe)])
                    result = subprocess.run(command,capture_output=True,text=True,timeout=60)
                    self.assertEqual(result.returncode,0,result.stderr)
                    result = subprocess.run([str(exe)],capture_output=True,text=True,timeout=10)
                    self.assertEqual(result.returncode,0,result.stderr)
                    self.assertNotIn('runtime error:',result.stderr)

    @unittest.skipUnless(CC,'native GCC required')
    def test_positive_native_c_o0_o3_ubsan(self):
        self.execute_neighbours(rust=False)

    @unittest.skipUnless(RUSTC,'native Rust required')
    def test_positive_native_rust_o0_o3(self):
        self.execute_neighbours(rust=True)

    @unittest.skipUnless(RUSTC,'native Rust required')
    def test_negative_rust_borrow_checker_oracle(self):
        for name,body in REJECTED.items():
            p,c = frontend(body)
            with self.subTest(name=name), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                source = root / 'program.rs'
                source.write_text(emit_rust(p,c,crate_type='bin'))
                result = subprocess.run([RUSTC,'--edition=2021','--error-format=json',str(source),'-o',str(root/'never')],capture_output=True,text=True,timeout=60)
                self.assertNotEqual(result.returncode,0)
                codes = {row.get('code',{}).get('code') for line in result.stderr.splitlines() if line.startswith('{') for row in [json.loads(line)] if row.get('code')}
                self.assertTrue(codes & {'E0502','E0503','E0499'},result.stderr)
                self.assertFalse((root/'never').exists())
