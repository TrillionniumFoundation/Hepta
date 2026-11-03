"""Match reads a returned Copy enum before dispatch, without consuming owners."""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import unittest

from hepta.backend import emit_rust
from hepta.c_backend import emit_c
from hepta.checker import check
from hepta.parser import parse
from hepta.resource_ir import verify_resource_ir
from hepta.resource_lowering import lower_resource_ir

CC = os.environ.get('CC') or shutil.which('gcc')
RUSTC = os.environ.get('RUSTC') or shutil.which('rustc')
PREFIX = '''
enum Choice { Yes(i32), No(i32) }
fn peek(x:read Choice)->read Choice effects {} {return read x;}
fn edit(x:mut Choice)->mut Choice effects {} {return mut x;}
fn forward(x:read Choice)->read Choice effects {} {return read peek(read x);}
fn observe(x:read Choice)->i32 effects {} {
    match x {Choice::Yes(n)=>{return n;},Choice::No(n)=>{return n;}}
}
'''
CASES = {
    'shared_yes': 'let x:Choice=Choice::Yes(7);match peek(read x){Choice::Yes(n)=>{assert(n==7);},Choice::No(n)=>{assert(false);}}assert(observe(read x)==7);',
    'shared_no': 'let x:Choice=Choice::No(8);match peek(read x){Choice::Yes(n)=>{assert(false);},Choice::No(n)=>{assert(n==8);}}',
    'mutable_snapshot_then_arm_write': 'let mut x:Choice=Choice::Yes(7);match edit(mut x){Choice::Yes(n)=>{x=Choice::No(9);assert(n==7);},Choice::No(n)=>{assert(false);}}assert(observe(read x)==9);',
    'returned_loan_chain': 'let mut x:Choice=Choice::No(8);match forward(read x){Choice::Yes(n)=>{assert(false);},Choice::No(n)=>{assert(n==8);}}x=Choice::Yes(3);assert(observe(read x)==3);',
    'nested_match': 'let x:Choice=Choice::Yes(7);let y:Choice=Choice::No(8);match peek(read x){Choice::Yes(n)=>{match forward(read y){Choice::Yes(m)=>{assert(false);},Choice::No(m)=>{assert(n+m==15);}}},Choice::No(n)=>{assert(false);}}',
    'held_read_parameter': 'let x:Choice=Choice::Yes(7);assert(observe(read x)==7);',
    'bound_copy': 'let mut x:Choice=Choice::Yes(7);let snapshot=peek(read x);x=Choice::No(9);match snapshot{Choice::Yes(n)=>{assert(n==7);},Choice::No(n)=>{assert(false);}}',
}
TRAP = 'let x:Choice=Choice::Yes(7);match peek(read x){Choice::Yes(n)=>{assert(false);},Choice::No(n)=>{}}'


def frontend(body, *, borrowed_observer=False):
    prefix = PREFIX.replace('match x {', 'match peek(read x) {') if borrowed_observer else PREFIX
    p = parse(prefix+'fn main()->Unit effects{write,panic}{'+body+'}')
    c = check(p)
    if not c.ok:
        raise AssertionError([d.to_dict() for d in c.diagnostics])
    return p,c


class ResourceCopyMatchTests(unittest.TestCase):
    def test_returned_loan_is_read_and_ended_before_switch(self):
        for name,body in CASES.items():
            with self.subTest(name=name):
                p,c = frontend(body,borrowed_observer=name=='held_read_parameter')
                graph = lower_resource_ir(p,c)
                self.assertTrue(verify_resource_ir(json.loads(json.dumps(graph)))['ok'])
                for fn in graph['functions']:
                    for block in fn['blocks']:
                        if block['term']['op'] != 'switch':
                            continue
                        ops = block['ops']
                        result_loans = [op['result_loan'] for op in ops if op['op']=='call' and op['result_loan']]
                        if result_loans:
                            loan = result_loans[-1]
                            use = next(i for i,op in enumerate(ops) if op['op']=='use' and op.get('loan')==loan)
                            end = next(i for i,op in enumerate(ops) if op['op']=='end_borrow' and op['id']==loan)
                            self.assertLess(use,end)
                            self.assertNotEqual(block['term']['src'],loan)
                self.assertIn('int main(void)',emit_c(p,c))

    def test_incoming_read_parameter_remains_read_only(self):
        p,c = frontend(CASES['shared_yes'],borrowed_observer=True)
        graph = lower_resource_ir(p,c)
        observer = next(fn for fn in graph['functions'] if fn['name']=='observe')
        self.assertEqual(observer['params'][0]['mode'],'read')
        self.assertTrue(all(op.get('id')!='p0' for block in observer['blocks'] for op in block['ops'] if op['op']=='end_borrow'))
        invalid = parse(PREFIX+'fn wrong(x:read Choice)->Unit effects{write}{match peek(read x){Choice::Yes(n)=>{x=Choice::No(n);},Choice::No(n)=>{}}}')
        self.assertFalse(check(invalid).ok)

    def test_unconsumed_returned_loan_is_still_rejected(self):
        p,c = frontend(CASES['shared_yes'])
        graph = lower_resource_ir(p,c)
        main = next(fn for fn in graph['functions'] if fn['name']=='main')
        first = main['blocks'][0]
        first['ops'] = [op for op in first['ops'] if op['op']!='end_borrow']
        self.assertFalse(verify_resource_ir(graph)['ok'])

    def test_owned_returned_enum_still_cannot_be_consumed(self):
        source = '''enum Owner {Data(Buffer<u8>), Empty(i32)}
fn peek(x:read Owner)->read Owner effects{} {return read x;}
fn main()->Unit effects{alloc,block,panic}{let x=Owner::Data(buffer(1));
match peek(read x){Owner::Data(b)=>{release(move b);},Owner::Empty(n)=>{}}drop(move x);}'''
        c = check(parse(source))
        self.assertFalse(c.ok)
        self.assertIn('E_MOVE_BORROW',[d.code for d in c.diagnostics])

    def native(self, *, rust):
        for name,body in {**CASES,'selected_arm_traps':TRAP}.items():
            p,c = frontend(body,borrowed_observer=name=='held_read_parameter')
            with self.subTest(name=name), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                source = root / ('program.rs' if rust else 'program.c')
                source.write_text(emit_rust(p,c,crate_type='bin') if rust else emit_c(p,c))
                for opt in ('0','3'):
                    exe = root / 'program'
                    command = ([RUSTC,'--edition=2021','-C','opt-level='+opt,'-C','overflow-checks=yes','-C','panic=abort',str(source),'-o',str(exe)] if rust else
                        [CC,'-std=c11','-O'+opt,'-fsanitize=undefined','-fno-sanitize-recover=all',str(source),'-lm','-o',str(exe)])
                    built = subprocess.run(command,capture_output=True,text=True,timeout=60)
                    self.assertEqual(built.returncode,0,built.stderr)
                    run = subprocess.run([str(exe)],capture_output=True,text=True,timeout=10)
                    self.assertEqual(run.returncode,-signal.SIGABRT if name=='selected_arm_traps' else 0,run.stderr)
                    if not rust:
                        self.assertNotIn('runtime error:',run.stderr)

    @unittest.skipUnless(CC,'native GCC required')
    def test_native_c_copy_match_and_trap_o0_o3(self):
        self.native(rust=False)

    @unittest.skipUnless(RUSTC,'native Rust required')
    def test_native_rust_copy_match_and_trap_o0_o3(self):
        self.native(rust=True)
