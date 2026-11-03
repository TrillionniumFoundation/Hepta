"""Unit is a Copy payload, even though calls and returns have no result slot."""
import copy
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
from hepta.resource_ir import ResourceIRError, verify_resource_ir
from hepta.resource_lowering import lower_resource_ir

CC = os.environ.get('CC') or shutil.which('gcc')
RUSTC = os.environ.get('RUSTC') or shutil.which('rustc')
PREFIX = '''
fn noop()->Unit effects{} {}
fn id<T:Copy>(x:T)->T effects{} {return x;}
fn first<T:Copy>(a:T,b:T)->T effects{} {return a;}
fn bump(x:mut u64)->Unit effects{write,panic}{x=x+1;}
fn digit(x:mut u64,d:u64)->Unit effects{write,panic}{x=x*10+d;}
'''
CASES = {
 'generic_unit_argument': 'let u=id::<Unit>(noop());let v=id::<Unit>(id::<Unit>(move u));',
 'effectful_generic_arguments': 'let mut x:u64=0;let u=first::<Unit>(digit(mut x,1),digit(mut x,2));assert(x==12);',
 'unit_result_while_owner_live': 'let b=buffer(1);let mut x:u64=0;let r:Result<Unit,u8>=Result::Ok(bump(mut x));match r{Result::Ok(u)=>{let v=id::<Unit>(move u);assert(x==1);},Result::Err(e)=>{assert(false);}}drop(move b);',
 'unit_from_drop_is_payload': 'let b=buffer(1);let r:Result<Unit,u8>=Result::Ok(drop(move b));match r{Result::Ok(u)=>{},Result::Err(e)=>{assert(false);}}',
 'owned_enum_unit_and_owner_arms': 'let a=Outcome::Ready(noop());match move a{Outcome::Ready(u)=>{let v=id::<Unit>(u);},Outcome::Failed(b)=>{drop(move b);}}let c=Outcome::Failed(buffer(2));match move c{Outcome::Ready(u)=>{},Outcome::Failed(b)=>{assert(len(b)==2);drop(move b);}}',
 'unit_payload_order_and_loop': 'let mut x:u64=0;for i in 0..3{let p=Steps::Done(digit(mut x,1),digit(mut x,2),x);match p{Steps::Done(a,b,n)=>{assert(n==x);}}}assert(x==121212);',
 'bound_unit_returns': 'again(true);again(false);',
}
DECLS = '''
enum Outcome{Ready(Unit),Failed(Buffer<u8>)}
enum Steps{Done(Unit,Unit,u64)}
fn again(flag:bool)->Unit effects{} {let u=noop();if flag{return u;}return move u;}
'''
TRAPS = {
 'trapping_argument': 'let u=id::<Unit>(assert(false));',
 'reversed_argument_order': 'let mut x:u64=0;let u=first::<Unit>(digit(mut x,2),digit(mut x,1));assert(x==12);',
 'reversed_payload_order': 'let mut x:u64=0;let p=Steps::Done(digit(mut x,2),digit(mut x,1),x);assert(x==12);',
}


def frontend(body):
    p = parse(PREFIX+DECLS+'fn main()->Unit effects{alloc,block,panic,write}{'+body+'}')
    c = check(p)
    if not c.ok:
        raise AssertionError([d.to_dict() for d in c.diagnostics])
    return p,c


class ResourceUnitValueTests(unittest.TestCase):
    def test_all_unit_copy_contexts_verify_and_emit(self):
        for name,body in CASES.items():
            with self.subTest(name=name):
                p,c = frontend(body)
                self.assertTrue(verify_resource_ir(lower_resource_ir(p,c))['ok'])
                self.assertIn('int main(void)',emit_c(p,c))

    def test_unit_call_result_stays_absent_but_payload_has_typed_slot(self):
        p,c = frontend(CASES['unit_from_drop_is_payload']+CASES['generic_unit_argument'])
        graph = lower_resource_ir(p,c)
        main = next(f for f in graph['functions'] if f['name']=='main')
        slots = {v['id']:v['type'] for v in main['locals']}
        ops = [op for b in main['blocks'] for op in b['ops']]
        for op in ops:
            if op['op']=='call' and op['function'] in {'noop','id'}:
                self.assertIsNone(op['result'])
            if op['op']=='call' and op['function']=='id':
                self.assertEqual(slots[op['args'][0]['id']],'Unit')
        pack = next(op for op in ops if op['op']=='pack')
        self.assertEqual(slots[pack['fields'][0]],'Unit')
        bad = copy.deepcopy(graph)
        bad_main = next(f for f in bad['functions'] if f['name']=='main')
        bad_pack = next(op for b in bad_main['blocks'] for op in b['ops'] if op['op']=='pack')
        bad_pack['fields'][0] = None
        self.assertFalse(verify_resource_ir(bad)['ok'])

    def test_bound_unit_return_retains_no_value_result(self):
        p,c = frontend(CASES['bound_unit_returns'])
        graph = lower_resource_ir(p,c)
        again = next(f for f in graph['functions'] if f['name']=='again')
        returns = [b['term'] for b in again['blocks'] if b['term']['op']=='return']
        self.assertEqual(len(returns),2)
        self.assertTrue(all(t['value'] is None and t['loan'] is None for t in returns))

    def test_explicit_unit_parameter_boundary_is_unchanged(self):
        c = check(parse('fn unsupported(x:Unit)->Unit effects{} {}'))
        self.assertFalse(c.ok)
        self.assertIn('E_UNIT_PARAMETER',[d.code for d in c.diagnostics])

    def test_unit_materialization_cannot_erase_owner_or_live_loan(self):
        cases = [
            ('let b=buffer(1);let u=id::<Unit>(noop());', 'E_LINEAR_UNCONSUMED'),
            ('let b=buffer(1);let r:Result<Unit,u8>=Result::Ok(drop(move b));drop(move b);', 'E_USE_AFTER_MOVE'),
            ('let mut x:u64=0;bad::<Unit>(mut x,bump(mut x));', 'E_RIR_LOAN_CONFLICT'),
        ]
        for body,code in cases:
            p = parse(PREFIX+'fn bad<T:Copy>(x:mut u64,u:T)->Unit effects{} {}'+
                      'fn main()->Unit effects{alloc,block,panic,write}{'+body+'}')
            c = check(p)
            if code.startswith('E_RIR_'):
                self.assertTrue(c.ok,c.diagnostics)
                with self.assertRaises(ResourceIRError) as error:
                    lower_resource_ir(p,c)
                self.assertEqual(error.exception.code,code)
            else:
                self.assertFalse(c.ok)
                self.assertIn(code,[d.code for d in c.diagnostics])

    def native(self,rust):
        for name,body in {**CASES,**TRAPS}.items():
            p,c = frontend(body)
            with self.subTest(name=name), tempfile.TemporaryDirectory() as td:
                root=Path(td)
                src=root/('program.rs' if rust else 'program.c')
                src.write_text(emit_rust(p,c,crate_type='bin') if rust else emit_c(p,c))
                for opt in ('0','3'):
                    exe=root/'program'
                    args=([RUSTC,'--edition=2021','-C','opt-level='+opt,'-C','overflow-checks=yes','-C','panic=abort',str(src),'-o',str(exe)] if rust else
                          [CC,'-std=c11','-O'+opt,'-fsanitize=undefined','-fno-sanitize-recover=all',str(src),'-lm','-o',str(exe)])
                    built=subprocess.run(args,capture_output=True,text=True,timeout=60)
                    self.assertEqual(built.returncode,0,built.stderr)
                    run=subprocess.run([str(exe)],capture_output=True,text=True,timeout=10)
                    self.assertEqual(run.returncode,-signal.SIGABRT if name in TRAPS else 0,run.stderr)
                    if not rust:
                        self.assertNotIn('runtime error:',run.stderr)

    @unittest.skipUnless(CC,'native GCC required')
    def test_native_c_unit_effects_and_trap_o0_o3(self):
        self.native(False)

    @unittest.skipUnless(RUSTC,'native Rust required')
    def test_native_rust_unit_effects_and_trap_o0_o3(self):
        self.native(True)


if __name__=='__main__':
    unittest.main()
