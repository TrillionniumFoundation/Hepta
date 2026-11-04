"""Ordinary assignment checks RHS ownership before its destination exactly once."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import unittest

from hepta.ast import HeptaError
from hepta.backend import compile_rust, emit_rust
from hepta.c_backend import compile_c, emit_c
from hepta.checker import _Checker, check
from hepta.parser import parse
from hepta.resource_ir import verify_resource_ir
from hepta.resource_lowering import lower_resource_ir
from tests.test_resource_evaluation_order import REJECTED

CC = os.environ.get('CC') or shutil.which('gcc')
RUSTC = os.environ.get('RUSTC') or shutil.which('rustc')
RETURNED = '''fn slot(out:mut [usize], data:take Buffer<u8>)->mut [usize] from out effects {alloc,block} {
    release(move data); return mut out;
}
fn main()->Unit effects {alloc,block,panic,write} {
    let owner=buffer(7); let mut values:[usize;1]=[0];
    slot(mut values,move owner)[0]=len(read owner);
    assert(values[0]==7);
}'''
INDEXED = '''fn position(data:take Buffer<u8>)->usize effects {alloc,block} {release(move data);return 0;}
fn main()->Unit effects {alloc,block,panic} {
    let owner=buffer(7);let mut values:[usize;1]=[0];
    values[position(move owner)]=len(read owner);assert(values[0]==7);
}'''
INDEX_MUTATION = '''fn payload(index:mut usize)->i64 effects {write} {index=1;return 42;}
fn main()->Unit effects {write,panic} {
    let mut values:[i64;2]=[0,0];let mut index:usize=0;
    values[index]=payload(mut index);assert(values[0]==0);assert(values[1]==42);
}'''
CONTEXT = '''struct Box<T>{value:T}
fn view<T>(b:mut Box<T>)->mut Box<T> effects {} {return mut b;}
fn main()->Unit effects {write,panic} {
    let mut tiny:u8=0;tiny=255;assert(tiny==255);
    let mut values:[u8;2]=[0,0];values[0]=255;assert(values[0]==255);values=[255,1];assert(values[1]==1);
    let mut b:Box<u8>=Box{value:0};view::<u8>(mut b).value=255;assert(b.value==255);
    let mut nested:Box<Box<u8>>=Box{value:Box{value:0}};
    view::<Box<u8>>(mut nested).value=Box{value:255};assert(nested.value.value==255);
    let mut tag:Result<u8,u16>=Result::Ok(0);tag=Result::Ok(255);
    match tag {Result::Ok(x)=>{assert(x==255);},Result::Err(e)=>{assert(false);}}
}'''
HELPER = r'''#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
void event(int64_t code) {
    putchar((int)('0'+code));fflush(stdout);
    const char *failure=getenv("HEPTA_ASSIGN_FAIL");
    if(failure && failure[0]=='0'+code) abort();
}
'''
TRACE = '''extern "C" fn event(code:i64)->Unit effects {ffi};
fn value()->usize effects {ffi,unsafe} {unsafe {event(1);}return 7;}
fn target(out:mut [usize])->mut [usize] effects {ffi,unsafe} {unsafe {event(2);}return mut out;}
fn main()->Unit effects {ffi,unsafe,write,panic} {
    let mut out:[usize;1]=[0];
    unsafe {target(mut out)[0]=value();assert(out[0]==7);event(3);}
}'''


def frontend(source):
    p=parse(source);c=check(p)
    if not c.ok:
        raise AssertionError([d.to_dict() for d in c.diagnostics])
    return p,c


class AssignmentOrderFrontendTests(unittest.TestCase):
    def test_rhs_owner_read_precedes_returned_target_consumption(self):
        p,c=frontend(RETURNED)
        self.assertTrue(verify_resource_ir(lower_resource_ir(p,c))['ok'])

    def test_rhs_owner_read_precedes_named_index_consumption(self):
        p,c=frontend(INDEXED)
        self.assertTrue(verify_resource_ir(lower_resource_ir(p,c))['ok'])
        with self.assertRaises(HeptaError) as caught:
            emit_c(p,c)
        self.assertEqual(caught.exception.diagnostic.code,'E_C_BACKEND_EVALUATION')

    def test_rhs_consuming_destination_or_its_index_rejects(self):
        sources=list(REJECTED.values())+['''fn dispose(data:take Buffer<u8>)->u8 effects {alloc,block} {release(move data);return 7;}
        fn main()->Unit effects {alloc,block,panic} {let mut out=buffer(8);out[0]=dispose(move out);}''']
        for source in sources:
            with self.subTest(source=source):
                checked=check(parse(source))
                self.assertFalse(checked.ok)
                self.assertIn('E_USE_AFTER_MOVE',[d.code for d in checked.diagnostics])

    def test_frozen_original_resource_negatives_still_reject(self):
        raw=(Path(__file__).parent/'fixtures/assignment_order/baseline.json').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),'1d79ea5e0064569df4077260854e3fda89a2525a7b54cadcb9dcb8829ca54b93')
        original=json.loads(raw)
        self.assertEqual(set(original['cases']),set(REJECTED))
        for name,source in REJECTED.items():
            case=original['cases'][name]
            self.assertEqual(case['source_sha256'],hashlib.sha256(source.encode()).hexdigest())
            result=verify_resource_ir(case['resource_ir'])
            self.assertFalse(result['ok'])
            self.assertIn('E_RIR_USE_AFTER_MOVE',str(result['diagnostics']))

    def test_pure_hints_preserve_narrow_and_nominal_inference(self):
        p,c=frontend(CONTEXT)
        self.assertTrue(verify_resource_ir(lower_resource_ir(p,c))['ok'])

    def test_hint_and_real_check_do_not_double_visit_effectful_operands(self):
        p=parse(RETURNED);assignment=p.functions[1].body[2]
        target=assignment.data['target'];rhs=assignment.data['expr'];seen=[]
        class RecordingChecker(_Checker):
            def expr(self,expression,*args,**kwargs):
                if expression is target or expression is rhs:
                    seen.append('target' if expression is target else 'rhs')
                return super().expr(expression,*args,**kwargs)
        checked=RecordingChecker(p).run()
        self.assertTrue(checked.ok,[d.to_dict() for d in checked.diagnostics])
        self.assertEqual(seen,['rhs','target'])

    def test_named_mutability_type_range_and_read_permissions_remain_enforced(self):
        cases=[
          ('fn f()->Unit effects {} {let x:u8=0;x=1;}','E_IMMUTABLE'),
          ('fn f()->Unit effects {} {let mut x:u8=0;x=256;}','E_INTEGER_RANGE'),
          ('fn f()->Unit effects {} {let mut x:u8=0;x=true;}','E_TYPE'),
          ('fn f(x:read u8)->Unit effects {} {x=1;}','E_READ_ONLY'),
          ('fn view(x:read [u8])->read [u8] effects {} {return read x;} fn f(x:mut [u8])->Unit effects {panic,write} {view(read x)[0]=1;}','E_READ_ONLY'),
          ('fn f()->Unit effects {} {missing=1;}','E_UNKNOWN_NAME'),
        ]
        for source,code in cases:
            with self.subTest(code=code):
                c=check(parse(source));self.assertFalse(c.ok)
                self.assertIn(code,[d.code for d in c.diagnostics])

    def test_live_owned_field_overwrite_remains_rejected(self):
        source='''struct Pair{left:Buffer<u8>,right:Buffer<u8>}
        fn reuse(x:take Buffer<u8>)->Buffer<u8> effects {} {return move x;}
        fn main()->Unit effects {alloc,block,panic} {
        let mut p=Pair{left:buffer(1),right:buffer(1)};
        p.left=reuse(move p.left);drop(move p);}'''
        c=check(parse(source));self.assertFalse(c.ok)
        self.assertIn('E_LINEAR_REASSIGN',[d.code for d in c.diagnostics])

    def test_stored_borrow_permission_and_scalar_context_are_preserved(self):
        source='''struct View<'a>{bytes:mut 'a [u8]}
        fn main()->Unit effects {alloc,block,panic,write} {
        let mut data=buffer(1);let mut v=View{bytes:mut data};v.bytes[0]=255;drop(move v);release(move data);}'''
        p,c=frontend(source)
        self.assertTrue(verify_resource_ir(lower_resource_ir(p,c))['ok'])
        bad=source.replace("bytes:mut 'a","bytes:read 'a").replace('bytes:mut data','bytes:read data').replace('drop(move v);','')
        c=check(parse(bad));self.assertFalse(c.ok)
        self.assertIn('E_READ_ONLY',[d.code for d in c.diagnostics])

    def test_stored_scalar_write_metadata_is_preserved(self):
        source="""struct View<'a>{value:mut 'a u8}
        fn main()->Unit effects {write} {let mut x:u8=0;let mut v=View{value:mut x};v.value=255;drop(move v);}"""
        _,c=frontend(source)
        self.assertIn('write',c.effects['main'])
        c=check(parse(source.replace('effects {write}','effects {}')))
        self.assertFalse(c.ok)
        self.assertIn('E_EFFECT',[d.code for d in c.diagnostics])

    def test_rhs_mutation_keeps_named_index_runtime_semantics(self):
        frontend(INDEX_MUTATION)


class AssignmentOrderNativeTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='hepta-assignment-order-')
        self.addCleanup(temporary.cleanup);self.root=Path(temporary.name)

    def build(self,source,backend,optimize,helper=False):
        p,c=frontend(source);exe=self.root/'program';links=[]
        if helper:
            path=self.root/'events.c';path.write_text(HELPER)
            if backend=='rust':
                obj=self.root/'events.o'
                proc=subprocess.run([CC,'-std=c11','-c',str(path),'-o',str(obj)],capture_output=True,text=True,timeout=30)
                self.assertEqual(proc.returncode,0,proc.stderr);links=[str(obj)]
            else: links=[str(path)]
        result=(compile_c(emit_c(p,c),cc=CC,output=exe,optimize=optimize,sanitize=True,link_args=links) if backend=='c' else
                compile_rust(emit_rust(p,c,crate_type='bin'),rustc=RUSTC,output=exe,crate_type='bin',optimize=optimize,link_args=links))
        self.assertTrue(result['ok'],result['diagnostics']);return exe

    def execute(self,exe,expected=b'',failure=None):
        env=os.environ.copy();env.pop('HEPTA_ASSIGN_FAIL',None)
        if failure: env['HEPTA_ASSIGN_FAIL']=failure
        result=subprocess.run([str(exe)],capture_output=True,env=env,timeout=10)
        self.assertEqual(result.returncode,-signal.SIGABRT if failure else 0,result.stderr)
        self.assertEqual(result.stdout,expected);self.assertNotIn(b'runtime error:',result.stderr)

    def cases(self,backend):
        for source in [RETURNED,INDEX_MUTATION,CONTEXT]+([INDEXED] if backend=='rust' else []):
            for optimize in [False,True]:
                with self.subTest(backend=backend,optimize=optimize,source=source):
                    self.execute(self.build(source,backend,optimize))

    def trace(self,backend):
        for optimize in [False,True]:
            exe=self.build(TRACE,backend,optimize,helper=True)
            self.execute(exe,b'123')
            self.execute(exe,b'1','1');self.execute(exe,b'12','2')

    @unittest.skipUnless(CC,'GCC required')
    def test_c_safe_ownership_context_and_mutation(self): self.cases('c')

    @unittest.skipUnless(CC,'GCC required')
    def test_c_rhs_then_target_effect_and_abort_prefix(self): self.trace('c')

    @unittest.skipUnless(RUSTC and Path(RUSTC).is_file(),'actual Rust required')
    def test_rust_safe_ownership_context_and_mutation(self): self.cases('rust')

    @unittest.skipUnless(CC and RUSTC and Path(RUSTC).is_file(),'GCC and actual Rust required')
    def test_rust_rhs_then_target_effect_and_abort_prefix(self): self.trace('rust')
