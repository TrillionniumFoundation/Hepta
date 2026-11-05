"""Bounded builtin Result lowering with native Copy-value and refusal controls."""
from pathlib import Path
import subprocess
import sys
import unittest

from hepta.ast import HeptaError, Type
from hepta.c_backend import CEmitter, emit_c
from hepta.checker import _Checker
from hepta.pipeline import analyze
import test_c_fieldless_enums as fieldless

ROOT = Path(__file__).resolve().parents[1]


class ResultTests(unittest.TestCase):
    setUp = fieldless.FieldlessEnumTests.setUp
    frontend = fieldless.FieldlessEnumTests.frontend
    execute = fieldless.FieldlessEnumTests.execute

    def test_builtin_definition_matches_frontend_without_ast_mutation(self):
        program, checked = self.frontend('fn main()->Unit effects {} {}')
        emitter = CEmitter(program, checked, 'bin')
        self.assertEqual(emitter.enums['Result'], _Checker(program).enums['Result'])
        self.assertEqual(program.enums, [])
        self.assertEqual(emitter.variant_tags['Result'], {'Ok': 0, 'Err': 1})
        emitted = emitter.emit()
        self.assertNotIn('__hepta_cb_enum_', emitted)

    def test_expected_and_explicit_success_and_error(self):
        self.execute('''fn value(ok:bool)->Result<i32,u8> effects {} {
            if ok {return Result::Ok(17);}return Result::Err(23);
        }
        fn code(r:Result<i32,u8>)->i32 effects {} {
            match r {Result::Err(e)=>{return (e as i32);},Result::Ok(x)=>{return x;}}
        }
        fn main()->Unit effects {panic} {
            let a:Result<i32,u8>=Result::Ok(7);let b=Result::<i32,u8>::Err(11);
            assert(code(a)==7);assert(code(b)==11);assert(code(value(true))==17);
            assert(code(value(false))==23);assert(code(Result::Ok(29))==29);
        }''')

    def test_distinct_reordered_and_scalar_specializations(self):
        self.execute('''fn main()->Unit effects {panic} {
            let a=Result::<i64,u8>::Ok(-1234567);let b=Result::<u8,i64>::Err(-7654321);
            let c=Result::<bool,f64>::Ok(true);let d=Result::<f32,bool>::Ok(2.5);
            let e=Result::<bool,f64>::Err(3.25);
            match a {Result::Ok(x)=>{assert(x==-1234567);},Result::Err(_)=>{assert(false);}}
            match b {Result::Err(x)=>{assert(x==-7654321);},Result::Ok(_)=>{assert(false);}}
            match c {Result::Ok(x)=>{assert(x);},Result::Err(_)=>{assert(false);}}
            match d {Result::Ok(x)=>{assert(x==2.5);},Result::Err(_)=>{assert(false);}}
            match e {Result::Err(x)=>{assert(x==3.25);},Result::Ok(_)=>{assert(false);}}
        }''')

    def test_both_variants_hold_arrays_and_records(self):
        self.execute('''struct Record{xs:[i32;2],flag:bool}
        fn main()->Unit effects {panic} {
            let a=Result::<[i32;2],Record>::Ok([31,37]);
            let b=Result::<[i32;2],Record>::Err(Record{xs:[41,43],flag:true});
            match a {Result::Ok(xs)=>{assert(xs[0]==31);assert(xs[1]==37);},Result::Err(_)=>{assert(false);}}
            match b {Result::Err(r)=>{assert(r.xs[0]==41);assert(r.xs[1]==43);assert(r.flag);},Result::Ok(_)=>{assert(false);}}
        }''')

    def test_nested_result_success_and_error_types(self):
        self.execute('''fn main()->Unit effects {panic} {
            let a:Result<Result<i32,u8>,Result<bool,i16>>=Result::Ok(Result::Err(47));
            let b:Result<Result<i32,u8>,Result<bool,i16>>=Result::Err(Result::Ok(true));
            match a {Result::Ok(inner)=>{match inner {Result::Err(n)=>{assert(n==47);},Result::Ok(_)=>{assert(false);}}},Result::Err(_)=>{assert(false);}}
            match b {Result::Err(inner)=>{match inner {Result::Ok(flag)=>{assert(flag);},Result::Err(_)=>{assert(false);}}},Result::Ok(_)=>{assert(false);}}
        }''')

    def test_generic_records_enums_and_result_compose(self):
        self.execute('''struct Box<T>{value:T} enum Maybe<T>{None,Some(T)}
        struct Packet<T>{value:Result<T,u8>} enum Reply<T>{Idle,Done(Result<T,u8>)}
        fn main()->Unit effects {panic} {
            let a=Box::<Result<i32,u8>>{value:Result::Ok(53)};
            let b=Result::<Maybe<Box<i32>>,u8>::Ok(Maybe::Some(Box{value:59}));
            let c=Reply::<Packet<i32>>::Done(Result::Ok(Packet{value:Result::Err(61)}));
            match a.value {Result::Ok(n)=>{assert(n==53);},Result::Err(_)=>{assert(false);}}
            match b {Result::Ok(m)=>{match m {Maybe::Some(box)=>{assert(box.value==59);},Maybe::None=>{assert(false);}}},Result::Err(_)=>{assert(false);}}
            match c {Reply::Done(r)=>{match r {Result::Ok(p)=>{match p.value {Result::Err(e)=>{assert(e==61);},Result::Ok(_)=>{assert(false);}}},Result::Err(_)=>{assert(false);}}},Reply::Idle=>{assert(false);}}
        }''')

    def test_payload_effects_execute_once_even_when_ignored(self):
        self.execute('''fn next(n:mut i32)->i32 effects {write,panic} {n=n+1;return n;}
        fn main()->Unit effects {write,panic} {
            let mut n:i32=0;
            let a=Result::<i32,i32>::Ok(next(mut n));
            let b=Result::<i32,i32>::Err(next(mut n));
            match a {Result::Ok(_)=>{},Result::Err(_)=>{assert(false);}}
            match b {Result::Err(_)=>{},Result::Ok(_)=>{assert(false);}}
            assert(n==2);
        }''')

    def test_nested_constructor_source_order_and_snapshots(self):
        self.execute('''struct Pair<T>{first:T,second:T}
        fn replace(x:mut Result<[i32;2],u8>)->Result<[i32;2],u8> effects {write} {x=Result::Err(71);return x;}
        fn main()->Unit effects {write,panic} {
            let mut x:Result<[i32;2],u8>=Result::Ok([67,69]);
            let p=Pair::<Result<[i32;2],u8>>{second:x,first:replace(mut x)};
            match p.second {Result::Ok(xs)=>{assert(xs[0]==67);assert(xs[1]==69);},Result::Err(_)=>{assert(false);}}
            match p.first {Result::Err(e)=>{assert(e==71);},Result::Ok(_)=>{assert(false);}}
            match x {Result::Err(e)=>{assert(e==71);},Result::Ok(_)=>{assert(false);}}
        }''')

    def test_scrutinee_once_and_payload_snapshot_before_mutation(self):
        self.execute('''fn next(n:mut i32)->Result<[i32;2],u8> effects {write,panic} {n=n+1;return Result::Ok([73,79]);}
        fn main()->Unit effects {write,panic} {
            let mut n:i32=0;
            match next(mut n) {Result::Ok(xs)=>{assert(xs[1]==79);},Result::Err(_)=>{assert(false);}}
            assert(n==1);
            let mut r:Result<[i32;2],u8>=Result::Ok([83,89]);
            match r {Result::Ok(xs)=>{r=Result::Err(97);assert(xs[0]==83);assert(xs[1]==89);},Result::Err(_)=>{assert(false);}}
            match r {Result::Err(e)=>{assert(e==97);},Result::Ok(_)=>{assert(false);}}
        }''')

    def test_copy_assignment_read_mut_slices_and_returns(self):
        self.execute('''fn score(r:read Result<i32,u8>)->i32 effects {} {
            match r {Result::Ok(n)=>{return n;},Result::Err(e)=>{return (e as i32);}}
        }
        fn copy(r:read Result<i32,u8>)->Result<i32,u8> effects {} {return r;}
        fn replace(r:mut Result<i32,u8>)->Unit effects {write} {r=Result::Err(107);}
        fn visit(rs:mut [Result<i32,u8>])->Unit effects {write,panic} {for i in 0..len(rs) {replace(mut rs[i]);}}
        fn main()->Unit effects {write,panic} {
            let mut rs:[Result<i32,u8>;2]=[Result::Ok(101),Result::Err(103)];
            let before=rs;let saved=copy(read rs[0]);visit(mut rs);
            assert(score(read before[0])==101);assert(score(read before[1])==103);
            assert(score(read saved)==101);assert(score(read rs[0])==107);assert(score(read rs[1])==107);
            let mut r=saved;r=copy(read before[1]);assert(score(read r)==103);
        }''')

    def test_nested_matches_return_continue_and_arm_scopes(self):
        self.execute('''fn code(r:Result<i32,u8>)->i32 effects {panic} {
            match r {Result::Err(x)=>{return (x as i32);},Result::Ok(x)=>{if x>0 {return x;}}}return -1;
        }
        fn main()->Unit effects {write,panic} {
            let mut total:i32=0;
            for i in 0..4 {let r:Result<i32,u8>=Result::Ok((i as i32));
                match r {Result::Ok(value)=>{total=total+code(Result::Ok(value));},Result::Err(value)=>{total=total+(value as i32);}}}
            assert(total==5);assert(code(Result::Err(109))==109);
        }''')

    def test_raw_pointer_payload_keeps_explicit_unsafe_boundary(self):
        self.execute('''fn main()->Unit effects {panic,unsafe} {
            let xs:[i32;2]=[113,127];unsafe {
                let a=Result::<raw const i32,u8>::Ok(ptr_read(read xs));
                let b=Result::<u8,raw const i32>::Err(ptr_read(read xs));
                match a {Result::Ok(p)=>{assert(load(p,0)==113);},Result::Err(_)=>{assert(false);}}
                match b {Result::Err(p)=>{assert(load(p,1)==127);},Result::Ok(_)=>{assert(false);}}
            }
        }''')

    def test_result_is_shared_across_module_aliases_with_nominal_payloads(self):
        (self.root/'left.hepta').write_text('pub struct Item{value:i32} pub fn make()->Result<Item,u8> effects {} {return Result::Ok(Item{value:131});}')
        (self.root/'right.hepta').write_text('pub struct Item{value:u16} pub fn make()->Result<Item,u8> effects {} {return Result::Ok(Item{value:137});}')
        entry=self.root/'main.hepta'
        entry.write_text('''import left as a;import right as b;
        fn main()->Unit effects {panic} {
            let x:Result<a::Item,u8>=a::make();let y:Result<b::Item,u8>=b::make();
            match x {Result::Ok(i)=>{assert(i.value==131);},Result::Err(_)=>{assert(false);}}
            match y {Result::Ok(i)=>{assert(i.value==137);},Result::Err(_)=>{assert(false);}}
        }''')
        self.execute(project=entry)

    def test_public_cli_result_example(self):
        result=subprocess.run([sys.executable,'-m','hepta','run',str(ROOT/'examples/c_results.hepta'),'--backend','c'],cwd=ROOT,capture_output=True,timeout=30)
        self.assertEqual((result.returncode,result.stdout,result.stderr),(0,b'',b''))

    def test_unsupported_variants_fail_even_if_never_constructed(self):
        for typ in ['Unit','i128','[i32;0]','[Unit;2]','Result<Unit,u8>','raw const [i32;2]']:
            for result_type in [f'Result<i32,{typ}>',f'Result<{typ},u8>']:
                with self.subTest(type=result_type):
                    program,checked=self.frontend(f'fn unused(x:{result_type})->Unit effects {{}} {{}} fn main()->Unit effects {{}} {{}}')
                    with self.assertRaises(HeptaError) as raised:emit_c(program,checked)
                    self.assertEqual(raised.exception.diagnostic.code,'E_C_BACKEND_SUBSET')
        program,checked=self.frontend('fn main()->Unit effects {} {let x:Result<i32,Unit>=Result::Ok(3);}')
        with self.assertRaises(HeptaError) as raised:emit_c(program,checked)
        self.assertEqual(raised.exception.diagnostic.code,'E_C_BACKEND_SUBSET')

    def test_frontend_result_refusals_remain(self):
        cases=[
            ('fn f(x:Result<i32>)->Unit effects {} {}','E_GENERIC_ARITY'),
            ('fn f()->Result<i32,u8> effects {} {return Result::Ok(true);}','E_TYPE'),
            ('fn f(x:Result<Buffer<u8>,u8>)->Unit effects {} {}','E_GENERIC_COPY'),
            ('fn f(x:Result<i32,Cancellation>)->Unit effects {} {}','E_GENERIC_COPY'),
            ('fn f(x:Result<i32,u8>)->Unit effects {} {match x {Result::Ok(_)=>{}}}','E_MATCH_EXHAUSTIVE'),
            ('fn f(x:Result<i32,u8>)->Unit effects {write} {match x {Result::Ok(n)=>{n=2;},Result::Err(_)=>{}}}','E_IMMUTABLE'),
            ('fn f(x:Result<i32,u8>)->Unit effects {panic} {match x {Result::Ok(n)=>{},Result::Err(e)=>{}} assert(n==2);}','E_UNKNOWN_NAME'),
        ]
        for source,code in cases:
            with self.subTest(code=code):
                report=analyze(source,backend='c',native=False).report
                self.assertFalse(report['ok'],report)
                self.assertIn(code,{d['code'] for d in report['diagnostics']})

    def test_foreign_result_boundaries_remain_rejected(self):
        for source in [
            'pub export "C" fn f(x:Result<i32,u8>)->i32 effects {} {return 0;}',
            'extern "C" fn f(x:Result<i32,u8>)->i32 effects {};',
            'pub export "C" fn f()->Result<i32,u8> effects {} {return Result::Ok(1);}',
            'repr(C) struct Public{value:Result<i32,u8>}',
            'extern "C" fn f(x:raw const Result<i32,u8>)->Unit effects {};',
        ]:
            with self.subTest(source=source):
                report=analyze(source,backend='c',native=False).report
                self.assertFalse(report['ok'],report)
                self.assertIn('E_C_ABI',{d['code'] for d in report['diagnostics']})

    def test_conservative_borrow_and_generic_function_refusals_remain(self):
        source='''fn both(a:read Result<i32,u8>,b:mut Result<i32,u8>)->Unit effects {} {}
        fn main()->Unit effects {} {let mut r:Result<i32,u8>=Result::Ok(3);both(read r,mut r);}'''
        report=analyze(source,backend='c',native=False).report
        self.assertFalse(report['ok'],report)
        self.assertIn('E_C_BORROW',{d['code'] for d in report['diagnostics']})
        program,checked=self.frontend('fn same<T>(x:Result<T,u8>)->Result<T,u8> effects {} {return x;} fn main()->Unit effects {} {}')
        with self.assertRaises(HeptaError) as raised:emit_c(program,checked)
        self.assertEqual(raised.exception.diagnostic.code,'E_C_BACKEND_SUBSET')


if __name__ == '__main__':
    unittest.main()
