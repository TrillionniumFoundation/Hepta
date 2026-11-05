"""Internal Unit objects, ordered effects and unchanged foreign boundaries."""
from pathlib import Path
import os
import shutil
import signal
import subprocess
import sys
import unittest
from unittest.mock import patch

from hepta.ast import HeptaError
from hepta.backend import compile_rust, emit_rust
from hepta.c_backend import compile_c, emit_c
from hepta.pipeline import analyze
import test_c_fieldless_enums as fieldless

ROOT = Path(__file__).resolve().parents[1]


class UnitValueTests(unittest.TestCase):
    setUp = fieldless.FieldlessEnumTests.setUp
    frontend = fieldless.FieldlessEnumTests.frontend
    execute = fieldless.FieldlessEnumTests.execute

    def test_locals_copies_moves_assignments_and_explicit_returns(self):
        self.execute('''fn unit()->Unit effects {} {} fn copy()->Unit effects {} {return unit();}
        fn main()->Unit effects {write,panic} {
            let a=unit();let b:Unit=a;let mut c=move b;c=copy();
            let d=assert(true);let e=d;return c;
        }''')

    def test_unit_calls_return_early_and_execute_once(self):
        self.execute('''fn tick(n:mut i32)->Unit effects {write,panic} {n=n+1;}
        fn early(n:mut i32)->Unit effects {write,panic} {return tick(mut n);}
        fn main()->Unit effects {write,panic} {
            let mut n:i32=0;let mut x=tick(mut n);let y=x;x=early(mut n);let z=y;
            assert(n==2);
        }''')

    def test_records_preserve_source_field_order(self):
        self.execute('''struct Marks {first:Unit,second:Unit,n:i32}
        fn mark(n:mut i32,d:i32)->Unit effects {write,panic} {n=n*10+d;}
        fn main()->Unit effects {write,panic} {
            let mut n:i32=0;let p=Marks{second:mark(mut n,2),n:11,first:mark(mut n,1)};
            assert(n==21);let u=p.first;let v=p.second;assert(p.n==11);
        }''')

    def test_all_unit_records_generic_nesting_and_mutation(self):
        self.execute('''struct Marks {a:Unit,b:Unit} struct Box<T>{value:T}
        fn unit()->Unit effects {} {} fn copy(p:read Marks)->Marks effects {} {return p;}
        fn replace(p:mut Marks)->Unit effects {write} {p.a=unit();p.b=p.a;}
        fn main()->Unit effects {write,panic} {
            let mut p=Marks{a:unit(),b:unit()};let q=copy(read p);replace(mut p);
            let box=Box::<Box<Marks>>{value:Box{value:q}};let u=box.value.value.b;
            let pair=Box::<[Unit;2]>{value:[u,p.a]};assert(len(read pair.value)==2);
        }''')

    def test_enum_payload_order_and_ignored_unit_effects(self):
        self.execute('''enum Event {Done(Unit,i32,Unit),Idle}
        fn tick(n:mut i32)->Unit effects {write,panic} {n=n+1;}
        fn number(n:mut i32)->i32 effects {write,panic} {n=n+1;return n;}
        fn main()->Unit effects {write,panic} {
            let mut n:i32=0;let e=Event::Done(tick(mut n),number(mut n),tick(mut n));
            assert(n==3);match e {Event::Done(a,v,_)=>{let u=a;assert(v==2);},Event::Idle=>{assert(false);}}
        }''')

    def test_result_unit_alternatives_and_finite_nesting(self):
        self.execute('''fn unit()->Unit effects {} {} enum Maybe<T>{None,Some(T)}
        fn choose(ok:bool)->Result<Unit,Unit> effects {} {
            if ok {return Result::Ok(unit());}return Result::Err(unit());
        }
        fn main()->Unit effects {panic} {
            let a=choose(true);let b=choose(false);
            match a {Result::Ok(u)=>{let v=u;},Result::Err(_)=>{assert(false);}}
            match b {Result::Err(u)=>{let v=u;},Result::Ok(_)=>{assert(false);}}
            let c=Result::<Maybe<Unit>,Result<Unit,u8>>::Ok(Maybe::Some(unit()));
            match c {Result::Ok(m)=>{match m {Maybe::Some(u)=>{let v=u;},Maybe::None=>{assert(false);}}},Result::Err(_)=>{assert(false);}}
            let d:Result<i32,Unit>=Result::Err(unit());
            match d {Result::Err(u)=>{let v=u;},Result::Ok(_)=>{assert(false);}}
        }''')

    def test_unit_return_scrutinee_effect_runs_once(self):
        self.execute('''fn next(n:mut i32)->Result<Unit,u8> effects {write,panic} {n=n+1;return Result::Ok(assert(n==1));}
        fn main()->Unit effects {write,panic} {let mut n:i32=0;
            match next(mut n) {Result::Ok(u)=>{let v=u;},Result::Err(_)=>{assert(false);}}
            assert(n==1);
        }''')

    def test_unit_arrays_evaluate_once_in_source_order(self):
        self.execute('''fn mark(n:mut i32,d:i32)->Unit effects {write,panic} {n=n*10+d;}
        fn main()->Unit effects {write,panic} {
            let mut n:i32=0;let mut xs:[Unit;3]=[mark(mut n,1),mark(mut n,2),mark(mut n,3)];
            let saved=xs;xs[1]=mark(mut n,4);let u=saved[2];
            assert(n==1234);assert(len(read xs)==3);
        }''')

    def test_unit_slices_read_mut_index_and_nested_arrays(self):
        self.execute('''fn unit()->Unit effects {} {}
        fn fill(xs:mut [Unit],n:mut i32)->Unit effects {write,panic} {
            for i in 0..len(xs) {xs[i]=unit();n=n+1;}
        }
        fn inspect(xs:read [Unit])->usize effects {write,panic} {
            for i in 0..len(xs) {let u=xs[i];}return len(xs);
        }
        fn main()->Unit effects {write,panic} {
            let mut rows:[[Unit;2];2]=[[unit(),unit()],[unit(),unit()]];let mut n:i32=0;
            fill(mut rows[1],mut n);assert(n==2);assert(inspect(read rows[0])==2);
        }''')

    def test_unit_index_preserves_index_evaluation(self):
        self.execute('''fn unit()->Unit effects {} {} fn index()->usize effects {} {return 1;}
        fn main()->Unit effects {panic} {let xs:[Unit;2]=[unit(),unit()];let u=xs[index()];let v=u;}''')

    def test_unit_values_cross_source_module_aliases(self):
        (self.root/'values.hepta').write_text('pub struct Item{value:Unit} pub fn make()->Item effects {} {return Item{value:unit()};} pub fn unit()->Unit effects {} {}')
        entry=self.root/'main.hepta'
        entry.write_text('''import values as v;fn main()->Unit effects {} {
            let i=v::make();let u=i.value;let r:Result<v::Item,Unit>=Result::Ok(i);
            match r {Result::Ok(item)=>{let v=item.value;},Result::Err(error)=>{let v=error;}}
        }''')
        self.execute(project=entry)

    def test_assert_and_store_builtins_produce_unit_values(self):
        self.execute('''struct Box{value:Unit}
        fn main()->Unit effects {panic,unsafe,write} {
            let a=Box{value:assert(true)};let mut xs:[i32;2]=[3,5];unsafe {
                let p=ptr_mut(mut xs);let b=Box{value:store(p,1,7)};let c=b.value;
                assert(load(p,1)==7);
            }
        }''')

    def test_bounds_and_assert_failures_trap_before_later_effects(self):
        prefix='fn unit()->Unit effects {} {} fn invalid()->usize effects {} {return 2;} fn main()->Unit effects {panic,io,block,alloc,write} {let mut xs:[Unit;2]=[unit(),unit()];'
        for operation in ['let bad=xs[invalid()];','xs[invalid()]=unit();','let bad=assert(false);',
                          'let bad=Result::<Unit,u8>::Ok(assert(false));']:
            with self.subTest(operation=operation):
                program,checked=self.frontend(prefix+operation+'print_i64(991);}')
                generated=emit_c(program,checked)
                for optimize in (False,True):
                    report=compile_c(generated,output=self.root/'trap',optimize=optimize,sanitize=True)
                    self.assertTrue(report['ok'],report)
                    run=subprocess.run([report['artifact']],capture_output=True,timeout=10)
                    self.assertEqual(run.returncode,-signal.SIGABRT)
                    self.assertEqual((run.stdout,run.stderr),(b'',b''))
                if os.environ.get('HEPTA_ENUM_REQUIRE_RUST')=='1':
                    compiler=os.environ.get('RUSTC') or shutil.which('rustc')
                    self.assertTrue(compiler,'Native Rust required but unavailable')
                    for optimize in (False,True):
                        report=compile_rust(emit_rust(program,checked,crate_type='bin'),rustc=compiler,crate_type='bin',optimize=optimize,output=self.root/'rust-trap')
                        self.assertTrue(report['ok'],report)
                        run=subprocess.run([report['artifact']],capture_output=True,timeout=10)
                        self.assertEqual(run.returncode,-signal.SIGABRT)
                        self.assertEqual(run.stdout,b'')

    def test_rust_trap_requests_binary_contract_without_native_rust(self):
        """Mocked Rust call contract only; all C compilations/runs stay real."""
        original_run = subprocess.run
        calls = []
        artifact = str(self.root / 'mocked-rust-contract-not-an-executable')

        def compile_contract(source, **kwargs):
            self.assertEqual(kwargs.get('crate_type'), 'bin')
            self.assertIn('fn main()', source)
            self.assertEqual(kwargs['rustc'], 'mocked-rust-contract')
            calls.append(kwargs['optimize'])
            return {'ok': True, 'artifact': artifact}

        def run_contract(args, *positional, **kwargs):
            if args == [artifact]:
                return subprocess.CompletedProcess(args, -signal.SIGABRT, b'', b'')
            return original_run(args, *positional, **kwargs)

        with patch.dict(os.environ, {'HEPTA_ENUM_REQUIRE_RUST': '1',
                                     'RUSTC': 'mocked-rust-contract'}), \
             patch(__name__ + '.compile_rust', side_effect=compile_contract), \
             patch('subprocess.run', side_effect=run_contract):
            self.test_bounds_and_assert_failures_trap_before_later_effects()
        self.assertEqual(calls, [False, True] * 4)

    def test_void_return_and_opaque_unit_pointer_abi_are_unchanged(self):
        source='''pub export "C" fn identity(p:raw const Unit)->raw const Unit effects {} {return p;}
        pub export "C" fn noop()->Unit effects {} {}'''
        program,checked=self.frontend(source)
        generated=emit_c(program,checked,crate_type='obj')
        self.assertIn('typedef const void *',generated)
        self.assertIn('void noop(void)',generated)
        self.assertNotIn('unsigned char unused',generated)
        driver=self.root/'driver.c'
        driver.write_text('#include <assert.h>\nextern const void *identity(const void *);\nextern void noop(void);\nint main(void){int x=7;noop();assert(identity(&x)==&x);return 0;}\n')
        for optimize in (False,True):
            report=compile_c(generated,crate_type='obj',output=self.root/'unit.o',optimize=optimize,sanitize=True)
            self.assertTrue(report['ok'],report)
            command=['gcc','-std=c11','-O3' if optimize else '-O0','-fsanitize=undefined','-fno-sanitize-recover=all',str(driver),report['artifact'],'-o',str(self.root/'driver')]
            run=subprocess.run(command,capture_output=True,timeout=30)
            self.assertEqual((run.returncode,run.stderr),(0,b''))
            run=subprocess.run([self.root/'driver'],capture_output=True,timeout=10)
            self.assertEqual((run.returncode,run.stdout,run.stderr),(0,b'',b''))

    def test_raw_unit_pointers_remain_opaque(self):
        for mode,operation in [('const','let value=load(p,0);'),('mut','store(p,0,unit());')]:
            program,checked=self.frontend(f'fn unit()->Unit effects {{}} {{}} fn f(p:raw {mode} Unit)->Unit effects {{unsafe,write}} {{unsafe {{{operation}}}}}')
            with self.assertRaises(HeptaError) as raised:emit_c(program,checked,crate_type='obj')
            self.assertEqual(raised.exception.diagnostic.code,'E_C_BACKEND_SUBSET')
            self.assertIn('opaque',raised.exception.diagnostic.message)

    def test_frontend_unit_mutability_effects_and_parameter_rules_remain(self):
        for source,code in [
            ('fn f(x:Unit)->Unit effects {} {}','E_UNIT_PARAMETER'),
            ('fn f(x:read Unit)->Unit effects {} {}','E_UNIT_PARAMETER'),
            ('fn f(x:mut Unit)->Unit effects {} {}','E_UNIT_PARAMETER'),
            ('fn unit()->Unit effects {} {} fn f()->Unit effects {write} {let u=unit();u=unit();}','E_IMMUTABLE'),
            ('fn f()->Unit effects {} {let u=assert(true);}','E_EFFECT'),
            ('fn unit()->Unit effects {} {} fn f()->Unit effects {panic} {assert(unit()==unit());}','E_BINARY_TYPE'),
            ('fn f()->Unit effects {} {let u:Unit=3;}','E_TYPE'),
            ('enum E {V(Unit)} fn f(e:E)->Unit effects {write} {match e {E::V(u)=>{u=u;}}}','E_IMMUTABLE'),
        ]:
            with self.subTest(source=source):
                report=analyze(source,backend='c',native=False).report
                self.assertFalse(report['ok'],report)
                self.assertIn(code,{d['code'] for d in report['diagnostics']})

    def test_foreign_unit_aggregate_boundaries_remain_rejected(self):
        for source in [
            'repr(C) struct Bad{value:Unit}',
            'repr(C) struct Bad{value:[Unit;2]}',
            'struct Box{value:Unit} pub export "C" fn f(x:Box)->Unit effects {} {}',
            'pub export "C" fn f(x:Result<Unit,u8>)->Unit effects {} {}',
            'extern "C" fn f(x:raw const [Unit;2])->Unit effects {ffi};',
        ]:
            with self.subTest(source=source):
                report=analyze(source,backend='c',native=False).report
                self.assertFalse(report['ok'],report)
                self.assertIn('E_C_ABI',{d['code'] for d in report['diagnostics']})

    def test_unsupported_layouts_and_generic_functions_remain_rejected(self):
        for source in [
            'struct Empty {}',
            'struct Bad{value:[Unit;0]}',
            'enum Bad{Value(Unit,i128)}',
            'fn f(x:Result<Unit,i128>)->Unit effects {} {}',
            'fn f<T>()->Unit effects {} {}',
        ]:
            with self.subTest(source=source):
                program,checked=self.frontend(source+' fn main()->Unit effects {} {}')
                with self.assertRaises(HeptaError) as raised:emit_c(program,checked)
                self.assertEqual(raised.exception.diagnostic.code,'E_C_BACKEND_SUBSET')

    def test_public_cli_unit_example(self):
        result=subprocess.run([sys.executable,'-m','hepta','run',str(ROOT/'examples/c_unit_values.hepta'),'--backend','c'],cwd=ROOT,capture_output=True,timeout=30)
        self.assertEqual((result.returncode,result.stdout,result.stderr),(0,b'',b''))


if __name__=='__main__':unittest.main()
