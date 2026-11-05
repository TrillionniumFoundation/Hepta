"""Ordered ordinary stores composed with concrete Copy ADTs and Unit."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import unittest
from unittest.mock import patch

from hepta.ast import HeptaError
from hepta.backend import compile_rust, emit_rust
from hepta.c_backend import compile_c, emit_c
from hepta.checker import check
from hepta.parser import parse
import test_c_float_int_casts as numeric
import raw_store_order_origin as origin


class StoreAdtCompositionTests(unittest.TestCase):
    setUp = numeric.FloatIntCastTests.setUp
    frontend = numeric.FloatIntCastTests.frontend
    execute = numeric.FloatIntCastTests.execute

    def test_pointer_index_payload_order_and_record_snapshot(self):
        self.execute('''
        struct Cell<T>{value:T,done:Unit} fn unit()->Unit effects {} {}
        fn pick(a:raw mut Cell<f64>,b:raw mut Cell<f64>,selected:read usize,log:mut i64)->raw mut Cell<f64> effects {write,panic} {
            log=log*10+1;if selected==0{return a;}return b;
        }
        fn index(log:mut i64)->usize effects {write,panic} {log=log*10+2;return 0;}
        fn payload(selected:mut usize,log:mut i64)->Cell<f64> effects {write,panic} {
            log=log*10+3;selected=1;return Cell{value:257.75,done:unit()};
        }
        fn main()->Unit effects {unsafe,write,panic} {
            let mut a:[Cell<f64>;1]=[Cell{value:1.0,done:unit()}];let mut b:[Cell<f64>;1]=[Cell{value:2.0,done:unit()}];
            let mut selected:usize=0;let mut log:i64=0;
            unsafe {let pa=ptr_mut(mut a);let pb=ptr_mut(mut b);let before=load(pa,0);
                store(pick(pa,pb,read selected,mut log),index(mut log),payload(mut selected,mut log));
                let after=load(pa,0);assert(after.value as u8==255);assert(before.value==1.0);}
            assert(a[0].value==257.75);assert(b[0].value==2.0);assert(log==123);assert(selected==1);
        }''')

    def test_result_enum_returned_array_payload_and_unit(self):
        self.execute('''
        struct Cell<T>{value:T,done:Unit} enum Event<T>{Data(T),Empty(Unit)} fn unit()->Unit effects {} {}
        fn values(n:mut i64)->[Result<Event<Cell<f32>>,Unit>;2] effects {write,panic} {
            n=n+1;return [Result::Err(unit()),Result::Ok(Event::Data(Cell{value:16777217 as f32,done:unit()}))];
        }
        fn main()->Unit effects {unsafe,write,panic} {let mut n:i64=0;
            let mut cells:[Result<Event<Cell<f32>>,Unit>;1]=[Result::Err(unit())];
            unsafe {store(ptr_mut(mut cells),0,values(mut n)[1]);}
            match cells[0] {Result::Ok(e)=>{match e {Event::Data(c)=>{assert(c.value as i64==16777216);let u=c.done;},Event::Empty(_)=>{assert(false);}}},Result::Err(_)=>{assert(false);}}
            assert(n==1);
        }''')

    def test_plain_index_is_snapshotted_before_aggregate_value(self):
        self.execute('''
        struct Cell<T>{value:T,done:Unit} fn unit()->Unit effects {} {}
        fn change(i:mut usize)->Cell<f64> effects {write} {i=1;return Cell{value:-3.75,done:unit()};}
        fn main()->Unit effects {unsafe,write,panic} {let mut i:usize=0;
            let mut cells:[Cell<f64>;2]=[Cell{value:1.0,done:unit()},Cell{value:2.0,done:unit()}];
            unsafe {store(ptr_mut(mut cells),i,change(mut i));}
            assert(cells[0].value as i32 == -3);assert(cells[1].value==2.0);assert(i==1);
        }''')

    def test_nested_store_unit_result_and_outer_snapshot(self):
        self.execute('''
        struct Cell<T>{value:T,done:Unit} fn unit()->Unit effects {} {}
        fn inner(p:raw mut Cell<f64>,n:mut i64)->Cell<f64> effects {unsafe,write,panic} {
            n=n+1;unsafe {let result:Result<Unit,i64>=Result::Ok(store(p,0,Cell{value:1.0,done:unit()}));
                match result {Result::Ok(u)=>{return Cell{value:8.75,done:u};},Result::Err(_)=>{return Cell{value:0.0,done:unit()};}}}
        }
        fn main()->Unit effects {unsafe,write,panic} {let mut n:i64=0;let mut cells:[Cell<f64>;1]=[Cell{value:2.0,done:unit()}];
            unsafe {let p=ptr_mut(mut cells);let old=load(p,0);let u=store(p,0,inner(p,mut n));
                let done:Result<Unit,i64>=Result::Ok(u);match done {Result::Ok(_)=>{},Result::Err(_)=>{assert(false);}}
                assert(old.value==2.0);}
            assert(cells[0].value as i32==8);assert(n==1);
        }''')

    def test_short_circuit_and_loop_dispatch_preserve_effects(self):
        self.execute('''
        enum Item<T>{Data(T),Empty(Unit)} fn unit()->Unit effects {} {}
        fn payload(n:mut i64)->Item<f64> effects {write,panic} {n=n+1;return Item::Data(n as f64);}
        fn perform(p:raw mut Item<f64>,n:mut i64)->bool effects {unsafe,write,panic} {unsafe {store(p,0,payload(mut n));}return true;}
        fn main()->Unit effects {unsafe,write,panic} {let mut n:i64=0;let mut cells:[Item<f64>;1]=[Item::Empty(unit())];
            unsafe {let p=ptr_mut(mut cells);assert(true || perform(p,mut n));assert(!(false && perform(p,mut n)));assert(n==0);
                assert(true && perform(p,mut n));assert(false || perform(p,mut n));
                let mut i:usize=0;while i<3 {store(p,0,payload(mut n));i=i+1;}}
            match cells[0] {Item::Data(v)=>{assert(v as i64==5);},Item::Empty(_)=>{assert(false);}}assert(n==5);
        }''')

    def test_store_used_in_unit_array_and_struct_fields(self):
        self.execute('''
        struct Cell<T>{value:T,done:Unit} fn unit()->Unit effects {} {}
        fn next(n:mut i64)->i64 effects {write,panic} {n=n+1;return n;}
        fn main()->Unit effects {unsafe,write,panic} {let mut n:i64=0;let mut xs:[i64;1]=[0];
            unsafe {let p=ptr_mut(mut xs);let units:[Unit;2]=[store(p,0,next(mut n)),store(p,0,next(mut n))];
                let c:Cell<f64>=Cell{value:3.75,done:store(p,0,next(mut n))};let u=units[1];let v=c.done;assert(c.value as i64==3);}
            assert(n==3);assert(xs[0]==3);
        }''')

    def test_module_alias_store_payload_uses_private_generic_layout(self):
        (self.root/'payload.hepta').write_text('''pub struct Cell<T>{value:T,done:Unit} fn unit()->Unit effects {} {}
        pub fn next(n:mut i64)->Cell<f64> effects {write,panic} {n=n+1;return Cell{value:257.75,done:unit()};}''')
        path=self.root/'main.hepta';path.write_text('''import payload as p;fn unit()->Unit effects {} {}
        fn main()->Unit effects {unsafe,write,panic} {let mut n:i64=0;let mut xs:[p::Cell<f64>;1]=[p::Cell{value:1.0,done:unit()}];
        unsafe {store(ptr_mut(mut xs),0,p::next(mut n));}assert(xs[0].value as u8==255);assert(n==1);}''')
        self.execute(None,project=path)

    def test_aggregate_operand_failure_stops_later_effects(self):
        helper=self.root/'trace.c';helper.write_text('''#include <stdio.h>\n#include <stdlib.h>\n#include <stdint.h>\nvoid event(int64_t n){printf("%lld",(long long)n);fflush(stdout);const char *p=getenv("HEPTA_FAIL");if(p && p[0]-'0'==n)abort();}\n''')
        source='''extern "C" fn event(n:i64)->Unit effects {ffi};
        struct Cell<T>{value:T,done:Unit} fn unit()->Unit effects {} {}
        fn pointer(p:raw mut Cell<f64>)->raw mut Cell<f64> effects {ffi,unsafe} {unsafe {event(1);}return p;}
        fn index()->usize effects {ffi,unsafe} {unsafe {event(2);}return 0;}
        fn payload()->Cell<f64> effects {ffi,unsafe} {unsafe {event(3);}return Cell{value:257.75,done:unit()};}
        fn main()->Unit effects {ffi,unsafe,write,panic} {let mut xs:[Cell<f64>;1]=[Cell{value:1.0,done:unit()}];
            unsafe {store(pointer(ptr_mut(mut xs)),index(),payload());event(4);}assert(xs[0].value as u8==255);}
        '''
        p,c=self.frontend(source)
        for backend in (['c','rust'] if os.environ.get('HEPTA_ENUM_REQUIRE_RUST')=='1' else ['c']):
            obj=self.root/'trace-helper.o'
            if backend=='rust':
                build=subprocess.run([os.environ.get('CC','gcc'),'-c',str(helper),'-o',str(obj)],capture_output=True,text=True,timeout=30)
                self.assertEqual(build.returncode,0,build.stderr)
            for optimize in [False,True]:
                report=(compile_c(emit_c(p,c),output=self.root/'trace',optimize=optimize,sanitize=True,link_args=[str(helper)]) if backend=='c' else
                        compile_rust(emit_rust(p,c,crate_type='bin'),crate_type='bin',output=self.root/'trace-rust',optimize=optimize,rustc=os.environ.get('RUSTC','rustc'),link_args=[str(obj)]))
                self.assertTrue(report['ok'],report)
                for fail,expected in [('',b'1234'),('1',b'1'),('2',b'12'),('3',b'123')]:
                    run=subprocess.run([report['artifact']],env={**os.environ,'HEPTA_FAIL':fail},capture_output=True,timeout=10)
                    self.assertEqual((run.returncode,run.stdout),(-signal.SIGABRT if fail else 0,expected),run.stderr)
                    self.assertNotIn(b'runtime error:',run.stderr)

    def test_rust_trace_requests_binary_contract_without_native_rust(self):
        """Mocked Rust boundary only; original C work remains real."""
        original_run = subprocess.run
        calls, observations = [], []
        artifact = str(self.root / 'mocked-rust-trace-contract-not-an-executable')

        def compile_contract(source, **kwargs):
            self.assertEqual(kwargs.get('crate_type'), 'bin')
            self.assertIn('fn main()', source)
            self.assertEqual(kwargs['rustc'], 'mocked-rust-contract')
            self.assertEqual(kwargs['output'], self.root / 'trace-rust')
            self.assertEqual(kwargs['link_args'], [str(self.root / 'trace-helper.o')])
            self.assertGreater((self.root / 'trace-helper.o').stat().st_size, 0)
            calls.append(kwargs['optimize'])
            return {'ok': True, 'artifact': artifact}

        def run_contract(args, *positional, **kwargs):
            if args == [artifact]:
                failure = kwargs['env']['HEPTA_FAIL']
                observations.append(failure)
                output = b'1234' if not failure else b'123'[:int(failure)]
                return subprocess.CompletedProcess(args, -signal.SIGABRT if failure else 0, output, b'')
            return original_run(args, *positional, **kwargs)

        with patch.dict(os.environ, {'HEPTA_ENUM_REQUIRE_RUST': '1',
                                     'RUSTC': 'mocked-rust-contract'}), \
             patch(__name__ + '.compile_rust', side_effect=compile_contract), \
             patch('subprocess.run', side_effect=run_contract):
            self.test_aggregate_operand_failure_stops_later_effects()
        self.assertEqual(calls, [False, True])
        self.assertEqual(observations, ['', '1', '2', '3'] * 2)

    def test_scalar_origin_order_control_without_volatile_admission(self):
        # The original combined method also requires unsupported volatile_store.
        # Preserve it verbatim as a fixture and execute its ordinary-store branch.
        case=origin.RawStoreOrderTests();case.setUp();self.addCleanup(case.doCleanups)
        for optimize in [False,True]:
            exe=case.native_c(origin.source('store'),optimize);case.execute(exe,'PIVA:42:0\n')
            for failure,expected in [('P','P'),('I','PI'),('V','PIV')]:case.execute(exe,expected,failure)

    def test_public_cli_executes_joint_example(self):
        root=Path(__file__).resolve().parents[1]
        result=subprocess.run([sys.executable,'-m','hepta','run',str(root/'examples/c_store_adt.hepta'),'--backend','c'],cwd=self.root,capture_output=True,text=True,timeout=60,env={**os.environ,'PYTHONPATH':str(root)})
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue(result.stdout.rstrip().endswith('255'),result.stdout)

    def test_narrow_backend_boundaries_remain_rejected(self):
        for source,code in [
            ('fn main()->Unit effects {write} {let mut a:[i64;1]=[0];store(ptr_mut(mut a),0,1);}','E_UNSAFE_REQUIRED'),
            ('fn main()->Unit effects {unsafe,write} {let a:[i64;1]=[0];unsafe {store(ptr_read(read a),0,1);}}','E_READ_ONLY')]:
            checked=check(parse(source));self.assertFalse(checked.ok);self.assertIn(code,[d.code for d in checked.diagnostics])
        p,c=self.frontend('fn f(p:raw mut Unit)->Unit effects {unsafe,write,panic} {unsafe {store(p,0,assert(true));}}')
        with self.assertRaisesRegex(HeptaError,'Raw Unit pointers are opaque'):emit_c(p,c,crate_type='obj')
        p,c=self.frontend('fn f<T>(x:T)->T effects {} {return x;} fn main()->Unit effects {} {let x=f::<i64>(1);}')
        with self.assertRaisesRegex(HeptaError,'explicit monomorphization'):emit_c(p,c)


if __name__=='__main__':unittest.main()
