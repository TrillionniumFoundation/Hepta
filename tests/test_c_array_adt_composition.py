"""Joint qualification of temporary Copy arrays with Unit and numeric ADTs."""
import os
from pathlib import Path
import subprocess
import sys
import unittest

from hepta.ast import HeptaError
from hepta.c_backend import emit_c
from hepta.checker import check
from hepta.parser import parse
import test_c_float_int_casts as numeric


class ArrayAdtCompositionTests(unittest.TestCase):
    setUp = numeric.FloatIntCastTests.setUp
    frontend = numeric.FloatIntCastTests.frontend
    execute = numeric.FloatIntCastTests.execute

    def test_unit_rvalues_preserve_exact_once_and_len_effects(self):
        self.execute('''
        fn tick(n:mut i64)->Unit effects {write,panic} {n=n+1;}
        fn values(n:mut i64)->[Unit;2] effects {write,panic} {return [tick(mut n),tick(mut n)];}
        fn main()->Unit effects {write,panic} {let mut n:i64=0;
            let u=values(mut n)[1];assert(n==2);
            assert(len(values(mut n))==2);assert(n==4);
            let v=[[tick(mut n)],[tick(mut n)]][1][0];assert(n==6);
            assert(true || len(values(mut n))==0);assert(!(false && len(values(mut n))==0));assert(n==6);
        }''')

    def test_generic_result_payloads_and_unit_record_fields(self):
        self.execute('''
        struct Cell<T>{value:T,done:Unit} enum Event<T>{Value(T),Empty(Unit)}
        fn unit()->Unit effects {} {}
        fn values()->[Result<Event<Cell<f32>>,Unit>;2] effects {} {
            return [Result::Ok(Event::Value(Cell{value:16777217 as f32,done:unit()})),Result::Err(unit())];
        }
        fn main()->Unit effects {panic} {
            match values()[0] {Result::Ok(e)=>{match e {Event::Value(c)=>{let u=c.done;assert((c.value as i64)==16777216);},Event::Empty(_)=>{assert(false);}}},Result::Err(_)=>{assert(false);}}
            match values()[1] {Result::Ok(_)=>{assert(false);},Result::Err(u)=>{let v=u;}}
        }''')

    def test_returned_generic_record_nested_array_and_snapshot(self):
        self.execute('''
        struct Grid<T>{rows:[[T;2];2],done:Unit} fn unit()->Unit effects {} {}
        fn grid()->Grid<f64> effects {} {return Grid{rows:[[3.75,-8.75],[16777217.0,257.75]],done:unit()};}
        fn main()->Unit effects {write,panic} {
            let row=grid().rows[1];let mut copy=row;copy[0]=9.0;
            assert((row[0] as f32) as i64==16777216);assert(copy[0]==9.0);
            assert(grid().rows[0][1] as i8 == -8);assert(grid().rows[1][1] as u8==255);
            assert(len(grid().rows[0])==2);
        }''')

    def test_array_base_precedes_index_and_match_uses_snapshot(self):
        self.execute('''
        struct Cell<T>{value:T,done:Unit} fn unit()->Unit effects {} {}
        fn values(n:mut i64)->[Cell<f64>;2] effects {write,panic} {
            n=n+1;return [Cell{value:3.75,done:unit()},Cell{value:8.75,done:unit()}];
        }
        fn index(n:read i64)->usize effects {panic} {return n as usize;}
        fn main()->Unit effects {write,panic} {let mut n:i64=0;
            let item=values(mut n)[index(read n)];assert(n==1);assert(item.value as i32==8);
            let u=item.done;assert(len(values(mut n))==2);assert(n==2);
        }''')

    def test_named_unit_array_mutation_and_borrow_stay_place_based(self):
        self.execute('''
        fn tick(n:mut i64)->Unit effects {write,panic} {n=n+1;}
        fn mutate(xs:mut [Unit],n:mut i64)->Unit effects {write,panic} {xs[1]=tick(mut n);}
        fn main()->Unit effects {write,panic} {let mut n:i64=0;
            let mut xs:[Unit;2]=[tick(mut n),tick(mut n)];let saved=xs;
            mutate(mut xs,mut n);assert(n==3);let u=saved[0];assert(len(saved)==2);
        }''')

    def test_module_alias_returned_array_with_private_concrete_types(self):
        (self.root/'values.hepta').write_text('''pub struct Cell<T>{value:T,done:Unit}
        fn unit()->Unit effects {} {}
        pub fn values()->[Cell<f32>;2] effects {} {return [Cell{value:16777217 as f32,done:unit()},Cell{value:-3.75 as f32,done:unit()}];}''')
        path=self.root/'main.hepta'
        path.write_text('''import values as v;fn main()->Unit effects {panic} {
        assert((v::values()[0].value as i64)==16777216);let u=v::values()[1].done;assert(len(v::values())==2);}''')
        self.execute(None,project=path)

    def test_generic_functions_still_rejected_without_resource_gate(self):
        p,c=self.frontend('''fn pair<T>(x:T)->[T;2] effects {} {return [x,x];}
        fn main()->Unit effects {panic} {assert(pair::<i64>(7)[1]==7);}''')
        with self.assertRaisesRegex(HeptaError,'explicit monomorphization'):
            emit_c(p,c)

    def test_effectful_indices_still_rejected(self):
        p,c=self.frontend('''fn index(n:mut usize)->usize effects {write,panic} {n=n+1;return n;}
        fn main()->Unit effects {write,panic} {let mut n:usize=0;let x=[1,2][index(mut n)];}''')
        with self.assertRaisesRegex(HeptaError,'Effectful nested calls'):
            emit_c(p,c)

    def test_temporary_assignment_borrow_and_resource_arrays_still_rejected(self):
        for source in [
            'fn main()->Unit effects {write,panic} {[1,2][0]=3;}',
            'fn use(x:read [Unit;1])->Unit effects {} {} fn unit()->Unit effects {} {} fn main()->Unit effects {} {use(read [unit()]);}',
            'fn main()->Unit effects {alloc,panic} {let a:[Buffer<u8>;1]=[buffer(1)];}',
        ]:
            with self.subTest(source=source):
                self.assertFalse(check(parse(source)).ok)

    def test_public_cli_executes_joint_example(self):
        root=Path(__file__).resolve().parents[1]
        result=subprocess.run([sys.executable,'-m','hepta','run',str(root/'examples/c_array_adt.hepta'),'--backend','c'],cwd=self.root,capture_output=True,text=True,timeout=60,env={**os.environ,'PYTHONPATH':str(root)})
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue(result.stdout.rstrip().endswith('16777216'),result.stdout)


if __name__=='__main__': unittest.main()
