"""Joint consumers of existing numeric casts and concrete Copy ADT lowering."""
from pathlib import Path
import unittest
import test_c_float_int_casts as floats
TARGETS = floats.TARGETS


class NumericAdtCompositionTests(unittest.TestCase):
    setUp = floats.FloatIntCastTests.setUp
    frontend = floats.FloatIntCastTests.frontend
    execute = floats.FloatIntCastTests.execute

    def test_all_pairs_compose_with_generic_records_enums_results_and_unit(self):
        declarations=['struct Cell<T>{value:T,done:Unit} enum Event<T>{Value(T),Empty(Unit)}',
                      'fn unit()->Unit effects {} {}']
        assertions=[]
        pairs=[(a,b) for a in ('f32','f64') for b in TARGETS]
        pairs += [(a,b) for a in TARGETS for b in ('f32','f64')]
        pairs += [('f32','f64'),('f64','f32')]
        for a,b in pairs:
            name=a+'_'+b
            declarations.append(f'fn {name}(x:{a})->Result<Event<Cell<{b}>>,Unit> effects {{}} {{return Result::Ok(Event::Value(Cell{{value:x as {b},done:unit()}}));}}')
            value='17.75' if a.startswith('f') else '17'
            expected='17.75' if a.startswith('f') and b.startswith('f') else '17.0' if b.startswith('f') else '17'
            assertions.append(f'match {name}({value}) {{Result::Ok(e)=>{{match e {{Event::Value(c)=>{{let u=c.done;assert(c.value=={expected});}},Event::Empty(_)=>{{assert(false);}}}}}},Result::Err(_)=>{{assert(false);}}}}')
        self.execute(''.join(declarations)+'fn main()->Unit effects {panic} {'+''.join(assertions)+'}')

    def test_copy_snapshots_and_mutated_generic_float_arrays(self):
        self.execute('''struct Cell<T>{value:T,done:Unit} fn unit()->Unit effects {} {}
        fn mutate(c:mut Cell<f32>)->Unit effects {write} {c.value=16777219 as f32;}
        fn main()->Unit effects {write,panic} {
            let mut cells:[Cell<f32>;2]=[Cell{value:16777217 as f32,done:unit()},Cell{value:3.75 as f32,done:unit()}];
            let before=cells;mutate(mut cells[0]);cells[1].value=-9.75 as f32;
            assert((before[0].value as i64)==16777216);assert((cells[0].value as i64)==16777220);
            assert((before[1].value as i8)==3);assert((cells[1].value as i8)==-9);
        }''')

    def test_match_payload_keeps_numeric_value_when_source_is_replaced(self):
        self.execute('''enum Reading<T>{Value(T),Empty(Unit)} fn unit()->Unit effects {} {}
        fn replace(x:mut Reading<f32>)->Unit effects {write} {x=Reading::Empty(unit());}
        fn main()->Unit effects {write,panic} {let mut x:Reading<f32>=Reading::Value(16777217 as f32);
            match x {Reading::Value(v)=>{replace(mut x);assert((v as i64)==16777216);},Reading::Empty(_)=>{assert(false);}}
            match x {Reading::Empty(u)=>{let v=u;},Reading::Value(_)=>{assert(false);}}
        }''')

    def test_unit_and_numeric_payload_effects_remain_ordered(self):
        self.execute('''enum Values{Data(Unit,f32,f64,Unit)}
        fn tick(n:mut i32)->Unit effects {write,panic} {n=n+1;}
        fn number(n:mut i32)->i64 effects {write,panic} {n=n+1;return 16777217;}
        fn main()->Unit effects {write,panic} {let mut n:i32=0;
            let x=Values::Data(tick(mut n),number(mut n) as f32,number(mut n) as f64,tick(mut n));
            assert(n==4);match x {Values::Data(a,b,c,d)=>{let u=a;let v=d;assert((b as i64)==16777216);assert((c as i64)==16777217);}}
            assert(true || ((number(mut n) as f32) as i64)==0);assert(n==4);
        }''')

    def test_read_mut_slices_with_nested_numeric_results(self):
        self.execute('''struct Cell<T>{value:T,done:Unit} fn unit()->Unit effects {} {}
        fn narrow(xs:mut [Cell<f64>])->Unit effects {write,panic} {
            for i in 0..len(xs) {xs[i].value=(xs[i].value as f32) as f64;}
        }
        fn extract(xs:read [Cell<f64>])->Result<u32,Unit> effects {panic} {return Result::Ok(xs[0].value as u32);}
        fn main()->Unit effects {write,panic} {
            let mut xs:[Cell<f64>;2]=[Cell{value:16777217.0,done:unit()},Cell{value:-3.75,done:unit()}];
            narrow(mut xs);match extract(read xs) {Result::Ok(x)=>{assert(x==16777216);},Result::Err(_)=>{assert(false);}}
            assert((xs[1].value as i8)==-3);
        }''')

    def test_generic_payloads_cross_modules_with_all_cast_families(self):
        (self.root/'values.hepta').write_text('''pub struct Cell<T>{value:T,done:Unit}
        pub enum Event<T>{Value(T),Empty(Unit)}
        pub fn make(n:u64)->Result<Event<Cell<f32>>,Unit> effects {} {
            return Result::Ok(Event::Value(Cell{value:n as f32,done:unit()}));
        } fn unit()->Unit effects {} {}''')
        entry=self.root/'main.hepta'
        entry.write_text('''import values as v;fn main()->Unit effects {panic} {
            match v::make(16777219) {Result::Ok(e)=>{match e {v::Event::Value(c)=>{let x:f64=c.value as f64;assert((x as u64)==16777220);let u=c.done;},v::Event::Empty(_)=>{assert(false);}}},Result::Err(_)=>{assert(false);}}
        }''')
        self.execute(None,project=entry)

    def test_loop_and_match_dispatch_keep_numeric_helpers_distinct(self):
        self.execute('''enum Number{Wide(f64),Narrow(f32)}
        fn main()->Unit effects {write,panic} {
            let values=[Number::Wide(257.75),Number::Narrow(-8 as f32),Number::Wide(3.75)];let mut sum:i32=0;
            for i in 0..len(read values) {match values[i] {Number::Wide(v)=>{sum=sum+(v as u8) as i32;},Number::Narrow(v)=>{sum=sum+((v as f64) as i32);}}}
            assert(sum==250);
        }''')

    def test_unused_numeric_functions_keep_layout_and_cast_validation(self):
        self.execute('''struct Cell<T>{value:T} enum Event<T>{Value(T),Empty}
        fn unused(x:u64)->Result<Event<Cell<f32>>,i32> effects {} {return Result::Ok(Event::Value(Cell{value:x as f32}));}
        fn main()->Unit effects {panic} {assert(true);}''')


if __name__ == '__main__': unittest.main()
