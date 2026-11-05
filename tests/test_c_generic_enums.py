"""Concrete Copy-generic enum specialization with native C consumers."""
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from hepta.ast import HeptaError
from hepta.c_backend import emit_c
from hepta.pipeline import analyze
import test_c_fieldless_enums as fieldless

ROOT = Path(__file__).resolve().parents[1]


class GenericEnumTests(unittest.TestCase):
    setUp = fieldless.FieldlessEnumTests.setUp
    frontend = fieldless.FieldlessEnumTests.frontend
    execute = fieldless.FieldlessEnumTests.execute

    def test_expected_and_explicit_type_arguments(self):
        self.execute('''enum Maybe<T> {None,Some(T)}
        fn choose(x:Maybe<i32>)->i32 effects {} {match x {Maybe::None=>{return 0;},Maybe::Some(v)=>{return v;}}}
        fn make()->Maybe<i32> effects {} {return Maybe::Some(17);}
        fn main()->Unit effects {panic} {
            let x:Maybe<i32>=Maybe::Some(7);let y=Maybe::<i32>::None;
            assert(choose(x)==7);assert(choose(y)==0);assert(choose(Maybe::Some(11))==11);assert(choose(make())==17);
        }''')

    def test_multiple_specializations_keep_layouts_distinct(self):
        self.execute('''enum Maybe<T> {None,Some(T)}
        fn main()->Unit effects {panic} {
            let a=Maybe::<u8>::Some(211);let b=Maybe::<i64>::Some(-1234567);let c=Maybe::<bool>::Some(true);
            let d=Maybe::<f64>::Some(2.5);let e=Maybe::<[i32;3]>::Some([3,5,7]);
            match a {Maybe::Some(v)=>{assert(v==211);},Maybe::None=>{assert(false);}}
            match b {Maybe::None=>{assert(false);},Maybe::Some(v)=>{assert(v==-1234567);}}
            match c {Maybe::Some(v)=>{assert(v);},Maybe::None=>{assert(false);}}
            match d {Maybe::Some(v)=>{assert(v==2.5);},Maybe::None=>{assert(false);}}
            match e {Maybe::Some(v)=>{assert(v[0]==3);assert(v[2]==7);},Maybe::None=>{assert(false);}}
        }''')

    def test_multiple_parameters_substitute_nested_fields(self):
        self.execute('''enum Pair<A,B> {Empty,Left(A),Right(B),Both(A,B,[A;2])}
        fn main()->Unit effects {panic} {
            let a=Pair::<i32,bool>::Both(17,true,[19,23]);
            let b=Pair::<bool,i32>::Both(false,29,[true,false]);
            match a {Pair::Both(x,y,z)=>{assert(x==17);assert(y);assert(z[0]==19);assert(z[1]==23);},Pair::Empty=>{assert(false);},Pair::Left(_)=>{assert(false);},Pair::Right(_)=>{assert(false);}}
            match b {Pair::Both(x,y,z)=>{assert(!x);assert(y==29);assert(z[0]);assert(!z[1]);},Pair::Empty=>{assert(false);},Pair::Left(_)=>{assert(false);},Pair::Right(_)=>{assert(false);}}
        }''')

    def test_nested_same_declaration_and_cross_template_instances(self):
        self.execute('''enum Boxed<T> {Empty,Value(T)} enum Envelope<T> {Empty,Value(Boxed<[T;2]>)}
        fn main()->Unit effects {panic} {
            let a=Boxed::<Boxed<i32>>::Value(Boxed::Value(31));
            match a {Boxed::Value(inner)=>{match inner {Boxed::Value(v)=>{assert(v==31);},Boxed::Empty=>{assert(false);}}},Boxed::Empty=>{assert(false);}}
            let b=Envelope::<u16>::Value(Boxed::Value([37,41]));
            match b {Envelope::Value(inner)=>{match inner {Boxed::Value(v)=>{assert(v[0]==37);assert(v[1]==41);},Boxed::Empty=>{assert(false);}}},Envelope::Empty=>{assert(false);}}
        }''')

    def test_arrays_records_and_enum_type_arguments(self):
        self.execute('''enum Maybe<T> {None,Some(T)} enum Flag {Off,On} struct Cell {value:Maybe<i32>}
        fn main()->Unit effects {write,panic} {
            let mut cell=Cell{value:Maybe::Some(43)};let boxed=Maybe::<Cell>::Some(cell);cell.value=Maybe::None;
            let flags=Maybe::<[Flag;2]>::Some([Flag::Off,Flag::On]);
            match boxed {Maybe::Some(c)=>{match c.value {Maybe::Some(n)=>{assert(n==43);},Maybe::None=>{assert(false);}}},Maybe::None=>{assert(false);}}
            match flags {Maybe::Some(xs)=>{match xs[0] {Flag::Off=>{},Flag::On=>{assert(false);}}match xs[1] {Flag::On=>{},Flag::Off=>{assert(false);}}},Maybe::None=>{assert(false);}}
        }''')

    def test_constructor_order_and_ignored_payload_snapshots(self):
        self.execute('''enum Pair<T> {Empty,Values(T,T,T)}
        fn next(n:mut i32)->i32 effects {write,panic} {n=n+1;return n;}
        fn main()->Unit effects {write,panic} {
            let mut n:i32=5;let p=Pair::<i32>::Values(n,next(mut n),next(mut n));
            assert(n==7);match p {Pair::Values(a,b,c)=>{assert(a==5);assert(b==6);assert(c==7);},Pair::Empty=>{assert(false);}}
            let q=Pair::<i32>::Values(next(mut n),next(mut n),next(mut n));
            match q {Pair::Values(_,b,_)=>{assert(b==9);},Pair::Empty=>{assert(false);}}assert(n==10);
        }''')

    def test_match_binds_copies_before_source_replacement(self):
        self.execute('''enum Maybe<T> {None,Some(T)}
        fn main()->Unit effects {write,panic} {
            let mut v=Maybe::<[i32;2]>::Some([47,53]);let saved=v;
            match v {Maybe::Some(xs)=>{v=Maybe::None;assert(xs[0]==47);assert(xs[1]==53);},Maybe::None=>{assert(false);}}
            match v {Maybe::None=>{},Maybe::Some(_)=>{assert(false);}}
            v=Maybe::Some([59,61]);match saved {Maybe::Some(xs)=>{assert(xs[0]==47);assert(xs[1]==53);},Maybe::None=>{assert(false);}}
        }''')

    def test_read_mut_parameters_slices_and_returns(self):
        self.execute('''enum Maybe<T> {None,Some(T)}
        fn get(x:read Maybe<i32>)->i32 effects {} {match x {Maybe::None=>{return 0;},Maybe::Some(n)=>{return n;}}}
        fn step(x:mut Maybe<i32>)->Unit effects {write,panic} {match x {Maybe::None=>{x=Maybe::Some(1);},Maybe::Some(n)=>{x=Maybe::Some(n+1);}}}
        fn visit(xs:mut [Maybe<i32>])->Unit effects {write,panic} {for i in 0..len(xs) {step(mut xs[i]);}}
        fn copy(x:read Maybe<i32>)->Maybe<i32> effects {} {return x;}
        fn main()->Unit effects {write,panic} {
            let mut xs:[Maybe<i32>;2]=[Maybe::None,Maybe::Some(67)];let before=copy(read xs[1]);
            visit(mut xs);assert(get(read xs[0])==1);assert(get(read xs[1])==68);assert(get(read before)==67);
        }''')

    def test_raw_pointer_type_arguments_and_template_fields(self):
        self.execute('''enum Value<T> {Empty,Item(T)} enum View<T> {Empty,Pointer(raw const T)}
        fn main()->Unit effects {panic,unsafe} {
            let xs:[i32;2]=[71,73];unsafe {
                let a=Value::<raw const i32>::Item(ptr_read(read xs));let b=View::<i32>::Pointer(ptr_read(read xs));
                match a {Value::Item(p)=>{unsafe {assert(load(p,0)==71);}},Value::Empty=>{assert(false);}}
                match b {View::Pointer(p)=>{unsafe {assert(load(p,1)==73);}},View::Empty=>{assert(false);}}
            }
        }''')

    def test_module_aliases_and_parameter_spelling_are_not_identity(self):
        (self.root/'a.hepta').write_text('pub enum Item<T> {Empty,Value(T)} pub fn item()->Item<i32> effects {} {return Item::Value(79);}')
        (self.root/'b.hepta').write_text('pub enum Item<T> {Value(T),Empty} pub fn item()->Item<bool> effects {} {return Item::Value(true);}')
        entry=self.root/'main.hepta'
        entry.write_text('''import a as left;import b as right;
        fn main()->Unit effects {panic} {
            let a:left::Item<i32>=left::item();let b:right::Item<bool>=right::item();
            match a {left::Item::Value(n)=>{assert(n==79);},left::Item::Empty=>{assert(false);}}
            match b {right::Item::Empty=>{assert(false);},right::Item::Value(v)=>{assert(v);}}
        }''')
        self.execute(project=entry)

    def test_unused_templates_need_no_invented_concrete_argument(self):
        self.execute('''enum Unused<T> {None,Some(T)} enum Other<A,B> {A(A),B(B)}
        fn main()->Unit effects {} {}''')

    def test_public_cli_example_executes(self):
        result=subprocess.run([sys.executable,'-m','hepta','run',str(ROOT/'examples/generic_enums.hepta'),'--backend','c'],cwd=ROOT,capture_output=True,timeout=30)
        self.assertEqual((result.returncode,result.stdout,result.stderr),(0,b'',b''))

    def test_specialized_unsupported_types_fail_before_native(self):
        for typ in ['Unit','i128','[i32;0]','[Unit;2]','Result<i32,Unit>']:
            with self.subTest(typ=typ):
                program,checked=self.frontend(f'enum Maybe<T> {{None,Some(T)}} fn unused(x:Maybe<{typ}>)->Unit effects {{}} {{}} fn main()->Unit effects {{}} {{}}')
                with self.assertRaises(HeptaError) as raised:emit_c(program,checked)
                self.assertEqual(raised.exception.diagnostic.code,'E_C_BACKEND_SUBSET')
        for source in ['struct Record<T> {value:T} enum E {Value(Record<Unit>)}',
                       'enum E<T> {Value(T)} fn id<T>(x:T)->T effects {} {return x;}']:
            with self.subTest(source=source):
                program,checked=self.frontend(source+' fn main()->Unit effects {} {}')
                with self.assertRaises(HeptaError) as raised:emit_c(program,checked)
                self.assertEqual(raised.exception.diagnostic.code,'E_C_BACKEND_SUBSET')

    def test_recursive_template_layouts_reject_before_specialization(self):
        # Typecheck only. No recursive program is emitted, compiled or executed.
        cases = [
            'enum E<T> {Value(T),Next(raw const E<T>)}',
            'enum E<T> {Value(T),Next(raw const E<[T;2]>)}',
            'enum E<T> {Value(T),Next(raw const F<T>)} enum F<T> {Value(T),Next(raw const E<T>)}',
        ]
        for declaration in cases:
            with self.subTest(declaration=declaration):
                program,checked=self.frontend(declaration+' fn main()->Unit effects {} {}')
                with patch('hepta.c_backend.CEmitter.typ', side_effect=AssertionError('specialization reached')):
                    with self.assertRaises(HeptaError) as raised:emit_c(program,checked)
                self.assertEqual(raised.exception.diagnostic.code,'E_C_BACKEND_SUBSET')
                self.assertIn('Recursive generic enum',raised.exception.diagnostic.message)

    def test_generic_frontend_refusals_remain(self):
        cases=[
            ('enum E<T>{Value(T)} fn f(x:E<i32,u8>)->Unit effects {} {}','E_GENERIC_ARITY'),
            ('enum E<T>{Value(T)} fn f()->E<i32> effects {} {return E::Value(true);}','E_TYPE'),
            ('enum E<T>{Value(T),Empty} fn f(x:E<i32>)->Unit effects {} {match x {E::Empty=>{}}}','E_MATCH_EXHAUSTIVE'),
            ('enum E<T>{Value(T)} fn f(x:E<i32>)->Unit effects {write} {match x {E::Value(v)=>{v=7;}}}','E_IMMUTABLE'),
            ('enum E<T>{Value(T)} fn f(x:E<Buffer<u8>>)->Unit effects {} {}','E_GENERIC_COPY'),
            ('enum E<T>{Value(T)} fn f(x:E<Cancellation>)->Unit effects {} {}','E_GENERIC_COPY'),
            ('enum E<T>{Value(T)} fn f(x:E<i32>)->E<u8> effects {} {return x;}','E_TYPE'),
        ]
        for source,code in cases:
            with self.subTest(code=code):
                report=analyze(source,backend='c',native=False).report
                self.assertFalse(report['ok'],report)
                self.assertIn(code,{d['code'] for d in report['diagnostics']})

    def test_generic_foreign_boundaries_remain_rejected(self):
        for suffix in ['pub export "C" fn f(x:E<i32>)->i32 effects {} {return 0;}',
                       'extern "C" fn f(x:E<i32>)->i32 effects {};',
                       'repr(C) struct Public {value:E<i32>}',
                       'extern "C" fn f(x:raw const E<i32>)->i32 effects {};']:
            with self.subTest(suffix=suffix):
                report=analyze('enum E<T> {Value(T)} '+suffix,backend='c',native=False).report
                self.assertFalse(report['ok'],report)
                self.assertIn('E_C_ABI',{d['code'] for d in report['diagnostics']})

    def test_conservative_borrow_refusal_remains(self):
        source='''enum E<T> {Value(T)} fn both(a:read E<i32>,b:mut E<i32>)->Unit effects {} {}
        fn main()->Unit effects {} {let mut e=E::<i32>::Value(3);both(read e,mut e);}'''
        report=analyze(source,backend='c',native=False).report
        self.assertFalse(report['ok'],report)
        self.assertIn('E_C_BORROW',{d['code'] for d in report['diagnostics']})


if __name__ == '__main__':
    unittest.main()
