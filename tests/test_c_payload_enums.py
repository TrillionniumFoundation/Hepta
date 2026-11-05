"""Bounded Copy-payload enums: actual native consumers and retained refusals."""
from pathlib import Path
import subprocess
import sys
import unittest

from hepta.ast import HeptaError
from hepta.c_backend import emit_c
from hepta.pipeline import analyze
import test_c_fieldless_enums as fieldless

ROOT = Path(__file__).resolve().parents[1]


class PayloadEnumTests(unittest.TestCase):
    setUp = fieldless.FieldlessEnumTests.setUp
    frontend = fieldless.FieldlessEnumTests.frontend
    execute = fieldless.FieldlessEnumTests.execute

    def test_mixed_payloads_and_reordered_arms(self):
        self.execute('''enum Message { Empty, Number(i32), Pair(u8,i64), Flag(bool,f32,f64) }
        fn score(m:Message)->i32 effects {panic} {
            match m {Message::Pair(a,b)=>{assert(a==3);assert(b==9001);return 11;},
                     Message::Empty=>{return 7;},Message::Flag(a,b,c)=>{assert(a);assert(b==1.5);assert(c==2.25);return 13;},
                     Message::Number(x)=>{return x;}}
        }
        fn main()->Unit effects {panic} {
            assert(score(Message::Empty)==7);assert(score(Message::Number(-27))==-27);
            assert(score(Message::Pair(3,9001))==11);assert(score(Message::Flag(true,1.5,2.25))==13);
        }''')

    def test_constructor_order_and_value_snapshot(self):
        self.execute('''enum Pair {Values(i32,i32,i32)}
        fn next(n:mut i32)->i32 effects {write,panic} {n=n+1;return n;}
        fn main()->Unit effects {write,panic} {
            let mut n:i32=7;let p=Pair::Values(n,next(mut n),next(mut n));
            assert(n==9);match p {Pair::Values(a,b,c)=>{assert(a==7);assert(b==8);assert(c==9);}}
        }''')

    def test_ignored_fields_still_evaluate_once(self):
        self.execute('''enum Item {Empty,Values(i32,i32,i32)}
        fn next(n:mut i32)->i32 effects {write,panic} {n=n+1;return n;}
        fn main()->Unit effects {write,panic} {
            let mut n:i32=0;let item=Item::Values(next(mut n),next(mut n),next(mut n));
            match item {Item::Values(_,middle,_)=>{assert(middle==2);},Item::Empty=>{assert(false);}}
            assert(n==3);match item {Item::Values(_,_,_)=>{},Item::Empty=>{assert(false);}}
            assert(n==3);
        }''')

    def test_array_record_payloads_copy_independently(self):
        self.execute('''struct Cell {n:i32} enum Packet {None,Data([Cell;2],i32)}
        fn check_packet(p:read Packet,want:i32)->Unit effects {panic} {
            match p {Packet::None=>{assert(false);},Packet::Data(xs,n)=>{assert(xs[0].n==want);assert(xs[1].n==5);assert(n==11);}}
        }
        fn main()->Unit effects {write,panic} {
            let mut xs:[Cell;2]=[Cell{n:3},Cell{n:5}];let mut packet=Packet::Data(xs,11);
            xs[0].n=9;let original=packet;packet=Packet::Data(xs,11);
            check_packet(read original,3);check_packet(read packet,9);
        }''')

    def test_nested_enums_records_and_forward_declarations(self):
        self.execute('''enum Outer {Empty,Wrapped(Wrapper,Inner)} struct Wrapper {inner:Inner}
        enum Inner {No,Value(i32)}
        fn val(x:Inner)->i32 effects {} {match x {Inner::Value(n)=>{return n;},Inner::No=>{return 0;}}}
        fn main()->Unit effects {panic} {
            let x=Outer::Wrapped(Wrapper{inner:Inner::Value(7)},Inner::Value(11));
            match x {Outer::Wrapped(a,b)=>{assert(val(a.inner)==7);assert(val(b)==11);},Outer::Empty=>{assert(false);}}
        }''')

    def test_variant_changes_and_differently_sized_payloads(self):
        self.execute('''enum Value {Small(u8),Large([i64;4]),Empty,Pair(bool,u16)}
        fn main()->Unit effects {write,panic} {
            let mut v=Value::Large([11,13,17,19]);let first=v;
            v=Value::Small(201);match v {Value::Small(x)=>{assert(x==201);},Value::Large(_)=>{assert(false);},Value::Empty=>{assert(false);},Value::Pair(_,_)=>{assert(false);}}
            v=Value::Empty;match v {Value::Empty=>{},Value::Small(_)=>{assert(false);},Value::Large(_)=>{assert(false);},Value::Pair(_,_)=>{assert(false);}}
            v=Value::Pair(true,54321);match v {Value::Pair(a,b)=>{assert(a);assert(b==54321);},Value::Small(_)=>{assert(false);},Value::Large(_)=>{assert(false);},Value::Empty=>{assert(false);}}
            match first {Value::Large(xs)=>{assert(xs[0]==11);assert(xs[3]==19);},Value::Small(_)=>{assert(false);},Value::Empty=>{assert(false);},Value::Pair(_,_)=>{assert(false);}}
        }''')

    def test_scrutinee_and_binding_snapshots_survive_original_mutation(self):
        self.execute('''enum Item {Value([i32;2]),Empty}
        fn next(n:mut i32)->Item effects {write,panic} {n=n+1;return Item::Value([n,17]);}
        fn main()->Unit effects {write,panic} {
            let mut n:i32=0;match next(mut n) {Item::Value(xs)=>{assert(xs[0]==1);assert(xs[1]==17);},Item::Empty=>{assert(false);}}assert(n==1);
            let mut item=Item::Value([3,5]);match item {Item::Value(xs)=>{item=Item::Empty;assert(xs[0]==3);assert(xs[1]==5);},Item::Empty=>{assert(false);}}
            match item {Item::Empty=>{},Item::Value(_)=>{assert(false);}}
        }''')

    def test_read_mut_parameters_and_slice_elements(self):
        self.execute('''enum Item {Empty,Value(i32)}
        fn read_value(item:read Item)->i32 effects {} {match item {Item::Empty=>{return 0;},Item::Value(n)=>{return n;}}}
        fn increment(item:mut Item)->Unit effects {write,panic} {match item {Item::Empty=>{item=Item::Value(1);},Item::Value(n)=>{item=Item::Value(n+1);}}}
        fn visit(items:mut [Item])->Unit effects {write,panic} {for i in 0..len(items) {increment(mut items[i]);}}
        fn main()->Unit effects {write,panic} {
            let mut items:[Item;3]=[Item::Empty,Item::Value(4),Item::Value(8)];let saved=items;
            visit(mut items);assert(read_value(read items[0])==1);assert(read_value(read items[1])==5);assert(read_value(read items[2])==9);
            assert(read_value(read saved[0])==0);assert(read_value(read saved[1])==4);assert(read_value(read saved[2])==8);
        }''')

    def test_nested_matches_arm_scopes_and_loop_continuation(self):
        self.execute('''enum Item {Empty,Value(i32)}
        fn choose(x:Item,y:Item)->i32 effects {panic} {match x {Item::Empty=>{},Item::Value(n)=>{match y {Item::Value(m)=>{return n+m;},Item::Empty=>{}}}}return 19;}
        fn main()->Unit effects {write,panic} {
            assert(choose(Item::Value(3),Item::Value(5))==8);assert(choose(Item::Value(3),Item::Empty)==19);
            let mut sum:i32=0;for i in 0..4 {match Item::Value(i as i32) {Item::Value(n)=>{let local=n;sum=sum+local;},Item::Empty=>{let local:i32=9;sum=sum+local;}}sum=sum+10;}
            assert(sum==46);let mut i:i32=0;while i<3 {match Item::Value(i) {Item::Value(n)=>{sum=sum+n;},Item::Empty=>{assert(false);}}i=i+1;}assert(sum==49);
        }''')

    def test_many_variants_and_payload_positions(self):
        # Independent Python arithmetic supplies each expected result.
        variants=[];arms=[];calls=[]
        for i in range(73):
            arity=i%5;fields=','.join('i32' for _ in range(arity));names=[f'x{j}' for j in range(arity)]
            variants.append(f'V{i}'+(f'({fields})' if arity else ''))
            pattern=f'Event::V{i}'+('('+','.join(names)+')' if arity else '')
            score=str(i*101)+''.join(f'+{name}*{j+1}' for j,name in enumerate(names))
            arms.append(pattern+'=>{return '+score+';}')
            args=[i*7+j for j in range(arity)]
            value=f'Event::V{i}'+('('+','.join(map(str,args))+')' if arity else '')
            calls.append(f'assert(score({value})=={i*101+sum(v*(j+1) for j,v in enumerate(args))});')
        self.execute('enum Event{'+','.join(variants)+'}fn score(e:Event)->i32 effects {panic}{match e {'+','.join(reversed(arms))+'}}fn main()->Unit effects {panic}{'+''.join(calls)+'}')

    def test_module_aliases_preserve_payload_identity(self):
        (self.root/'a.hepta').write_text('pub enum Item {Value(i32),Empty} pub fn item()->Item effects {} {return Item::Value(7);}')
        (self.root/'b.hepta').write_text('pub enum Item {Empty,Value(u8)} pub fn item()->Item effects {} {return Item::Value(11);}')
        entry=self.root/'main.hepta'
        entry.write_text('''import a as left;import b as right;
        fn main()->Unit effects {panic} {
            match left::item() {left::Item::Value(n)=>{assert(n==7);},left::Item::Empty=>{assert(false);}}
            match right::item() {right::Item::Empty=>{assert(false);},right::Item::Value(n)=>{assert(n==11);}}
        }''')
        self.execute(project=entry)

    def test_raw_pointer_payload_uses_existing_unsafe_boundary(self):
        self.execute('''enum View {None,Pointer(raw const i32)}
        fn main()->Unit effects {panic,unsafe} {
            let values:[i32;2]=[7,11];unsafe {let view=View::Pointer(ptr_read(read values));
            match view {View::None=>{assert(false);},View::Pointer(p)=>{unsafe {assert(load(p,0)==7);assert(load(p,1)==11);}}}}
        }''')

    def test_public_cli_example_executes(self):
        result=subprocess.run([sys.executable,'-m','hepta','run',str(ROOT/'examples/payload_enums.hepta'),'--backend','c'],cwd=ROOT,capture_output=True,timeout=30)
        self.assertEqual((result.returncode,result.stdout,result.stderr),(0,b'',b''))

    def test_unsupported_payloads_still_reject_even_unused(self):
        cases=['enum E {Value(Unit),Empty}', 'struct E<T> {value:T} enum Holder {Value(E<Unit>)}',
               'enum E {Value([Unit;2]),Empty}', 'enum E {Value([i32;0]),Empty}',
               'enum E {Value(Result<i32,Unit>),Empty}']
        for decl in cases:
            with self.subTest(decl=decl):
                p,c=self.frontend(decl+' fn main()->Unit effects {} {}')
                with self.assertRaises(HeptaError) as raised:emit_c(p,c)
                self.assertEqual(raised.exception.diagnostic.code,'E_C_BACKEND_SUBSET')

    def test_frontend_payload_refusals_are_preserved(self):
        cases=[
            ('enum E {Value(i32)} fn f()->E effects {} {return E::Value(true);}','E_TYPE'),
            ('enum E {Value(i32)} fn f()->E effects {} {return E::Value();}','E_VARIANT_ARITY'),
            ('enum E {Value(i32)} fn f(e:E)->Unit effects {} {match e {E::Value=>{}}}','E_PATTERN_ARITY'),
            ('enum E {Value(i32)} fn f(e:E)->Unit effects {write} {match e {E::Value(x)=>{x=3;}}}','E_IMMUTABLE'),
            ('enum E {Value(i32,i32)} fn f(e:E)->Unit effects {} {match e {E::Value(x,x)=>{}}}','E_DUPLICATE_LOCAL'),
            ('enum E {Value(i32)} fn f(e:E,x:read i32)->Unit effects {} {match e {E::Value(x)=>{}}}','E_DUPLICATE_LOCAL'),
            ('enum E {Value(Buffer<u8>)}','E_NESTED_LINEAR'),
            ('enum E {Value(i32)} fn f(e:E)->Unit effects {} {match e {E::Value(x)=>{}}let y=x;}','E_UNKNOWN_NAME'),
        ]
        for source,code in cases:
            with self.subTest(code=code):
                report=analyze(source,backend='c',native=False).report
                self.assertFalse(report['ok'],report)
                self.assertIn(code,{d['code'] for d in report['diagnostics']})

    def test_payload_enum_foreign_boundaries_remain_rejected(self):
        for suffix in ['pub export "C" fn f(x:E)->i32 effects {} {return 0;}',
                       'extern "C" fn f(x:E)->i32 effects {};',
                       'repr(C) struct Public {value:E}',
                       'extern "C" fn f(x:raw const E)->i32 effects {};']:
            with self.subTest(suffix=suffix):
                report=analyze('enum E {Value(i32)} '+suffix,backend='c',native=False).report
                self.assertFalse(report['ok'],report)
                self.assertIn('E_C_ABI',{d['code'] for d in report['diagnostics']})

    def test_overlapping_payload_enum_borrows_still_reject(self):
        source='''enum E {Value(i32)} fn f(a:mut E,b:read E)->Unit effects {write} {a=b;}
        fn main()->Unit effects {write} {let mut e=E::Value(3);f(mut e,read e);}'''
        p,c=self.frontend(source)
        with self.assertRaises(HeptaError) as raised:emit_c(p,c)
        self.assertEqual(raised.exception.diagnostic.code,'E_C_BORROW')


if __name__=='__main__':unittest.main()
