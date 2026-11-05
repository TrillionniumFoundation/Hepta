"""Concrete Copy-generic record layouts, ordered field evaluation and value copies."""
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


class GenericStructTests(unittest.TestCase):
    setUp = fieldless.FieldlessEnumTests.setUp
    frontend = fieldless.FieldlessEnumTests.frontend
    execute = fieldless.FieldlessEnumTests.execute

    def test_expected_and_explicit_type_arguments(self):
        self.execute('''struct Box<T>{value:T}
        fn make()->Box<i32> effects {} {return Box{value:17};}
        fn get(b:Box<i32>)->i32 effects {} {return b.value;}
        fn main()->Unit effects {panic} {
            let a:Box<i32>=Box{value:7};let b=Box::<i32>{value:11};
            assert(a.value==7);assert(get(b)==11);assert(get(make())==17);
            assert(get(Box{value:19})==19);
        }''')

    def test_many_specializations_and_reordered_parameters(self):
        self.execute('''struct Pair<A,B>{left:A,right:B}
        fn main()->Unit effects {panic} {
            let a=Pair::<u8,bool>{left:211,right:true};let b=Pair::<bool,u8>{right:199,left:false};
            let c=Pair::<i64,f64>{left:-1234567,right:2.5};let d=Pair::<[i32;2],i16>{left:[23,29],right:-31};
            assert(a.left==211);assert(a.right);assert(!b.left);assert(b.right==199);
            assert(c.left==-1234567);assert(c.right==2.5);assert(d.left[0]==23);assert(d.left[1]==29);assert(d.right==-31);
        }''')

    def test_nested_same_template_and_composite_substitution(self):
        self.execute('''struct Box<T>{value:T} struct Row<T>{cells:[Box<T>;2]}
        fn main()->Unit effects {panic} {
            let b=Box::<Box<i32>>{value:Box{value:37}};
            let r=Row::<u16>{cells:[Box{value:41},Box{value:43}]};
            assert(b.value.value==37);assert(r.cells[0].value==41);assert(r.cells[1].value==43);
        }''')

    def test_structs_and_generic_enums_compose_both_directions(self):
        self.execute('''struct Box<T>{value:T} enum Maybe<T>{None,Some(T)}
        struct Envelope<T>{value:Maybe<Box<T>>} enum Packet<T>{Empty,Value(Envelope<T>)}
        fn main()->Unit effects {panic} {
            let a=Box::<Maybe<i32>>{value:Maybe::Some(47)};
            match a.value {Maybe::Some(n)=>{assert(n==47);},Maybe::None=>{assert(false);}}
            let b=Packet::<u16>::Value(Envelope{value:Maybe::Some(Box{value:53})});
            match b {Packet::Value(e)=>{match e.value {Maybe::Some(inner)=>{assert(inner.value==53);},Maybe::None=>{assert(false);}}},Packet::Empty=>{assert(false);}}
        }''')

    def test_constructor_source_order_differs_from_field_order(self):
        self.execute('''struct Triple<T>{first:T,second:T,third:T}
        fn next(n:mut i32)->i32 effects {write,panic} {n=n+1;return n;}
        fn main()->Unit effects {write,panic} {
            let mut n:i32=5;
            let p=Triple::<i32>{third:n,first:next(mut n),second:next(mut n)};
            assert(n==7);assert(p.first==6);assert(p.second==7);assert(p.third==5);
            let q=Triple::<i32>{second:next(mut n),third:next(mut n),first:next(mut n)};
            assert(n==10);assert(q.first==10);assert(q.second==8);assert(q.third==9);
        }''')

    def test_nested_field_snapshots_survive_later_argument_mutation(self):
        self.execute('''struct Box<T>{value:T} struct Pair<T>{before:T,after:T}
        fn replace(b:mut Box<[i32;2]>)->Box<[i32;2]> effects {write} {b.value=[67,71];return b;}
        fn main()->Unit effects {write,panic} {
            let mut b=Box::<[i32;2]>{value:[59,61]};
            let p=Pair::<Box<[i32;2]>>{before:b,after:replace(mut b)};
            assert(p.before.value[0]==59);assert(p.before.value[1]==61);
            assert(p.after.value[0]==67);assert(b.value[1]==71);
        }''')

    def test_copies_assignments_and_nested_field_mutation(self):
        self.execute('''struct Box<T>{value:T} struct Pair<A,B>{left:A,right:B}
        fn main()->Unit effects {write,panic} {
            let mut p=Pair::<Box<[i32;2]>,bool>{left:Box{value:[73,79]},right:true};let saved=p;
            p.left.value[0]=83;p.right=false;assert(saved.left.value[0]==73);assert(saved.right);
            let mut q=p;q= saved;q.left.value[1]=89;
            assert(q.left.value[0]==73);assert(q.left.value[1]==89);assert(saved.left.value[1]==79);assert(p.left.value[0]==83);
        }''')

    def test_read_mut_parameters_slices_and_returns(self):
        self.execute('''struct Box<T>{value:T}
        fn get(x:read Box<i32>)->i32 effects {} {return x.value;}
        fn step(x:mut Box<i32>)->Unit effects {write,panic} {x.value=x.value+1;}
        fn visit(xs:mut [Box<i32>])->Unit effects {write,panic} {for i in 0..len(xs) {step(mut xs[i]);}}
        fn copy(x:read Box<i32>)->Box<i32> effects {} {return x;}
        fn main()->Unit effects {write,panic} {
            let mut xs:[Box<i32>;2]=[Box{value:97},Box{value:101}];let before=copy(read xs[1]);
            visit(mut xs);assert(get(read xs[0])==98);assert(get(read xs[1])==102);assert(get(read before)==101);
        }''')

    def test_generic_structs_in_nongeneric_record_and_enum(self):
        self.execute('''struct Box<T>{value:T} struct Record{small:Box<u8>,wide:Box<i64>}
        enum Event{None,Some(Box<i32>)}
        fn main()->Unit effects {panic} {
            let r=Record{small:Box{value:103},wide:Box{value:-107}};
            let e=Event::Some(Box{value:109});assert(r.small.value==103);assert(r.wide.value==-107);
            match e {Event::Some(b)=>{assert(b.value==109);},Event::None=>{assert(false);}}
        }''')

    def test_raw_pointer_substitution_uses_existing_unsafe_boundary(self):
        self.execute('''struct View<T>{pointer:raw const T} struct Box<T>{value:T}
        fn main()->Unit effects {panic,unsafe} {
            let xs:[i32;2]=[113,127];unsafe {
                let a=View::<i32>{pointer:ptr_read(read xs)};
                let b=Box::<raw const i32>{value:ptr_read(read xs)};
                assert(load(a.pointer,0)==113);assert(load(b.value,1)==127);
            }
        }''')

    def test_module_aliases_and_nominal_specialization_identity(self):
        (self.root/'a.hepta').write_text('pub struct Item<T>{value:T} pub fn item()->Item<i32> effects {} {return Item{value:131};}')
        (self.root/'b.hepta').write_text('pub struct Item<T>{flag:bool,value:T} pub fn item()->Item<u16> effects {} {return Item{value:137,flag:true};}')
        entry=self.root/'main.hepta'
        entry.write_text('''import a as left;import b as right;
        fn main()->Unit effects {panic} {
            let a:left::Item<i32>=left::item();let b:right::Item<u16>=right::item();
            assert(a.value==131);assert(b.value==137);assert(b.flag);
            let c=left::Item::<bool>{value:false};assert(!c.value);
        }''')
        self.execute(project=entry)

    def test_unused_templates_do_not_invent_arguments(self):
        self.execute('''struct Unused<T>{value:T} struct Other<A,B>{left:A,right:B}
        fn main()->Unit effects {} {}''')

    def test_specialization_names_do_not_collide_with_array_helpers(self):
        self.execute('''struct array_1<T>{value:T} struct struct_1<T>{value:T}
        fn main()->Unit effects {panic} {
            let a=array_1::<i32>{value:139};let b=struct_1::<u8>{value:149};let c:[i32;2]=[151,157];
            assert(a.value==139);assert(b.value==149);assert(c[1]==157);
        }''')

    def test_public_cli_example_executes(self):
        result=subprocess.run([sys.executable,'-m','hepta','run',str(ROOT/'examples/generic_structs.hepta'),'--backend','c'],cwd=ROOT,capture_output=True,timeout=30)
        self.assertEqual((result.returncode,result.stdout,result.stderr),(0,b'',b''))

    def test_specialized_unsupported_types_fail_before_native(self):
        for typ in ['u128','i128','[i32;0]','[i128;2]','Result<i32,i128>']:
            with self.subTest(typ=typ):
                program,checked=self.frontend(f'struct Box<T>{{value:T}} fn unused(x:Box<{typ}>)->Unit effects {{}} {{}} fn main()->Unit effects {{}} {{}}')
                with self.assertRaises(HeptaError) as raised:emit_c(program,checked)
                self.assertEqual(raised.exception.diagnostic.code,'E_C_BACKEND_SUBSET')
        program,checked=self.frontend('struct Box<T>{value:T} fn id<T>(x:T)->T effects {} {return x;} fn main()->Unit effects {} {}')
        with self.assertRaises(HeptaError) as raised:emit_c(program,checked)
        self.assertEqual(raised.exception.diagnostic.code,'E_C_BACKEND_SUBSET')

    def test_recursive_template_layouts_reject_before_specialization(self):
        # Typecheck and reject at construction only; no recursive program is
        # emitted, compiled or executed, including pointer-broken cycles.
        cases=[
            'struct E<T>{value:T,next:raw const E<T>}',
            'struct E<T>{value:T,next:raw const E<[T;2]>}',
            'struct E<T>{value:T,next:raw const F<T>} struct F<T>{value:T,next:raw const E<T>}',
            'struct E<T>{value:T,next:raw const F<T>} enum F<T>{Value(T),Next(raw const E<T>)}',
        ]
        for declaration in cases:
            with self.subTest(declaration=declaration):
                program,checked=self.frontend(declaration+' fn main()->Unit effects {} {}')
                with patch('hepta.c_backend.CEmitter.typ',side_effect=AssertionError('specialization reached')):
                    with self.assertRaises(HeptaError) as raised:emit_c(program,checked)
                self.assertEqual(raised.exception.diagnostic.code,'E_C_BACKEND_SUBSET')
                self.assertIn('Recursive generic struct',raised.exception.diagnostic.message)

    def test_generic_frontend_refusals_remain(self):
        cases=[
            ('struct B<T>{value:T} fn f(x:B<i32,u8>)->Unit effects {} {}','E_GENERIC_ARITY'),
            ('struct B<T>{value:T} fn f()->B<i32> effects {} {return B{value:true};}','E_TYPE'),
            ('struct B<T>{value:T} fn f()->Unit effects {write} {let b=B::<i32>{value:7};b.value=9;}','E_IMMUTABLE'),
            ('struct B<T>{value:T} fn f(x:B<Buffer<u8>>)->Unit effects {} {}','E_GENERIC_COPY'),
            ('struct B<T>{value:T} fn f(x:B<Cancellation>)->Unit effects {} {}','E_GENERIC_COPY'),
            ('struct B<T>{value:T} fn f(x:B<i32>)->B<u8> effects {} {return x;}','E_TYPE'),
        ]
        for source,code in cases:
            with self.subTest(code=code):
                report=analyze(source,backend='c',native=False).report
                self.assertFalse(report['ok'],report)
                self.assertIn(code,{d['code'] for d in report['diagnostics']})

    def test_generic_foreign_boundaries_remain_rejected(self):
        for source in [
            'repr(C) struct B<T>{value:T}',
            'struct B<T>{value:T} pub export "C" fn f(x:B<i32>)->i32 effects {} {return 0;}',
            'struct B<T>{value:T} extern "C" fn f(x:B<i32>)->i32 effects {};',
            'struct B<T>{value:T} repr(C) struct Public{value:B<i32>}',
        ]:
            with self.subTest(source=source):
                report=analyze(source,backend='c',native=False).report
                self.assertFalse(report['ok'],report)
                self.assertIn('E_C_ABI',{d['code'] for d in report['diagnostics']})

    def test_conservative_borrow_refusal_remains(self):
        source='''struct B<T>{value:T} fn both(a:read B<i32>,b:mut B<i32>)->Unit effects {} {}
        fn main()->Unit effects {} {let mut b=B::<i32>{value:3};both(read b,mut b);}'''
        report=analyze(source,backend='c',native=False).report
        self.assertFalse(report['ok'],report)
        self.assertIn('E_C_BORROW',{d['code'] for d in report['diagnostics']})


if __name__ == '__main__':
    unittest.main()
