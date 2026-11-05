"""Native qualification of the independent backend's bounded fieldless enums.

Set HEPTA_ENUM_REQUIRE_RUST=1 to require real pinned Rust comparisons as well.
C always executes at O0/O3 with nonrecovering UBSan; missing tools are failures.
"""
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from hepta.ast import HeptaError
from hepta.backend import compile_rust, emit_rust
from hepta.c_backend import compile_c, emit_c
from hepta.checker import check
from hepta.parser import parse
from hepta.pipeline import analyze, analyze_project

ROOT = Path(__file__).resolve().parents[1]


class FieldlessEnumTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-fieldless-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def frontend(self, source):
        program = parse(source)
        checked = check(program)
        self.assertTrue(checked.ok, [d.to_dict() for d in checked.diagnostics])
        return program, checked

    def execute(self, source=None, *, project=None):
        if project is None:
            program, checked = self.frontend(source)
        else:
            result = analyze_project(project, backend="c", native=False, crate_type="bin")
            self.assertTrue(result.report["ok"], result.report)
            program, checked = result.program, result.checked
        generated = emit_c(program, checked)
        rust = emit_rust(program, checked, crate_type="bin")
        self.assertTrue(rust)
        self.assertIsNotNone(shutil.which("gcc"), "Native GCC is required")
        results = []
        for optimize in (False, True):
            report = compile_c(generated, output=self.root / f"c-{optimize}",
                               optimize=optimize, sanitize=True)
            self.assertTrue(report["ok"], report)
            self.assertFalse(report["rustc_used"])
            self.assertIn("-fno-sanitize-recover=all", report["flags"])
            result = subprocess.run([report["artifact"]], capture_output=True, timeout=10)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b"", b""))
            results.append((result.returncode, result.stdout, result.stderr))
        if os.environ.get("HEPTA_ENUM_REQUIRE_RUST") == "1":
            compiler = os.environ.get("RUSTC") or shutil.which("rustc")
            self.assertTrue(compiler, "Native Rust was required but is unavailable")
            for optimize in (False, True):
                report = compile_rust(rust, rustc=compiler, crate_type="bin", optimize=optimize,
                                      output=self.root / f"rust-{optimize}")
                self.assertTrue(report["ok"], report)
                result = subprocess.run([report["artifact"]], capture_output=True, timeout=10)
                self.assertEqual((result.returncode, result.stdout, result.stderr), results[0])

    def test_each_variant_and_reordered_exhaustive_match(self):
        self.execute('''enum Color { Red, Green, Blue }
        fn code(value: Color) -> i32 effects {} {
            match value { Color::Blue => {return 19;}, Color::Red => {return 7;},
                          Color::Green => {return 11;} }
        }
        fn main() -> Unit effects {panic} {
            assert(code(Color::Red)==7); assert(code(Color::Green)==11);
            assert(code(Color::Blue)==19);
        }''')

    def test_single_variant_and_unused_declarations(self):
        self.execute('''enum Only { Here } enum Unused { First, Second }
        fn one(value: Only) -> i32 effects {} {match value {Only::Here=>{return 23;}}}
        fn main()->Unit effects {panic} {assert(one(Only::Here)==23);}''')

    def test_scrutinee_once_and_source_snapshot_before_mutation(self):
        self.execute('''enum Flag { A, B }
        fn next(n: mut i32) -> Flag effects {write,panic} {n=n+1;return Flag::B;}
        fn code(value: Flag)->i32 effects {} {
            match value {Flag::A=>{return 3;},Flag::B=>{return 5;}}
        }
        fn main()->Unit effects {write,panic} {
            let mut n:i32=0;
            match next(mut n) {Flag::A=>{assert(false);},Flag::B=>{n=n+10;}}
            assert(n==11);
            let mut f=Flag::A;
            match f {Flag::A=>{f=Flag::B;},Flag::B=>{assert(false);}}
            assert(code(f)==5);
        }''')

    def test_nested_match_return_and_continuing_arm_scopes(self):
        self.execute('''enum Flag { A, B }
        fn code(a:Flag,b:Flag)->i32 effects {} {
            match a {
                Flag::A=>{match b {Flag::A=>{return 11;},Flag::B=>{return 13;}}},
                Flag::B=>{match b {Flag::B=>{return 17;},Flag::A=>{}}}
            }
            return 19;
        }
        fn main()->Unit effects {panic} {
            assert(code(Flag::A,Flag::A)==11);assert(code(Flag::A,Flag::B)==13);
            assert(code(Flag::B,Flag::B)==17);assert(code(Flag::B,Flag::A)==19);
            let mut out:i32=0;
            match Flag::B {Flag::A=>{let local:i32=2;out=local;},
                           Flag::B=>{let local:i32=3;out=local;}}
            assert(out==3);
        }''')

    def test_arrays_records_copies_and_borrowed_parameters(self):
        self.execute('''enum Flag { A, B }
        struct Cell { flag: Flag, count: i32 }
        struct Row { cells: [Cell; 2] }
        fn code(f:read Flag)->i32 effects {} {
            match f {Flag::A=>{return 2;},Flag::B=>{return 7;}}
        }
        fn flip(f:mut Flag)->Unit effects {write} {
            match f {Flag::A=>{f=Flag::B;},Flag::B=>{f=Flag::A;}}
        }
        fn edit(xs:mut [Flag])->Unit effects {write,panic} {xs[1]=Flag::B;}
        fn sum(xs:read [Flag])->i32 effects {panic} {
            return code(read xs[0])+code(read xs[1]);
        }
        fn main()->Unit effects {write,panic} {
            let mut row:Row=Row{cells:[Cell{flag:Flag::A,count:3},Cell{flag:Flag::B,count:5}]};
            let original=row;
            flip(mut row.cells[0].flag);
            assert(code(read row.cells[0].flag)==7);
            assert(code(read original.cells[0].flag)==2);
            assert(original.cells[1].count==5);
            let mut values:[Flag;2]=[Flag::A,Flag::A];
            let before=values;edit(mut values);
            assert(sum(read before)==4);assert(sum(read values)==9);
        }''')

    def test_match_inside_for_and_while_does_not_exit_outer_loop(self):
        self.execute('''enum Flag { A, B }
        fn main()->Unit effects {panic} {
            let flags:[Flag;2]=[Flag::A,Flag::B];let mut total:i32=0;
            for i in 0..2 {match flags[i as usize] {
                Flag::A=>{total=total+3;},Flag::B=>{total=total+5;}
            } total=total+1;}
            let mut n:i32=0;while n<4 {
                match Flag::A {Flag::A=>{total=total+2;},Flag::B=>{total=99;}}
                n=n+1;
            }
            assert(total==18);assert(n==4);
        }''')

    def test_many_variants_and_distinct_nominal_types(self):
        # Python generates independent expected outputs; declaration and arm order differ.
        count=129
        variants=",".join(f"V{i}" for i in range(count))
        arms=",".join(f"Many::V{i}=>{{return {i*7+3};}}" for i in reversed(range(count)))
        checks="".join(f"assert(code(Many::V{i})=={i*7+3});" for i in range(count))
        self.execute(f'''enum Many {{{variants}}} enum Other {{V0,V1}}
        fn code(x:Many)->i32 effects {{}} {{match x {{{arms}}}}}
        fn other(x:Other)->i32 effects {{}} {{match x {{Other::V1=>{{return 71;}},Other::V0=>{{return 31;}}}}}}
        fn main()->Unit effects {{panic}} {{{checks}assert(other(Other::V0)==31);assert(other(Other::V1)==71);}}''')

    def test_enum_names_do_not_collide_with_array_type_helpers(self):
        self.execute('''enum array_1 { A, B } enum array_2 { A }
        struct Holder { values: [array_1; 2], other: array_2 }
        fn main()->Unit effects {panic} {
            let h=Holder{values:[array_1::A,array_1::B],other:array_2::A};
            match h.values[1] {array_1::A=>{assert(false);},array_1::B=>{}}
            match h.other {array_2::A=>{}}
        }''')

    def test_source_modules_with_same_variant_names(self):
        (self.root/"a.hepta").write_text('pub enum Flag {A,B} pub fn value()->Flag effects {} {return Flag::A;}')
        (self.root/"b.hepta").write_text('pub enum Flag {A,B} pub fn value()->Flag effects {} {return Flag::B;}')
        entry=self.root/"main.hepta"
        entry.write_text('''import a as left; import b as right;
        fn main()->Unit effects {panic} {
            match left::value() {left::Flag::A=>{},left::Flag::B=>{assert(false);}}
            match right::value() {right::Flag::B=>{},right::Flag::A=>{assert(false);}}
        }''')
        self.execute(project=entry)

    def test_public_cli_example_executes(self):
        result=subprocess.run([sys.executable,"-m","hepta","run",
            str(ROOT/"examples/fieldless_enums.hepta"),"--backend","c"],
            cwd=ROOT,capture_output=True,timeout=30)
        self.assertEqual((result.returncode,result.stdout,result.stderr),(0,b"",b""))

    def test_payload_enums_and_generics_remain_unsupported(self):
        for source in ('enum Payload {Value(i32),Empty} fn main()->Unit effects {} {}',
                       'enum Generic<T> {Value(T),Empty} fn main()->Unit effects {} {}',
                       'fn main()->Unit effects {} {let x:Result<i32,u8>=Result::Ok(3);}',
                       'enum Flag {A} fn id<T>(x:T)->T effects {} {return x;}'):
            with self.subTest(source=source):
                p,c=self.frontend(source)
                with self.assertRaises(HeptaError) as error: emit_c(p,c)
                self.assertEqual(error.exception.diagnostic.code,"E_C_BACKEND_SUBSET")

    def test_frontend_refusals_are_preserved(self):
        cases=[
            ('enum E {A,B} fn f(x:E)->Unit effects {} {match x {E::A=>{}}}', 'E_MATCH_EXHAUSTIVE'),
            ('enum E {A} fn f(x:E)->Unit effects {} {match x {E::A=>{},E::A=>{}}}', 'E_MATCH_DUPLICATE'),
            ('enum E {A} fn f(x:E)->Unit effects {} {match x {E::B=>{}}}', 'E_UNKNOWN_VARIANT'),
            ('enum E {A} enum F {A} fn f(x:E)->Unit effects {} {match x {F::A=>{}}}', 'E_PATTERN_TYPE'),
            ('enum E {A} fn f()->E effects {} {return E::B;}', 'E_UNKNOWN_VARIANT'),
            ('enum E {A} fn f()->E effects {} {return E::A();}', 'E_VARIANT_FORM'),
            ('enum E {A} fn f()->Unit effects {} {let x=E::A;x=E::A;}', 'E_IMMUTABLE'),
            ('enum E {A} fn f(x:E)->Unit effects {} {match x {E::A=>{assert(false);}}}', 'E_EFFECT'),
        ]
        for source,code in cases:
            with self.subTest(code=code):
                report=analyze(source,backend="c",native=False).report
                self.assertFalse(report["ok"],report)
                self.assertIn(code,{d["code"] for d in report["diagnostics"]})

    def test_nominal_mismatch_and_foreign_boundaries_remain_rejected(self):
        cases=[
            ('enum E {A} enum F {A} fn f()->E effects {} {return F::A;}', 'E_TYPE'),
            ('enum E {A} pub export "C" fn f(x:E)->i32 effects {} {return 0;}', 'E_C_ABI'),
            ('enum E {A} extern "C" fn f(x:E)->i32 effects {};', 'E_C_ABI'),
            ('enum E {A} repr(C) struct S {value:E}', 'E_C_ABI'),
        ]
        for source,code in cases:
            with self.subTest(source=source):
                report=analyze(source,backend="c",native=False).report
                self.assertFalse(report["ok"],report)
                self.assertIn(code,{d["code"] for d in report["diagnostics"]})

    def test_overlapping_enum_borrows_remain_rejected(self):
        source='''enum E {A,B}
        fn f(a:mut E,b:read E)->Unit effects {write} {a=b;}
        fn main()->Unit effects {write} {let mut e=E::A;f(mut e,read e);}'''
        p,c=self.frontend(source)
        with self.assertRaises(HeptaError) as error: emit_c(p,c)
        self.assertEqual(error.exception.diagnostic.code,"E_C_BORROW")

    def test_unchecked_program_is_not_lowered(self):
        p=parse('enum E {A} fn f()->E effects {} {return true;}')
        c=check(p);self.assertFalse(c.ok)
        with self.assertRaises(HeptaError) as error: emit_c(p,c)
        self.assertEqual(error.exception.diagnostic.code,"E_C_BACKEND_UNCHECKED")


if __name__=="__main__":unittest.main()
