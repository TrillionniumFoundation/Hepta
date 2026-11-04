"""Real C execution for source bindings next to unchanged foreign symbols."""
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from hepta.backend import compile_rust, emit_header, emit_rust
from hepta.c_backend import compile_c, emit_c
from hepta.checker import check
from hepta.parser import parse

ROOT = Path(__file__).resolve().parents[1]
RUSTC = os.environ.get("RUSTC") or shutil.which("rustc")
EXPORT = 'export "C" fn h_value()->i32 effects {} {return 42;}\n'


@unittest.skipUnless(shutil.which("gcc"), "requires actual GCC")
class CLocalSymbolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-local-symbols-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def frontend(self, source):
        program = parse(source)
        checked = check(program)
        self.assertTrue(checked.ok, [d.to_dict() for d in checked.diagnostics])
        return program, checked

    def execute(self, source, *, extra="", expected=0, crate_type="bin"):
        program, checked = self.frontend(source)
        generated = emit_c(program, checked, crate_type=crate_type)
        for optimized in (False, True):
            with self.subTest(optimized=optimized):
                built = compile_c(generated + extra, output=self.directory / "program",
                                  optimize=optimized, sanitize=True)
                self.assertTrue(built["ok"], built["diagnostics"])
                self.assertFalse(built["rustc_used"])
                result = subprocess.run([built["artifact"]], capture_output=True, timeout=15)
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertNotIn(b"runtime error:", result.stderr)
        return generated

    def test_exported_symbol_with_local_binding(self):
        self.execute(EXPORT + 'fn main()->i32 effects {} {let value:i32=1;return h_value();}', expected=42)

    def test_extern_symbol_with_local_binding(self):
        source = 'extern "C" fn h_value()->i32 effects {ffi}; fn main()->i32 effects {ffi,unsafe} {let value:i32=1;unsafe {return h_value();}}'
        self.execute(source, extra='\nint32_t h_value(void) { return 42; }\n', expected=42)

    def test_value_read_and_mut_parameters(self):
        for mode, arg, effects in (("", "value", "panic"), ("read ", "read value", "panic"),
                                   ("mut ", "mut value", "panic,write")):
            with self.subTest(mode=mode):
                assign = "value=3;" if mode == "mut " else ""
                source = EXPORT + f'fn use(value:{mode}i32)->i32 effects {{{effects}}} {{{assign}return h_value()+value;}}'
                self.execute(source + f'fn main()->Unit effects {{panic,write}} {{let mut value:i32=3;assert(use({arg})==45);}}')

    def test_for_binding_and_scope_exit(self):
        self.execute(EXPORT + '''fn main()->Unit effects {panic,write} {
            let mut sum:i32=0;for value in 0..3 {sum=sum+h_value()+value as i32;}
            assert(sum==129);assert(h_value()==42);
        }''')

    def test_match_payload_binding_and_discard(self):
        self.execute(EXPORT + '''enum Choice {Some(i32),None}
        fn use(choice:Choice)->i32 effects {panic} {
            match choice {Choice::Some(value)=>{return h_value()+value;},Choice::None=>{return 0;}}
        }
        fn main()->Unit effects {panic} {assert(use(Choice::Some(3))==45);assert(use(Choice::None)==0);
            match Choice::Some(3) {Choice::Some(_)=>{assert(h_value()==42);},Choice::None=>{assert(false);}}
        }''')

    def test_returned_read_and_mut_places(self):
        self.execute(EXPORT + '''
        fn view(value:read i32)->read i32 effects {panic} {assert(h_value()==42);return read value;}
        fn writable(value:mut i32)->mut i32 effects {panic} {assert(h_value()==42);return mut value;}
        fn set(value:mut i32)->Unit effects {write,panic} {value=h_value();}
        fn main()->Unit effects {write,panic} {let mut value:i32=3;assert(view(read value)==3);
            set(mut writable(mut value));assert(value==42);}
        ''')

    def test_slice_parameter_and_index_place(self):
        self.execute(EXPORT + '''
        fn view(value:read [i32])->read [i32] effects {panic} {assert(h_value()==42);return read value;}
        fn set(value:mut [i32])->Unit effects {write,panic} {value[0]=h_value();}
        fn main()->Unit effects {write,panic} {let mut value:[i32;2]=[3,5];set(mut value);
            assert(view(read value)[0]==42);assert(value[1]==5);}
        ''')

    def test_struct_fields_remain_distinct_from_local_names(self):
        generated = self.execute(EXPORT + '''struct Pair {value:i32}
        fn main()->Unit effects {panic,write} {let mut value:Pair=Pair{value:3};
            value.value=h_value();assert(value.value==42);}
        ''')
        self.assertIn(".h_value", generated)
        self.assertIn(" h_value;", generated)

    def test_generic_value_and_owned_bindings(self):
        self.execute(EXPORT + '''
        fn copy<T:Copy>(value:T)->T effects {panic} {assert(h_value()==42);return value;}
        fn dispose<T:Owned>(value:take T)->Unit effects {alloc,block,panic} {assert(h_value()==42);drop(move value);}
        fn main()->Unit effects {alloc,block,panic} {assert(copy::<i32>(3)==3);
            let value=buffer(2);assert(h_value()==42);dispose::<Buffer<u8>>(move value);}
        ''')

    def test_new_and_old_local_spellings_cannot_alias(self):
        self.execute(EXPORT + '''fn main()->Unit effects {panic} {
            let value:i32=3;let __hepta_cb_local_value:i32=5;let _value:i32=7;
            assert(value==3);assert(__hepta_cb_local_value==5);assert(_value==7);assert(h_value()==42);
        }''')

    def test_multiple_collision_families_remain_injective(self):
        self.execute(EXPORT + '''export "C" fn h___hepta_cb_local_value()->i32 effects {} {return 19;}
        fn main()->Unit effects {panic} {let value:i32=3;let __hepta_cb_local_value:i32=5;
            assert(value==3);assert(__hepta_cb_local_value==5);
            assert(h_value()==42);assert(h___hepta_cb_local_value()==19);}
        ''')

    def test_exported_self_recursion_uses_the_original_symbol(self):
        self.execute('''export "C" fn h_value(value:i32)->i32 effects {panic} {
            if value==0 {return 42;}return h_value(value-1);
        } fn main()->i32 effects {panic} {return h_value(3);}''', expected=42)

    def test_source_shadowing_and_reserved_c_names_still_rejected(self):
        for source, code in (
            (EXPORT + 'fn main()->Unit effects {} {let h_value:i32=3;}', "E_NAME_COLLISION"),
            ('extern "C" fn __hepta_cb_local_value()->i32 effects {};', "E_C_IDENTIFIER"),
            ('export "C" fn __hepta_cb_local_value()->i32 effects {} {return 3;}', "E_C_IDENTIFIER")):
            with self.subTest(source=source):
                checked = check(parse(source))
                self.assertFalse(checked.ok)
                self.assertIn(code, [d.code for d in checked.diagnostics])

    def test_unaffected_debug_local_names_remain_stable(self):
        program, checked = self.frontend((ROOT / "examples/debug/main.hepta").read_text())
        generated = emit_c(program, checked)
        for name in ("h_input", "h_base", "h_result"):
            self.assertIn(name, generated)
        self.assertNotIn("__hepta_cb_local_", generated)

    def test_cli_build_executes_the_colliding_source(self):
        source = self.directory / "main.hepta"
        source.write_text(EXPORT + 'fn main()->i32 effects {} {let value:i32=1;return h_value();}', encoding="utf-8")
        output = self.directory / "cli-program"
        result = subprocess.run([sys.executable, "-m", "hepta", "build", str(source),
                                 "--backend", "c", "-o", str(output)], cwd=ROOT,
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(subprocess.run([output], timeout=15).returncode, 42)

    def test_exact_export_names_link_from_c_and_cpp(self):
        source = EXPORT + 'export "C" fn answer(value:i32)->i32 effects {panic} {return h_value()+value;}'
        program, checked = self.frontend(source)
        header = emit_header(program)
        self.assertIn("int32_t h_value(void);", header)
        self.assertIn("int32_t answer(int32_t value);", header)
        (self.directory / "api.h").write_text(header, encoding="utf-8")
        obj = self.directory / "api.o"
        built = compile_c(emit_c(program, checked, crate_type="obj"), crate_type="obj", output=obj)
        self.assertTrue(built["ok"], built["diagnostics"])
        for compiler, standard in (("gcc", "c11"), ("g++", "c++17")):
            with self.subTest(compiler=compiler):
                self.assertIsNotNone(shutil.which(compiler), "Actual C/C++ client compiler is required")
                client = self.directory / ("client.c" if compiler == "gcc" else "client.cpp")
                client.write_text('#include "api.h"\nint main(void) {return h_value()!=42 || answer(3)!=45;}\n')
                output = self.directory / ("client-" + compiler)
                linked = subprocess.run([compiler, "-std=" + standard, "-Werror", str(client), str(obj), "-lm", "-o", str(output)], capture_output=True, timeout=30)
                self.assertEqual(linked.returncode, 0, linked.stderr)
                self.assertEqual(subprocess.run([output], timeout=15).returncode, 0)

    @unittest.skipUnless(RUSTC and Path(RUSTC).is_file(), "requires real pinned Rust reference")
    def test_native_rust_reference_matches_c(self):
        source = EXPORT + '''
        enum Choice {Some(i32),None}
        fn use(value:i32)->i32 effects {panic} {return h_value()+value;}
        fn main()->Unit effects {panic,write,io} {let mut sum:i32=0;
            for value in 0..3 {sum=sum+use(value as i32);}
            match Choice::Some(sum) {Choice::Some(value)=>{assert(value==129);print_i64((h_value()+value) as i64);},Choice::None=>{assert(false);}}
        }'''
        program, checked = self.frontend(source)
        observed = []
        for backend in ("c", "rust"):
            output = self.directory / backend
            built = (compile_c(emit_c(program, checked), output=output) if backend == "c" else
                     compile_rust(emit_rust(program, checked, crate_type="bin"), rustc=RUSTC, crate_type="bin", output=output))
            self.assertTrue(built["ok"], built["diagnostics"])
            ran = subprocess.run([output], capture_output=True, timeout=15)
            self.assertEqual(ran.returncode, 0, ran.stderr)
            observed.append(ran.stdout)
        self.assertEqual(observed, [b"171\n", b"171\n"])


if __name__ == "__main__":
    unittest.main()
