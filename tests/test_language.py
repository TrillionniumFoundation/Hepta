"""Behavioral and rejection tests for ADTs and the bounded generic subset.

Native tests compile and execute source through the public analysis pipeline.
They exercise different variants and instantiations rather than matching emitted
Rust text.  Frontend tests require rejection before the native validator runs.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from hepta.ast import HeptaError, Type
from hepta.backend import compile_rust
from hepta.checker import check
from hepta.parser import parse
from hepta.pipeline import analyze


ROOT = Path(__file__).resolve().parents[1]
RUSTC = Path(os.environ.get("RUSTC", ROOT.parent / "toolchains" / "rust-1.90.0" / "bin" / "rustc"))
NATIVE_AVAILABLE = RUSTC.is_file() and os.access(RUSTC, os.X_OK)


class LanguageSyntax(unittest.TestCase):
    def test_imports_visibility_generics_and_qualified_calls(self):
        source = """module package::main;
        import package::values as values;
        import package::util;
        pub struct Pair<T, E> { left: T, right: E }
        pub enum Maybe<T> { None, Some(T) }
        pub fn select<T>(value: Maybe<T>, fallback: T) -> T effects {} {
            match value {
                Maybe::None => { return fallback; },
                Maybe::Some(payload) => { return util::identity::<T>(payload); },
            }
        }"""
        program = parse(source, "unicode.hepta")
        self.assertEqual(program.name, "package::main")
        self.assertEqual([(x.name, x.alias) for x in program.imports], [("package::values", "values"), ("package::util", "util")])
        self.assertTrue(program.structs[0].public)
        self.assertEqual(program.structs[0].type_params, ("T", "E"))
        self.assertTrue(program.enums[0].public)
        fn = program.functions[0]
        self.assertEqual(fn.type_params, ("T",))
        arm = fn.body[0].data["arms"][1]
        self.assertEqual(arm.pattern.bindings, ["payload"])
        self.assertEqual(arm.body[0].data["expr"].value, "util::identity")
        self.assertEqual(arm.body[0].data["expr"].type_args, (Type("T"),))

    def test_unicode_spans_include_exact_patterns_and_arm_blocks(self):
        source = "// 中文 🦀\r\nenum Flag { A, B }\r\nfn f(x:Flag)->Unit effects {} { match x { Flag::A => {}, Flag::B => {} } }"
        program = parse(source, "example.hepta")
        arm = program.functions[0].body[0].data["arms"][0]
        self.assertEqual(source[arm.pattern.span.start:arm.pattern.span.end], "Flag::A")
        self.assertEqual(source[arm.span.start:arm.span.end], "Flag::A => {}")
        self.assertEqual(arm.span.line, 3)
        self.assertEqual(arm.span.path, "example.hepta")

    def test_nested_generics_adjacent_to_assignment(self):
        program = parse("struct Box<T>{value:T} fn f()->Unit effects {} {let x:Box<Result<u64,u32>>=Box::<Result<u64,u32>>{value:Result::Ok(5)};}")
        self.assertEqual(str(program.functions[0].body[0].data["type"]), "Box<Result<u64, u32>>")

    def test_unsupported_pattern_forms_fail_closed(self):
        for pattern in ("_", "Flag::A if true", "Flag::A(nested(x))", "Flag::A | Flag::B"):
            with self.subTest(pattern=pattern), self.assertRaises(HeptaError):
                parse("enum Flag{A,B} fn f(x:Flag)->Unit effects {} {match x {" + pattern + " => {}}}")


class LanguageRejections(unittest.TestCase):
    def rejects(self, source: str, code: str) -> dict:
        report = analyze(source, rustc=str(RUSTC)).report
        self.assertFalse(report["ok"], report)
        self.assertEqual(report["checks"]["rust_borrows_types"], "not_run", report)
        self.assertIn(code, {d["code"] for d in report["diagnostics"]}, report)
        return report

    def test_nonexhaustive_match_is_rejected(self):
        self.rejects("enum Flag{A,B} fn f(x:Flag)->i32 effects {} {match x {Flag::A=>{return 1;}}}", "E_MATCH_EXHAUSTIVE")

    def test_duplicate_and_unknown_variants_are_rejected(self):
        self.rejects("enum Flag{A,B} fn f(x:Flag)->Unit effects {} {match x {Flag::A=>{},Flag::A=>{},Flag::B=>{}}}", "E_MATCH_DUPLICATE")
        self.rejects("enum Flag{A} fn f()->Flag effects {} {return Flag::Missing;}", "E_UNKNOWN_VARIANT")
        self.rejects("enum Flag{A} fn f(x:Flag)->Unit effects {} {match x {Flag::Missing=>{}}}", "E_UNKNOWN_VARIANT")

    def test_wrong_enum_and_non_enum_scrutinees_are_rejected(self):
        self.rejects("enum A{X} enum B{X} fn f(x:A)->Unit effects {} {match x {B::X=>{}}}", "E_PATTERN_TYPE")
        self.rejects("enum Flag{A} fn f(x:u64)->Unit effects {} {match x {Flag::A=>{}}}", "E_MATCH_TYPE")

    def test_payload_arity_types_and_unit_syntax_are_checked(self):
        for body, code in (("return Choice::A(true);", "E_TYPE"), ("return Choice::A;", "E_VARIANT_ARITY"), ("return Choice::A(1,2);", "E_VARIANT_ARITY"), ("return Choice::B();", "E_VARIANT_FORM")):
            with self.subTest(body=body):
                self.rejects("enum Choice{A(u32),B} fn f()->Choice effects {} {" + body + "}", code)
        self.rejects("enum Choice{A(u32)} fn f(x:Choice)->Unit effects {} {match x {Choice::A=>{}}}", "E_PATTERN_ARITY")

    def test_pattern_bindings_are_local_immutable_and_unique(self):
        self.rejects("enum Choice{A(u32)} fn f(x:Choice)->Unit effects {} {match x {Choice::A(value)=>{value=2;}}}", "E_IMMUTABLE")
        self.rejects("enum Choice{A(u32,u32)} fn f(x:Choice)->Unit effects {} {match x {Choice::A(v,v)=>{}}}", "E_DUPLICATE_LOCAL")
        self.rejects("enum Choice{A(u32)} fn f(x:Choice)->u32 effects {} {match x {Choice::A(v)=>{}} return v;}", "E_UNKNOWN_NAME")

    def test_generic_calls_require_explicit_complete_arguments(self):
        for call in ("identity(1)", "identity::<u32,u64>(1)"):
            self.rejects("fn identity<T>(x:T)->T effects {} {return x;} fn f()->u32 effects {} {return " + call + ";}", "E_GENERIC_ARITY")
        self.rejects("fn f()->u64 effects {} {return wrapping_add::<u64>(1,2);}", "E_GENERIC_ARITY")
        self.rejects("fn f(x:u64)->u64 effects {} {return x::<u64>;}", "E_GENERIC_CONTEXT")

    def test_generic_body_is_checked_even_when_never_instantiated(self):
        self.rejects("fn bad<T>(x:T)->T effects {panic} {return x+1;}", "E_BINARY_TYPE")
        self.rejects("fn bad<T>(x:T)->bool effects {} {return x==x;}", "E_BINARY_TYPE")
        self.rejects("fn bad<T>(x:T)->T effects {} {return true;}", "E_TYPE")

    def test_generic_parameter_declarations_are_checked(self):
        self.rejects("struct Pair<T,T>{left:T}", "E_GENERIC_PARAMETER")
        self.rejects("fn f<u64>(x:u64)->u64 effects {} {return x;}", "E_GENERIC_PARAMETER")
        self.rejects("struct Empty<T>{value:u64}", "E_GENERIC_UNUSED")
        self.rejects("enum Empty<T>{A}", "E_GENERIC_UNUSED")

    def test_type_argument_arity_and_unknown_types_are_checked(self):
        self.rejects("struct Box<T>{value:T} fn f(x:Box)->Unit effects {} {}", "E_GENERIC_ARITY")
        self.rejects("fn f(x:Result<u64>)->Unit effects {} {}", "E_GENERIC_ARITY")
        self.rejects("struct Box<T>{value:T} fn f(x:Box<Missing>)->Unit effects {} {}", "E_UNKNOWN_TYPE")

    def test_resources_cannot_be_hidden_in_generic_type_arguments(self):
        for typ in ("Task<u64>", "Cancellation", "[u8]"):
            with self.subTest(typ=typ):
                self.rejects("struct Box<T>{value:T} fn f(x:Box<" + typ + ">)->Unit effects {} {}", "E_GENERIC_COPY")
        self.rejects("struct Box<T>{value:T} fn f(x:Box<Buffer<u8>>)->Unit effects {} {}", "E_LINEAR_MODE")
        self.rejects("fn identity<T>(x:T)->T effects {} {return x;} fn f()->Unit effects {alloc,block,panic} {let b=buffer(4); let c=identity::<Buffer<u8>>(move b); release(move c);}", "E_GENERIC_COPY")

    def test_resource_payload_obligations_and_borrowed_capabilities_are_checked(self):
        self.rejects("enum Bad{Value(Buffer<u8>)} fn f(x:take Bad)->Unit effects {} {}", "E_LINEAR_UNCONSUMED")
        self.rejects("enum Bad{Value(Cancellation)}", "E_CANCELLATION_TYPE")

    def test_recursive_enum_and_instantiated_struct_layouts_are_rejected(self):
        self.rejects("enum Bad{More(Bad),End}", "E_RECURSIVE_LAYOUT")
        self.rejects("struct Box<T>{value:T} struct Bad{next:Box<Bad>}", "E_RECURSIVE_LAYOUT")
        self.rejects("enum A{Next(B)} struct B{next:A}", "E_RECURSIVE_LAYOUT")

    def test_generic_and_enum_c_boundaries_are_rejected(self):
        self.rejects("repr(C) struct Pair<T>{value:T}", "E_C_ABI")
        self.rejects('pub export "C" fn f<T>(x:T)->T effects {} {return x;}', "E_GENERIC_BOUNDARY")
        self.rejects('enum Flag{A} pub export "C" fn f(x:Flag)->u32 effects {} {return 0;}', "E_C_ABI")

    def test_result_is_reserved_and_constructor_checks_payload(self):
        self.rejects("enum Result<T,E>{A(T),B(E)}", "E_DUPLICATE")
        self.rejects("fn f()->Result<u32,u8> effects {} {return Result::Ok(true);}", "E_TYPE")

    def test_match_branches_preserve_resource_and_effect_obligations(self):
        source = "enum Flag{A,B} fn f(x:Flag)->Unit effects {alloc,block,panic} {let b=buffer(4); match x {Flag::A=>{release(move b);},Flag::B=>{}}}"
        self.rejects(source, "E_LINEAR_BRANCH")
        self.rejects("enum Flag{A,B} fn f(x:Flag)->Unit effects {} {match x {Flag::A=>{assert(false);},Flag::B=>{}}}", "E_EFFECT")
        self.rejects("enum Flag{A,B} fn f(x:Flag)->Unit effects {alloc,block,panic} {let b=buffer(4); match x {Flag::A=>{return;},Flag::B=>{release(move b);}}}", "E_LINEAR_UNCONSUMED")

    def test_generic_function_cannot_be_a_task_worker(self):
        self.rejects("fn worker<T>(data:take Buffer<u8>,cancel:read Cancellation)->u64 effects {alloc,block} {release(move data); return 0;} fn f()->Unit effects {alloc,block,panic,spawn} {let t=spawn(worker,move buffer(4));join(move t);}", "E_TASK_WORKER")

    def test_unresolved_imports_are_never_treated_as_native_namespaces(self):
        self.rejects("import std::process; fn f()->Unit effects {} {process::exit(0);}", "E_IMPORT_UNRESOLVED")

    def test_generic_match_cannot_hide_transitive_worker_unsafe(self):
        source = """
        enum Flag{A,B}
        fn helper<T>(value:T)->Unit effects {unsafe} {unsafe {}}
        fn worker(data:take Buffer<u8>,token:read Cancellation)->u64 effects {alloc,block,unsafe} {
            match Flag::A {Flag::A=>{unsafe {helper::<u32>(1);}},Flag::B=>{}}
            release(move data);return 0;
        }
        fn parent()->Unit effects {alloc,block,spawn,panic,unsafe} {
            let task=spawn(worker,move buffer(1));join(move task);
        }"""
        self.rejects(source, "E_TASK_WORKER_EFFECT")

    def test_long_nominal_cycle_reports_diagnostic_without_python_recursion(self):
        source = "\n".join(f"struct N{i}{{next:N{(i+1)%1050}}}" for i in range(1050))
        checked = check(parse(source))
        self.assertFalse(checked.ok)
        self.assertIn("E_RECURSIVE_LAYOUT", {d.code for d in checked.diagnostics})

    def test_group_owners_and_sender_capabilities_cannot_hide_in_adts(self):
        for typ in ("TaskGroup", "Sender<u64>"):
            with self.subTest(typ=typ):
                self.rejects("struct Box<T>{value:T} fn f(x:Box<" + typ + ">)->Unit effects {} {}", "E_GENERIC_COPY")
        self.rejects("enum Bad{Sender(Sender<u64>)}", "E_SENDER_TYPE")
        self.rejects("enum Bad{Group(TaskGroup)}", "E_NESTED_LINEAR")
        self.rejects("enum TaskGroup{Fake}", "E_DUPLICATE")

    def test_group_worker_generics_and_effect_hiding_are_rejected(self):
        parent = "fn main()->Unit effects {alloc,block,spawn,panic,write,unsafe} {let mut g=task_group(1,1,1);group_spawn(mut g,worker,move buffer(1));group_drain_and_join(move g);}"
        worker = "fn worker<T>(data:take Buffer<u8>,cancel:read Cancellation,out:read Sender<u64>)->u64 effects {alloc,block} {release(move data);return 0;}"
        self.rejects(worker + parent, "E_TASK_WORKER")
        source = """
        enum Choice{A,B}
        fn helper<T>(value:T)->Unit effects {unsafe} {unsafe {}}
        fn worker(data:take Buffer<u8>,cancel:read Cancellation,out:read Sender<u64>)->u64 effects {alloc,block,unsafe} {
            match Choice::A {Choice::A=>{unsafe {helper::<u64>(1);}},Choice::B=>{}}
            release(move data);return 0;
        }"""
        self.rejects(source + parent, "E_TASK_WORKER_EFFECT")


@unittest.skipUnless(NATIVE_AVAILABLE, "pinned native rustc is unavailable")
class NativeLanguage(unittest.TestCase):
    def run_program(self, source: str, *, supplement: str = "", no_std: bool = False) -> None:
        crate_type = "rlib" if supplement or no_std else "bin"
        result = analyze(source, rustc=str(RUSTC), crate_type=crate_type, no_std=no_std)
        self.assertTrue(result.report["ok"], result.report)
        self.assertEqual(result.report["checks"]["rust_borrows_types"], "rustc_checked")
        self.assertFalse(result.report["claims"]["whole_language_soundness_proved"])
        with tempfile.TemporaryDirectory(prefix="hepta-language-") as directory:
            target = Path(directory) / ("unit.o" if no_std else "program")
            built = compile_rust(result.rust + supplement, rustc=str(RUSTC), crate_type="obj" if no_std else "bin", output=target)
            self.assertTrue(built["ok"], built)
            if not no_std:
                executed = subprocess.run([str(target)], capture_output=True, timeout=5)
                self.assertEqual(executed.returncode, 0, executed.stderr.decode())

    def test_result_success_error_and_expected_constructor_inference(self):
        self.run_program("""
        fn divide(a:i64,b:i64)->Result<i64,u8> effects {panic} {
            if b==0 {return Result::Err(7);}
            return Result::Ok(a/b);
        }
        fn main()->Unit effects {panic} {
            match divide(42,6) {
                Result::Ok(value)=>{assert(value==7);},
                Result::Err(code)=>{assert(false);},
            }
            match divide(42,0) {
                Result::Ok(value)=>{assert(false);},
                Result::Err(code)=>{assert(code==7);},
            }
        }""")

    def test_user_generics_multiple_instantiations_and_borrowed_match(self):
        self.run_program("""
        struct Pair<T,E>{left:T,right:E}
        enum Maybe<T>{None,Some(T)}
        fn identity<T>(value:T)->T effects {} {return value;}
        fn forward<T>(value:T)->T effects {} {return identity::<T>(value);}
        fn choose<T>(value:read Maybe<T>,fallback:T)->T effects {} {
            match value {Maybe::None=>{return fallback;},Maybe::Some(payload)=>{return payload;}}
        }
        fn main()->Unit effects {panic} {
            let pair:Pair<u64,bool>=Pair{left:forward::<u64>(13),right:identity::<bool>(true)};
            let some=Maybe::<Pair<u64,bool>>::Some(pair);
            let none:Maybe<Pair<u64,bool>>=Maybe::None;
            let got=choose::<Pair<u64,bool>>(read some,pair);
            let fallback=choose::<Pair<u64,bool>>(read none,pair);
            assert(got.left==13);assert(got.right);assert(fallback.left==13);
            assert(2+got.left==15);
        }""")

    def test_nested_result_generic_reconstruction_and_ignored_payload(self):
        self.run_program("""
        struct Box<T>{value:T}
        fn wrap<T,E>(value:Result<T,E>)->Result<Box<T>,E> effects {} {
            match value {
                Result::Ok(payload)=>{return Result::Ok(Box{value:payload});},
                Result::Err(error)=>{return Result::Err(error);},
            }
        }
        fn main()->Unit effects {panic} {
            let ok=wrap::<u64,u32>(Result::Ok(99));
            match ok {Result::Ok(payload)=>{assert(payload.value==99);},Result::Err(_)=>{assert(false);}}
            let bad=wrap::<u64,u32>(Result::Err(12));
            match bad {Result::Ok(_)=>{assert(false);},Result::Err(code)=>{assert(code==12);}}
        }""")

    def test_tuple_payloads_all_variants_and_arm_scopes_execute(self):
        self.run_program("""
        enum Event{Idle,Point(i64,i64),Done(bool)}
        fn score(event:Event)->i64 effects {panic} {
            match event {
                Event::Idle=>{return 0;},
                Event::Point(x,y)=>{return x+y;},
                Event::Done(success)=>{if success {return 100;} return 1;},
            }
        }
        fn main()->Unit effects {panic} {
            assert(score(Event::Idle)==0);
            assert(score(Event::Point(9,12))==21);
            assert(score(Event::Done(true))==100);
            assert(score(Event::Done(false))==1);
        }""")

    def test_resource_consumption_and_early_return_across_match_arms(self):
        self.run_program("""
        enum Flag{A,B}
        fn consume(flag:Flag,data:take Buffer<u8>)->u64 effects {alloc,block} {
            match flag {Flag::A=>{release(move data);return 11;},Flag::B=>{}}
            release(move data);return 22;
        }
        fn main()->Unit effects {alloc,block,panic} {
            assert(consume(Flag::A,move buffer(3))==11);
            assert(consume(Flag::B,move buffer(3))==22);
        }""")

    def test_copy_generic_adt_compiles_as_no_std_object(self):
        self.run_program("""
        enum Either<T,E>{Left(T),Right(E)}
        pub fn left_or<T,E>(value:Either<T,E>,fallback:T)->T effects {} {
            match value {Either::Left(found)=>{return found;},Either::Right(_)=>{return fallback;}}
        }
        pub fn calculate()->u64 effects {} {return left_or::<u64,u32>(Either::Left(41),0);}
        """, no_std=True)

    def test_generic_mutation_and_copy_from_read_parameters(self):
        self.run_program("""
        struct Box<T>{value:T}
        fn replace<T>(target:mut T,source:read T)->Unit effects {write} {target=source;}
        fn main()->Unit effects {write,panic} {
            let mut target:Box<u64>=Box{value:4};
            let source:Box<u64>=Box{value:91};
            replace::<Box<u64>>(mut target,read source);
            assert(target.value==91);assert(source.value==91);
        }""")

    def test_generic_borrows_still_require_real_rust_alias_validation(self):
        source = """
        fn replace<T>(target:mut T,source:read T)->Unit effects {write} {target=source;}
        fn main()->Unit effects {write} {let mut value:u32=1;replace::<u32>(mut value,read value);}
        """
        frontend = analyze(source, native=False, crate_type="bin")
        self.assertTrue(frontend.report["ok"], frontend.report)
        self.assertEqual(frontend.report["status"], "frontend_only")
        native = analyze(source, rustc=str(RUSTC), crate_type="bin")
        self.assertFalse(native.report["ok"], native.report)
        self.assertEqual(native.report["checks"]["types_effects_resources"], "passed_in_supported_subset")
        self.assertTrue(any(d["phase"] == "backend" and d["code"] == "E0502" for d in native.report["diagnostics"]), native.report)

    def test_recursive_pointer_layout_and_nested_nominal_values_are_accepted(self):
        self.run_program("""
        struct Link<U>{pointer:raw const U}
        struct Node{link:Link<Node>}
        struct Box<U>{value:U}
        struct T{result:Result<u32,u8>}
        fn main()->Unit effects {panic} {
            let nested:Box<Box<u64>>=Box{value:Box{value:7}};
            let value:T=T{result:Result::Ok(9)};
            assert(nested.value.value==7);
            match value.result {Result::Ok(number)=>{assert(number==9);},Result::Err(_)=>{assert(false);}}
        }""")

    def test_group_reports_pass_through_result_and_generic_match(self):
        self.run_program("""
        enum Choice{Send,Skip}
        fn identity<T>(value:T)->T effects {} {return value;}
        fn producer(data:take Buffer<u8>,token:read Cancellation,out:read Sender<u64>)->u64 effects {alloc,block,panic,write} {
            match Choice::Send {
                Choice::Send=>{group_send(read out,10);group_send(read out,20);},
                Choice::Skip=>{},
            }
            release(move data);return 2;
        }
        fn main()->Unit effects {alloc,block,panic,spawn,write} {
            let mut group=task_group(1,2,1);
            assert(group_spawn(mut group,producer,move buffer(2)));
            let report=group_drain_and_join(move group);
            let result=identity::<Result<GroupReport,u32>>(Result::Ok(report));
            match result {
                Result::Ok(finished)=>{
                    assert(finished.joined);assert(finished.completed_tasks==1);
                    assert(finished.discarded==2);assert(finished.sum==2);
                    assert(finished.peak_queued<=1);
                },
                Result::Err(_)=>{assert(false);},
            }
        }""")

    def test_group_runtime_is_available_for_type_only_enum_payloads(self):
        self.run_program("enum Envelope{Report(GroupReport),Empty} fn main()->Unit effects {} {}")

    def test_group_runtime_is_available_for_type_only_generic_arguments(self):
        self.run_program("fn phantom<T>()->Unit effects {} {} fn main()->Unit effects {} {phantom::<GroupReport>();}")

    def test_match_arms_consume_group_handle_before_returning_report(self):
        self.run_program("""
        enum Choice{Cancel,Drain}
        fn finish(choice:Choice)->GroupReport effects {alloc,block,panic,write} {
            let group=task_group(0,0,1);
            match choice {
                Choice::Cancel=>{return group_cancel_and_join(move group);},
                Choice::Drain=>{return group_drain_and_join(move group);},
            }
        }
        fn main()->Unit effects {alloc,block,panic,write} {
            assert(finish(Choice::Cancel).joined);
            assert(finish(Choice::Drain).joined);
        }""")


if __name__ == "__main__":
    unittest.main()
