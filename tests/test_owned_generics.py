"""Finite ownership polymorphism, real cleanup and independent graph attacks."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from hepta.ast import HeptaError
from hepta.backend import compile_rust, find_rustc
from hepta.checker import check
from hepta.parser import parse
from hepta.pipeline import analyze, analyze_project, interface_hash
from hepta.resource_ir import verify_resource_ir
from hepta.resource_lowering import lower_resource_ir
from hepta.semantic_ir import lower_checked_program


ROOT = Path(__file__).resolve().parents[1]
OPERATIONS = (ROOT / "examples/owned_generics/operations.hepta").read_text().split(";", 1)[1]
GENERIC = """
struct Box<T>{value:T}
fn identity<T:Owned>(value:take T)->T effects {} {return move value;}
fn wrap<T:Owned>(value:take T)->Box<T> effects {} {return Box{value:move value};}
fn dispose<T:Owned>(value:take T)->Unit effects {alloc,block} {drop(move value);}
fn unused<T:Owned>(value:take T)->Unit effects {alloc,block} {drop(move value);}
fn main()->Unit effects {alloc,block,panic} {
  let boxed=wrap::<Buffer<u8>>(move buffer(7));
  dispose::<Box<Buffer<u8>>>(move identity::<Box<Buffer<u8>>>(move boxed));
}
"""


def compiler():
    try:
        return find_rustc(os.environ.get("RUSTC"))
    except HeptaError:
        return None


RUSTC = compiler()


def graph(source=GENERIC):
    program = parse(source)
    checked = check(program)
    if not checked.ok:
        raise AssertionError([d.to_dict() for d in checked.diagnostics])
    return lower_resource_ir(program, checked)


def fn(doc, name):
    return next(f for f in doc["functions"] if f["name"] == name)


def ops(function, operation):
    return [op for block in function["blocks"] for op in block["ops"] if op["op"] == operation]


class OwnedGenericChecks(unittest.TestCase):
    def reject(self, source, code):
        report = analyze(source, native=False).report
        self.assertFalse(report["ok"], report)
        self.assertIn(code, [d["code"] for d in report["diagnostics"]], report)
        self.assertEqual(report["checks"]["rust_borrows_types"], "not_run")

    def test_explicit_copy_and_implicit_copy_have_the_same_interface(self):
        implicit = parse("fn id<T>(x:T)->T effects {} {return x;}")
        explicit = parse("fn id<T:Copy>(x:T)->T effects {} {return x;}")
        self.assertEqual(interface_hash(implicit), interface_hash(explicit))
        self.assertEqual(explicit.functions[0].type_bounds, {"T": "Copy"})

    def test_owned_constraint_is_part_of_interface_and_semantic_ir(self):
        copy_source = "fn view<T:Copy>(x:read T)->read T effects {} {return read x;}"
        owned_source = copy_source.replace("T:Copy", "T:Owned")
        a, b = parse(copy_source), parse(owned_source)
        self.assertNotEqual(interface_hash(a), interface_hash(b))
        hsir = lower_checked_program(b, check(b))
        self.assertEqual(hsir["functions"][0]["type_bounds"], {"T": "Owned"})

    def test_unknown_constraint_is_rejected_even_without_instantiations(self):
        self.reject("fn f<T:Send>(x:T)->T effects {} {return x;}", "E_GENERIC_BOUND")

    def test_owned_parameter_requires_explicit_take_or_borrow(self):
        self.reject("fn f<T:Owned>(x:T)->Unit effects {alloc,block} {drop(move x);}", "E_LINEAR_MODE")

    def test_generic_body_cannot_implicitly_copy_its_owner(self):
        self.reject("fn f<T:Owned>(x:take T)->T effects {} {return x;}", "E_MOVE_REQUIRED")
        self.reject("fn f<T:Owned>(x:take T)->Unit effects {alloc,block} {let y=x;drop(move x);drop(move y);}", "E_MOVE_REQUIRED")

    def test_unused_generic_bodies_still_have_linear_obligations(self):
        self.reject("fn never_called<T:Owned>(x:take T)->Unit effects {} {}", "E_LINEAR_UNCONSUMED")

    def test_generic_owner_cannot_be_moved_twice(self):
        self.reject("fn f<T:Owned>(x:take T)->Unit effects {alloc,block} {drop(move x);drop(move x);}", "E_USE_AFTER_MOVE")

    def test_early_return_branch_and_loop_keep_generic_obligations(self):
        cases = [
            ("if stop {return;}drop(move x);", "E_LINEAR_UNCONSUMED"),
            ("if stop {drop(move x);}", "E_LINEAR_BRANCH"),
            ("while stop {drop(move x);}drop(move x);", "E_LINEAR_LOOP"),
        ]
        for body, code in cases:
            with self.subTest(body=body):
                self.reject("fn f<T:Owned>(x:take T,stop:bool)->Unit effects {alloc,block} {" + body + "}", code)

    def test_result_match_cannot_ignore_generic_owned_payload(self):
        self.reject("fn f<T:Owned,E:Copy>(x:take Result<T,E>)->Unit effects {} {match move x {Result::Ok(_)=>{},Result::Err(e)=>{}}}", "E_LINEAR_DISCARD")

    def test_owned_instantiation_requires_owned_not_just_sized(self):
        self.reject("fn f<T:Owned>(x:take T)->T effects {} {return move x;}fn main()->Unit effects {} {let n=f::<u64>(move 7);}", "E_GENERIC_OWNED")
        self.reject("struct Box<T>{value:T}fn f<T:Owned>(x:take T)->T effects {} {return move x;}fn main()->Unit effects {} {let n=f::<Box<u64>>(move Box{value:7});}", "E_GENERIC_OWNED")

    def test_copy_callee_cannot_receive_abstract_owned_parameter(self):
        self.reject("fn id<T:Copy>(x:T)->T effects {} {return x;}fn f<U:Owned>(x:take U)->U effects {} {return move id::<U>(move x);}", "E_GENERIC_COPY")

    def test_owned_callee_cannot_receive_abstract_copy_parameter(self):
        self.reject("fn id<T:Owned>(x:take T)->T effects {} {return move x;}fn f<U:Copy>(x:U)->U effects {} {return id::<U>(move x);}", "E_GENERIC_OWNED")

    def test_generic_drop_keeps_destructor_effects(self):
        self.reject("fn f<T:Owned>(x:take T)->Unit effects {} {drop(move x);}", "E_EFFECT")

    def test_opaque_owned_does_not_imply_methods_or_operators(self):
        self.reject("fn f<T:Owned>(x:take T)->usize effects {alloc,block} {let n=len(x);drop(move x);return n;}", "E_BUILTIN_TYPE")

    def test_owned_parameters_cannot_hide_unsupported_containers(self):
        for value in ("[T;2]", "raw const T", "Buffer<T>"):
            with self.subTest(value=value):
                self.reject("fn f<T:Owned>(x:take " + value + ")->Unit effects {alloc,block} {drop(move x);}", "E_NESTED_LINEAR")

    def test_abstract_owned_borrow_cannot_be_consumed(self):
        self.reject("fn f<T:Owned>(x:read T)->Unit effects {alloc,block} {drop(move x);}", "E_MOVE_BORROW")

    def test_scoped_task_cannot_be_hidden_in_owned_instantiation(self):
        source = """
        fn discard<T:Owned>(x:take T)->Unit effects {alloc,block} {drop(move x);}
        fn worker(data:take Buffer<u8>,token:read Cancellation)->u64 effects {alloc,block} {release(move data);return 0;}
        fn main()->Unit effects {alloc,block,panic,spawn} {let task=spawn(worker,move buffer(1));discard::<Task<u64>>(move task);}
        """
        self.reject(source, "E_GENERIC_COPY")

    def test_generic_owned_functions_keep_c_boundary_restrictions(self):
        self.reject('export "C" fn f<T:Owned>(x:take T)->T effects {} {return move x;}', "E_GENERIC_BOUNDARY")
        result = analyze(GENERIC, native=False, backend="c")
        self.assertTrue(result.report["ok"], result.report)
        self.assertIsNone(result.rust)
        self.assertIn("__hepta_cb_generic_", result.c)


class GenericResourceIR(unittest.TestCase):
    def reject(self, document, code):
        result = verify_resource_ir(document)
        self.assertFalse(result["ok"], result)
        self.assertEqual(result["diagnostics"][0]["code"], code, result)

    def test_every_generic_body_is_verified_without_specialization(self):
        document = graph()
        result = verify_resource_ir(document)
        self.assertTrue(result["ok"], result)
        self.assertEqual(document["schema"], "hepta.resource-ir.v3")
        self.assertIn("unused", {f["function"] for f in result["functions"]})
        self.assertEqual(fn(document, "unused")["type_params"], ["@unused::T"])
        self.assertFalse(result["claims"]["source_to_ir_refinement_proved"])

    def test_serialized_verifier_never_imports_the_source_frontend(self):
        document = graph()
        code = "import json,sys;from hepta.resource_ir import verify_resource_ir;r=verify_resource_ir(json.load(sys.stdin));assert r['ok'],r;assert 'hepta.checker' not in sys.modules;assert 'hepta.parser' not in sys.modules"
        result = subprocess.run([sys.executable, "-c", code], input=json.dumps(document), text=True, capture_output=True, cwd=ROOT, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_remove_drop_from_uncalled_generic_body_is_rejected(self):
        document = graph()
        body = fn(document, "unused")["blocks"][0]["ops"]
        body[:] = [op for op in body if op["op"] != "drop"]
        self.reject(document, "E_RIR_LEAK")

    def test_duplicated_abstract_owner_move_is_rejected(self):
        document = graph()
        body = fn(document, "identity")["blocks"][0]["ops"]
        body.insert(1, copy.deepcopy(body[0]))
        self.reject(document, "E_RIR_USE_AFTER_MOVE")

    def test_owned_type_argument_constraint_is_checked_independently(self):
        document = graph()
        ops(fn(document, "main"), "call")[0]["type_args"] = ["u8"]
        self.reject(document, "E_RIR_GENERIC")

    def test_missing_type_argument_is_not_inferred_from_unsafe_slots(self):
        document = graph()
        del ops(fn(document, "main"), "call")[0]["type_args"]
        self.reject(document, "E_RIR_GENERIC")

    def test_callee_type_parameter_cannot_escape_into_caller_scope(self):
        document = graph()
        ops(fn(document, "main"), "call")[0]["type_args"] = ["@wrap::T"]
        self.reject(document, "E_RIR_GENERIC")

    def test_unbound_and_rebound_type_parameters_are_rejected(self):
        document = graph()
        fn(document, "unused").pop("type_params")
        self.reject(document, "E_RIR_GENERIC")
        document = graph()
        fn(document, "unused")["type_params"] = ["@dispose::T"]
        self.reject(document, "E_RIR_GENERIC")

    def test_concrete_aggregate_cannot_forge_generic_payload_shape(self):
        document = graph()
        document["types"]["Box<Buffer<u8>>"]["fields"][0]["type"] = "u8"
        self.reject(document, "E_RIR_GENERIC")

    def test_copy_and_owned_parameters_are_scoped_by_function(self):
        source = "fn copy<T:Copy>(x:T)->T effects {} {return x;}" + GENERIC
        document = graph(source)
        self.assertFalse(verify_resource_ir(document)["owned_types"].count("@copy::T"))
        self.assertIn("@identity::T", verify_resource_ir(document)["owned_types"])

    def test_legacy_graphs_still_verify_but_cannot_smuggle_generic_types(self):
        document = graph("fn main()->Unit effects {alloc,block,panic} {let x=buffer(3);drop(move x);}")
        document["schema"] = "hepta.resource-ir.v1"
        self.assertTrue(verify_resource_ir(document)["ok"])
        document = graph()
        document["schema"] = "hepta.resource-ir.v1"
        self.reject(document, "E_RIR_SCHEMA")


@unittest.skipUnless(RUSTC, "requires pinned native Rust compiler")
class NativeOwnedGenerics(unittest.TestCase):
    def execute(self, source, harness=""):
        analysis = analyze(source, rustc=RUSTC, crate_type="rlib" if harness else "bin")
        self.assertTrue(analysis.report["ok"], analysis.report)
        with tempfile.TemporaryDirectory(prefix="hepta-generic-native-") as directory:
            built = compile_rust(analysis.rust + harness, rustc=RUSTC, crate_type="bin", output=Path(directory) / "run")
            self.assertTrue(built["ok"], built)
            executed = subprocess.run([built["artifact"]], capture_output=True, text=True, timeout=15)
            self.assertEqual(executed.returncode, 0, executed.stderr)
        return analysis

    def test_copy_and_owned_constraints_monomorphize_without_boxing(self):
        analysis = self.execute("fn copy<T:Copy>(x:T)->T effects {} {return x;}" + GENERIC.replace("let boxed=", "assert(copy::<u64>(41)==41);let boxed="))
        self.assertIn("fn h_identity<G_T>(", analysis.rust)
        self.assertIn("fn h_copy<G_T: core::marker::Copy>(", analysis.rust)

    def test_native_borrow_gate_still_rejects_aliased_generic_mut_and_read(self):
        source = "fn pair<T:Owned>(x:mut T,y:read T)->Unit effects {} {}fn main()->Unit effects {alloc,block,panic} {let mut x=buffer(3);pair::<Buffer<u8>>(mut x,read x);drop(move x);}"
        result = analyze(source, rustc=RUSTC)
        self.assertFalse(result.report["ok"])
        self.assertEqual(result.report["checks"]["types_effects_resources"], "passed_in_supported_subset")
        self.assertEqual(result.report["checks"]["rust_borrows_types"], "rejected")

    def test_normal_error_and_early_return_free_actual_allocations(self):
        source = OPERATIONS + """
        fn exercise()->Unit effects {alloc,block,panic} {
          let a=choose::<Buffer<u8>,Buffer<u8>>(move buffer(4093),move buffer(8161),true);
          dispose::<Result<Buffer<u8>,Buffer<u8>>>(move a);
          let b=choose::<Buffer<u8>,Buffer<u8>>(move buffer(12281),move buffer(16381),false);
          dispose::<Result<Buffer<u8>,Buffer<u8>>>(move b);
          let c=finish::<Buffer<u8>,u8>(move buffer(24571),false,7);
          dispose::<Result<Buffer<u8>,u8>>(move c);
        }
        """
        harness = r'''
struct Counting;
static TRACK:std::sync::atomic::AtomicBool=std::sync::atomic::AtomicBool::new(false);
static ALLOC:std::sync::atomic::AtomicUsize=std::sync::atomic::AtomicUsize::new(0);
static FREE:std::sync::atomic::AtomicUsize=std::sync::atomic::AtomicUsize::new(0);
static BYTES:std::sync::atomic::AtomicIsize=std::sync::atomic::AtomicIsize::new(0);
unsafe impl std::alloc::GlobalAlloc for Counting {
  unsafe fn alloc(&self,l:std::alloc::Layout)->*mut u8 {
    let p=std::alloc::GlobalAlloc::alloc(&std::alloc::System,l);
    if TRACK.load(std::sync::atomic::Ordering::SeqCst)&&!p.is_null(){
      ALLOC.fetch_add(1,std::sync::atomic::Ordering::SeqCst);
      BYTES.fetch_add(l.size() as isize,std::sync::atomic::Ordering::SeqCst);
    } p
  }
  unsafe fn dealloc(&self,p:*mut u8,l:std::alloc::Layout){
    if TRACK.load(std::sync::atomic::Ordering::SeqCst){
      FREE.fetch_add(1,std::sync::atomic::Ordering::SeqCst);
      BYTES.fetch_sub(l.size() as isize,std::sync::atomic::Ordering::SeqCst);
    }std::alloc::GlobalAlloc::dealloc(&std::alloc::System,p,l);
  }
}
#[global_allocator]static A:Counting=Counting;
fn main(){TRACK.store(true,std::sync::atomic::Ordering::SeqCst);h_exercise();TRACK.store(false,std::sync::atomic::Ordering::SeqCst);
assert_eq!(ALLOC.load(std::sync::atomic::Ordering::SeqCst),5);assert_eq!(FREE.load(std::sync::atomic::Ordering::SeqCst),5);assert_eq!(BYTES.load(std::sync::atomic::Ordering::SeqCst),0);}
'''
        self.execute(source, harness)

    def test_cooperative_cancellation_and_worker_failure_use_generic_cleanup(self):
        source = OPERATIONS + """
        fn cancelled_worker(data:take Buffer<u8>,token:read Cancellation)->u64 effects {alloc,block} {
          let pending=forward::<Buffer<u8>>(move data);
          while !cancelled(read token) {}
          let n=len(view::<Buffer<u8>>(read pending));dispose::<Buffer<u8>>(move pending);return n as u64;
        }
        fn failing_worker(data:take Buffer<u8>,token:read Cancellation,out:read Sender<u64>)->u64 effects {alloc,block,panic,write} {
          let error:Result<u64,Buffer<u8>>=Result::Err(move data);
          group_fail(read out,37);dispose::<Result<u64,Buffer<u8>>>(move error);return 0;
        }
        fn exercise()->Unit effects {alloc,block,panic,spawn,write} {
          let task=spawn(cancelled_worker,move buffer(65519));assert(cancel_and_join(move task)==65519);
          let mut group=task_group(1,65521,1);assert(group_spawn(mut group,failing_worker,move buffer(65521)));
          let report=group_drain_and_join(move group);assert(report.failed);assert(report.failure_code==37);
          assert(report.active_tasks==0);assert(report.completed_tasks==1);assert(report.joined);
        }
        """
        harness = r'''
struct Observed;
static LIVE:std::sync::atomic::AtomicIsize=std::sync::atomic::AtomicIsize::new(0);
static ALLOC:std::sync::atomic::AtomicUsize=std::sync::atomic::AtomicUsize::new(0);
static FREE:std::sync::atomic::AtomicUsize=std::sync::atomic::AtomicUsize::new(0);
fn tracked(l:std::alloc::Layout)->bool{matches!(l.size(),65519|65521)}
unsafe impl std::alloc::GlobalAlloc for Observed {
 unsafe fn alloc(&self,l:std::alloc::Layout)->*mut u8{
  let p=std::alloc::GlobalAlloc::alloc(&std::alloc::System,l);
  if !p.is_null()&&tracked(l){ALLOC.fetch_add(1,std::sync::atomic::Ordering::SeqCst);LIVE.fetch_add(1,std::sync::atomic::Ordering::SeqCst);}p
 }
 unsafe fn dealloc(&self,p:*mut u8,l:std::alloc::Layout){
  if tracked(l){FREE.fetch_add(1,std::sync::atomic::Ordering::SeqCst);LIVE.fetch_sub(1,std::sync::atomic::Ordering::SeqCst);}
  std::alloc::GlobalAlloc::dealloc(&std::alloc::System,p,l);
 }
}
#[global_allocator]static A:Observed=Observed;
fn main(){h_exercise();assert_eq!(ALLOC.load(std::sync::atomic::Ordering::SeqCst),2);assert_eq!(FREE.load(std::sync::atomic::Ordering::SeqCst),2);assert_eq!(LIVE.load(std::sync::atomic::Ordering::SeqCst),0);}
'''
        self.execute(source, harness)

    def test_allocator_refusal_survives_generic_result_forwarding(self):
        source = OPERATIONS + """
        fn probe(size:usize)->u8 effects {alloc,block} {
          let outcome=forward::<Result<Buffer<u8>,u8>>(move try_buffer(size));
          match move outcome {
            Result::Ok(bytes)=>{dispose::<Buffer<u8>>(move bytes);return 0;},
            Result::Err(error)=>{return error;}
          }
        }
        """
        harness = r'''
struct Refusing;
static REFUSE:std::sync::atomic::AtomicBool=std::sync::atomic::AtomicBool::new(true);
static REFUSALS:std::sync::atomic::AtomicUsize=std::sync::atomic::AtomicUsize::new(0);
unsafe impl std::alloc::GlobalAlloc for Refusing {
 unsafe fn alloc(&self,l:std::alloc::Layout)->*mut u8{
  if l.size()==65519&&REFUSE.load(std::sync::atomic::Ordering::SeqCst){REFUSALS.fetch_add(1,std::sync::atomic::Ordering::SeqCst);return core::ptr::null_mut();}
  std::alloc::GlobalAlloc::alloc(&std::alloc::System,l)
 }
 unsafe fn dealloc(&self,p:*mut u8,l:std::alloc::Layout){std::alloc::GlobalAlloc::dealloc(&std::alloc::System,p,l);}
}
#[global_allocator]static A:Refusing=Refusing;
fn main(){assert_eq!(h_probe(65519),1);assert_eq!(REFUSALS.load(std::sync::atomic::Ordering::SeqCst),1);REFUSE.store(false,std::sync::atomic::Ordering::SeqCst);assert_eq!(h_probe(65519),0);assert_eq!(REFUSALS.load(std::sync::atomic::Ordering::SeqCst),1);}
'''
        self.execute(source, harness)

    def test_real_two_file_generic_library_runs_and_verifies_independently(self):
        entry = ROOT / "examples/owned_generics/main.hepta"
        analysis = analyze_project(entry, rustc=RUSTC, crate_type="bin")
        self.assertTrue(analysis.report["ok"], analysis.report)
        document = lower_resource_ir(analysis.program, analysis.checked, project_sha256=analysis.project.identity)
        self.assertEqual(len(document["functions"]), 7)
        self.assertTrue(verify_resource_ir(document)["ok"])
        with tempfile.TemporaryDirectory(prefix="hepta-generic-library-") as directory:
            built = compile_rust(analysis.rust, rustc=RUSTC, crate_type="bin", output=Path(directory) / "run")
            self.assertTrue(built["ok"], built)
            executed = subprocess.run([built["artifact"]], capture_output=True, text=True, timeout=15)
            self.assertEqual(executed.returncode, 0, executed.stderr)


if __name__ == "__main__":
    unittest.main()
