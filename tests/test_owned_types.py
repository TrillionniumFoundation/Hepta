"""Owned ADTs are executed natively; rejected programs never reach lowering.

Allocation accounting checks real destructor behavior, independently of the
frontend's owner sets. Failure and cancellation cases use real worker threads.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from hepta.ast import HeptaError, Type
from hepta.backend import compile_rust, find_rustc
from hepta.checker import check, is_owned_type
from hepta.parser import parse
from hepta.pipeline import analyze, analyze_project


ROOT = Path(__file__).resolve().parents[1]
EFFECTS = "alloc,block,panic"
PACKET = "struct Packet{bytes:Buffer<u8>,tag:u32}"
RESULT = "Result<Buffer<u8>,u8>"


def native_compiler():
    try:
        return find_rustc(os.environ.get("RUSTC"))
    except HeptaError:
        return None


RUSTC = native_compiler()


class OwnedTypeChecks(unittest.TestCase):
    def reject(self, source, code):
        report = analyze(source, native=False).report
        self.assertFalse(report["ok"], report)
        self.assertIn(code, [d["code"] for d in report["diagnostics"]], report)
        self.assertEqual(report["checks"]["rust_borrows_types"], "not_run")

    def body(self, body, declarations=""):
        return declarations + f"fn f()->Unit effects {{{EFFECTS}}} {{{body}}}"

    def test_resource_classification_is_recursive_and_public(self):
        p = parse("struct Box<T>{value:T} enum Event<T>{Done,Data(Box<T>)}")
        self.assertTrue(is_owned_type(p, Type("Event", (Type("Buffer", (Type("u8"),)),))))
        self.assertFalse(is_owned_type(p, Type("Event", (Type("u64"),))))
        checked = check(parse(self.body("let value:Result<Buffer<u8>,u8>=Result::Ok(buffer(4));drop(move value);")))
        self.assertTrue(checked.ok, checked.diagnostics)
        self.assertIn(Type("Result", (Type("Buffer", (Type("u8"),)), Type("u8"))), checked.owned_types)

    def test_error_variant_still_has_an_owner_obligation(self):
        self.reject(self.body("let value:Result<Buffer<u8>,u8>=Result::Err(4);"), "E_LINEAR_UNCONSUMED")

    def test_owned_places_are_not_implicitly_copied(self):
        self.reject(self.body("let a:Result<Buffer<u8>,u8>=Result::Ok(buffer(4));let b=a;drop(move a);drop(move b);"), "E_MOVE_REQUIRED")
        self.reject(self.body("let b=buffer(3);let p=Packet{bytes:b,tag:1};drop(move p);release(move b);", PACKET), "E_MOVE_REQUIRED")
        self.reject(self.body("let b=buffer(3);let p:Result<Buffer<u8>,u8>=Result::Ok(b);drop(move p);release(move b);"), "E_MOVE_REQUIRED")

    def test_double_move_into_tuple_payload_is_rejected(self):
        self.reject(self.body("let b=buffer(3);let p=Pair::Both(move b,move b);drop(move p);", "enum Pair{Both(Buffer<u8>,Buffer<u8>)}"), "E_USE_AFTER_MOVE")

    def test_consuming_match_requires_move_and_forbids_later_use(self):
        arms = "{Result::Ok(data)=>{release(move data);},Result::Err(code)=>{}}"
        self.reject(self.body("let r:Result<Buffer<u8>,u8>=Result::Err(1);match r " + arms + "drop(move r);"), "E_MOVE_REQUIRED")
        self.reject(self.body("let r:Result<Buffer<u8>,u8>=Result::Err(1);match move r " + arms + "drop(move r);"), "E_USE_AFTER_MOVE")

    def test_owned_payload_cannot_be_ignored_or_escape_arm(self):
        self.reject(self.body("let r:Result<Buffer<u8>,u8>=Result::Ok(buffer(4));match move r {Result::Ok(_)=>{},Result::Err(code)=>{}}"), "E_LINEAR_DISCARD")
        self.reject(self.body("let r:Result<Buffer<u8>,u8>=Result::Ok(buffer(4));match move r {Result::Ok(data)=>{},Result::Err(code)=>{}}"), "E_LINEAR_UNCONSUMED")
        self.reject(self.body("let r:Result<Buffer<u8>,u8>=Result::Err(1);match move r {Result::Ok(data)=>{release(move data);},Result::Err(code)=>{}} release(move data);"), "E_UNKNOWN_NAME")

    def test_every_early_return_consumes_payload_and_other_owners(self):
        self.reject(self.body("let r:Result<Buffer<u8>,u8>=Result::Ok(buffer(4));match move r {Result::Ok(data)=>{return;},Result::Err(code)=>{}}"), "E_LINEAR_UNCONSUMED")
        self.reject(self.body("let extra=buffer(2);let r:Result<Buffer<u8>,u8>=Result::Err(1);match move r {Result::Ok(data)=>{release(move data);release(move extra);return;},Result::Err(code)=>{return;}}"), "E_LINEAR_UNCONSUMED")

    def test_branch_loop_and_short_circuit_obligations_include_aggregates(self):
        self.reject(self.body("let p=Packet{bytes:buffer(1),tag:0};if true {drop(move p);}", PACKET), "E_LINEAR_BRANCH")
        self.reject(self.body("let r:Result<Buffer<u8>,u8>=Result::Ok(buffer(2));match move r {Result::Ok(data)=>{for i in 0..2 {release(move data);}},Result::Err(code)=>{}}"), "E_LINEAR_LOOP")
        helper = PACKET + "fn done(p:take Packet)->bool effects {alloc,block} {drop(move p);return true;}"
        self.reject(self.body("let p=Packet{bytes:buffer(1),tag:0};let answer=false&&done(move p);drop(move p);", helper), "E_LINEAR_SHORT_CIRCUIT")

    def test_whole_use_after_partial_move_and_temporary_projection_are_rejected(self):
        self.reject(self.body("let p=Packet{bytes:buffer(3),tag:4};let data=move p.bytes;release(move data);drop(move p);", PACKET), "E_USE_AFTER_MOVE")
        helper = PACKET + "fn make()->Packet effects {alloc,block,panic} {return Packet{bytes:buffer(3),tag:4};}"
        self.reject(self.body("let tag=make().tag;", helper), "E_LINEAR_TEMPORARY")

    def test_borrowed_aggregate_cannot_be_consumed(self):
        self.reject(PACKET + "fn f(p:read Packet)->Unit effects {alloc,block} {drop(move p);}", "E_MOVE_BORROW")
        self.reject("fn f(r:read Result<Buffer<u8>,u8>)->Unit effects {alloc,block} {match move r {Result::Ok(b)=>{release(move b);},Result::Err(e)=>{}}}", "E_MOVE_BORROW")

    def test_take_return_and_reassignment_are_explicit(self):
        self.reject(PACKET + "fn f(p:Packet)->Unit effects {alloc,block} {drop(move p);}", "E_LINEAR_MODE")
        self.reject(PACKET + "fn f(p:take Packet)->Packet effects {} {return p;}", "E_MOVE_REQUIRED")
        self.reject(self.body("let mut p=Packet{bytes:buffer(3),tag:0};p=Packet{bytes:buffer(5),tag:1};drop(move p);", PACKET), "E_LINEAR_REASSIGN")

    def test_drop_must_not_disguise_task_detachment(self):
        worker = "fn worker(b:take Buffer<u8>,c:read Cancellation)->u64 effects {alloc,block} {release(move b);return 0;}"
        self.reject(worker + "fn f()->Unit effects {alloc,block,spawn,panic} {let t=spawn(worker,move buffer(1));drop(move t);}", "E_BUILTIN_TYPE")
        self.reject("enum Hidden{Task(Task<u64>)}", "E_NESTED_LINEAR")
        self.reject("struct Hidden<T>{value:T} fn f(x:take Hidden<TaskGroup>)->Unit effects {} {}", "E_NESTED_LINEAR")

    def test_aggregate_drop_effects_cannot_be_omitted(self):
        self.reject(PACKET + "fn f(p:take Packet)->Unit effects {} {drop(move p);}", "E_EFFECT")

    def test_copy_generic_functions_cannot_accept_owned_instantiations(self):
        self.reject("fn id<T>(x:T)->T effects {} {return x;}" + self.body("let p:Result<Buffer<u8>,u8>=Result::Err(1);let q=id::<Result<Buffer<u8>,u8>>(move p);drop(move q);"), "E_GENERIC_COPY")

    def test_generic_payloads_cannot_hide_unsupported_resource_containers(self):
        for payload in ("[T;2]", "Buffer<T>", "raw const T", "raw mut T"):
            with self.subTest(payload=payload):
                self.reject("struct Hidden<T>{value:" + payload + "} fn f(x:take Hidden<Buffer<u8>>)->Unit effects {alloc,block} {drop(move x);}", "E_NESTED_LINEAR")
        self.reject("struct Inner<T>{value:raw const T} struct Outer<T>{inner:Inner<T>} fn f(x:take Outer<Buffer<u8>>)->Unit effects {alloc,block} {drop(move x);}", "E_NESTED_LINEAR")

    def test_fallible_buffer_is_still_owned_and_effect_checked(self):
        self.reject("fn f()->Unit effects {alloc,block} {try_buffer(8);}", "E_LINEAR_DISCARD")
        self.reject("fn f()->Unit effects {alloc,block} {let r=try_buffer(8);}", "E_LINEAR_UNCONSUMED")
        self.reject("fn f()->Unit effects {} {let r=try_buffer(8);drop(move r);}", "E_EFFECT")

    def test_owned_result_does_not_gain_a_c_abi(self):
        self.reject('export "C" fn f()->Result<Buffer<u8>,u8> effects {} {return Result::Err(1);}', "E_C_ABI")
        result = analyze("fn f()->Result<Buffer<u8>,u8> effects {} {return Result::Err(1);}", native=False, backend="c")
        self.assertTrue(result.report["ok"], result.report)
        self.assertIsNone(result.rust)
        self.assertIn("payload.v_Err", result.c)

    def test_failure_and_cancellation_paths_cannot_drop_obligations(self):
        worker = """fn worker(data:take Buffer<u8>,token:read Cancellation,out:read Sender<u64>)->u64
        effects {alloc,block,panic,write} {
          let pending:Result<Buffer<u8>,u8>=Result::Ok(move data);
          if cancelled(read token) {return 0;}
          drop(move pending);return 1;
        }"""
        self.reject(worker, "E_LINEAR_UNCONSUMED")
        self.reject(worker.replace("if cancelled(read token) {return 0;}", "group_fail(read out,7);return 0;"), "E_LINEAR_UNCONSUMED")


@unittest.skipUnless(RUSTC, "requires the real pinned Rust compiler")
class NativeOwnedTypes(unittest.TestCase):
    def execute(self, source, supplement=""):
        analysis = analyze(source, rustc=RUSTC, crate_type="rlib" if supplement else "bin")
        self.assertTrue(analysis.report["ok"], analysis.report)
        self.assertEqual(analysis.report["checks"]["rust_borrows_types"], "rustc_checked")
        with tempfile.TemporaryDirectory(prefix="hepta-owned-native-") as td:
            built = compile_rust(analysis.rust + supplement, rustc=RUSTC, crate_type="bin", output=Path(td) / "run")
            self.assertTrue(built["ok"], built)
            proc = subprocess.run([built["artifact"]], capture_output=True, text=True, timeout=15)
            self.assertEqual(proc.returncode, 0, proc.stderr)
        return analysis

    def test_result_buffer_success_error_nested_and_early_return(self):
        self.execute("""
        struct Packet<T>{data:T,id:u32}
        enum Envelope<T>{Empty,Value(T)}
        fn make(ok:bool)->Result<Envelope<Packet<Buffer<u8>>>,u8> effects {alloc,block,panic} {
          if !ok {return Result::Err(7);}
          let bytes=buffer(8);
          return Result::Ok(Envelope::Value(Packet{data:move bytes,id:5}));
        }
        fn take_size(result:take Result<Envelope<Packet<Buffer<u8>>>,u8>)->usize effects {alloc,block} {
          match move result {
            Result::Ok(envelope)=>{
              match move envelope {
                Envelope::Empty=>{return 0;},
                Envelope::Value(packet)=>{let n=len(packet.data);drop(move packet);return n;}
              }
            },
            Result::Err(error)=>{return error as usize;}
          }
        }
        fn main()->Unit effects {alloc,block,panic} {
          assert(take_size(move make(true))==8);
          assert(take_size(move make(false))==7);
          let e:Result<u8,Buffer<u8>>=Result::Err(buffer(11));
          match move e {Result::Ok(code)=>{assert(false);},Result::Err(bytes)=>{assert(len(bytes)==11);release(move bytes);}}
        }
        """)

    def test_tuple_payloads_transfer_each_owner_once(self):
        self.execute("""
        enum Pair{Both(Buffer<u8>,Buffer<u8>,u32),Empty}
        fn consume(value:take Pair)->u32 effects {alloc,block,panic} {
          match move value {
            Pair::Empty=>{return 0;},
            Pair::Both(left,right,tag)=>{assert(len(left)==3);assert(len(right)==9);release(move left);release(move right);return tag;}
          }
        }
        fn main()->Unit effects {alloc,block,panic} {
          let value=Pair::Both(buffer(3),buffer(9),17);
          assert(consume(move value)==17);
          assert(consume(move Pair::Empty)==0);
        }
        """)

    def test_same_generic_adt_has_copy_and_owned_instantiations(self):
        self.execute("""
        struct Box<T>{value:T}
        enum Maybe<T>{None,Some(T)}
        fn number(x:Maybe<Box<u64>>)->u64 effects {} {
          match x {Maybe::None=>{return 0;},Maybe::Some(box)=>{return box.value;}}
        }
        fn main()->Unit effects {alloc,block,panic} {
          let v:Maybe<Box<u64>>=Maybe::Some(Box{value:21});
          assert(number(v)==21);assert(number(v)==21);
          let b:Maybe<Box<Buffer<u8>>>=Maybe::Some(Box{value:buffer(4)});
          drop(move b);
        }
        """)

    def test_recursive_drop_frees_real_allocations(self):
        source = """
        struct Pair{left:Buffer<u8>,right:Buffer<u8>}
        enum Item<T>{None,Some(T)}
        fn exercise()->Unit effects {alloc,block,panic} {
          let pair=Pair{left:buffer(4093),right:buffer(8161)};
          let wrapper:Result<Item<Pair>,u8>=Result::Ok(Item::Some(move pair));
          drop(move wrapper);
          let failure:Result<u32,Buffer<u8>>=Result::Err(buffer(12281));
          release(move failure);
        }
        """
        harness = r'''
struct Counting;
static TRACK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static ALLOC: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static FREE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static BYTES: std::sync::atomic::AtomicIsize = std::sync::atomic::AtomicIsize::new(0);
unsafe impl std::alloc::GlobalAlloc for Counting {
    unsafe fn alloc(&self,l:std::alloc::Layout)->*mut u8 {
        let p=std::alloc::GlobalAlloc::alloc(&std::alloc::System,l);
        if TRACK.load(std::sync::atomic::Ordering::SeqCst) && !p.is_null() {
            ALLOC.fetch_add(1,std::sync::atomic::Ordering::SeqCst);
            BYTES.fetch_add(l.size() as isize,std::sync::atomic::Ordering::SeqCst);
        }
        p
    }
    unsafe fn dealloc(&self,p:*mut u8,l:std::alloc::Layout) {
        if TRACK.load(std::sync::atomic::Ordering::SeqCst) {
            FREE.fetch_add(1,std::sync::atomic::Ordering::SeqCst);
            BYTES.fetch_sub(l.size() as isize,std::sync::atomic::Ordering::SeqCst);
        }
        std::alloc::GlobalAlloc::dealloc(&std::alloc::System,p,l);
    }
}
#[global_allocator] static A:Counting=Counting;
fn main(){
    TRACK.store(true,std::sync::atomic::Ordering::SeqCst);
    h_exercise();
    TRACK.store(false,std::sync::atomic::Ordering::SeqCst);
    assert_eq!(ALLOC.load(std::sync::atomic::Ordering::SeqCst),3);
    assert_eq!(FREE.load(std::sync::atomic::Ordering::SeqCst),3);
    assert_eq!(BYTES.load(std::sync::atomic::Ordering::SeqCst),0);
}
'''
        self.execute(source, harness)

    def test_fallible_buffer_success_zero_length_capacity_error_and_single_evaluation(self):
        self.execute("""
        fn next(counter:mut usize)->usize effects {write} {counter=wrapping_add(counter,1);return 17;}
        fn capacity_failure()->u8 effects {alloc,block} {
          let maximum:usize=!0;
          match try_buffer(maximum) {
            Result::Ok(bytes)=>{release(move bytes);return 9;},
            Result::Err(code)=>{return code;}
          }
        }
        fn main()->Unit effects {alloc,block,panic,write} {
          let mut counter:usize=0;
          match try_buffer(next(mut counter)) {
            Result::Ok(bytes)=>{assert(len(bytes)==17);for i in 0..len(bytes) {assert(bytes[i]==0);}release(move bytes);},
            Result::Err(code)=>{assert(false);}
          }
          assert(counter==1);assert(capacity_failure()==1);
          match try_buffer(0) {
            Result::Ok(bytes)=>{assert(len(bytes)==0);release(move bytes);},
            Result::Err(code)=>{assert(false);}
          }
        }
        """)

    def test_allocator_refusal_is_a_result_not_an_abort(self):
        source = """
        fn probe(size:usize)->u8 effects {alloc,block} {
          match try_buffer(size) {
            Result::Ok(bytes)=>{release(move bytes);return 0;},
            Result::Err(code)=>{return code;}
          }
        }
        """
        harness = r'''
struct Refusing;
static REFUSE:std::sync::atomic::AtomicUsize=std::sync::atomic::AtomicUsize::new(0);
static REFUSALS:std::sync::atomic::AtomicUsize=std::sync::atomic::AtomicUsize::new(0);
unsafe impl std::alloc::GlobalAlloc for Refusing {
    unsafe fn alloc(&self,l:std::alloc::Layout)->*mut u8 {
        if l.size()==REFUSE.load(std::sync::atomic::Ordering::SeqCst) {
            REFUSALS.fetch_add(1,std::sync::atomic::Ordering::SeqCst);
            return core::ptr::null_mut();
        }
        std::alloc::GlobalAlloc::alloc(&std::alloc::System,l)
    }
    unsafe fn dealloc(&self,p:*mut u8,l:std::alloc::Layout) {
        std::alloc::GlobalAlloc::dealloc(&std::alloc::System,p,l);
    }
}
#[global_allocator] static A:Refusing=Refusing;
fn main(){
    REFUSE.store(65519,std::sync::atomic::Ordering::SeqCst);
    assert_eq!(h_probe(65519),1);
    assert_eq!(REFUSALS.load(std::sync::atomic::Ordering::SeqCst),1);
    assert_eq!(h_probe(0),0);
    REFUSE.store(0,std::sync::atomic::Ordering::SeqCst);
    assert_eq!(h_probe(65519),0);
    assert_eq!(REFUSALS.load(std::sync::atomic::Ordering::SeqCst),1);
}
'''
        self.execute(source, harness)

    def test_cooperative_cancellation_releases_owned_payload(self):
        self.execute("""
        struct Pending{bytes:Buffer<u8>}
        fn worker(data:take Buffer<u8>,token:read Cancellation)->u64 effects {alloc,block} {
          let pending=Pending{bytes:move data};
          while !cancelled(read token) {}
          let n=len(pending.bytes);drop(move pending);return n as u64;
        }
        fn main()->Unit effects {alloc,block,panic,spawn} {
          let task=spawn(worker,move buffer(64));
          assert(cancel_and_join(move task)==64);
        }
        """)

    def test_reported_worker_failure_consumes_owned_error_payload(self):
        self.execute("""
        fn failed(data:take Buffer<u8>)->Result<u64,Buffer<u8>> effects {} {return Result::Err(move data);}
        fn worker(data:take Buffer<u8>,token:read Cancellation,out:read Sender<u64>)->u64 effects {alloc,block,panic,write} {
          let outcome=failed(move data);
          match move outcome {
            Result::Ok(value)=>{return value;},
            Result::Err(bytes)=>{group_fail(read out,31);release(move bytes);return 0;}
          }
        }
        fn main()->Unit effects {alloc,block,panic,spawn,write} {
          let mut g=task_group(1,32,1);
          assert(group_spawn(mut g,worker,move buffer(32)));
          let report=group_drain_and_join(move g);
          assert(report.failed);assert(report.failure_code==31);
          assert(report.active_tasks==0);assert(report.completed_tasks==1);assert(report.joined);
        }
        """)

    def test_owned_library_module_executes(self):
        entry = ROOT / "examples/owned/main.hepta"
        result = analyze_project(entry, rustc=RUSTC, crate_type="bin")
        self.assertTrue(result.report["ok"], result.report)
        with tempfile.TemporaryDirectory(prefix="hepta-owned-library-") as td:
            built = compile_rust(result.rust, rustc=RUSTC, crate_type="bin", output=Path(td) / "run")
            self.assertTrue(built["ok"], built)
            executed = subprocess.run([built["artifact"]], capture_output=True, timeout=10)
            self.assertEqual(executed.returncode, 0, executed.stderr)


if __name__ == "__main__":
    unittest.main()
