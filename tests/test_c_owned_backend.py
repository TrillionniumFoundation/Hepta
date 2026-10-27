"""Independent C ownership, specialization and native resource regressions."""
from pathlib import Path
import copy
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.backend import compile_rust
from hepta.c_backend import compile_c
from hepta.pipeline import analyze, analyze_project
from tools.validate_c_owned import qualify, validate_c_owned_qualification


ROOT = Path(__file__).resolve().parents[1]
RUSTC = os.environ.get("RUSTC") or shutil.which("rustc")

OPERATIONS = """
struct Packet<T>{data:T,tag:u64}
fn forward<T:Owned>(value:take T)->T effects {} {return move value;}
fn dispose<T:Owned>(value:take T)->Unit effects {alloc,block} {drop(move value);}
fn view<T:Owned>(value:read T)->read T effects {} {return read value;}
fn finish<T:Owned,E:Copy>(value:take T,ok:bool,error:E)->Result<T,E> effects {alloc,block} {
  if !ok {dispose::<T>(move value);return Result::Err(error);}
  return Result::Ok(move forward::<T>(move value));
}
fn probe(size:usize,ok:bool)->u64 effects {alloc,block,panic} {
  let allocated=try_buffer(size);
  match move allocated {
    Result::Err(allocation_error)=>{return 1000+allocation_error as u64;},
    Result::Ok(bytes)=>{
      let result=finish::<Packet<Buffer<u8>>,u8>(move Packet{data:move bytes,tag:23},ok,19);
      match move result {
        Result::Ok(packet)=>{
          let observed_size=len(view::<Buffer<u8>>(read packet.data));
          let answer=observed_size as u64+view::<Packet<Buffer<u8>>>(read packet).tag;
          dispose::<Packet<Buffer<u8>>>(move packet);return answer;
        },
        Result::Err(problem)=>{return problem as u64;}
      }
    }
  }
}
"""

ALLOCATION_HARNESS = r'''
void *__real_calloc(size_t, size_t);
void __real_free(void *);
static size_t allocations=0, frees=0, live=0, refusals=0;
static bool refuse=false;
void *__wrap_calloc(size_t count,size_t size) {
    if (refuse) { refusals++;return NULL; }
    void *p=__real_calloc(count,size);
    if (p) { allocations++;live++; }
    return p;
}
void __wrap_free(void *p) { if (p) { frees++;live--; } __real_free(p); }
int main(void) {
    if (__hepta_cb_fn_probe(7,true)!=30) return 1;
    if (__hepta_cb_fn_probe(13,false)!=19) return 2;
    refuse=true;
    if (__hepta_cb_fn_probe(65519,true)!=1001) return 3;
    refuse=false;
    if (__hepta_cb_fn_probe(17,true)!=40) return 4;
    if (__hepta_cb_fn_probe(SIZE_MAX,true)!=1001) return 5;
    if (__hepta_cb_fn_probe(0,true)!=23) return 6;
    printf("%zu %zu %zu %zu\n",allocations,frees,live,refusals);
    return allocations!=3 || frees!=3 || live!=0 || refusals!=1;
}
'''


@unittest.skipUnless(shutil.which("gcc"), "native GCC required")
class COwnedBackendTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-owned-c-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def c_program(self, source, harness="", *, path="<input>", mutate=None):
        with patch("hepta.backend.compile_rust", side_effect=AssertionError("C cannot invoke Rust")):
            result = analyze(source, path=path, backend="c", crate_type="obj" if harness else "bin")
        self.assertTrue(result.report["ok"], result.report)
        self.assertIsNone(result.rust)
        self.assertEqual(result.report["checks"]["rust_borrows_types"], "not_run")
        self.assertFalse(result.report["backend"]["rustc_used"])
        emitted = result.c if mutate is None else mutate(result.c)
        build = compile_c(emitted + harness, output=self.directory / "c-native", sanitize=True,
                          link_args=(["-fno-builtin-calloc", "-fno-builtin-free", "-Wl,--wrap=calloc", "-Wl,--wrap=free"] if harness else []))
        self.assertTrue(build["ok"], build)
        execution = subprocess.run([build["artifact"]], capture_output=True, text=True, timeout=20)
        self.assertNotIn("runtime error:", execution.stderr)
        return result, execution

    def pair(self, source):
        result, execution = self.c_program(source)
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertTrue(RUSTC and Path(RUSTC).is_file(), "native Rust reference is required")
        rust = analyze(source, rustc=RUSTC, crate_type="bin")
        self.assertTrue(rust.report["ok"], rust.report)
        build = compile_rust(rust.rust, rustc=RUSTC, crate_type="bin", output=self.directory / "rust-native")
        self.assertTrue(build["ok"], build)
        reference = subprocess.run([build["artifact"]], capture_output=True, text=True, timeout=20)
        self.assertEqual(reference.returncode, 0, reference.stderr)
        self.assertEqual(reference.stdout, execution.stdout)
        return result

    def reject(self, source, code="E_C_RESOURCE_IR"):
        result = analyze(source, backend="c", native=False)
        self.assertFalse(result.report["ok"], result.report)
        self.assertIn(code, [d["code"] for d in result.report["diagnostics"]])
        self.assertIsNone(result.c)

    def test_owned_generic_library_executes_both_result_paths_and_allocations(self):
        self.pair(OPERATIONS + "fn main()->Unit effects {alloc,block,panic,io} {assert(probe(7,true)==30);assert(probe(13,false)==19);assert(probe(0,true)==23);print_i64(probe(127,true) as i64);}")

    def test_actual_allocator_failure_early_return_zero_and_oversized_recovery(self):
        _, execution = self.c_program(OPERATIONS, ALLOCATION_HARNESS)
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertEqual(execution.stdout, "3 3 0 1\n")

    def test_compiling_leak_mutation_is_caught_by_native_allocation_oracle(self):
        _, execution = self.c_program(OPERATIONS, ALLOCATION_HARNESS,
            mutate=lambda source: source.replace("free(value.data);", "(void)value;"))
        self.assertNotEqual(execution.returncode, 0)
        self.assertEqual(execution.stdout, "3 0 3 1\n")

    def test_nested_enum_payload_cleanup_releases_only_the_live_variant(self):
        source = """
        enum Either<A,B>{First(A),Second(B),Empty}
        struct Pair<T>{left:T,right:T}
        fn dispose<T:Owned>(value:take T)->Unit effects {alloc,block} {drop(move value);}
        fn run(first:bool)->Unit effects {alloc,block,panic} {
          let pair:Pair<Buffer<u8>>=Pair{left:buffer(7),right:buffer(11)};
          if first {
            let value:Either<Pair<Buffer<u8>>,Buffer<u8>>=Either::First(move pair);
            dispose::<Either<Pair<Buffer<u8>>,Buffer<u8>>>(move value);return;
          }
          drop(move pair);
          let value:Either<Pair<Buffer<u8>>,Buffer<u8>>=Either::Second(move buffer(13));
          match move value {
            Either::First(unused)=>{drop(move unused);assert(false);},
            Either::Second(bytes)=>{assert(len(bytes)==13);drop(move bytes);},
            Either::Empty=>{assert(false);}
          }
        }
        fn main()->Unit effects {alloc,block,panic} {run(true);run(false);}
        """
        self.pair(source)

    def test_copy_generics_arrays_recursive_calls_and_unused_abstract_body(self):
        self.pair("""
        struct Box<T>{value:T}
        enum Maybe<T>{Nothing,Just(T)}
        fn id<T:Copy>(value:T)->T effects {} {return value;}
        fn never<T:Owned>(value:take T)->Unit effects {alloc,block} {drop(move value);}
        fn repeat<T:Copy>(value:T,count:u64)->T effects {panic} {
          if count==0 {return value;}return repeat::<T>(value,count-1);
        }
        fn main()->Unit effects {panic} {
          let wrapped=id::<Box<[u8;3]>>(Box{value:[1,2,3]});
          assert(wrapped.value[2]==3);
          let m:Maybe<u64>=Maybe::Just(repeat::<u64>(41,7));
          match m {Maybe::Just(value)=>{assert(value==41);},Maybe::Nothing=>{assert(false);}}
        }
        """)

    def test_aggregate_and_specialization_names_cannot_collide_with_source_names(self):
        self.pair("""
        struct array_0{data:u64}
        fn id<T:Copy>(value:T)->T effects {} {return value;}
        fn id__00(value:u64)->u64 effects {} {return value;}
        fn main()->Unit effects {panic} {
          let a:[u64;1]=[7];let b:array_0=array_0{data:9};
          assert(id::<u64>(a[0])+id__00(b.data)==16);
        }
        """)

    def test_internal_slice_cache_does_not_collide_with_generic_nominal_types(self):
        self.pair("""
        struct c_slice_read<T>{item:T,count:usize}
        struct c_slice_mut<T>{item:T,count:usize}
        fn first(bytes:read [u8])->u8 effects {panic} {return bytes[0];}
        fn write(bytes:mut [u8])->Unit effects {write,panic} {bytes[0]=9;}
        fn main()->Unit effects {panic,write} {
          let a:c_slice_read<u8>=c_slice_read{item:7,count:2};
          let b:c_slice_mut<u8>=c_slice_mut{item:11,count:3};
          let mut bytes:[u8;1]=[a.item];assert(first(read bytes)==7);
          write(mut bytes);assert(bytes[0]==9);assert(b.item==11);
        }
        """)

    def test_borrowed_scalar_and_slice_return_chains_mutate_correct_region(self):
        self.pair("""
        struct Pair{left:u64,right:u64}
        fn left(pair:mut Pair)->mut u64 effects {} {return mut pair.left;}
        fn set(value:mut u64)->Unit effects {write} {value=11;}
        fn bytes(data:mut Buffer<u8>)->mut [u8] effects {} {return mut data;}
        fn sum(data:read [u8])->u64 effects {panic} {return data[0] as u64+data[1] as u64;}
        fn forward(data:read [u8])->read [u8] effects {} {return read data;}
        fn main()->Unit effects {alloc,block,panic,write} {
          let mut p=Pair{left:1,right:2};set(mut left(mut p));assert(p.left==11);assert(p.right==2);
          let mut b=buffer(2);bytes(mut b)[0]=7;bytes(mut b)[1]=9;
          assert(sum(read forward(read b))==16);drop(move b);
        }
        """)

    def test_separate_struct_fields_remain_disjoint_in_owned_profile(self):
        self.pair("""
        struct Pair{left:Buffer<u8>,right:Buffer<u8>}
        fn set(a:mut Buffer<u8>,b:read Buffer<u8>)->Unit effects {write,panic} {a[0]=b[0];}
        fn main()->Unit effects {alloc,block,panic,write} {
          let mut p=Pair{left:buffer(1),right:buffer(1)};p.right[0]=37;
          set(mut p.left,read p.right);assert(p.left[0]==37);drop(move p);
        }
        """)

    def test_allocation_in_loops_is_consumed_before_each_backedge(self):
        self.pair("fn main()->Unit effects {alloc,block,panic} {for i in 0..100 {let b=buffer(i as usize);assert(len(b)==i as usize);drop(move b);}}")

    def test_unit_enum_payload_preserves_effects(self):
        self.pair("""
        fn effect(value:mut u64)->Unit effects {write} {value=7;}
        fn main()->Unit effects {write,panic} {
          let mut x:u64=0;let r:Result<Unit,u8>=Result::Ok(effect(mut x));
          match r {Result::Ok(done)=>{done;assert(x==7);},Result::Err(e)=>{assert(false);}}
        }
        """)

    def test_same_owned_place_cannot_be_read_and_mutably_borrowed(self):
        self.reject("fn pair<T:Owned>(a:mut T,b:read T)->Unit effects {} {}fn main()->Unit effects {alloc,block,panic} {let mut b=buffer(4);pair::<Buffer<u8>>(mut b,read b);drop(move b);}")

    def test_nested_returned_view_cannot_overlap_later_mutation(self):
        self.reject("fn view(x:read Buffer<u8>)->read Buffer<u8> effects {} {return read x;}fn pair(a:read Buffer<u8>,b:mut Buffer<u8>)->Unit effects {} {}fn main()->Unit effects {alloc,block,panic} {let mut x=buffer(3);pair(read view(read x),mut x);drop(move x);}")

    def test_later_argument_cannot_move_owner_under_an_earlier_loan(self):
        self.reject("fn length_and_drop(a:read Buffer<u8>,b:take Buffer<u8>)->usize effects {alloc,block} {let n=len(a);drop(move b);return n;}fn main()->Unit effects {alloc,block,panic} {let x=buffer(7);let n=length_and_drop(read x,move x);}")

    def test_unused_owned_generic_body_still_requires_consumption(self):
        self.reject("fn unused<T:Owned>(value:take T)->Unit effects {} {}fn main()->Unit effects {} {}", "E_LINEAR_UNCONSUMED")

    def test_polymorphic_recursion_has_explicit_finite_specialization_limit(self):
        self.reject("struct Box<T>{value:T}fn grow<T:Copy>(x:T)->Unit effects {} {grow::<Box<T>>(Box{value:x});}fn main()->Unit effects {} {grow::<u64>(1);}", "E_C_SPECIALIZATION_LIMIT")

    def test_raw_pointer_owned_combinations_remain_explicitly_unsupported(self):
        self.reject("fn main()->Unit effects {alloc,block,panic,unsafe} {let x=buffer(1);unsafe {let p=ptr_read(read x);}drop(move x);}")

    def test_function_and_statement_source_line_locations_are_emitted(self):
        result, executed = self.c_program("fn main()->Unit effects {panic} {\nlet x:u64=7;\nassert(x==7);\n}", path="/tmp/quoted-\"source.hepta")
        self.assertEqual(executed.returncode, 0)
        self.assertIn('#line 1 "/tmp/quoted-\\"source.hepta"', result.c)
        self.assertIn('#line 3 "/tmp/quoted-\\"source.hepta"', result.c)

    def test_generated_temporaries_do_not_advance_hepta_statement_lines(self):
        result, executed = self.c_program("fn main()->Unit effects {panic} {\nlet base:u64=7+5;\nlet answer=base*3;\nassert(answer==36);\n}", path="/tmp/lines.hepta")
        self.assertEqual(executed.returncode, 0)
        rows = result.c[result.c.index('#line 1 "/tmp/lines.hepta"'):].splitlines()
        source_line = None
        expected = {" h_base = ": 2, " h_answer = ": 3, " = h_answer;": 4}
        for row in rows:
            if row.startswith("#line "):
                source_line = int(row.split()[1])
            for needle, number in expected.items():
                if needle in row:
                    self.assertEqual(source_line, number, row)

    def test_partial_moves_restore_and_consuming_error_paths_run_on_both_backends(self):
        source = (ROOT / "examples/places/library.hepta").read_text()
        self.pair(source + "fn main()->Unit effects {alloc,block,panic} {assert(exercise(true,7)==7);assert(exercise(false,7)==7);assert(exercise(false,18446744073709551615)==1);assert(cycles()==11);}")

    def test_partial_moves_have_actual_allocator_failure_and_no_remaining_owners(self):
        source = (ROOT / "examples/places/library.hepta").read_text()
        harness = r'''
        void *__real_calloc(size_t,size_t);void __real_free(void *);
        static size_t allocations=0,frees=0,live=0,refusals=0;static bool refuse=false;
        void *__wrap_calloc(size_t count,size_t size) {
            if (refuse&&count*size==12281) {refusals++;return NULL;}
            void *p=__real_calloc(count,size);if(p){allocations++;live++;}return p;
        }
        void __wrap_free(void *p) {if(p){frees++;live--;}__real_free(p);}
        int main(void) {
            if(__hepta_cb_fn_exercise(true,7)!=7)return 1;
            if(__hepta_cb_fn_exercise(false,7)!=7)return 2;
            refuse=true;if(__hepta_cb_fn_exercise(false,12281)!=1)return 3;
            refuse=false;if(__hepta_cb_fn_exercise(false,12281)!=12281)return 4;
            if(__hepta_cb_fn_cycles()!=11)return 5;
            printf("%zu %zu %zu %zu\n",allocations,frees,live,refusals);
            return allocations!=16||frees!=16||live!=0||refusals!=1;
        }
        '''
        _, executed = self.c_program(source, harness)
        self.assertEqual(executed.returncode, 0, executed.stdout + executed.stderr)
        self.assertEqual(executed.stdout, "16 16 0 1\n")

    def test_selected_borrow_origin_retains_only_its_declared_argument(self):
        source = """
        fn chosen(a:read Buffer<u8>,b:read Buffer<u8>)->read Buffer<u8> from a effects {} {return read a;}
        fn consume(b:take Buffer<u8>)->u64 effects {alloc,block} {drop(move b);return 9;}
        fn combine(a:read Buffer<u8>,n:u64)->u64 effects {panic} {return len(a) as u64+n;}
        fn main()->Unit effects {alloc,block,panic} {
          let a=buffer(7);let b=buffer(11);
          assert(combine(read chosen(read a,read b),consume(move b))==16);drop(move a);
        }
        """
        self.pair(source)
        self.reject(source.replace("from a", "from b").replace("return read a;", "return read b;"))

    def test_copy_fields_materialize_before_later_aggregate_argument_effects(self):
        self.pair("""
        struct Pair{first:u64,last:u64}
        enum Both{Values(u64,u64)}
        fn view(value:read u64)->read u64 effects {} {return read value;}
        fn change(value:mut u64)->u64 effects {write} {value=7;return value;}
        fn main()->Unit effects {write,panic} {
          let mut value:u64=1;
          let pair=Pair{first:view(read value),last:change(mut value)};
          assert(pair.first==1);assert(pair.last==7);assert(value==7);
          value=3;
          let both=Both::Values(view(read value),change(mut value));
          match both {Both::Values(first,last)=>{assert(first==3);assert(last==7);}}
          assert(value==7);
        }
        """)

    def test_index_argument_cannot_consume_its_sequence_before_load(self):
        for expression in ("bytes[consume(move bytes)]", "view(read bytes)[consume(move bytes)]"):
            with self.subTest(expression=expression):
                self.reject("fn view(b:read Buffer<u8>)->read Buffer<u8> effects {} {return read b;}fn consume(b:take Buffer<u8>)->usize effects {alloc,block} {drop(move b);return 0;}fn main()->Unit effects {alloc,block,panic} {let bytes=buffer(1);let value=" + expression + ";}")

    def test_existing_multifile_owned_library_builds_without_rust(self):
        result = analyze_project(ROOT / "examples/owned_generics/main.hepta", backend="c", crate_type="bin")
        self.assertTrue(result.report["ok"], result.report)
        build = compile_c(result.c, output=self.directory / "library", sanitize=True)
        self.assertTrue(build["ok"], build)
        executed = subprocess.run([build["artifact"]], capture_output=True, text=True, timeout=20)
        self.assertEqual(executed.returncode, 0, executed.stderr)

    def test_qualification_validator_rejects_incomplete_or_inflated_evidence(self):
        report = qualify(self.directory / "qualification.json", RUSTC)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertTrue(validate_c_owned_qualification(report)["ok"])
        mutations = [
            (("ok",), False),
            (("compiler_sha256",), "0" * 64),
            (("claims", "whole_project_blockers_closed"), True),
            (("claims", "source_to_c_refinement_proved"), True),
            (("resource_ir", "sha256"), "0" * 64),
            (("resource_ir", "bytes"), 0),
            (("resource_verification", "ok"), False),
            (("differential", "paired_calls"), 257),
            (("differential", "checksum"), 13505),
            (("differential", "backends", "c", "build", "rustc_used"), True),
            (("differential", "backends", "c", "build", "artifact_bytes"), 0),
            (("differential", "backends", "c", "build", "artifact_sha256"), "0" * 64),
            (("differential", "backends", "c", "build", "flags"), []),
            (("differential", "backends", "c", "source", "sha256"), "0" * 64),
            (("differential", "backends", "rust", "build", "check_only"), True),
            (("differential", "backends", "rust", "execution", "returncode"), False),
            (("differential", "backends", "c", "frontend", "backend", "check_only"), False),
            (("allocations", "c", "execution", "stdout"), "3 2 1 1\n"),
            (("allocations", "rust", "calls"), 7),
            (("native_leak_control", "execution", "returncode"), 0),
            (("native_leak_control", "mutation"), "forged"),
            (("rejections",), report["rejections"][:-1]),
            (("rejections",), [report["rejections"][0]] * len(report["rejections"])),
            (("sources", "examples/c_owned_backend/main.hepta"), "0" * 64),
        ]
        for path, value in mutations:
            with self.subTest(path=path):
                altered = copy.deepcopy(report)
                target = altered
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                with self.assertRaises(ValueError):
                    validate_c_owned_qualification(altered)


if __name__ == "__main__":
    unittest.main()
