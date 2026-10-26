"""Native ownership, failure cleanup and source-identity LLVM regressions."""
from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import ctypes
import os
from pathlib import Path
import random
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.backend import compile_rust
from hepta.c_backend import compile_c
from hepta.llvm_owned_backend import LLVMOwnedRejected, compile_owned_llvm, emit_owned_llvm, _resources_allowed
from hepta.llvm_owned_pipeline import build_llvm_owned_source
from hepta.pipeline import analyze

ROOT = Path(__file__).resolve().parents[1]
OWNED = (ROOT / "examples/llvm_owned/owned.hepta").read_text()
EXPORT = """
export "C" fn owned_case(size:usize,value:u8,index:usize,reject:u32,early:u32)->u64
effects {alloc,block,panic,write} {
    return run_owned(size,value,index,reject!=0,early!=0);
}
"""
CLEANUP = """
fn forward<T:Owned>(value:take T)->T effects {} {return move value;}
export "C" fn two_alloc(second:usize,refuse:u32)->u64 effects {alloc,block,panic,write} {
    match try_buffer(7) {
        Result::Err(code)=>{return 100+code as u64;},
        Result::Ok(initial)=>{
            let mut first=move initial;
            first[0]=19;
            match try_buffer(second) {
                Result::Err(code)=>{drop(move first);return code as u64;},
                Result::Ok(bytes)=>{
                    let moved=forward::<Buffer<u8>>(move bytes);
                    if refuse!=0 {drop(move moved);drop(move first);return 2;}
                    let result=len(moved) as u64+first[0] as u64;
                    drop(move moved);drop(move first);return result;
                }
            }
        }
    }
}
export "C" fn zeroed(size:usize,index:usize)->u8 effects {alloc,block,panic} {
    let bytes=buffer(size);let value=bytes[index];drop(move bytes);return value;
}
export "C" fn panic_index()->u8 effects {alloc,block,panic} {
    let bytes=buffer(1);let value=bytes[1];drop(move bytes);return value;
}
export "C" fn panic_overflow(value:u8)->u8 effects {alloc,block,panic} {
    let bytes=buffer(1);let result=value+1;drop(move bytes);return result;
}
"""
NESTED = """
struct Pair<T> {left:T,right:T,tag:u64}
enum Choice<T> {Empty,One(T),Two(T,T)}
export "C" fn nested_owner(mode:u32)->u64 effects {alloc,block,panic} {
    let pair:Pair<Buffer<u8>>=Pair{left:buffer(11),right:buffer(13),tag:17};
    if mode==0 {
        drop(move pair);
        let variant:Choice<Pair<Buffer<u8>>>=Choice::Empty;
        drop(move variant);return 0;
    }
    if mode==1 {
        let variant:Choice<Pair<Buffer<u8>>>=Choice::One(move pair);
        drop(move variant);return 1;
    }
    let other:Pair<Buffer<u8>>=Pair{left:buffer(17),right:buffer(19),tag:23};
    let variant:Choice<Pair<Buffer<u8>>>=Choice::Two(move pair,move other);
    drop(move variant);return 2;
}
export "C" fn restore_and_drop()->u64 effects {alloc,block,panic} {
    let mut pair:Pair<Buffer<u8>>=Pair{left:buffer(23),right:buffer(29),tag:31};
    let old=move pair.left;drop(move old);pair.left=buffer(31);
    let answer=pair.tag+len(pair.left) as u64+len(pair.right) as u64;
    drop(move pair);return answer;
}
export "C" fn echo_u8(value:u8)->u8 effects {} {return value;}
export "C" fn echo_u16(value:u16)->u16 effects {} {return value;}
export "C" fn echo_i8(value:i8)->i8 effects {} {return value;}
export "C" fn echo_i16(value:i16)->i16 effects {} {return value;}
fn returned_choice(mode:u32)->Choice<Pair<Buffer<u8>>> effects {alloc,block,panic} {
    if mode==0 {return Choice::Empty;}
    let pair:Pair<Buffer<u8>>=Pair{left:buffer(11),right:buffer(13),tag:17};
    if mode==1 {return Choice::One(move pair);}
    let other:Pair<Buffer<u8>>=Pair{left:buffer(17),right:buffer(19),tag:23};
    return Choice::Two(move pair,move other);
}
export "C" fn nested_return(mode:u32)->u64 effects {alloc,block,panic} {
    match returned_choice(mode) {
        Choice::Empty=>{return 0;},
        Choice::One(pair)=>{
            let value=len(pair.left) as u64+len(pair.right) as u64+pair.tag;
            drop(move pair);return value;
        },
        Choice::Two(first,second)=>{
            let value=len(first.left) as u64+len(first.right) as u64+first.tag
                +len(second.left) as u64+len(second.right) as u64+second.tag;
            drop(move first);drop(move second);return value;
        },
    }
}
"""
ALLOCATOR_HARNESS = r"""
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
void *__real_calloc(size_t, size_t);
void *__real_malloc(size_t);
void __real_free(void *);
static volatile size_t allocations=0, frees=0, live=0, refusals=0;
static volatile int fail_second=0;
void *__wrap_calloc(size_t count, size_t size) {
    if (fail_second && ((count==12281 && size==1) || (count==1 && size==12281))) {
        refusals++; return NULL;
    }
    void *value=__real_calloc(count,size);
    if(value) { allocations++; live++; }
    return value;
}
void *__wrap_malloc(size_t size) {
    if (fail_second && size==12281) { refusals++; return NULL; }
    void *value=__real_malloc(size);
    if(value) { allocations++; live++; }
    return value;
}
void __wrap_free(void *value) {
    if(value) { frees++; live--; }
    __real_free(value);
}
extern uint64_t two_alloc(size_t,uint32_t);
int main(void) {
    if(two_alloc(3,0)!=22) return 11;
    if(two_alloc(5,1)!=2) return 12;
    if(two_alloc(0,0)!=19) return 13;
    fail_second=1;
    if(two_alloc(12281,0)!=1) return 14;
    if(two_alloc((size_t)-1,0)!=1) return 15;
    printf("%zu %zu %zu %zu\n",allocations,frees,live,refusals);
    return allocations!=7 || frees!=7 || live!=0 || refusals!=1;
}
"""


def checked(source):
    result = analyze(source, "<llvm-owned-tests>", native=False, crate_type="cdylib")
    if not result.report["ok"]:
        raise AssertionError(result.report)
    return result


class LLVMOwnedIdentityTests(unittest.TestCase):
    def test_checked_nonallocating_nonblocking_source_clauses_lower(self):
        source = '''
        export "C" fn constrained(value:u32)->u32
        effects {panic}
        resources {heap_allocations=0;may_block=false;may_suspend=false;may_spawn=false;} {
            return value + 1;
        }
        '''
        analyzed = checked(source)
        self.assertEqual(analyzed.program.functions[0].resources,
                         {"heap_allocations": 0, "may_block": False,
                          "may_suspend": False, "may_spawn": False})
        self.assertTrue(_resources_allowed(analyzed.program.functions[0], analyzed.checked))
        ir = emit_owned_llvm(analyzed.program, analyzed.checked)
        self.assertEqual(ir.functions, ("constrained",))
        self.assertIn("define", ir.text)

    def test_owned_llvm_resource_contract_literals_and_effects_fail_closed(self):
        from types import SimpleNamespace
        def permitted(resources, declared=(), inferred=()):
            fn = SimpleNamespace(name="f", resources=resources, effects=set(declared))
            checked_effects = SimpleNamespace(effects={"f": set(inferred)})
            return _resources_allowed(fn, checked_effects)

        self.assertTrue(permitted({}))
        self.assertTrue(permitted({"heap_allocations": 0, "may_block": False,
                                   "may_spawn": False, "may_suspend": False},
                                  declared=("panic",)))
        for case, resources, declared, inferred in (
            ("allocation-bool", {"heap_allocations": False}, (), ()),
            ("may-block-int", {"may_block": 0}, (), ()),
            ("may-spawn-int", {"may_spawn": 0}, (), ()),
            ("suspend-true", {"may_suspend": True}, (), ()),
            ("allocation-effect", {"heap_allocations": 0}, (), ("alloc",)),
            ("blocking-effect", {"may_block": False}, ("block",), ()),
            ("spawning-effect", {"may_spawn": False}, (), ("spawn",)),
            ("unknown-resource", {"max_rss_bytes": 4096}, (), ()),
        ):
            with self.subTest(case=case):
                self.assertFalse(permitted(resources, declared, inferred))

    def test_excessive_aggregate_return_leaf_expansion_rejects(self):
        fields = ",".join(f"f{index}:u8" for index in range(128))
        values = ",".join(f"f{index}:0" for index in range(128))
        result = checked("struct Leaf{" + fields + "} struct Wide{left:Leaf,right:Leaf,flag:u8} "
                         "fn leaf()->Leaf effects {} {return Leaf{" + values + "};} "
                         "fn make()->Wide effects {} {return Wide{left:leaf(),right:leaf(),flag:0};}")
        with self.assertRaisesRegex(ValueError, "E_LLVM_OWNED_LIMIT: Aggregate result"):
            emit_owned_llvm(result.program, result.checked)

    def test_rehashed_wrong_free_or_scalar_cannot_pass_source_replay(self):
        analyzed = checked(OWNED + EXPORT)
        ir = emit_owned_llvm(analyzed.program, analyzed.checked)
        self.assertEqual(ir.functions, ("owned_case",))
        for old, new in (("call void @free(ptr %data)", "; deliberately removed free"),
                         ("i64 1000", "i64 1001")):
            wrong = ir.text.replace(old, new, 1)
            self.assertNotEqual(wrong, ir.text)
            candidate = replace(ir, text=wrong, sha256=sha256(wrong.encode()).hexdigest())
            with patch("hepta.llvm_owned_backend._clang_run", side_effect=AssertionError("compiler must not run")):
                with self.assertRaisesRegex(LLVMOwnedRejected, "ORIGIN"):
                    compile_owned_llvm(candidate, program=analyzed.program, checked=analyzed.checked,
                                       output="/tmp/never-published-owned.so")

    def test_normalized_equal_llvm_cannot_rebind_to_different_source(self):
        before, after = checked(OWNED + EXPORT), checked("\n// different source identity\n" + OWNED + EXPORT)
        old = emit_owned_llvm(before.program, before.checked)
        new = emit_owned_llvm(after.program, after.checked)
        self.assertEqual(old.text, new.text)
        self.assertNotEqual(old.semantic_sha256, new.semantic_sha256)
        with patch("hepta.llvm_owned_backend._clang_run", side_effect=AssertionError("compiler must not run")):
            with self.assertRaisesRegex(LLVMOwnedRejected, "ORIGIN"):
                compile_owned_llvm(old, program=after.program, checked=after.checked,
                                   output="/tmp/never-rebound-owned.so")

    def test_independent_resource_gate_rejects_move_during_earlier_loan(self):
        source = """
        fn bad(a:read Buffer<u8>,b:take Buffer<u8>)->usize effects {alloc,block} {
            let n=len(a);drop(move b);return n;
        }
        fn main()->Unit effects {alloc,block,panic} {
            let owner=buffer(4);let result=bad(read owner,move owner);
        }
        """
        analyzed = checked(source)
        with patch("hepta.backend.compile_rust", side_effect=AssertionError("independent gate uses no Rust")):
            with self.assertRaisesRegex(ValueError, "loan|LOAN|move|MOVE"):
                emit_owned_llvm(analyzed.program, analyzed.checked)

    def test_unsupported_features_and_missing_consumption_have_no_fallback(self):
        sources = [
            "fn read_word(values:read [u32])->u32 effects {panic} {return values[0];}",
            "fn value(x:f64)->f64 effects {} {return x;}",
            "extern \"C\" fn foreign()->u64 effects {ffi};",
            "fn never<T:Owned>(value:take T)->Unit effects {} {}",
            "fn bad()->Unit effects {alloc,block,panic} {let b=buffer(2);}",
            "struct Pair{left:Buffer<u8>,right:Buffer<u8>} fn bad()->Unit effects {alloc,block,panic} "
            "{let pair=Pair{left:buffer(1),right:buffer(2)};drop(move pair.left);drop(move pair);}",
            'export "C" fn malloc(size:usize)->usize effects {} {return size;}',
        ]
        for source in sources:
            with self.subTest(source=source):
                analyzed = analyze(source, native=False)
                if analyzed.report["ok"]:
                    with self.assertRaises(ValueError):
                        emit_owned_llvm(analyzed.program, analyzed.checked)
                else:
                    self.assertTrue(analyzed.report["diagnostics"])


@unittest.skipUnless(shutil.which("clang") and shutil.which("gcc")
                     and shutil.which(os.environ.get("RUSTC", "rustc")),
                     "native owned LLVM tests require Clang, GCC and pinned Rust")
class LLVMOwnedNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="hepta-llvm-owned-tests-")
        cls.root = Path(cls.temp.name)
        cls.source = OWNED + EXPORT + CLEANUP + NESTED
        cls.analyzed = checked(cls.source)
        cls.ir = emit_owned_llvm(cls.analyzed.program, cls.analyzed.checked)
        cls.libraries = {}
        llvm = cls.root / "llvm.so"
        cls.llvm_receipt = compile_owned_llvm(cls.ir, program=cls.analyzed.program,
            checked=cls.analyzed.checked, output=llvm)
        cls.libraries["llvm"] = llvm
        rust = analyze(cls.source, "<llvm-owned-tests>", native=True, crate_type="cdylib")
        if not rust.report["ok"]:
            raise AssertionError(rust.report)
        for backend in ("rust", "c"):
            path = cls.root / (backend + ".so")
            if backend == "rust":
                receipt = compile_rust(rust.rust, crate_type="cdylib", output=path)
            else:
                c = analyze(cls.source, "<llvm-owned-tests>", backend="c", native=False, crate_type="cdylib")
                if not c.report["ok"]:
                    raise AssertionError(c.report)
                receipt = compile_c(c.c, crate_type="cdylib", output=path, sanitize=True)
            if not receipt["ok"]:
                raise AssertionError(receipt)
            cls.libraries[backend] = path
        cls.loaded = {name: ctypes.CDLL(str(path)) for name, path in cls.libraries.items()}

    @classmethod
    def tearDownClass(cls):
        cls.loaded.clear()
        cls.temp.cleanup()

    def test_owned_llvm_shared_exposes_only_checked_source_dynamic_abi(self):
        from hepta.elf_shared_abi import inspect_owned_shared_elf

        exact_bytes = (self.root / "llvm.so").read_bytes()
        independently_rechecked = inspect_owned_shared_elf(exact_bytes, self.ir.functions)
        self.assertEqual(self.llvm_receipt["dynamic_abi"], independently_rechecked)
        self.assertEqual(independently_rechecked["dynamic_exports"], list(self.ir.functions))
        self.assertTrue(independently_rechecked["source_exports_rechecked"])
        self.assertFalse(independently_rechecked["claims"]["backend_refinement_proven"])

    def test_native_owned_llvm_rejects_output_mutation_after_link(self):
        from hepta import artifact_publication
        output = self.root / "mutated-after-link.so"
        original = artifact_publication.os.link

        def corrupt(stage, destination, *args, **kwargs):
            original(stage, destination, *args, **kwargs)
            Path(destination).write_bytes(b"mutated-ELF-payload")

        with patch.object(artifact_publication.os, "link", side_effect=corrupt):
            with self.assertRaisesRegex(LLVMOwnedRejected, "E_LLVM_OWNED_PUBLICATION"):
                compile_owned_llvm(self.ir, program=self.analyzed.program,
                    checked=self.analyzed.checked, output=output)
        self.assertFalse(output.exists())

    def test_same_hepta_source_executes_all_owned_result_paths_on_three_backends(self):
        functions = []
        for library in self.loaded.values():
            function = library.owned_case
            function.argtypes = [ctypes.c_size_t, ctypes.c_uint8, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]
            function.restype = ctypes.c_uint64
            functions.append(function)
        cases = [(size, value, index, reject, early)
                 for size in (0, 1, 2, 7, 31, 257)
                 for value in (0, 1, 90, 127, 255)
                 for index in (0, 1, size, size + 1)
                 for reject in (0, 1) for early in (0, 1)]
        rng = random.Random(0x0B0FF3)
        cases += [(rng.randrange(1025), rng.randrange(256), rng.randrange(1026),
                   rng.randrange(2), rng.randrange(2)) for _ in range(512)]
        cases += [(2**64-1, 19, 0, reject, early) for reject in (0, 1) for early in (0, 1)]
        for arguments in cases:
            size, value, index, reject, early = arguments
            expected = (1001 if size > 2**63-1 else 1002 if reject else 2002 if early
                        else 2003 if index >= size else size + 2 * (value ^ 90 if index == 0 else value))
            self.assertEqual([function(*arguments) for function in functions], [expected] * 3, arguments)
        self.assertEqual(len(cases), 996)

    def test_buffer_initialization_and_generic_move_cleanup_match(self):
        for name, library in self.loaded.items():
            zeroed = library.zeroed
            zeroed.argtypes, zeroed.restype = [ctypes.c_size_t, ctypes.c_size_t], ctypes.c_uint8
            transfer = library.two_alloc
            transfer.argtypes, transfer.restype = [ctypes.c_size_t, ctypes.c_uint32], ctypes.c_uint64
            with self.subTest(backend=name):
                for size in (1, 3, 255, 4096):
                    for index in (0, size // 2, size - 1):
                        self.assertEqual(zeroed(size, index), 0)
                    self.assertEqual(transfer(size, 0), size + 19)
                    self.assertEqual(transfer(size, 1), 2)
                self.assertEqual(transfer(0, 0), 19)
                self.assertEqual(transfer(2**64-1, 0), 1)

    def test_nested_generic_enum_variants_and_restored_aggregate_drop(self):
        for name, library in self.loaded.items():
            function = library.nested_owner
            function.argtypes, function.restype = [ctypes.c_uint32], ctypes.c_uint64
            restored = library.restore_and_drop
            restored.argtypes, restored.restype = [], ctypes.c_uint64
            returned = library.nested_return
            returned.argtypes, returned.restype = [ctypes.c_uint32], ctypes.c_uint64
            with self.subTest(backend=name):
                self.assertEqual([function(mode) for mode in (0, 1, 2, 3)], [0, 1, 2, 2])
                self.assertEqual(restored(), 91)
                self.assertEqual([returned(mode) for mode in (0, 1, 2, 3)], [0, 41, 100, 100])
        prefix = ALLOCATOR_HARNESS[:ALLOCATOR_HARNESS.index("extern uint64_t two_alloc")]
        source = prefix + r"""
extern uint64_t nested_owner(uint32_t);
extern uint64_t restore_and_drop(void);
extern uint64_t nested_return(uint32_t);
extern uint8_t echo_u8(uint8_t);
extern uint16_t echo_u16(uint16_t);
extern int8_t echo_i8(int8_t);
extern int16_t echo_i16(int16_t);
int main(void) {
    for(uint32_t mode=0;mode<3;mode++) if(nested_owner(mode)!=mode) return 11;
    if(restore_and_drop()!=91) return 12;
    if(echo_u8(255)!=255 || echo_u8(128)!=128) return 13;
    if(echo_u16(65535)!=65535 || echo_u16(32768)!=32768) return 14;
    if(echo_i8(-128)!=-128 || echo_i8(-1)!=-1 || echo_i8(127)!=127) return 15;
    if(echo_i16(-32768)!=-32768 || echo_i16(-1)!=-1 || echo_i16(32767)!=32767) return 16;
    printf("%zu %zu %zu\n",allocations,frees,live);
    if(allocations!=11 || frees!=11 || live!=0) return 17;
    allocations=0;frees=0;live=0;
    if(nested_return(0)!=0 || nested_return(1)!=41 || nested_return(2)!=100) return 18;
    printf("%zu %zu %zu\n",allocations,frees,live);
    return allocations!=6 || frees!=6 || live!=0;
}
"""
        object_file, executable, harness = self.root / "nested.o", self.root / "nested", self.root / "nested.c"
        harness.write_text(source)
        compile_owned_llvm(self.ir, program=self.analyzed.program, checked=self.analyzed.checked,
                           output=object_file, kind="object")
        linked = subprocess.run(["gcc", "-std=c11", "-O3", str(harness), str(object_file),
            "-Wl,--wrap=malloc", "-Wl,--wrap=calloc", "-Wl,--wrap=free", "-o", str(executable)],
            capture_output=True, text=True, timeout=60)
        self.assertEqual(linked.returncode, 0, linked.stderr)
        run = subprocess.run([str(executable)], capture_output=True, text=True, timeout=15)
        self.assertEqual(run.returncode, 0, run.stderr + run.stdout)
        self.assertEqual(run.stdout, "11 11 0\n6 6 0\n")

    def allocation_run(self, *, mutate=False):
        stem = "leaked" if mutate else "balanced"
        object_file, executable = self.root / (stem + ".o"), self.root / stem
        harness = self.root / (stem + ".c")
        harness.write_text(ALLOCATOR_HARNESS)
        if mutate:
            wrong = self.ir.text.replace("call void @free(ptr %data)", "; deliberately removed free")
            self.assertNotEqual(wrong, self.ir.text)
            source = self.root / "wrong.ll"
            source.write_text(wrong)
            # A deliberately wrong derived LLVM negative control bypasses the
            # source-facing compiler, whose exact-origin gate rejects it.
            built = subprocess.run(["clang", "-x", "ir", "-O3", "-fPIC", "-c",
                                    str(source), "-o", str(object_file)], capture_output=True, text=True, timeout=60)
            self.assertEqual(built.returncode, 0, built.stderr)
        else:
            compile_owned_llvm(self.ir, program=self.analyzed.program, checked=self.analyzed.checked,
                               output=object_file, kind="object")
        linked = subprocess.run(["clang", "-std=c11", "-O2", str(harness), str(object_file),
                                 "-Wl,--wrap=calloc", "-Wl,--wrap=malloc", "-Wl,--wrap=free", "-o", str(executable)],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(linked.returncode, 0, linked.stderr)
        return subprocess.run([str(executable)], capture_output=True, text=True, timeout=15)

    def test_real_allocator_refusal_cleans_earlier_owner_and_every_error_branch(self):
        result = self.allocation_run()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(result.stdout, "7 7 0 1\n")

    def test_actual_native_leak_mutation_fails_allocation_oracle(self):
        result = self.allocation_run(mutate=True)
        self.assertNotEqual(result.returncode, 0)
        # Removing free changes optimizer-visible effects as well: Clang may
        # delete now-unused constant allocations. Every allocation that
        # actually remains must still be observed live and unreleased.
        allocations, frees, live, refusals = map(int, result.stdout.split())
        self.assertGreater(allocations, 0)
        self.assertEqual((frees, live, refusals), (0, allocations, 1))

    def test_bounds_and_overflow_abort_in_children_on_all_backends(self):
        for backend, path in self.libraries.items():
            for symbol in ("panic_index", "panic_overflow"):
                with self.subTest(backend=backend, symbol=symbol):
                    child = subprocess.run([os.sys.executable, "-c",
                        "import ctypes,sys; fn=getattr(ctypes.CDLL(sys.argv[1]),sys.argv[2]); "
                        "fn.argtypes=[ctypes.c_uint8] if sys.argv[2]=='panic_overflow' else []; "
                        "fn.restype=ctypes.c_uint8; fn(*([255] if sys.argv[2]=='panic_overflow' else []))", str(path), symbol],
                        capture_output=True, text=True, timeout=15)
                    self.assertEqual(child.returncode, -6, child.stderr)

    def test_actual_multifile_source_pipeline_and_stale_input_rejection(self):
        project = self.root / "project"
        project.mkdir()
        for name in ("main.hepta", "owned.hepta"):
            shutil.copyfile(ROOT / "examples/llvm_owned" / name, project / name)
        destination = self.root / "project.so"
        report = build_llvm_owned_source(project / "main.hepta", destination)
        self.assertTrue(report["ok"], report)
        self.assertTrue(report["claims"]["actual_source_replayed"])
        from hepta.elf_shared_abi import inspect_owned_shared_elf
        native_abi = inspect_owned_shared_elf(destination.read_bytes(),
                                               tuple(report["source_binding"]["exports"]))
        self.assertEqual(report["native_backend"]["dynamic_abi"], native_abi)
        self.assertFalse(report["claims"]["fallback_used"])
        real_compile = compile_owned_llvm
        def changed(*args, **kwargs):
            receipt = real_compile(*args, **kwargs)
            (project / "owned.hepta").write_text(OWNED + "\n// changed after native compilation\n")
            return receipt
        stale = self.root / "stale.so"
        with patch("hepta.llvm_owned_pipeline.compile_owned_llvm", side_effect=changed):
            result = build_llvm_owned_source(project / "main.hepta", stale)
        self.assertFalse(result["ok"])
        self.assertFalse(stale.exists())
        self.assertIn("STALE", result["diagnostics"][0]["code"])

    def test_second_owned_source_publication_corruption_fails_after_receipt(self):
        # A mutation after the inner publisher succeeds must still be caught
        # at the outer source-facing receipt boundary. The original PR #136
        # test injected os.link; this compiler now uses publish_verified.
        from hepta import llvm_owned_pipeline
        project = self.root / "outer-owned-publication-race"
        project.mkdir()
        for name in ("main.hepta", "owned.hepta"):
            shutil.copyfile(ROOT / "examples/llvm_owned" / name, project / name)
        output = self.root / "outer-owned-mutant.so"
        original = llvm_owned_pipeline.publish_verified

        def corrupt_after_first_receipt(stage, destination, expected):
            receipt = original(stage, destination, expected)
            Path(destination).write_bytes(b"corrupted-after-initial-publisher")
            return receipt

        with patch.object(llvm_owned_pipeline, "publish_verified",
                          side_effect=corrupt_after_first_receipt):
            report = build_llvm_owned_source(project / "main.hepta", output)
        self.assertFalse(report["ok"], report)
        self.assertEqual(report["diagnostics"][0]["code"], "E_LLVM_OWNED_PUBLICATION")
        # Reject the candidate and retract only the destination that still
        # aliases this build's own staged inode; never publish a bad receipt.
        self.assertFalse(output.exists())

    def test_source_changed_during_publisher_does_not_mint_native_receipt(self):
        from hepta import llvm_owned_pipeline
        project = self.root / "post-publication"
        project.mkdir()
        for name in ("main.hepta", "owned.hepta"):
            shutil.copyfile(ROOT / "examples/llvm_owned" / name, project / name)
        output = self.root / "postpublication.so"
        original = llvm_owned_pipeline.publish_verified

        def modify_after_publish(stage, destination, expected):
            receipt = original(stage, destination, expected)
            (project / "owned.hepta").write_text(OWNED + "\n// post-publication edit\n")
            return receipt

        with patch.object(llvm_owned_pipeline, "publish_verified",
                          side_effect=modify_after_publish):
            report = build_llvm_owned_source(project / "main.hepta", output)
        self.assertFalse(report["ok"], report)
        self.assertFalse(output.exists())
        self.assertEqual(report["diagnostics"][0]["code"], "E_LLVM_OWNED_STALE")



if __name__ == "__main__":
    unittest.main()
