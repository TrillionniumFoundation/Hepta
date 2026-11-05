"""Exact SSE2 sum matching, full-range guards, native traps and owner cleanup."""
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
import ctypes
import json
import os
from pathlib import Path
import random
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_byte_sum import INTRINSIC, byte_sum_plans
from hepta.hia_program import execute_program, verify_program
from hepta.hia_program_runtime import HIAProgramTrap
from hepta.hia_program_source import lower_source
from hepta.hia_program_llvm import (
    HIAProgramLLVMRejected, TARGET, TARGET_AARCH64, TARGET_RISCV64,
    build_program_native, compile_program_llvm, emit_program_llvm,
)
from hepta.hia_reduction import propose_reduction_pipeline, reduction_program

ROOT = Path(__file__).resolve().parents[1]
CLANG = os.environ.get("HIA_TEST_CLANG20")
MASK = 2**64 - 1


def variable(name, typ):
    return {"name": name, "type": typ}


def operation(opcode, arguments=(), outputs=(), **attributes):
    return {"op": opcode, "args": list(arguments),
            "out": [variable(*item) for item in outputs], "attrs": attributes}


def constant(name, typ, value):
    return operation("const", outputs=[(name, typ)], value=value)


def jump(target, *arguments):
    return {"op": "jump", "target": target, "args": list(arguments)}


def branch(condition, left, left_arguments, right, right_arguments):
    return {"op": "branch", "cond": condition,
            "then": {"target": left, "args": list(left_arguments)},
            "else": {"target": right, "args": list(right_arguments)}}


def block(name, parameters, operations, terminal):
    return {"id": name, "params": [variable(*p) for p in parameters],
            "ops": operations, "term": terminal}


def sample_function(name="sum_wrap", *, checked_sum=False, checked_index=False):
    """Physical extent, logical limit, start and initial sum are independent."""
    parameters = [("n", "usize"), ("limit", "usize"), ("start", "usize"),
                  ("initial", "u64"), ("byte", "u8")]
    fill_types = ["buffer", "usize", "usize", "usize", "u64", "u8", "usize"]
    fill = ["f_owner", "f_n", "f_limit", "f_start", "f_initial", "f_byte", "f_index"]
    write = ["w_owner", "w_n", "w_limit", "w_start", "w_initial", "w_byte", "w_index"]
    header = ["s_owner", "s_limit", "s_index", "s_total"]
    body = ["b_owner", "b_limit", "b_index", "b_total"]
    sum_types = ["buffer", "usize", "usize", "u64"]
    return {
        "name": name, "params": [variable(*p) for p in parameters], "returns": ["u64"],
        "effects": ["alloc", "read", "trap", "write"], "entry": "entry",
        "blocks": [
            block("entry", parameters, [
                operation("buffer.try_new", ["n"], [("owner", "buffer"), ("ok", "bool")]),
                constant("zero", "usize", 0),
            ], branch("ok", "fill", ["owner", "n", "limit", "start", "initial", "byte", "zero"],
                      "error", ["owner"])),
            block("fill", list(zip(fill, fill_types)), [
                operation("compare.lt", ["f_index", "f_n"], [("fill_more", "bool")]),
            ], branch("fill_more", "write", fill, "sum",
                      ["f_owner", "f_limit", "f_start", "f_initial"])),
            block("write", list(zip(write, fill_types)), [
                operation("borrow.mut", ["w_owner"], [("writer", "mutbuf")]),
                operation("buffer.store", ["writer", "w_index", "w_byte"]),
                operation("loan.end", ["writer"]),
                constant("fill_one", "usize", 1),
                operation("int.add.wrap", ["w_index", "fill_one"], [("fill_next", "usize")]),
            ], jump("fill", *write[:-1], "fill_next")),
            block("sum", list(zip(header, sum_types)), [
                operation("compare.lt", ["s_index", "s_limit"], [("sum_more", "bool")]),
            ], branch("sum_more", "body", header, "done", ["s_owner", "s_total"])),
            block("body", list(zip(body, sum_types)), [
                operation("borrow.read", ["b_owner"], [("reader", "readbuf")]),
                operation("buffer.load", ["reader", "b_index"], [("loaded", "u8")]),
                operation("loan.end", ["reader"]),
                operation("int.cast", ["loaded"], [("wide", "u64")], mode="wrap"),
                operation("int.add.checked" if checked_sum else "int.add.wrap",
                          ["b_total", "wide"], [("sum_next", "u64")]),
                constant("sum_one", "usize", 1),
                operation("int.add.checked" if checked_index else "int.add.wrap",
                          ["b_index", "sum_one"], [("index_next", "usize")]),
            ], jump("sum", "b_owner", "b_limit", "index_next", "sum_next")),
            block("done", [("done_owner", "buffer"), ("done_total", "u64")], [
                operation("owner.drop", ["done_owner"]),
            ], {"op": "ret", "values": ["done_total"]}),
            block("error", [("error_owner", "buffer")], [
                operation("owner.drop", ["error_owner"]),
                constant("allocation_error", "u64", 1001),
            ], {"op": "ret", "values": ["allocation_error"]}),
        ],
    }


def sample_program():
    return verify_program({
        "schema": "hepta.hia.program.v1", "module": "byte_sum_boundaries",
        "functions": [
            sample_function(),
            sample_function("sum_checked", checked_sum=True),
            sample_function("index_checked", checked_index=True),
        ],
    })


class ByteSumStructureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.program = sample_program()
        cls.function = cls.program.as_dict()["functions"][0]

    def test_exact_forward_wrapping_loop_only(self):
        self.assertEqual(set(byte_sum_plans(self.function)), {"body"})
        for function in self.program.as_dict()["functions"][1:]:
            self.assertEqual(byte_sum_plans(function), {})
        before = self.program.canonical_bytes
        ir = emit_program_llvm(self.program)
        self.assertEqual(ir.core_sha256, self.program.sha256)
        self.assertEqual(self.program.canonical_bytes, before)
        self.assertEqual(ir.text.count("call <2 x i64> @" + INTRINSIC), 2)
        self.assertIn("load <16 x i8>", ir.text)
        self.assertIn("align 1", ir.text)
        self.assertIn("call void @abort()", ir.text)

    def test_alpha_renaming_preserves_structural_recognition(self):
        names = {b["id"] for b in self.function["blocks"]}
        names.update(p["name"] for p in self.function["params"])
        for b in self.function["blocks"]:
            names.update(p["name"] for p in b["params"])
            names.update(p["name"] for op in b["ops"] for p in op["out"])
        mapping = {name: "renamed_" + str(i) for i, name in enumerate(sorted(names))}
        def rename(value):
            if isinstance(value, str):
                return mapping.get(value, value)
            if isinstance(value, list):
                return [rename(v) for v in value]
            if isinstance(value, dict):
                return {k: rename(v) for k, v in value.items()}
            return value
        self.assertEqual(set(byte_sum_plans(rename(self.function))), {mapping["body"]})

    def test_different_effect_stride_transport_or_predecessor_is_refused(self):
        mutants = []
        def mutate(action):
            f = deepcopy(self.function)
            blocks = {b["id"]: b for b in f["blocks"]}
            action(blocks)
            mutants.append(f)
        mutate(lambda b: b["body"]["ops"][4].update(op="int.add.checked"))
        mutate(lambda b: b["body"]["ops"][6].update(op="int.add.checked"))
        mutate(lambda b: b["body"]["ops"][5]["attrs"].update(value=2))
        mutate(lambda b: b["body"]["ops"][5]["attrs"].update(value=True))
        mutate(lambda b: b["body"]["ops"].append(constant("extra", "u8", 1)))
        mutate(lambda b: b["body"]["ops"][0].update(op="borrow.mut"))
        mutate(lambda b: b["body"]["ops"][1]["args"].reverse())
        mutate(lambda b: b["sum"]["ops"][0].update(op="compare.le"))
        mutate(lambda b: b["body"]["term"]["args"].__setitem__(1, "b_index"))
        mutate(lambda b: b["sum"]["term"]["then"]["args"].reverse())
        mutate(lambda b: b["sum"]["term"].update(
            **{"else": deepcopy(b["sum"]["term"]["then"])}))
        for index, f in enumerate(mutants):
            with self.subTest(mutation=index):
                self.assertEqual(byte_sum_plans(f), {})
        for malformed in ({}, {"blocks": []}, {"blocks": [None]}):
            self.assertEqual(byte_sum_plans(malformed), {})

    def test_other_declared_targets_keep_scalar_lowering(self):
        for target in (TARGET_AARCH64, TARGET_RISCV64):
            with self.subTest(target=target):
                text = emit_program_llvm(self.program, target=target).text
                self.assertNotIn(INTRINSIC, text)
                self.assertNotIn("load <16 x i8>", text)
                self.assertIn("load i8", text)
        self.assertIn(INTRINSIC, emit_program_llvm(self.program, target=TARGET).text)

    def test_both_range_checks_precede_vector_pointer_and_read(self):
        text = emit_program_llvm(self.program).text
        selected = text[text.index("byte_sum_vector_"):]
        vector_body = selected[selected.index("\nbyte_sum_vector_"):].split("\nbyte_sum_scalar_")[0]
        self.assertIn("getelementptr i8", vector_body)
        self.assertIn("load <16 x i8>", vector_body)
        prefix = text[:text.index("br i1", text.index("icmp uge i64"))]
        self.assertGreaterEqual(prefix.count("icmp ule i64"), 2)
        self.assertGreaterEqual(prefix.count("icmp uge i64"), 2)

    def test_scalar_tail_cannot_reenter_vector_checks(self):
        text = emit_program_llvm(self.program).text
        start = text.index("\nbyte_sum_scalar_head_")
        end = text.index("\nbyte_sum_finished_", start)
        tail = text[start:end]
        self.assertIn("load i8", tail)
        self.assertIn("call void @abort()", tail)
        self.assertIn("br label %byte_sum_scalar_head_", tail)
        self.assertNotIn("br label %byte_sum_vector", tail)
        self.assertNotIn("icmp uge i64", tail)

    def test_modular_arithmetic_and_nonwrapping_range_lemmas(self):
        import z3
        for width in (8, 16):
            with self.subTest(width=width):
                lanes = [z3.BitVec("lane_" + str(i), 8) for i in range(width)]
                initial = z3.BitVec("initial_sum", 64)
                widened = [z3.ZeroExt(56, b) for b in lanes]
                scalar = initial
                for value in widened:
                    scalar = scalar + value
                vector = initial + sum(widened[:8]) + sum(widened[8:])
                solver = z3.Solver(); solver.set(timeout=5000)
                solver.add(scalar != vector)
                self.assertEqual(solver.check(), z3.unsat)
                index, bound = z3.BitVecs("range_index range_bound", 64)
                solver = z3.Solver(); solver.set(timeout=5000)
                solver.add(z3.ULE(index, bound), z3.UGE(bound - index, width))
                solver.add(z3.Or(z3.UGE(index + width - 1, bound),
                                 z3.UGT(index + width, bound),
                                 z3.ULT(index + width, index)))
                self.assertEqual(solver.check(), z3.unsat)

    def test_interpreter_checked_overflow_bounds_and_refusal_are_unchanged(self):
        for name, args, code in (
            ("sum_checked", [16, 16, 0, MASK - 1, 255], "overflow"),
            ("sum_wrap", [15, 16, 0, 0, 255], "bounds"),
            ("sum_wrap", [16, 17, 0, 0, 255], "bounds"),
            ("sum_wrap", [16, MASK, MASK - 1, 0, 255], "bounds"),
        ):
            with self.subTest(name=name, args=args), self.assertRaises(HIAProgramTrap) as caught:
                execute_program(self.program, name, args)
            self.assertEqual(caught.exception.code, code)
        answer = execute_program(self.program, "sum_wrap", [17, 17, 1, MASK - 7, 255])
        self.assertEqual(answer["result"], (MASK - 7 + 16 * 255) & MASK)
        self.assertEqual(answer["resources"]["live_owners"], 0)
        self.assertEqual(answer["resources"]["live_local_loans"], 0)
        failed = execute_program(self.program, "sum_wrap", [12281, 12281, 0, 0, 255],
                                 allocation_fail_at=1)
        self.assertEqual(failed["result"], 1001)
        self.assertEqual(failed["resources"]["live_owners"], 0)

    def test_modified_vector_range_guard_is_rejected_before_tool_execution(self):
        ir = emit_program_llvm(self.program)
        for width in (8, 16):
            with self.subTest(width=width):
                changed = ir.text.replace(", " + str(width) + "\n",
                                          ", " + str(width - 1) + "\n", 1)
                self.assertNotEqual(changed, ir.text)
                forged = replace(ir, text=changed, sha256=sha256(changed.encode()).hexdigest())
                with tempfile.TemporaryDirectory() as folder, patch(
                        "hepta.hia_program_llvm.run_bounded",
                        side_effect=AssertionError("a forged module must not reach Clang")):
                    with self.assertRaisesRegex(HIAProgramLLVMRejected, "ORIGIN"):
                        compile_program_llvm(forged, program=self.program,
                                             output=Path(folder) / "forged.o", kind="object")


GUARD_DRIVER = r"""
#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

typedef uint64_t (*sum_fn)(size_t,size_t,size_t,uint64_t,uint8_t);
uint64_t sum_wrap(size_t,size_t,size_t,uint64_t,uint8_t);
uint64_t sum_checked(size_t,size_t,size_t,uint64_t,uint8_t);
uint64_t index_checked(size_t,size_t,size_t,uint64_t,uint8_t);
static void *mapping, *allocation;
static size_t mapped_size, calls, releases, refused, cases, prefix_cases;
static void *allocate(size_t n, int zeroed) {
    ++calls;
    if (n == 12281) { ++refused; return NULL; }
    if (allocation || !n || n > 1024*1024) exit(90);
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    size_t used = ((n+page-1)/page)*page;
    mapped_size = used+page;
    mapping = mmap(NULL,mapped_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if (mapping == MAP_FAILED) exit(91);
    unsigned char *guard = (unsigned char *)mapping+used;
    if (mprotect(guard,page,PROT_NONE)) exit(92);
    allocation = guard-n;
    memset(allocation,zeroed ? 0 : 0xa5,n);
    return allocation;
}
void *__wrap_malloc(size_t n) { return allocate(n,0); }
void *__wrap_calloc(size_t n, size_t width) {
    if (n && width > SIZE_MAX/n) exit(93);
    return allocate(n*width,1);
}
void __wrap_free(void *p) {
    if (!p) return;
    if (p != allocation || !mapping) exit(94);
    if (munmap(mapping,mapped_size)) exit(95);
    mapping = allocation = NULL; ++releases;
}
int main(int argc, char **argv) {
    struct rlimit no_core = {0,0}; if(setrlimit(RLIMIT_CORE,&no_core))return 96;
    if(argc==2) {
        if(!strcmp(argv[1],"short"))return (int)sum_wrap(15,16,0,0,255);
        if(!strcmp(argv[1],"last"))return (int)sum_wrap(16,17,0,0,255);
        if(!strcmp(argv[1],"tail19"))return (int)sum_wrap(19,20,0,0,255);
        if(!strcmp(argv[1],"halfshort"))return (int)sum_wrap(7,8,0,0,255);
        if(!strcmp(argv[1],"halflast"))return (int)sum_wrap(8,9,0,0,255);
        if(!strcmp(argv[1],"tail24"))return (int)sum_wrap(24,25,0,0,255);
        if(!strcmp(argv[1],"tail31"))return (int)sum_wrap(31,32,0,0,255);
        if(!strcmp(argv[1],"high"))return (int)sum_wrap(16,SIZE_MAX,SIZE_MAX-1,0,255);
        if(!strcmp(argv[1],"overflow"))return (int)sum_checked(16,16,0,UINT64_MAX-1,255);
        return 97;
    }
    const size_t sizes[] = {0,1,7,15,16,17,19,29,30,31,32,33,63,64,65,255,256,257,
                           4095,4096,4097,8191,8192,8193};
    const uint8_t bytes[] = {0,1,127,255};
    const uint64_t initial[] = {0,17,UINT64_MAX-7};
    sum_fn functions[] = {sum_wrap,sum_checked,index_checked};
    for(size_t f=0;f<3;f++)for(size_t s=0;s<sizeof(sizes)/sizeof(sizes[0]);s++)
    for(size_t b=0;b<4;b++)for(size_t a=0;a<(f==1 ? 2u : 3u);a++)
    for(size_t position=0;position<3;position++) {
        size_t n=sizes[s], start=position==0 ? 0 : position==1 ? (n<15?n:15) : n;
        uint64_t expected=initial[a]+(uint64_t)(n-start)*bytes[b];
        size_t before_calls=calls,before_frees=releases;
        uint64_t result=functions[f](n,n,start,initial[a],bytes[b]);
        if(result!=expected || allocation || calls-before_calls!=(n!=0)
            || releases-before_frees!=(n!=0))return 98;
        ++cases;
    }
    const size_t extents[] = {0,1,7,8,9,15,16,17,23,24,25,31,32,33,65};
    for(size_t f=0;f<3;f+=2)
    for(size_t s=0;s<sizeof(extents)/sizeof(extents[0]);s++)
    for(size_t limit=0;limit<=extents[s];limit++)for(size_t position=0;position<4;position++) {
        size_t n=extents[s], start=position==0 ? 0 : position==1 ? (limit<7?limit:7)
                          : position==2 ? limit : limit+1;
        uint64_t expected=UINT64_MAX-7+(uint64_t)(limit>start ? limit-start : 0)*255;
        size_t before_calls=calls,before_frees=releases;
        uint64_t result=functions[f](n,limit,start,UINT64_MAX-7,255);
        if(result!=expected || allocation || calls-before_calls!=(n!=0)
            || releases-before_frees!=(n!=0))return 102;
        ++prefix_cases;
    }
    for(size_t f=0;f<3;f++) {
        if(functions[f](12281,12281,0,0,255)!=1001 || allocation)return 99;
        if(functions[f](SIZE_MAX,SIZE_MAX,0,0,255)!=1001 || allocation)return 100;
    }
    if(calls!=releases+refused || refused!=3)return 101;
    printf("{\"cases\":%zu,\"prefix_cases\":%zu,\"allocator_calls\":%zu,\"frees\":%zu,\"refusals\":%zu,\"live\":0}\n",
           cases,prefix_cases,calls,releases,refused);
    return 0;
}
"""


@unittest.skipUnless(CLANG, "set HIA_TEST_CLANG20 for actual SSE2 and guard-page execution")
class ByteSumNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="hia-byte-sum-")
        cls.folder = Path(cls.temp.name)
        cls.program = sample_program()
        cls.ir = emit_program_llvm(cls.program)
        cls.obj = cls.folder / "sum.o"
        compile_program_llvm(cls.ir, program=cls.program, output=cls.obj, clang=CLANG, kind="object")
        cls.driver = cls.folder / "guard.c"
        cls.driver.write_text(GUARD_DRIVER)
        cls.binary = cls.folder / "guard"
        built = subprocess.run([CLANG, "-O2", str(cls.driver), str(cls.obj),
                                "-Wl,--wrap=malloc", "-Wl,--wrap=calloc", "-Wl,--wrap=free",
                                "-o", str(cls.binary)], capture_output=True, text=True, timeout=60)
        if built.returncode:
            raise AssertionError(built.stderr)
        cls.assembly = subprocess.run(["/usr/bin/objdump", "-d", str(cls.obj)],
                                      capture_output=True, text=True, timeout=10)
        if cls.assembly.returncode:
            raise AssertionError(cls.assembly.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_actual_sse2_with_unaligned_page_ends_and_exact_owner_events(self):
        self.assertIn("psadbw", self.assembly.stdout)
        completed = subprocess.run([str(self.binary)], capture_output=True, text=True, timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        facts = json.loads(completed.stdout)
        self.assertEqual(facts["cases"], 2304)
        self.assertEqual(facts["prefix_cases"], 2568)
        self.assertEqual(facts["allocator_calls"], facts["frees"] + facts["refusals"])
        self.assertEqual(facts["refusals"], 3)
        self.assertEqual(facts["live"], 0)

    def test_scalar_tail_bounds_and_checked_overflow_abort_not_page_fault(self):
        for mode in ("short", "last", "tail19", "tail31", "halfshort", "halflast", "tail24", "high", "overflow"):
            with self.subTest(mode=mode):
                trapped = subprocess.run([str(self.binary), mode], capture_output=True,
                                         text=True, timeout=10)
                self.assertEqual(trapped.returncode, -6, trapped.stdout + trapped.stderr)

    def test_both_registered_workloads_match_independent_arithmetic(self):
        functions = []
        for workload in ("linear", "affine"):
            source = lower_source((ROOT / ("benchmarks/hia_reduction_release/" + workload + ".hepta")).read_text())
            optimized = reduction_program(source, propose_reduction_pipeline(source, include_induction=True))
            function = optimized.as_dict()["functions"][0]
            function["name"] = "calculate_" + workload
            self.assertEqual(len(byte_sum_plans(function)), 1)
            functions.append(function)
        core = verify_program({"schema": "hepta.hia.program.v1", "module": "both_byte_sum_workloads",
                               "functions": functions})
        path = self.folder / "workloads.so"
        receipt = build_program_native(core, path, clang=CLANG, layout="guarded-outline-v1")
        self.assertEqual(receipt["entry_layout"], "guarded-outline-v1")
        library = ctypes.CDLL(str(path))
        for workload in ("linear", "affine"):
            entry = getattr(library, "calculate_" + workload)
            entry.argtypes = [ctypes.c_size_t, ctypes.c_uint32]
            entry.restype = ctypes.c_uint64
            for n in (0,1,7,15,16,17,19,29,30,31,32,33,63,64,65,95,96,97,255,256,257,4095,4096,4097,8193):
                for seed in (0,1,2,17,255,256,2**31,2**32-1):
                    expected = sum(((i + seed) if workload == "linear" else (i * seed + 17)) & 255
                                   for i in range(n))
                    with self.subTest(workload=workload,n=n,seed=seed):
                        self.assertEqual(entry(n,seed), expected)


if __name__ == "__main__":
    unittest.main()
