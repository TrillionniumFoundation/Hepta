"""Actual Rust/Python byte-bulk execution and independent native controls.

All six primitive v2-v6 memory operations reuse the shared Rust Machine.
These are finite observations; no native-refinement or all-input theorem is
asserted. The source builders use a weighted byte checksum so swaps and
partial/overlapping copies cannot disappear behind an order-insensitive sum.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import unittest

from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_runtime import HIAProgramBudgetExceeded, HIAProgramTrap, execute_program
from hepta.hia_swap_opt import rewrite_byte_swap
from tests import test_hia_rust_owned_vm as owned_tests
from tests.test_hia_program import b, c, f, i, m, ret

ROOT = Path(__file__).resolve().parents[1]
CLANG = os.environ.get("CLANG", "clang")
MAX = (1 << 64) - 1
VERSIONS = {"buffer.fill": 2, "buffer.copy": 2, "buffer.move_within": 3,
            "buffer.swap": 4, "buffer.copy_range": 5, "buffer.fill_range": 6}
PARAMS = [("size", "usize"), ("destination_size", "usize"),
          ("destination", "usize"), ("source", "usize"),
          ("count", "usize"), ("value", "u8")]


def edge(block, values):
    return {"target": block, "args": list(values)}


def jump(block, *values):
    return {"op": "jump", **edge(block, values)}


def branch(condition, yes, no):
    return {"op": "branch", "cond": condition, "then": yes, "else": no}


def memory_program(operation, *, reverse_owners=False, formal_siblings=False, schema=None):
    """Initialize source bytes to (index + 1) mod 256 and inspect every result.

    Each entry uses the same six scalar arguments for the native C harness.
    Copies allocate distinct roots; reverse_owners exercises either BTreeMap
    reference order. formal_siblings calls a helper with two read-only formals
    aliased to the same mutable caller view while one formal has a child.
    """
    copying = operation in {"buffer.copy", "buffer.copy_range"}
    if (reverse_owners or formal_siblings) and not copying:
        raise ValueError("copy-specific fixture option")
    fields = PARAMS + [("owner", "buffer"), ("loan", "mutbuf")]
    if reverse_owners:
        fields += [("target_owner", "buffer")]
    names = [name for name, _ in fields]
    indexed = fields + [("index", "usize")]
    indexed_names = [name for name, _ in indexed]
    entry_ops = []
    if reverse_owners:
        entry_ops.append(i("buffer.new", ["destination_size"], [("target_owner", "buffer")]))
    entry_ops += [i("buffer.new", ["size"], [("owner", "buffer")]),
                  i("borrow.mut", ["owner"], [("loan", "mutbuf")]), c("zero", "usize", 0)]
    blocks = [
        b("entry", PARAMS, entry_ops, jump("initialize", *names, "zero")),
        b("initialize", indexed, [i("compare.lt", ["index", "size"], [("more", "bool")])],
          branch("more", edge("initialize_body", indexed_names), edge("operate", names))),
        b("initialize_body", indexed, [
            c("one", "usize", 1), i("int.add.checked", ["index", "one"], [("next", "usize")]),
            i("int.cast", ["next"], [("byte", "u8")], mode="wrap"),
            i("buffer.store", ["loan", "index", "byte"]),
        ], jump("initialize", *names, "next")),
    ]
    helpers = []
    if copying:
        ops = [] if reverse_owners else [
            i("buffer.new", ["destination_size"], [("target_owner", "buffer")])]
        ops += [i("borrow.mut", ["target_owner"], [("target", "mutbuf")])]
        if formal_siblings:
            helper_params = [("target", "mutbuf"), ("left", "readbuf"), ("right", "readbuf"),
                             ("destination", "usize"), ("source", "usize"), ("count", "usize")]
            operands = (["target", "right", "count"] if operation == "buffer.copy" else
                        ["target", "right", "destination", "source", "count"])
            helpers.append(f("copy_helper", helper_params, [], ["read", "write", "trap"], [
                b("helper_entry", helper_params, [
                    i("borrow.read", ["left"], [("child", "readbuf")]),
                    i(operation, operands), i("loan.end", ["child"]),
                ], ret()),
            ]))
            ops += [i("call", ["target", "loan", "loan", "destination", "source", "count"],
                      function="copy_helper")]
        else:
            ops += [i("borrow.read", ["loan"], [("reader", "readbuf")])]
            operands = (["target", "reader", "count"] if operation == "buffer.copy" else
                        ["target", "reader", "destination", "source", "count"])
            ops += [i(operation, operands), i("loan.end", ["reader"])]
        ops += [i("loan.end", ["loan"]), i("owner.drop", ["owner"]), c("zero", "usize", 0)]
        continuation = jump("inspect", "destination_size", "target_owner", "target", "zero", "zero")
    else:
        operands = {
            "buffer.fill": ["loan", "value"],
            "buffer.move_within": ["loan", "destination", "source", "count"],
            "buffer.swap": ["loan", "destination", "source"],
            "buffer.fill_range": ["loan", "destination", "count", "value"],
        }[operation]
        ops = [i(operation, operands), c("zero", "usize", 0)]
        continuation = jump("inspect", "size", "owner", "loan", "zero", "zero")
    blocks.append(b("operate", fields, ops, continuation))
    inspection = [("size", "usize"), ("owner", "buffer"), ("loan", "mutbuf"),
                  ("index", "usize"), ("total", "usize")]
    blocks += [
        b("inspect", inspection, [i("compare.lt", ["index", "size"], [("more", "bool")])],
          branch("more", edge("inspect_body", [name for name, _ in inspection]),
                 edge("finish", ["owner", "loan", "total"]))),
        b("inspect_body", inspection, [
            c("one", "usize", 1), i("int.add.checked", ["index", "one"], [("next", "usize")]),
            i("buffer.load", ["loan", "index"], [("byte", "u8")]),
            i("int.cast", ["byte"], [("wide", "usize")], mode="checked"),
            i("int.mul.wrap", ["wide", "next"], [("weighted", "usize")]),
            i("int.add.wrap", ["total", "weighted"], [("new_total", "usize")]),
        ], jump("inspect", "size", "owner", "loan", "next", "new_total")),
        b("finish", [("owner", "buffer"), ("loan", "mutbuf"), ("total", "usize")],
          [i("loan.end", ["loan"]), i("owner.drop", ["owner"])], ret("total")),
    ]
    # Core SSA definitions are unique across an entire function. Give every
    # non-entry block's local parameters/results its own explicit namespace.
    for block in blocks[1:]:
        definitions = block["params"] + [out for op in block["ops"] for out in op["out"]]
        renamed = {item["name"]: block["id"] + "__" + item["name"] for item in definitions}
        for item in definitions:
            item["name"] = renamed[item["name"]]
        for op in block["ops"]:
            op["args"] = [renamed[name] for name in op["args"]]
        term = block["term"]
        if term["op"] == "branch":
            term["cond"] = renamed[term["cond"]]
            for label in ("then", "else"):
                term[label]["args"] = [renamed[name] for name in term[label]["args"]]
        elif term["op"] == "jump":
            term["args"] = [renamed[name] for name in term["args"]]
        else:
            term["values"] = [renamed[name] for name in term["values"]]
    document = m(*helpers, f("probe", PARAMS, ["usize"], ["alloc", "read", "write", "trap"], blocks))
    document["schema"] = schema or f"hepta.hia.program.v{VERSIONS[operation]}"
    document["exports"] = ["probe"]
    return document


def expected_bytes(operation, arguments):
    """Independent finite list model; invalid source-language ranges return None."""
    size, destination_size, destination, source, count, value = arguments
    original = [(index + 1) & 255 for index in range(size)]
    output = list(original)
    if operation in {"buffer.copy", "buffer.copy_range"}:
        output = [0] * destination_size
        if operation == "buffer.copy":
            destination = source = 0
        if (destination > destination_size or source > size
                or count > destination_size - destination or count > size - source):
            return None
        output[destination:destination + count] = original[source:source + count]
    elif operation == "buffer.fill":
        output = [value] * size
    elif operation == "buffer.fill_range":
        if destination > size or count > size - destination:
            return None
        output[destination:destination + count] = [value] * count
    elif operation == "buffer.move_within":
        if destination > size or source > size or count > size - destination or count > size - source:
            return None
        output[destination:destination + count] = original[source:source + count]
    elif operation == "buffer.swap":
        if destination >= size or source >= size:
            return None
        output[destination], output[source] = original[source], original[destination]
    else:
        raise AssertionError(operation)
    return sum((index + 1) * value for index, value in enumerate(output)) & MAX


@unittest.skipUnless(shutil.which("cargo"), "Cargo unavailable: NO Rust bulk execution qualification")
class RustOwnedBulkParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        owned_tests.RustByteOwnerVmParity.setUpClass.__func__(cls)
        cls.native_observations = 0

    @classmethod
    def tearDownClass(cls):
        print(f"Rust bulk/Python full-ledger parity observations: {cls.parity_observations}")
        print(f"Rust bulk/native result and allocator observations: {cls.native_observations}")

    raw_run = owned_tests.RustByteOwnerVmParity.raw_run

    def parity(self, document, args, *, entry="probe", steps=100_000,
               heap=16 * 1024 * 1024, fail=None):
        report = owned_tests.RustByteOwnerVmParity.parity(
            self, document, entry, args, steps=steps, heap=heap, fail=fail)
        self.assertEqual(report["profile"], "cfg-call-byte-owner-chain-v4")
        self.assertTrue(report["claims"]["byte_owner_bulk_memory"])
        return report

    def model_parity(self, operation, document, args, **options):
        report = self.parity(document, args, **options)
        if options.get("fail") or "heap" in options or "steps" in options:
            return report
        expected = expected_bytes(operation, args)
        if expected is None:
            self.assertEqual((report["status"], report["error"]["code"]), ("trapped", "bounds"))
        else:
            self.assertEqual(report["values"], [expected])
        return report

    def test_actual_registered_swap_candidate_has_independent_rust_execution(self):
        baseline = verify_program((ROOT / "examples/hia_ndu/byte_swap.json").read_bytes())
        candidate = rewrite_byte_swap(baseline).program
        positives = json.loads((ROOT / "examples/hia_ndu/byte_swap_cases.json").read_text())
        negatives = [[4, 0, 3, 0], [5, 5, 0, 0], [5, 0, 5, 0], [5, 0, 4, 5], [0, 0, 0, 0]]
        for args in positives + negatives:
            for failure in (None, 1):
                with self.subTest(args=args, failure=failure):
                    before = self.parity(baseline, args, entry="swap_candidate", fail=failure)
                    after = self.parity(candidate, args, entry="swap_candidate", fail=failure)
                    self.assertEqual(before["status"], after["status"])
                    self.assertEqual(before["resources"], after["resources"])
                    key = "values" if before["status"] == "returned" else "error"
                    self.assertEqual(before[key], after[key])

    def test_actual_registered_fill_loop_candidate_has_independent_rust_execution(self):
        from hepta.hia_fill_loop_opt import rewrite_full_view_fill_loop
        from tests.test_hia_fill_loop_opt import fill_loop_program

        baseline = verify_program(fill_loop_program())
        rewrite = rewrite_full_view_fill_loop(baseline)
        self.assertEqual(rewrite.replacements, 1)
        cases = [[size, byte, probe, mask] for size in (1, 7, 32)
                 for byte in (0, 173, 255) for probe in (0, size - 1)
                 for mask in (0, 93)]
        cases += [[0, 7, 0, 0], [7, 7, 7, 0], [7, 7, MAX, 0],
                  [7, 256, 0, 0], [7, 7, 0, 256], [0, 256, MAX, 256]]
        for args in cases:
            for failure in (None, 1):
                with self.subTest(args=args, failure=failure):
                    before = self.parity(baseline, args, entry="fill_probe", fail=failure)
                    after = self.parity(rewrite.program, args, entry="fill_probe", fail=failure)
                    self.assertEqual(before["status"], after["status"])
                    self.assertEqual(before["resources"], after["resources"])
                    key = "values" if before["status"] == "returned" else "error"
                    self.assertEqual(before[key], after[key])
                    # Each Core's step count is compared with Python by parity;
                    # eliminating loop iterations deliberately changes it.

    def test_fill_and_all_small_swap_offsets(self):
        fill = memory_program("buffer.fill")
        swap = memory_program("buffer.swap")
        for size in range(6):
            for value in (0, 255):
                self.model_parity("buffer.fill", fill, [size, 0, 0, 0, 0, value])
            for left in range(size + 1):
                for right in range(size + 1):
                    self.model_parity("buffer.swap", swap, [size, 0, left, right, 0, 0])
        for left, right in ((MAX, 0), (0, MAX), (MAX, MAX)):
            self.model_parity("buffer.swap", swap, [5, 0, left, right, 0, 0])

    def test_overlapping_move_and_zero_length_range_rules(self):
        operation = "buffer.move_within"
        program = memory_program(operation)
        for size in range(5):
            for destination in range(size + 1):
                for source in range(size + 1):
                    for count in range(size + 2):
                        self.model_parity(operation, program, [size, 0, destination, source, count, 0])
        for destination, source, count in ((6, 0, 0), (0, 6, 0), (5, 5, 0),
                                          (MAX, MAX, 0), (0, 0, MAX), (1, MAX, MAX)):
            self.model_parity(operation, program, [5, 0, destination, source, count, 0])

    def test_range_fill_retains_untouched_bytes_and_checks_empty_range_offsets(self):
        operation = "buffer.fill_range"
        program = memory_program(operation)
        for size in range(6):
            for offset in range(size + 2):
                for count in range(size + 2):
                    self.model_parity(operation, program, [size, 0, offset, 0, count, 193])
        for offset, count in ((MAX, 0), (0, MAX), (MAX, MAX)):
            self.model_parity(operation, program, [5, 0, offset, 0, count, 0])

    def test_distinct_owner_copy_both_allocation_orders_and_runtime_extents(self):
        for operation in ("buffer.copy", "buffer.copy_range"):
            for reverse in (False, True):
                program = memory_program(operation, reverse_owners=reverse)
                for size, destination_size in ((0, 0), (0, 3), (3, 0), (1, 4), (4, 1), (4, 4)):
                    for count in range(6):
                        self.model_parity(operation, program,
                                          [size, destination_size, 0, 0, count, 0])
                if operation == "buffer.copy_range":
                    for destination, source, count in ((0, 0, 3), (1, 0, 3), (0, 1, 3),
                        (4, 3, 0), (5, 3, 0), (4, 4, 0), (0, MAX, 0),
                        (MAX, 0, 0), (MAX, MAX, MAX), (0, 0, MAX)):
                        self.model_parity(operation, program, [3, 4, destination, source, count, 0])

    def test_mutable_actual_readonly_siblings_and_all_step_boundaries(self):
        for operation in ("buffer.copy", "buffer.copy_range"):
            program = memory_program(operation, formal_siblings=True)
            args = [3, 5, 1, 0, 3, 0]
            result = self.model_parity(operation, program, args)
            self.assertEqual(result["resources"]["live_local_loans"], 0)
            for steps in range(1, result["steps"]):
                self.parity(program, args, steps=steps)
            for failure in (1, 2, 3):
                self.parity(program, args, fail=failure)
            for heap in (0, 2, 3, 7, 8):
                self.parity(program, args, heap=heap)
            for schema in (f"hepta.hia.program.v{version}" for version in range(VERSIONS[operation], 8)):
                document = copy.deepcopy(program)
                document["schema"] = schema
                self.model_parity(operation, document, args)

    def test_downgraded_schema_readonly_and_alias_forgeries_refuse_before_execution(self):
        for operation, version in VERSIONS.items():
            document = memory_program(operation)
            if version > 1:
                old = copy.deepcopy(document)
                old["schema"] = f"hepta.hia.program.v{version - 1}"
                with self.assertRaises(HIAProgramRejected):
                    verify_program(old)
                result = self.raw_run(json.dumps(old).encode(), "probe", [4, 4, 0, 0, 1, 7])
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")
            invalid = copy.deepcopy(document)
            block = next(block for block in invalid["functions"][-1]["blocks"] if block["id"] == "operate")
            operation_index = next(n for n, op in enumerate(block["ops"]) if op["op"] == operation)
            original_loan = block["ops"][operation_index]["args"][0]
            block["ops"].insert(operation_index, i("borrow.read", [original_loan], [("readonly", "readbuf")]))
            block["ops"][operation_index + 1]["args"][0] = "readonly"
            with self.assertRaises(HIAProgramRejected):
                verify_program(invalid)
            result = self.raw_run(json.dumps(invalid).encode(), "probe", [4, 4, 0, 0, 1, 7])
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"")
        alias = memory_program("buffer.copy_range", formal_siblings=True)
        block = next(block for block in alias["functions"][-1]["blocks"] if block["id"] == "operate")
        call = next(op for op in block["ops"] if op["op"] == "call")
        call["args"][0] = call["args"][1]
        with self.assertRaises(HIAProgramRejected):
            verify_program(alias)
        result = self.raw_run(json.dumps(alias).encode(), "probe", [4, 4, 0, 0, 1, 7])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"E_HIA_LOAN", result.stderr)
        self.assertEqual(result.stdout, b"")

    @unittest.skipUnless(shutil.which(CLANG), "Clang unavailable: NO native bulk qualification")
    def test_actual_native_bulk_results_allocator_failures_and_bounds_traces(self):
        from hepta.clang_capture import run_bounded
        from hepta.hia_program_llvm import compile_program_llvm, emit_program_llvm
        documents = {}
        functions = []
        for operation in VERSIONS:
            name = operation.removeprefix("buffer.")
            document = memory_program(operation, schema="hepta.hia.program.v6")
            document["functions"][0]["name"] = name
            document["exports"] = [name]
            documents[name] = document
            functions.extend(document["functions"])
        combined = {"schema": "hepta.hia.program.v6", "module": "bulk_native_controls", "functions": functions}
        core = verify_program(combined)
        driver = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
_Static_assert(sizeof(size_t) == 8, "LP64 scalar ABI required");
#define DECL(name) uint64_t name(size_t,size_t,size_t,size_t,size_t,uint8_t)
DECL(fill); DECL(copy); DECL(move_within); DECL(swap); DECL(copy_range); DECL(fill_range);
void *__real_calloc(size_t,size_t); void *__real_malloc(size_t); void __real_free(void *);
__attribute__((noreturn)) void __real_abort(void);
static size_t attempts, allocations, frees, live, fail_at;
void *__wrap_calloc(size_t n,size_t w){ attempts++; if(attempts==fail_at)return NULL;
    void *p=__real_calloc(n,w);if(p){allocations++;live++;}return p; }
void *__wrap_malloc(size_t n){ attempts++; if(attempts==fail_at)return NULL;
    void *p=__real_malloc(n);if(p){allocations++;live++;}return p; }
void __wrap_free(void *p){ if(p){frees++;live--;}__real_free(p); }
static void record(int trapped,uint64_t answer){
    printf("{\"trapped\":%d,\"answer\":%llu,\"attempts\":%zu,\"allocations\":%zu,\"frees\":%zu,\"live\":%zu}\n",
        trapped,(unsigned long long)answer,attempts,allocations,frees,live);fflush(stdout);
}
__attribute__((noreturn)) void __wrap_abort(void){record(1,0);__real_abort();}
int main(int argc,char **argv){
    if(argc!=8&&argc!=9)return 99;
    size_t a[5];for(size_t i=0;i<5;i++)a[i]=(size_t)strtoull(argv[i+2],NULL,10);
    uint8_t value=(uint8_t)strtoul(argv[7],NULL,10);
    if(argc==9)fail_at=(size_t)strtoull(argv[8],NULL,10);
    uint64_t result;
#define RUN(name) if(!strcmp(argv[1],#name))result=name(a[0],a[1],a[2],a[3],a[4],value)
    RUN(fill); else RUN(copy); else RUN(move_within); else RUN(swap);
    else RUN(copy_range); else RUN(fill_range); else return 98;
    record(0,result);return 0;
}
'''
        cases = {
            "fill": [[0, 0, 0, 0, 0, 7], [5, 0, 0, 0, 0, 193]],
            "copy": [[0, 0, 0, 0, 0, 0], [5, 7, 0, 0, 4, 0], [5, 3, 0, 0, 4, 0]],
            "move_within": [[5, 0, 1, 0, 4, 0], [5, 0, 0, 1, 4, 0],
                            [0, 0, 0, 0, 0, 0], [5, 0, MAX, 0, 0, 0]],
            "swap": [[5, 0, 0, 4, 0, 0], [5, 0, 2, 2, 0, 0], [5, 0, 0, MAX, 0, 0]],
            "copy_range": [[5, 7, 2, 1, 4, 0], [5, 7, 7, 5, 0, 0],
                           [5, 7, 8, 5, 0, 0], [5, 7, MAX, MAX, MAX, 0]],
            "fill_range": [[5, 0, 1, 0, 3, 197], [5, 0, 5, 0, 0, 197],
                           [5, 0, 6, 0, 0, 197], [5, 0, 0, 0, MAX, 0]],
        }
        with tempfile.TemporaryDirectory(prefix="hia-rust-bulk-native-") as directory:
            directory = Path(directory)
            obj, source, binary = directory / "bulk.o", directory / "driver.c", directory / "driver"
            receipt = compile_program_llvm(emit_program_llvm(core), program=core, output=obj,
                                           clang=CLANG, kind="object")
            self.assertTrue(receipt["ok"])
            source.write_text(driver)
            built = run_bounded([CLANG, "-std=c11", "-O2", str(source), str(obj),
                "-Wl,--wrap=calloc", "-Wl,--wrap=malloc", "-Wl,--wrap=free", "-Wl,--wrap=abort",
                "-o", str(binary)])
            self.assertEqual(built.returncode, 0, built.stderr)
            for name, inputs in cases.items():
                for args in inputs:
                    for failure in (None, 1, 2):
                        with self.subTest(name=name, args=args, failure=failure):
                            rust = self.parity(core, args, entry=name, fail=failure)
                            command = [str(binary), name, *map(str, args)]
                            if failure is not None:
                                command.append(str(failure))
                            native = run_bounded(command)
                            trapped = rust["status"] == "trapped"
                            self.assertEqual(native.returncode, -signal.SIGABRT if trapped else 0, native.stderr)
                            observed = json.loads(native.stdout)
                            resources = rust["resources"]
                            self.assertEqual(observed["trapped"], int(trapped))
                            self.assertEqual(observed["attempts"], resources["allocation_attempts"])
                            self.assertEqual(observed["allocations"], resources["allocations"])
                            self.assertEqual(observed["frees"], resources["frees"])
                            self.assertEqual(observed["live"], resources["allocations"] - resources["frees"])
                            if not trapped:
                                self.assertEqual(observed["answer"], rust["values"][0])
                                self.assertEqual(observed["answer"], expected_bytes("buffer." + name, args))
                            type(self).native_observations += 1


if __name__ == "__main__":
    unittest.main()
