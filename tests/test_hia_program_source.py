"""Source adaptation is exercised through independent HIA/native consumers."""
from __future__ import annotations

import copy
import ctypes
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.ast import Type
from hepta.hia_program import HIAProgramRejected, execute_program, verify_program
from hepta.hia_program_source import (HIAProgramSourceRejected, lower_program,
                                      lower_source, lower_c_multi_owner, source_report)
from hepta.parser import parse
from hepta.executable_core_qualify import QUALIFICATION_SOURCE, qualification_cases

ROOT = Path(__file__).resolve().parents[1]
CLANG = os.environ.get("CLANG") or shutil.which("clang")
CXX = os.environ.get("CLANGXX") or (str(Path(CLANG).with_name("clang++")) if CLANG else None)
CC = os.environ.get("CC") or shutil.which("cc")


def database(directory, fixture=None):
    fixture = fixture or ROOT / "examples/hia_migration"
    path = directory / "compile_commands.json"
    path.write_text(json.dumps([{"directory": str(fixture), "file": "paired_bytes.c",
        "arguments": ["clang", "-std=c11", "-I.", "-c", "paired_bytes.c", "-o", "paired_bytes.o"]}]))
    return path


def expected_pair(left, right, seed, early=0):
    if not left or not right:
        return 0
    if early:
        return 2000
    return sum((i + seed) % 251 for i in range(left)) + sum(((i + seed) % 251) ^ 90 for i in range(right))


class HIASourceTests(unittest.TestCase):
    def test_standalone_execution_never_reparses_or_reads_source(self):
        program = parse('export "C" fn f(x:u64)->u64 effects{panic}{return x+7;}')
        program.source = "not Hepta source: the AST is the compiler input"
        core = lower_program(program)
        with patch("hepta.parser.parse", side_effect=AssertionError("source execution forbidden")):
            decoded = verify_program(core.canonical_bytes)
            self.assertEqual(execute_program(decoded, "f", [9])["result"], 16)
        self.assertFalse(execute_program(core, "f", [1])["source_used"])

    def test_full_existing_integer_owner_corpus_has_explicit_cfg(self):
        from hepta.executable_core import lower_executable_core, verify_executable_core
        from hepta.executable_core_runtime import execute_verified_core
        core = lower_source(QUALIFICATION_SOURCE)
        reference = lower_executable_core(parse(QUALIFICATION_SOURCE))
        verify_executable_core(reference, source=QUALIFICATION_SOURCE)
        for case in qualification_cases():
            with self.subTest(case=case):
                actual = execute_program(core, case["function"], case["arguments"])
                expected = execute_verified_core(reference, case["function"], case["arguments"])
                self.assertEqual(actual["result"], expected["result"])
                self.assertEqual(actual["resources"]["live_owners"], 0)
                self.assertEqual(actual["resources"]["loans_started"], actual["resources"]["loans_ended"])
        ops = {i["op"] for f in core.as_dict()["functions"] for b in f["blocks"] for i in b["ops"]}
        self.assertTrue({"call", "borrow.read", "borrow.mut", "owner.move", "owner.drop", "buffer.try_new"} <= ops)

    def test_result_return_consumes_inactive_empty_owner(self):
        source = '''
        fn make(n:usize)->Result<Buffer<u8>,u8> effects{alloc,block,panic}{
            if n==0{return Result::Err(7);}
            let value=buffer(n);return Result::Ok(move value);
        }
        export "C" fn run(n:usize)->u64 effects{alloc,block,panic}{
            let result=make(n);
            match move result {
                Result::Err(code)=>{return code as u64;},
                Result::Ok(owner)=>{let size=len(owner);drop(move owner);return size as u64;},
            }
        }'''
        core = lower_source(source)
        for n, expected in ((0, 7), (5, 5)):
            report = execute_program(core, "run", [n])
            self.assertEqual(report["result"], expected)
            self.assertEqual(report["resources"]["allocations"], bool(n))
            self.assertEqual(report["resources"]["live_owners"], 0)

    def test_second_failure_drops_first_owner_and_failed_empty_owner(self):
        core = lower_source(QUALIFICATION_SOURCE)
        report = execute_program(core, "second_allocation", [11], allocation_fail_at=2)
        self.assertEqual(report["result"], 101)
        self.assertEqual(report["resources"]["allocations"], 1)
        self.assertEqual(report["resources"]["frees"], 1)
        self.assertEqual(report["resources"]["owners_created"], report["resources"]["owners_dropped"])

    def test_scalar_record_mutation_and_copy_are_not_aliased(self):
        source = '''struct Pair{a:u64,b:u32}
        fn make(a:u64)->Pair effects{}{return Pair{a:a,b:2};}
        fn update(p:mut Pair,n:u64)->u64 effects{panic,write}{p.a=p.a+n;return p.a;}
        export "C" fn run(n:u64)->u64 effects{panic,write}{
            let mut p=make(n);let old=p;let first=update(mut p,3);
            if n<10{update(mut p,5);}else{update(mut p,7);}
            return first+p.a+old.a;
        }'''
        core = lower_source(source)
        self.assertEqual(execute_program(core, "run", [2])["result"], 17)
        self.assertEqual(execute_program(core, "run", [20])["result"], 73)

    def test_nested_short_circuit_preserves_mutable_argument_updates(self):
        source = '''fn bump(x:mut u64)->bool effects{panic,write}{x=x+1;return x>1;}
        export "C" fn run(n:u64)->u64 effects{panic,write}{
            let mut x=n;
            if n==0 || (bump(mut x) && bump(mut x)){x=x+10;}
            return x;
        }'''
        core = lower_source(source)
        for n, expected in ((0, 10), (1, 13), (9, 21)):
            self.assertEqual(execute_program(core, "run", [n])["result"], expected)

    def test_assertion_lowers_to_a_supported_explicit_trap(self):
        from hepta.hia_program_runtime import HIAProgramTrap
        core = lower_source('fn f(n:u64)->u64 effects{panic}{assert(n>0);return n;}')
        self.assertEqual(execute_program(core, "f", [3])["result"], 3)
        with self.assertRaises(HIAProgramTrap) as caught:
            execute_program(core, "f", [0])
        self.assertEqual(caught.exception.code, "user")
        self.assertEqual(caught.exception.report["status"], "trapped")

    def test_owned_record_and_returned_projection_are_executable(self):
        source = (ROOT / "examples/cpp/owned_migration/expected.hepta").read_text()
        core = lower_source(source)
        for args, expected in (([4, 5, 0, False, False], 194),
                               ([4, 5, 1, False, False], 14),
                               ([4, 5, 9, False, False], 2003),
                               ([4, 5, 0, False, True], 2002),
                               ([4, 5, 0, True, False], 1002)):
            report = execute_program(core, "run_owned", args)
            self.assertEqual(report["result"], expected)
            self.assertEqual(report["resources"]["live_owners"], 0)
        report = source_report(source)
        self.assertIn({"name": "OwnedBytes_data", "status": "inlined_borrow_projection"}, report["functions"])

    def test_aliased_mutable_call_rejects_in_standalone_resource_checker(self):
        source = '''fn f(a:mut Buffer<u8>,b:mut Buffer<u8>)->Unit effects{}{}
        fn bad()->Unit effects{alloc,block,panic}{let mut b=buffer(1);f(mut b,mut b);drop(move b);}'''
        with self.assertRaises((HIAProgramRejected, HIAProgramSourceRejected)):
            lower_source(source)

    def test_scalarized_aliases_reject_and_disjoint_fields_preserve_updates(self):
        source = '''fn f(a:mut u64,b:mut u64)->Unit effects{write}{a=1;b=2;}
        fn bad()->u64 effects{write}{let mut n:u64=0;f(mut n,mut n);return n;}'''
        with self.assertRaises(HIAProgramSourceRejected):
            lower_source(source)
        source = '''struct Pair{left:u64,right:u64}
        fn f(a:mut u64,b:mut u64)->Unit effects{write}{a=1;b=2;}
        fn run()->u64 effects{write,panic}{let mut p=Pair{left:0,right:0};
            f(mut p.left,mut p.right);return p.left*10+p.right;}'''
        self.assertEqual(execute_program(lower_source(source), "run", [])["result"], 12)

    def test_closed_generic_owner_record_result_instances_are_real_hia(self):
        source = (ROOT / "examples/hia_migration/generic_owners.hepta").read_text()
        core = lower_source(source)
        for n, ok, expected in ((0, False, 19), (7, False, 19), (0, True, 23), (7, True, 30)):
            report = execute_program(core, "probe", [n, ok])
            self.assertEqual(report["result"], expected)
            self.assertEqual(report["resources"]["live_owners"], 0)
            self.assertEqual(report["resources"]["loans_started"], report["resources"]["loans_ended"])
        self.assertEqual(execute_program(core, "probe", [7, True], allocation_fail_at=1)["result"], 1001)
        inventory = source_report(source)["specializations"]
        self.assertEqual(len([row for row in inventory if row["kind"] == "record"]), 1)
        self.assertEqual(len([row for row in inventory if row["status"] == "lowered"]), 3)
        self.assertTrue(all(not fn["name"] in {"forward", "dispose", "finish", "view"}
                            for fn in core.as_dict()["functions"]))

    def test_generic_copy_recursion_is_specialized_and_type_growth_rejects(self):
        source = '''struct Box<T>{value:T}
        fn repeat<T:Copy>(value:T,count:u64)->T effects{panic}{
            if count==0{return value;}return repeat::<T>(value,count-1);}
        fn run(n:u64)->u64 effects{panic}{let x=repeat::<Box<u64>>(Box{value:n},3);return x.value;}'''
        self.assertEqual(execute_program(lower_source(source), "run", [42])["result"], 42)
        growing = '''struct Box<T>{value:T}
        fn grow<T:Copy>(value:T)->Unit effects{}{grow::<Box<T>>(Box{value:value});}
        fn run()->Unit effects{}{grow::<u64>(1);}'''
        with self.assertRaisesRegex(HIAProgramSourceRejected, "specialization.*limit|specialization.*budget"):
            lower_source(growing)

    def test_removed_drop_cannot_be_resealed_into_valid_hia(self):
        core = lower_source('fn f()->u64 effects{alloc,block,panic}{let b=buffer(3);drop(move b);return 7;}')
        changed = core.as_dict()
        for block in changed["functions"][0]["blocks"]:
            block["ops"] = [op for op in block["ops"] if op["op"] != "owner.drop"]
        with self.assertRaises(HIAProgramRejected):
            verify_program(changed)

    def test_unmodeled_source_never_falls_back_to_foreign_or_rust_execution(self):
        for source in ('fn f(x:f64)->f64 effects{}{return x;}',
                       'extern "C" fn old(x:u64)->u64 effects{ffi};',
                       'repr(C) struct X{a:u64} export "C" fn f(x:X)->X effects{}{return x;}'):
            with self.subTest(source=source), self.assertRaises(HIAProgramSourceRejected):
                lower_source(source)


@unittest.skipUnless(CLANG and CXX and CC, "Clang C/C++ frontend and a native C compiler required")
class HIAMigrationTests(unittest.TestCase):
    def test_c_multi_owner_structural_translation_and_failure_cleanup(self):
        with tempfile.TemporaryDirectory() as td:
            report = lower_c_multi_owner(database(Path(td)), clang=CLANG)
            self.assertTrue(report["declaration_inventory_complete"])
            self.assertEqual(report["active_project_declarations"], 4)
            self.assertEqual(report["owners_lowered"], 2)
            core = report["program"]
            for left, right, seed, early in ((0, 9, 5, 0), (2, 3, 249, 0), (17, 31, 255, 1)):
                result = execute_program(core, "c_hia_paired_bytes", [left, right, seed, early])
                self.assertEqual(result["result"], expected_pair(left, right, seed, early))
                self.assertEqual(result["resources"]["allocations"], 2 if left and right else 0)
                self.assertEqual(result["resources"]["live_owners"], 0)
            for failure in (1, 2):
                result = execute_program(core, "c_hia_paired_bytes", [17, 31, 255, 0], allocation_fail_at=failure)
                self.assertEqual(result["result"], 1000 + failure)
                self.assertEqual(result["resources"]["allocations"], failure - 1)
                self.assertEqual(result["resources"]["frees"], failure - 1)

    def test_changed_c_algorithm_is_translated_and_missing_cleanup_rejects(self):
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td)
            fixture = directory / "fixture"; fixture.mkdir()
            for name in ("paired_bytes.c", "paired_bytes.h"):
                (fixture / name).write_bytes((ROOT / "examples/hia_migration" / name).read_bytes())
            db = database(directory, fixture)
            original = lower_c_multi_owner(db, clang=CLANG)
            source = (fixture / "paired_bytes.c").read_text()
            (fixture / "paired_bytes.c").write_text(source.replace("index + seed", "index ^ seed"))
            changed = lower_c_multi_owner(db, clang=CLANG)
            self.assertNotEqual(original["program"].sha256, changed["program"].sha256)
            args = [9, 7, 249, 0]
            expected = sum((i ^ 249) % 251 for i in range(9)) + sum(((i ^ 249) % 251) ^ 90 for i in range(7))
            self.assertEqual(execute_program(changed["program"], "c_hia_paired_bytes", args)["result"], expected)
            (fixture / "paired_bytes.c").write_text(source.replace("free(left);", "/* deliberately omitted release */", 1))
            with self.assertRaises(HIAProgramSourceRejected):
                lower_c_multi_owner(db, clang=CLANG)

    def test_existing_cpp_class_migration_and_module_resolution_reach_hia(self):
        from hepta.cpp_class_migrate import migrate_cpp_class
        from hepta.modules import load_project
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td)
            report = migrate_cpp_class(ROOT / "examples/cpp/class_migration/scalar_state.cpp",
                                       directory / "scalar_state.hepta", clangxx=CXX)
            self.assertTrue(report["ok"], report)
            (directory / "consumer.hepta").write_bytes((ROOT / "examples/cpp/class_migration/consumer.hepta").read_bytes())
            core = lower_program(load_project(directory / "consumer.hepta").program)
            self.assertEqual(execute_program(core, "word_trace", [4294967295, 1, 17, 3])["result"], 4294967275)
            self.assertEqual(execute_program(core, "balance_trace", [-11, -10, 10])["result"], -10)
            self.assertEqual(execute_program(core, "state_guard", [1, 2, 3, 4, 5, 6, -10, 10, 7])["result"], 0)

    def test_native_llvm_consumes_only_lowered_hia_for_complete_corpus(self):
        from hepta.hia_program_llvm import build_program_native
        core = lower_source(QUALIFICATION_SOURCE)
        kinds = {"u8": ctypes.c_uint8, "i8": ctypes.c_int8, "u16": ctypes.c_uint16,
                 "i16": ctypes.c_int16, "u32": ctypes.c_uint32, "i32": ctypes.c_int32,
                 "u64": ctypes.c_uint64, "i64": ctypes.c_int64, "usize": ctypes.c_size_t,
                 "isize": ctypes.c_ssize_t, "bool": ctypes.c_bool}
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "hia.so"
            with patch("hepta.parser.parse", side_effect=AssertionError("backend cannot reparse source")):
                receipt = build_program_native(core, output, clang=CLANG)
            self.assertTrue(receipt["ok"])
            library = ctypes.CDLL(str(output))
            signatures = {fn["name"]: fn for fn in core.as_dict()["functions"]}
            for case in qualification_cases():
                signature = signatures[case["function"]]
                function = getattr(library, case["function"])
                function.argtypes = [kinds[p["type"]] for p in signature["params"]]
                function.restype = kinds[signature["returns"][0]]
                self.assertEqual(function(*case["arguments"]),
                                 execute_program(core, case["function"], case["arguments"])["result"])

    def test_generic_owned_instances_compile_directly_to_native_llvm(self):
        from hepta.hia_program_llvm import build_program_native
        core = lower_source((ROOT / "examples/hia_migration/generic_owners.hepta").read_text())
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "generic.so"
            with patch("hepta.parser.parse", side_effect=AssertionError("source unavailable after lowering")):
                build_program_native(core.canonical_bytes, output, clang=CLANG)
            library = ctypes.CDLL(str(output))
            probe = library.probe
            probe.argtypes, probe.restype = [ctypes.c_size_t, ctypes.c_bool], ctypes.c_uint64
            for n, ok in ((0, False), (7, False), (0, True), (7, True), (4096, True)):
                self.assertEqual(probe(n, ok), execute_program(core, "probe", [n, ok])["result"])


if __name__ == "__main__":
    unittest.main()
