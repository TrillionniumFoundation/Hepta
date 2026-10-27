"""Actual standalone Core/LLVM behavior, ABI, traps and allocation cleanup."""
from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import ctypes
import json
import os
from pathlib import Path
import random
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta.clang_capture import run_bounded
from hepta.hia_program import execute_program, verify_program
from hepta.hia_program_runtime import HIAProgramTrap
from hepta.hia_program_llvm import (
    HIAProgramLLVMRejected, TARGET_AARCH64, _can_elide_zero_initialization,
    build_program_native, compile_program_llvm, emit_program_llvm,
)


CLANG = os.environ.get("CLANG", "/usr/lib/llvm-20/bin/clang")


from tools.qualify_hia_program import qualification_program, ALLOCATOR_DRIVER, _CTYPES


@unittest.skipUnless(shutil.which(CLANG), "actual Clang 20+ native toolchain required")
class StandaloneHIANativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="hia-program-tests-")
        cls.path = Path(cls.directory.name)
        cls.document = qualification_program()
        cls.program = verify_program(cls.document)
        cls.ir = emit_program_llvm(cls.program)
        cls.library_path = cls.path / "program.so"
        with patch("hepta.pipeline.analyze", side_effect=AssertionError("a source/Rust gate must not execute")):
            cls.receipt = compile_program_llvm(cls.ir, program=cls.program,
                                              output=cls.library_path, clang=CLANG)
        cls.library = ctypes.CDLL(str(cls.library_path))
        cls.functions = {fn["name"]: fn for fn in cls.document["functions"]}

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def call(self, name, args):
        function = self.functions[name]
        entry = getattr(self.library, name)
        entry.argtypes = [_CTYPES[p["type"]] for p in function["params"]]
        entry.restype = _CTYPES[function["returns"][0]]
        return entry(*args)

    def test_standalone_block_arguments_loops_and_internal_calls_execute(self):
        for n in (0, 1, 2, 3, 7, 31, 128, 1024):
            self.assertEqual(self.call("sum_to", [n]), n * (n - 1) // 2)
            self.assertEqual(self.call("invoke_sum", [n]), n * (n - 1))
        self.assertTrue(self.receipt["claims"]["standalone_core_reverified"])
        self.assertFalse(self.receipt["claims"]["rust_reference_required"])
        self.assertFalse(self.receipt["claims"]["source_ast_required"])
        self.assertFalse(self.receipt["claims"]["native_execution_qualified"])
        self.assertNotIn("transfer", self.receipt["exports"])

    def test_checked_widths_wrapping_shifts_division_and_narrow_c_abi(self):
        rng = random.Random(1607)
        for typ in ("i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64"):
            bits = int(typ[1:]); signed = typ[0] == "i"; mask = (1 << bits) - 1
            low, high = (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if signed else (0, mask)
            def narrow(value):
                value &= mask
                return value - (1 << bits) if signed and value >= (1 << (bits - 1)) else value
            cases = [(low, high), (high, low), (0, 1), (high, 1), (low, 1)]
            cases += [(rng.randint(low, high), rng.randint(low, high)) for _ in range(12)]
            for a, b in cases:
                for operation_name, value in (("add", a + b), ("sub", a - b), ("mul", a * b)):
                    self.assertEqual(self.call("int_" + operation_name + "_wrap_" + typ, [a, b]), narrow(value))
                for action, value in (("and", a & b), ("or", a | b), ("xor", a ^ b)):
                    self.assertEqual(self.call("bit_" + action + "_" + typ, [a, b]), narrow(value))
                cast = a & 255
                self.assertEqual(self.call("cast_i8_" + typ, [a]), cast - 256 if cast >= 128 else cast)
                if b and not (signed and a == low and b == -1):
                    quotient = abs(a) // abs(b)
                    if (a < 0) != (b < 0): quotient = -quotient
                    self.assertEqual(self.call("int_div_checked_" + typ, [a, b]), quotient)
                    self.assertEqual(self.call("int_rem_checked_" + typ, [a, b]), a - quotient * b)
                for count in (0, 1, bits - 1):
                    self.assertEqual(self.call("int_shl_checked_" + typ, [a, count]), narrow(a << count))
                    self.assertEqual(self.call("int_shr_checked_" + typ, [a, count]), a >> count)

    def test_owned_allocation_moves_loans_and_normal_error_cleanup(self):
        for n in (0, 1, 7, 255, 4096):
            for byte in (0, 1, 7, 255):
                self.assertEqual(self.call("lifecycle", [n, byte]), n + byte)
        self.assertEqual(self.call("lifecycle", [(1 << 64) - 1, 17]), 99)

    def test_independent_core_interpreter_matches_real_native_cfg_and_resources(self):
        cases = []
        cases += [("sum_to", [n]) for n in (0, 1, 7, 128, 1024)]
        cases += [("invoke_sum", [n]) for n in (0, 1, 7, 128)]
        cases += [("lifecycle", [n, byte]) for n in (0, 1, 255, 4096, (1 << 64) - 1) for byte in (0, 7, 255)]
        cases += [("fill_sum", [n, byte]) for n in (0, 1, 7, 128) for byte in (0, 7, 255)]
        cases += [("scalar_mix", [a, b, choose]) for a, b in ((-37, 5), (0, -1), (2147483647, 1), (-2147483648, 0)) for choose in (False, True)]
        cases += [("bool_gate", [a, b]) for a in (False, True) for b in (False, True)]
        cases += [("tuple_call", [a, b]) for a, b in ((0, 0), (3, 7), (7, 3), ((1 << 64) - 1, 19))]
        for typ in ("i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64"):
            bits = int(typ[1:]); signed = typ[0] == "i"
            low, high = (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if signed else (0, (1 << bits) - 1)
            for action in ("add", "sub", "mul"):
                for a, b in ((low, high), (high, 1), (0, 0)):
                    cases.append(("int_" + action + "_wrap_" + typ, [a, b]))
            for action in ("div", "rem", "shl", "shr"):
                cases.append(("int_" + action + "_checked_" + typ, [high, 1]))
            for action in ("and", "or", "xor"):
                cases.append(("bit_" + action + "_" + typ, [low, high]))
            cases.append(("cast_i8_" + typ, [high]))
        for name, args in cases:
            with self.subTest(name=name, arguments=args):
                reference = execute_program(self.program, name, args)
                self.assertEqual(self.call(name, args), reference["result"])
                self.assertEqual(reference["resources"]["live_owners"], 0)
                self.assertEqual(reference["resources"]["live_local_loans"], 0)
        self.assertNotIn("read_one", self.receipt["exports"])
        self.assertNotIn("pair", self.receipt["exports"])
        noop = self.library.no_result; noop.argtypes = []; noop.restype = None
        self.assertIsNone(noop())

    def test_reference_failure_injection_and_actual_allocator_observation_share_outcome(self):
        reference = execute_program(self.program, "lifecycle", [12281, 13], allocation_fail_at=2)
        self.assertEqual(reference["result"], 99)
        self.assertEqual(reference["resources"]["allocation_attempts"], 2)
        self.assertEqual(reference["resources"]["allocations"], 1)
        self.assertEqual(reference["resources"]["frees"], 1)
        self.assertEqual(reference["resources"]["live_bytes"], 0)
        for name, args, code in (("overflow_trap", [255], "overflow"), ("bounds_trap", [1], "bounds")):
            with self.assertRaises(HIAProgramTrap) as failure:
                execute_program(self.program, name, args)
            self.assertEqual(failure.exception.code, code)

    def test_native_allocator_null_and_live_address_observer(self):
        with tempfile.TemporaryDirectory(dir=self.path) as temporary:
            folder = Path(temporary); obj = folder / "program.o"
            receipt = compile_program_llvm(self.ir, program=self.program, output=obj, clang=CLANG, kind="object")
            self.assertEqual(receipt["kind"], "object")
            source, binary = folder / "allocator.c", folder / "allocator"
            source.write_text(ALLOCATOR_DRIVER)
            compile_result = run_bounded([CLANG, "-O2", str(source), str(obj), "-Wl,--wrap=calloc", "-Wl,--wrap=free", "-o", str(binary)])
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            executed = run_bounded([str(binary)])
            self.assertEqual(executed.returncode, 0, executed.stderr + executed.stdout)
            self.assertEqual(executed.stdout.strip(), "7 7 0 1")

    def test_allocator_observer_rejects_compiled_leak_with_correct_return_values(self):
        with tempfile.TemporaryDirectory(dir=self.path) as temporary:
            folder = Path(temporary); source = folder / "wrong.ll"
            wrong = "\n".join(line for line in self.ir.text.splitlines() if "call void @free(" not in line) + "\n"
            self.assertNotEqual(wrong, self.ir.text)
            source.write_text(wrong)
            obj, driver, binary = folder / "wrong.o", folder / "allocator.c", folder / "wrong"
            driver.write_text(ALLOCATOR_DRIVER)
            compile_result = run_bounded([CLANG, "-O3", "-c", "-x", "ir", str(source), "-o", str(obj)])
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            linked = run_bounded([CLANG, "-O2", str(driver), str(obj), "-Wl,--wrap=calloc", "-Wl,--wrap=free", "-o", str(binary)])
            self.assertEqual(linked.returncode, 0, linked.stderr)
            executed = run_bounded([str(binary)])
            self.assertEqual(executed.returncode, 91, executed.stdout + executed.stderr)
            self.assertEqual(executed.stdout.strip(), "7 0 7 1")

    def test_checked_overflow_and_bounds_abort_in_actual_child_processes(self):
        with tempfile.TemporaryDirectory(dir=self.path) as temporary:
            folder = Path(temporary)
            for name, declaration, expression in (
                ("overflow", "uint8_t overflow_trap(uint8_t);", "overflow_trap(255)"),
                ("bounds", "uint8_t bounds_trap(size_t);", "bounds_trap(1)"),
            ):
                source, binary = folder / (name + ".c"), folder / name
                source.write_text("#include <stdint.h>\n#include <stddef.h>\n" + declaration + "\nint main(void){return " + expression + ";}\n")
                result = run_bounded([CLANG, str(source), str(self.library_path), "-Wl,-rpath," + str(self.path), "-o", str(binary)])
                self.assertEqual(result.returncode, 0, result.stderr)
                child = run_bounded([str(binary)])
                self.assertEqual(child.returncode, -6)

    def test_rehashed_wrong_llvm_is_rejected_before_native_tool_runs(self):
        wrong = self.ir.text + "define i32 @extra(){ret i32 9}\n"
        forged = replace(self.ir, text=wrong, sha256=sha256(wrong.encode()).hexdigest())
        with patch("hepta.hia_program_llvm.run_bounded", side_effect=AssertionError("native compiler must not run")):
            with self.assertRaisesRegex(HIAProgramLLVMRejected, "ORIGIN"):
                compile_program_llvm(forged, program=self.program, output=self.path / "forged.so", clang=CLANG)
        self.assertFalse((self.path / "forged.so").exists())

    def test_existing_artifact_is_not_replaced(self):
        before = self.library_path.read_bytes()
        with self.assertRaisesRegex(HIAProgramLLVMRejected, "new output"):
            compile_program_llvm(self.ir, program=self.program, output=self.library_path, clang=CLANG)
        self.assertEqual(self.library_path.read_bytes(), before)

    def test_aarch64_uses_target_abi_and_actual_checked_object(self):
        ir = emit_program_llvm(self.program, target=TARGET_AARCH64)
        self.assertIn('target triple = "aarch64-unknown-linux-gnu"', ir.text)
        self.assertIn("define i8 @cast_i8_u64(i64 %a0)", ir.text)
        self.assertNotIn("signext", ir.text)
        self.assertNotIn("zeroext", ir.text)
        self.assertNotIn("read_one", ir.exports)
        self.assertNotIn("pair", ir.exports)
        with tempfile.TemporaryDirectory(dir=self.path) as temporary:
            receipt = compile_program_llvm(ir, program=self.program, output=Path(temporary) / "aarch64.o",
                                           clang=CLANG, kind="object")
            self.assertEqual(receipt["target"], TARGET_AARCH64)
            self.assertFalse(receipt["claims"]["cross_target_execution_qualified"])

    def test_aarch64_requires_object_and_target_origin_before_compilation(self):
        arm = emit_program_llvm(self.program, target=TARGET_AARCH64)
        with patch("hepta.hia_program_llvm.run_bounded", side_effect=AssertionError("native compiler must not run")):
            with self.assertRaisesRegex(HIAProgramLLVMRejected, "relocatable"):
                compile_program_llvm(arm, program=self.program, output=self.path / "bad-arm.so", clang=CLANG)
            with self.assertRaisesRegex(HIAProgramLLVMRejected, "ORIGIN"):
                compile_program_llvm(replace(self.ir, target=TARGET_AARCH64), program=self.program,
                                     output=self.path / "forged-arm.o", clang=CLANG, kind="object")
            with self.assertRaisesRegex(HIAProgramLLVMRejected, "unsupported"):
                emit_program_llvm(self.program, target="riscv32-unknown-linux-gnu")

    def test_unread_allocation_keeps_zero_reads_null_guards_and_real_allocator_events(self):
        from tools.qualify_hia_program import block, constant, function, jump, operation, ret
        unused = function("unused_buffer", [("n", "usize")], ["u64"], ["alloc"], [
            block("entry", [("n", "usize")], [
                operation("buffer.try_new", ["n"], [("owner", "buffer"), ("ok", "bool")]),
                operation("buffer.len", ["owner"], [("length", "usize")]),
                operation("owner.drop", ["owner"]),
                operation("int.cast", ["length"], [("wide", "u64")], mode="wrap"),
                constant("error", "u64", 99),
                operation("select", ["ok", "wide", "error"], [("answer", "u64")]),
            ], ret("answer")),
        ])
        read = function("read_zero_bytes", [("n", "usize")], ["u8"], ["alloc", "read", "trap"], [
            block("entry", [("n", "usize")], [operation("buffer.new", ["n"], [("owner", "buffer")])],
                  jump("later", "owner")),
            block("later", [("later_owner", "buffer")], [
                constant("at", "usize", 0), operation("borrow.read", ["later_owner"], [("view", "readbuf")]),
                operation("buffer.load", ["view", "at"], [("byte", "u8")]),
                operation("loan.end", ["view"]), operation("owner.drop", ["later_owner"]),
            ], ret("byte")),
        ])
        infallible = function("new_unused", [("n", "usize")], ["u64"], ["alloc", "trap"], [
            block("entry", [("n", "usize")], [
                operation("buffer.new", ["n"], [("owner", "buffer")]),
                operation("buffer.len", ["owner"], [("length", "usize")]), operation("owner.drop", ["owner"]),
                operation("int.cast", ["length"], [("answer", "u64")], mode="wrap"),
            ], ret("answer")),
        ])
        core = verify_program({"schema": "hepta.hia.program.v1", "module": "unread_allocation", "functions": [unused, read, infallible]})
        self.assertTrue(_can_elide_zero_initialization(unused))
        self.assertFalse(_can_elide_zero_initialization(read))
        self.assertTrue(_can_elide_zero_initialization(infallible))
        self.assertEqual(execute_program(core, "read_zero_bytes", [17])["result"], 0)
        self.assertEqual(execute_program(core, "unused_buffer", [12281], allocation_fail_at=1)["result"], 99)
        driver = r"""
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
void *__real_malloc(size_t); void *__real_calloc(size_t,size_t); void __real_free(void *);
static void *addresses[8];
static size_t plain=0,zeroed=0,releases=0,live=0,refused=0;
static void *remember(void *p) {
  if(p){size_t i;for(i=0;i<8;i++)if(!addresses[i])break;
    if(i==8)exit(80);addresses[i]=p;live++;}return p;
}
void *__wrap_malloc(size_t n) {
  if(n==12281){refused++;return NULL;}
  void *p=__real_malloc(n);if(p){memset(p,0xa5,n);plain++;}return remember(p);
}
void *__wrap_calloc(size_t n,size_t width) {
  if(n==1 && width==12281){refused++;return NULL;}
  void *p=__real_calloc(n,width);if(p)zeroed++;return remember(p);
}
void __wrap_free(void *p) {
  if(p){size_t i;for(i=0;i<8;i++)if(addresses[i]==p)break;
    if(i==8)exit(81);addresses[i]=NULL;releases++;live--;}__real_free(p);
}
uint64_t unused_buffer(size_t); uint8_t read_zero_bytes(size_t); uint64_t new_unused(size_t);
int main(int argc,char **argv) {
  (void)argv;
  if(argc>1)return (int)new_unused(12281);
  if(unused_buffer(17)!=17 || unused_buffer(0)!=0 || unused_buffer(12281)!=99 || unused_buffer(SIZE_MAX)!=99)return 82;
  if(read_zero_bytes(17)!=0 || read_zero_bytes(17)!=0 || new_unused(17)!=17)return 83;
  printf("%zu %zu %zu %zu %zu\n",plain,zeroed,releases,live,refused);
  return plain!=2 || zeroed!=2 || releases!=4 || live!=0 || refused!=1;
}
"""
        with tempfile.TemporaryDirectory(dir=self.path) as temporary:
            folder = Path(temporary); obj, source, binary = folder / "program.o", folder / "driver.c", folder / "driver"
            compile_program_llvm(emit_program_llvm(core), program=core, output=obj, clang=CLANG, kind="object")
            source.write_text(driver)
            linked = run_bounded([CLANG, "-O2", str(source), str(obj), "-Wl,--wrap=malloc",
                                  "-Wl,--wrap=calloc", "-Wl,--wrap=free", "-o", str(binary)])
            self.assertEqual(linked.returncode, 0, linked.stderr)
            executed = run_bounded([str(binary)])
            self.assertEqual(executed.returncode, 0, executed.stdout + executed.stderr)
            self.assertEqual(executed.stdout.strip(), "2 2 4 0 1")
            self.assertEqual(run_bounded([str(binary), "trap"]).returncode, -6)

    def test_zero_initialization_elision_rejects_future_ops_types_and_terminators(self):
        from copy import deepcopy
        function = self.functions["sum_to"]
        self.assertTrue(_can_elide_zero_initialization(function))
        for name in ("buffer.load", "buffer.store", "call", "future.byte_operation"):
            changed = deepcopy(function)
            changed["blocks"][-1]["ops"].append({"op": name, "args": [], "out": [], "attrs": {}})
            self.assertFalse(_can_elide_zero_initialization(changed))
        for typ in ("buffer", "readbuf", "mutbuf", "future_resource"):
            changed = deepcopy(function); changed["params"][0]["type"] = typ
            self.assertFalse(_can_elide_zero_initialization(changed))
            changed = deepcopy(function); changed["returns"] = [typ]
            self.assertFalse(_can_elide_zero_initialization(changed))
        changed = deepcopy(function); changed["blocks"][-1]["term"]["op"] = "future_escape"
        self.assertFalse(_can_elide_zero_initialization(changed))


if __name__ == "__main__":
    unittest.main()
