"""Allocation length normalization preserves independently submitted Core.

These programs intentionally do not all inspect try_new's success flag, and
their indices need not come from a source-language loop.  The native guard must
still reject an empty failed owner and an unrelated/out-of-range index.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.clang_capture import run_bounded
from hepta.hia_program import execute_program, verify_program
from hepta.hia_program_runtime import HIAProgramTrap
from hepta.hia_program_llvm import compile_program_llvm, emit_program_llvm
from tools.qualify_hia_program import block, branch, function, operation, ret


CLANG = os.environ.get("CLANG", "/usr/lib/llvm-20/bin/clang")


def allocation_invariant_program():
    functions = []
    for name, returns, value in (("try_length", ["usize"], "length"),
                                 ("try_success", ["bool"], "ok")):
        functions.append(function(name, [("size", "usize")], returns, ["alloc"], [
            block("entry", [("size", "usize")], [
                operation("buffer.try_new", ["size"], [("owner", "buffer"), ("ok", "bool")]),
                operation("buffer.len", ["owner"], [("length", "usize")]),
                operation("owner.drop", ["owner"]),
            ], ret(value)),
        ]))
    functions.append(function("forward", [("input", "buffer")], ["buffer"], [], [
        block("entry", [("input", "buffer")], [
            operation("owner.move", ["input"], [("output", "buffer")]),
        ], ret("output")),
    ]))
    for name, op in (("try_probe", "buffer.try_new"), ("new_probe", "buffer.new")):
        outputs = [("created", "buffer")] + ([("ok", "bool")] if op == "buffer.try_new" else [])
        functions.append(function(name, [("size", "usize"), ("index", "usize")], ["u8"],
                                  ["alloc", "read", "trap"], [
            block("entry", [("size", "usize"), ("index", "usize")], [
                operation(op, ["size"], outputs),
                operation("call", ["created"], [("owner", "buffer")], function="forward"),
                operation("borrow.read", ["owner"], [("view", "readbuf")]),
                operation("buffer.load", ["view", "index"], [("byte", "u8")]),
                operation("loan.end", ["view"]), operation("owner.drop", ["owner"]),
            ], ret("byte")),
        ]))
    parameters = [("left_size", "usize"), ("right_size", "usize"),
                  ("index", "usize"), ("choose_left", "bool")]
    branches = []
    for label, prefix, chosen in (("left", "l", "a"), ("right", "r", "b")):
        branches.append(block(label, [(prefix + "a", "buffer"), (prefix + "b", "buffer"),
                                      (prefix + "i", "usize")], [
            operation("borrow.read", [prefix + chosen], [(prefix + "view", "readbuf")]),
            operation("buffer.load", [prefix + "view", prefix + "i"], [(prefix + "byte", "u8")]),
            operation("loan.end", [prefix + "view"]),
            operation("owner.drop", [prefix + "a"]), operation("owner.drop", [prefix + "b"]),
        ], ret(prefix + "byte")))
    functions.append(function("two_owners", parameters, ["u8"], ["alloc", "read", "trap"], [
        block("entry", parameters, [
            operation("buffer.try_new", ["left_size"], [("first", "buffer"), ("first_ok", "bool")]),
            operation("buffer.try_new", ["right_size"], [("second", "buffer"), ("second_ok", "bool")]),
        ], branch("choose_left", "left", ["first", "second", "index"],
                  "right", ["first", "second", "index"])),
        *branches,
    ]))
    return {"schema": "hepta.hia.program.v1", "module": "allocation_invariant", "functions": functions}


class AllocationInvariantReferenceTests(unittest.TestCase):
    def test_independent_core_retains_failed_owner_length_and_success_distinction(self):
        core = verify_program(allocation_invariant_program())
        for size in (0, 1, 2, 7, 31, 4093):
            self.assertEqual(execute_program(core, "try_length", [size])["result"], size)
            self.assertIs(execute_program(core, "try_success", [size])["result"], True)
        for size in (1, 17, 12281):
            self.assertEqual(execute_program(core, "try_length", [size], allocation_fail_at=1)["result"], 0)
            self.assertIs(execute_program(core, "try_success", [size], allocation_fail_at=1)["result"], False)
        for size in (1 << 63, (1 << 64) - 1):
            self.assertEqual(execute_program(core, "try_length", [size])["result"], 0)
            self.assertIs(execute_program(core, "try_success", [size])["result"], False)

    def test_failed_and_unrelated_indices_still_trap_in_reference(self):
        core = verify_program(allocation_invariant_program())
        for name, args, failure in (("try_probe", [0, 0], None), ("try_probe", [7, 7], None),
                ("try_probe", [12281, 0], 1), ("try_probe", [1 << 63, 0], None),
                ("new_probe", [7, (1 << 64) - 1], None),
                ("two_owners", [1, 2, 1, True], None), ("two_owners", [17, 2, 0, True], 1)):
            with self.subTest(name=name, args=args, failure=failure):
                with self.assertRaises(HIAProgramTrap) as trapped:
                    execute_program(core, name, args, allocation_fail_at=failure)
                self.assertEqual(trapped.exception.code, "bounds")
        self.assertEqual(execute_program(core, "two_owners", [1, 2, 1, False])["result"], 0)
        self.assertEqual(execute_program(core, "two_owners", [17, 2, 1, False], allocation_fail_at=1)["result"], 0)
        self.assertEqual(execute_program(core, "two_owners", [2, 17, 1, True], allocation_fail_at=2)["result"], 0)


_DRIVER = r"""
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void *__real_malloc(size_t); void *__real_calloc(size_t,size_t); void __real_free(void *);
static void *live[32];
static size_t allocations, frees, refusals;
static void *remember(void *p) {
    if(p) { for(size_t i=0;i<32;i++) if(!live[i]) {live[i]=p;allocations++;return p;} exit(80); }
    return p;
}
void *__wrap_malloc(size_t n) {
    if(n==12281){refusals++;return NULL;}
    void *p=__real_malloc(n); if(p)memset(p,0xa7,n); return remember(p);
}
void *__wrap_calloc(size_t count,size_t n) {
    if(count==1 && n==12281){refusals++;return NULL;}
    return remember(__real_calloc(count,n));
}
void __wrap_free(void *p) {
    if(p) { size_t i;for(i=0;i<32 && live[i]!=p;i++); if(i==32)exit(81);live[i]=NULL;frees++; }
    __real_free(p);
}
size_t try_length(size_t); bool try_success(size_t);
uint8_t try_probe(size_t,size_t); uint8_t new_probe(size_t,size_t);
uint8_t two_owners(size_t,size_t,size_t,bool);
int main(int argc,char **argv) {
    unsigned mode=argc>1?(unsigned)strtoul(argv[1],NULL,10):0;
    switch(mode) {
      case 1:return try_probe(0,0);
      case 2:return try_probe(7,7);
      case 3:return try_probe(12281,0);
      case 4:return try_probe(UINT64_C(9223372036854775808),0);
      case 5:return new_probe(7,SIZE_MAX);
      case 6:return new_probe(12281,0);
      case 7:return new_probe(UINT64_C(9223372036854775808),0);
      case 8:return two_owners(1,2,1,true);
      case 9:return two_owners(12281,2,0,true);
      case 10:return two_owners(2,12281,0,false);
    }
    const size_t sizes[]={0,1,2,7,31,4093};
    for(size_t i=0;i<sizeof(sizes)/sizeof(sizes[0]);i++) {
        size_t n=sizes[i];if(try_length(n)!=n || !try_success(n))return 82;
        if(n && (try_probe(n,n-1)!=0 || new_probe(n,n-1)!=0))return 83;
    }
    const size_t failed[]={12281,UINT64_C(9223372036854775808),SIZE_MAX};
    for(size_t i=0;i<sizeof(failed)/sizeof(failed[0]);i++)
        if(try_length(failed[i])!=0 || try_success(failed[i]))return 84;
    if(two_owners(1,2,1,false)!=0 || two_owners(12281,2,1,false)!=0
       || two_owners(2,12281,1,true)!=0)return 85;
    for(size_t i=0;i<32;i++)if(live[i])return 86;
    printf("%zu %zu %zu\n",allocations,frees,refusals);
    return allocations!=24 || frees!=24 || refusals!=4;
}
"""


@unittest.skipUnless(shutil.which(CLANG), "actual Clang 20+ toolchain required")
class AllocationInvariantNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="hia-allocation-invariant-")
        cls.directory = Path(cls.temporary.name)
        cls.core = verify_program(allocation_invariant_program())
        cls.ir = emit_program_llvm(cls.core)
        cls.object = cls.directory / "program.o"
        compile_program_llvm(cls.ir, program=cls.core, output=cls.object, clang=CLANG, kind="object")
        cls.driver = cls.directory / "driver"
        source = cls.directory / "driver.c"
        source.write_text(_DRIVER)
        result = run_bounded([CLANG, "-std=c11", "-O2", "-Werror=implicit-function-declaration",
                              str(source), str(cls.object), "-Wl,--wrap=calloc", "-Wl,--wrap=malloc",
                              "-Wl,--wrap=free", "-o", str(cls.driver)])
        if result.returncode:
            raise AssertionError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_success_zero_oversize_actual_refusal_and_independent_owner_lengths(self):
        result = run_bounded([str(self.driver)])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), "24 24 4")

    def test_invalid_core_indices_and_failed_owners_abort_in_actual_native_children(self):
        for mode in range(1, 11):
            with self.subTest(mode=mode):
                result = run_bounded([str(self.driver), str(mode)])
                self.assertEqual(result.returncode, -6, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
