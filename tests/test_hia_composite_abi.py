"""Nominal erasure does not widen the public scalar native ABI."""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_program import verify_program
from hepta.clang_capture import run_bounded
from hepta.hia_program_llvm import HIAProgramLLVMRejected, compile_program_llvm, emit_program_llvm
from tools.qualify_hia_program import block, function, operation, ret
from tests.test_hia_program_composite import enum_owner_program, stored_loan_program, task_program


CLANG = os.environ.get("CLANG", "/usr/lib/llvm-20/bin/clang")


def nominal_identity_program(name="Packet", field="contents"):
    return {"schema": "hepta.hia.composite.v1", "module": "nominal_abi",
            "types": [{"name": name, "kind": "record", "params": [],
                       "fields": [{"name": field, "type": "u64"}]}],
            "functions": [
                function("inspect_packet", [("packet", name)], ["u64"], [], [
                    block("entry", [("packet", name)], [
                        operation("record.get", ["packet"], [("value", "u64")], field=field),
                    ], ret("value")),
                ]),
                function("public_identity", [("argument", "u64")], ["u64"], [], [
                    block("entry", [("argument", "u64")], [
                        operation("record.make", ["argument"], [("made", name)]),
                        operation("call", ["made"], [("result", "u64")], function="inspect_packet"),
                    ], ret("result")),
                ]),
            ]}


class NominalNativeOriginTests(unittest.TestCase):
    def test_erased_scalar_record_parameter_is_not_an_external_entrypoint(self):
        core = verify_program(nominal_identity_program())
        self.assertEqual(core.scalar_entrypoints, frozenset({"public_identity"}))
        lowered = next(fn for fn in core.as_dict()["functions"] if fn["name"] == "inspect_packet")
        self.assertEqual([p["type"] for p in lowered["params"]], ["u64"])
        ir = emit_program_llvm(core)
        self.assertEqual(ir.exports, ("public_identity",))
        self.assertNotIn("@inspect_packet(", ir.text)
        self.assertEqual(ir.input_sha256, core.input_sha256)
        normalized = verify_program(core.canonical_bytes)
        self.assertIsNone(normalized.structured_bytes)
        self.assertEqual(normalized.scalar_entrypoints, core.scalar_entrypoints)
        self.assertEqual(emit_program_llvm(normalized).exports, ir.exports)
        self.assertEqual(emit_program_llvm(normalized).text, ir.text)

    def test_identical_normalized_core_does_not_allow_different_nominal_origin_receipt(self):
        original = verify_program(nominal_identity_program())
        changed = verify_program(nominal_identity_program("DistinctPacket", "different"))
        self.assertEqual(original.canonical_bytes, changed.canonical_bytes)
        self.assertNotEqual(original.input_sha256, changed.input_sha256)
        first, second = emit_program_llvm(original), emit_program_llvm(changed)
        self.assertEqual(first.text, second.text)
        self.assertNotEqual(first, second)
        with tempfile.TemporaryDirectory() as directory:
            with patch("hepta.hia_program_llvm.run_bounded", side_effect=AssertionError("native tool must not execute")):
                with self.assertRaisesRegex(HIAProgramLLVMRejected, "E_HIA_PROGRAM_ORIGIN"):
                    compile_program_llvm(first, program=changed, output=Path(directory) / "forged.so", clang=CLANG)


@unittest.skipUnless(shutil.which(CLANG), "actual Clang 20+ native toolchain required")
class NominalNativeExportsTests(unittest.TestCase):
    def test_actual_elf_has_only_original_scalar_entrypoint(self):
        core = verify_program(nominal_identity_program())
        ir = emit_program_llvm(core)
        with tempfile.TemporaryDirectory() as directory:
            library_path = Path(directory) / "program.so"
            receipt = compile_program_llvm(ir, program=core, output=library_path, clang=CLANG)
            self.assertEqual(receipt["exports"], ["public_identity"])
            self.assertEqual(receipt["input_sha256"], core.input_sha256)
            library = ctypes.CDLL(str(library_path))
            entry = library.public_identity
            entry.argtypes, entry.restype = [ctypes.c_uint64], ctypes.c_uint64
            for value in (0, 17, (1 << 64) - 1):
                self.assertEqual(entry(value), value)
            with self.assertRaises(AttributeError):
                getattr(library, "inspect_packet")

    def test_actual_native_composition_cleanup_refusal_and_task_state_machine(self):
        driver = r"""
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
void *__real_malloc(size_t); void *__real_calloc(size_t,size_t); void __real_free(void *);
static void *live[16]; static size_t allocations, frees, refusals; static bool refuse;
static void *remember(void *p){
  if(p){for(size_t i=0;i<16;i++)if(!live[i]){live[i]=p;allocations++;return p;}exit(80);}return p;
}
void *__wrap_malloc(size_t n){if(refuse){refuse=false;refusals++;return NULL;}return remember(__real_malloc(n));}
void *__wrap_calloc(size_t n,size_t w){if(refuse){refuse=false;refusals++;return NULL;}return remember(__real_calloc(n,w));}
void __wrap_free(void *p){
  if(p){size_t i;for(i=0;i<16 && live[i]!=p;i++);if(i==16)exit(81);live[i]=NULL;frees++;}__real_free(p);
}
uint8_t stored(bool); size_t choose(bool,size_t); size_t task_case(uint8_t);
int main(void){
  if(stored(false)!=91 || stored(true)!=91)return 82;
  for(unsigned flag=0;flag<2;flag++){
    size_t extra=flag?0:10;
    if(choose(flag,0)!=extra || choose(flag,7)!=7+extra || choose(flag,SIZE_MAX)!=extra)return 83;
    refuse=true;if(choose(flag,7)!=extra || refuse)return 84;
  }
  const uint8_t modes[]={0,1,2,255};const size_t expected[]={33,13,28,28};
  for(size_t i=0;i<4;i++){
    if(task_case(modes[i])!=expected[i])return 85;
    refuse=true;if(task_case(modes[i])!=250 || refuse)return 86;
  }
  for(size_t i=0;i<16;i++)if(live[i])return 87;
  printf("%zu %zu %zu\n",allocations,frees,refusals);
  return allocations!=8 || frees!=8 || refusals!=6;
}
"""
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            objects = []
            for name, source, exports in (("stored", stored_loan_program(), ["stored"]),
                    ("enum", enum_owner_program(), ["choose"]), ("task", task_program(), ["task_case"])):
                core = verify_program(source)
                obj = folder / (name + ".o")
                receipt = compile_program_llvm(emit_program_llvm(core), program=core, output=obj,
                                               clang=CLANG, kind="object")
                self.assertEqual(receipt["exports"], exports)
                objects.append(str(obj))
            source, binary = folder / "driver.c", folder / "driver"
            source.write_text(driver)
            linked = run_bounded([CLANG, "-std=c11", "-O2", "-Werror=implicit-function-declaration", str(source),
                                  *objects, "-Wl,--wrap=malloc", "-Wl,--wrap=calloc", "-Wl,--wrap=free",
                                  "-o", str(binary)])
            self.assertEqual(linked.returncode, 0, linked.stderr)
            result = run_bounded([str(binary)])
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.strip(), "8 8 6")

    def test_actual_native_invalid_task_transitions_abort(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            for mutation, mode in (("double_start", 2), ("join_pending", 0),
                                   ("close_running", 1), ("poll_complete", 2)):
                with self.subTest(mutation=mutation):
                    program = task_program()
                    blocks = {b["id"]: b for b in program["functions"][2]["blocks"]}
                    if mutation == "double_start":
                        blocks["begin"]["ops"][1]["op"] = "task.start"
                    elif mutation == "join_pending":
                        blocks["pending_cancel"]["ops"] = [operation("task.join", ["pending_task"], [("answer", "usize")])]
                        blocks["pending_cancel"]["term"] = ret("answer")
                    elif mutation == "close_running":
                        blocks["running_cancel"]["ops"] = [operation("task.close", ["live_task"]),
                            operation("const", out=[("answer", "usize")], value=0)]
                        blocks["running_cancel"]["term"] = ret("answer")
                    else:
                        blocks["finish"]["ops"][0]["op"] = "task.poll"
                    core = verify_program(program)
                    obj = folder / (mutation + ".o")
                    compile_program_llvm(emit_program_llvm(core), program=core, output=obj,
                                         clang=CLANG, kind="object")
                    driver, binary = folder / (mutation + ".c"), folder / mutation
                    driver.write_text("#include <stddef.h>\n#include <stdint.h>\n"
                                      "size_t task_case(uint8_t);int main(void){return (int)task_case(" + str(mode) + ");}\n")
                    compiled = run_bounded([CLANG, str(driver), str(obj), "-o", str(binary)])
                    self.assertEqual(compiled.returncode, 0, compiled.stderr)
                    actual = run_bounded([str(binary)])
                    self.assertEqual(actual.returncode, -6, actual.stdout + actual.stderr)


if __name__ == "__main__":
    unittest.main()
