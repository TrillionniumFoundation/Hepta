"""Real native admission, byte effects, and caller-owned lifetime observations."""
from __future__ import annotations

from dataclasses import replace
import ctypes
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_llvm import HIAProgramLLVMRejected, compile_program_llvm, emit_program_llvm
from tools.qualify_hia_program import block, branch, constant, function, jump, operation, ret

CLANG = os.environ.get("CLANG", "clang")


def program_document():
    scalar = function("plain_scalar", [], ["u32"], [], [
        block("entry", [], [constant("answer", "u32", 42)], ret("answer"))])
    copy_params = [("source", "readbuf"), ("destination", "mutbuf"), ("status", "u32")]
    copy = function("copy_one", copy_params, ["u32"], ["read", "write", "trap"], [
        block("entry", copy_params, [
            operation("buffer.len", ["source"], [("sn", "usize")]),
            operation("buffer.len", ["destination"], [("dn", "usize")]),
            constant("zero", "usize", 0),
            operation("compare.gt", ["sn", "zero"], [("sok", "bool")]),
            operation("compare.gt", ["dn", "zero"], [("dok", "bool")]),
            operation("bool.and", ["sok", "dok"], [("enough", "bool")]),
        ], branch("enough", "copy", ["source", "destination", "status"], "empty", [])),
        block("copy", [("cs", "readbuf"), ("cd", "mutbuf"), ("cr", "u32")], [
            constant("index", "usize", 0),
            operation("buffer.load", ["cs", "index"], [("byte", "u8")]),
            operation("buffer.store", ["cd", "index", "byte"]),
        ], ret("cr")),
        block("empty", [], [constant("short", "u32", 19)], ret("short")),
    ])
    read_params = [("a", "readbuf"), ("b", "readbuf")]
    read = function("read_twice", read_params, ["u32"], ["read", "trap"], [
        block("entry", read_params, [
            constant("zero", "usize", 0),
            operation("buffer.load", ["a", "zero"], [("a0", "u8")]),
            operation("buffer.load", ["b", "zero"], [("b0", "u8")]),
            operation("int.cast", ["a0"], [("a32", "u32")], mode="wrap"),
            operation("int.cast", ["b0"], [("b32", "u32")], mode="wrap"),
            operation("int.add.wrap", ["a32", "b32"], [("sum", "u32")]),
        ], ret("sum"))])
    return {"schema": "hepta.hia.program.v6", "module": "foreign_admission_tests", "functions": [scalar, copy, read]}


EXPORTS = (("copy_one", 64), ("read_twice", 64))


class ForeignAdmissionStaticTests(unittest.TestCase):
    def test_default_scalar_abi_remains_closed(self):
        ir = emit_program_llvm(verify_program(program_document()))
        self.assertEqual(ir.exports, ("plain_scalar",))
        self.assertEqual(ir.foreign_buffer_exports, ())
        self.assertNotIn("define i64 @copy_one", ir.text)

    def test_manifest_is_immutable_bounded_unique_and_explicit(self):
        program = verify_program(program_document())
        for spec in ([('copy_one', 64)], (("copy_one", True),), (("copy_one", 0),),
                     (("copy_one", (1 << 20) + 1),), (("missing", 64),),
                     (("copy_one", 64), ("copy_one", 64)), (("plain_scalar", 64),)):
            with self.subTest(spec=spec), self.assertRaises(HIAProgramLLVMRejected):
                emit_program_llvm(program, foreign_buffer_exports=spec)
        valid = emit_program_llvm(program, foreign_buffer_exports=tuple(reversed(EXPORTS)))
        self.assertEqual(valid.foreign_buffer_exports, EXPORTS)
        self.assertTrue(valid.profile.endswith("foreign-buffers.v1"))

    def test_foreign_entries_cannot_be_put_into_scalar_exports(self):
        doc = program_document(); doc["exports"] = ["copy_one"]
        with self.assertRaises(HIAProgramRejected):
            verify_program(doc)

    def test_reserved_native_names_rejected(self):
        for name in ("abort", "memcpy", "__hia_fn_0", "not-a-C-name"):
            doc = program_document()
            doc["functions"][1]["name"] = name
            with self.subTest(name=name), self.assertRaises((HIAProgramRejected, HIAProgramLLVMRejected)):
                emit_program_llvm(verify_program(doc), foreign_buffer_exports=((name, 64),))

    def test_composite_and_erased_explicit_contract_cannot_widen_abi(self):
        doc = program_document()
        doc["schema"] = "hepta.hia.composite.v1"
        doc["types"] = []
        composite = verify_program(doc)
        self.assertIsNotNone(composite.structured_bytes)
        with self.assertRaises(HIAProgramLLVMRejected):
            emit_program_llvm(composite, foreign_buffer_exports=EXPORTS)
        normalized = verify_program(composite.canonical_bytes)
        self.assertIsNone(normalized.structured_bytes)
        with self.assertRaises(HIAProgramLLVMRejected):
            emit_program_llvm(normalized, foreign_buffer_exports=EXPORTS)
        self.assertEqual(emit_program_llvm(composite).exports, ("plain_scalar",))

    def test_owner_transfer_and_loan_escape_remain_rejected(self):
        doc = program_document()
        doc["functions"][1]["params"][0]["type"] = "buffer"
        doc["functions"][1]["blocks"][0]["params"][0]["type"] = "buffer"
        with self.assertRaises((HIAProgramRejected, HIAProgramLLVMRejected)):
            emit_program_llvm(verify_program(doc), foreign_buffer_exports=EXPORTS)
        loan = function("escape", [("src", "readbuf")], ["readbuf"], [], [
            block("entry", [("src", "readbuf")], [], ret("src"))])
        loan["return_loans"] = ["src"]
        doc = {"schema": "hepta.hia.program.v8", "module": "escape_test", "functions": [loan]}
        with self.assertRaises(HIAProgramLLVMRejected):
            emit_program_llvm(verify_program(doc), foreign_buffer_exports=(("escape", 64),))

    def test_calls_and_cycles_are_outside_finite_v1(self):
        doc = program_document()
        selected = function("indirect", [("src", "readbuf")], ["u32"], [], [
            block("entry", [("src", "readbuf")], [
                operation("call", [], [("answer", "u32")], function="plain_scalar")], ret("answer"))])
        doc["functions"].append(selected)
        with self.assertRaises(HIAProgramLLVMRejected):
            emit_program_llvm(verify_program(doc), foreign_buffer_exports=(("indirect", 64),))
        cyclic = function("cyclic", [("src", "readbuf")], ["u32"], [], [
            block("entry", [("src", "readbuf")], [], jump("loop", "src")),
            block("loop", [("loop_src", "readbuf")], [], jump("loop", "loop_src"))])
        doc["functions"] = [cyclic]
        with self.assertRaises(HIAProgramLLVMRejected):
            emit_program_llvm(verify_program(doc), foreign_buffer_exports=(("cyclic", 64),))

    def test_manifest_or_ir_tampering_is_rejected_before_tool_execution(self):
        program = verify_program(program_document())
        ir = emit_program_llvm(program, foreign_buffer_exports=EXPORTS)
        with tempfile.TemporaryDirectory() as directory:
            for forged in (replace(ir, foreign_buffer_exports=(("copy_one", 63), ("read_twice", 64))),
                           replace(ir, text=ir.text.replace("icmp ule i64 %a0_len, 64", "icmp ule i64 %a0_len, 65"))):
                with self.subTest(forged=forged.sha256), self.assertRaisesRegex(HIAProgramLLVMRejected, "ORIGIN"):
                    compile_program_llvm(forged, program=program, output=Path(directory)/"bad.o", clang="not-a-driver", kind="object")


@unittest.skipUnless(shutil.which(CLANG), "real Clang 20+ unavailable")
class ForeignAdmissionNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="hia-foreign-")
        cls.directory = Path(cls.temp.name)
        cls.program = verify_program(program_document())
        cls.ir = emit_program_llvm(cls.program, foreign_buffer_exports=EXPORTS)
        cls.receipt = compile_program_llvm(cls.ir, program=cls.program, output=cls.directory/"foreign.so", clang=CLANG)
        cls.lib = ctypes.CDLL(str(cls.directory/"foreign.so"))
        cls.copy = cls.lib.copy_one
        cls.copy.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint32]
        cls.copy.restype = ctypes.c_uint64
        cls.read = cls.lib.read_twice
        cls.read.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_uint64]
        cls.read.restype = ctypes.c_uint64

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_real_byte_effects_and_application_status_are_separate(self):
        for byte in (0, 1, 127, 255):
            for status in (0, 19, 0xffffffff):
                src = (ctypes.c_uint8*64)(byte, *([0x35]*63))
                dst = (ctypes.c_uint8*64)(*([0xa5]*64))
                self.assertEqual(self.copy(src, 64, dst, 64, status), status)
                self.assertEqual(bytes(dst), bytes([byte])+b'\xa5'*63)
                self.assertEqual(bytes(src), bytes([byte])+b'\x35'*63)
        self.assertTrue(self.receipt["claims"]["foreign_buffer_entrypoints_exposed"])
        self.assertFalse(self.receipt["claims"]["native_execution_qualified"])
        self.assertIn("dangling", " ".join(self.receipt["runtime_assumptions"]))

    def test_numeric_rejection_before_any_write(self):
        src = (ctypes.c_uint8*80)(*range(80)); dst = (ctypes.c_uint8*80)(*([0xa5]*80))
        for a, alen, b, blen, expected in [
            (src, 65, dst, 64, 1), (src, (1<<64)-1, dst, 1, 1),
            (src, 1, dst, 65, 1), (None, 1, dst, 1, 2),
            (src, 1, None, 1, 2), (ctypes.c_void_p((1<<64)-4), 8, dst, 1, 3),
            (src, 1, ctypes.c_void_p((1<<64)-4), 8, 3),
        ]:
            before = bytes(dst)
            self.assertEqual(self.copy(a, alen, b, blen, 9), expected<<32)
            self.assertEqual(bytes(dst), before)
        self.assertEqual(self.copy(None, 0, None, 0, 9), 19)
        self.assertEqual(self.copy(src, 0, dst, 1, 9), 19)
        self.assertEqual(self.copy(src, 1, dst, 0, 9), 19)

    def test_partial_and_identical_mutable_alias_rejected_read_alias_allowed(self):
        data = (ctypes.c_uint8*80)(*range(80)); base=ctypes.addressof(data)
        for source, destination in ((base, base), (base, base+1), (base+1, base)):
            before = bytes(data)
            self.assertEqual(self.copy(source, 16, destination, 16, 0), 4<<32)
            self.assertEqual(bytes(data), before)
        self.assertEqual(self.read(base+3, 16, base+3, 16), 6)
        self.assertEqual(self.read(base+3, 16, base+4, 16), 7)
        # Adjacent ranges are not overlapping and remain valid views of one allocation.
        self.assertEqual(self.copy(base, 16, base+16, 16, 7), 7)
        self.assertEqual(data[16], data[0])

    def test_native_caller_releases_buffers_once_after_call(self):
        obj = self.directory/"lifetime.o"
        compile_program_llvm(self.ir, program=self.program, output=obj, clang=CLANG, kind="object")
        c = self.directory/"lifetime.c"; exe=self.directory/"lifetime"
        c.write_text(r'''
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
extern uint64_t copy_one(const unsigned char *, uint64_t, unsigned char *, uint64_t, uint32_t);
static unsigned frees;
void __real_free(void *);
void __wrap_free(void *p) { if (p) ++frees; __real_free(p); }
int main(void) {
  unsigned char *a=malloc(32), *b=malloc(32);
  if(!a || !b) return 90;
  memset(a, 23, 32); memset(b, 91, 32);
  if(copy_one(a,32,b,32,0)!=0 || b[0]!=23 || b[1]!=91 || frees) return 91;
  free(a); free(b);
  return frees==2 ? 0 : 92;
}
''')
        build=subprocess.run([CLANG,"-O2","-fno-builtin-free",str(c),str(obj),"-Wl,--wrap=free","-o",str(exe)],capture_output=True,text=True,timeout=60)
        self.assertEqual(build.returncode,0,build.stderr)
        run=subprocess.run([str(exe)],capture_output=True,text=True,timeout=10)
        self.assertEqual(run.returncode,0,run.stderr)
