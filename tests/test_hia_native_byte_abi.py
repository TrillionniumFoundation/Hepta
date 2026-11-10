"""Actual direct-native borrowed-byte admission and caller-memory boundaries."""
from __future__ import annotations

from dataclasses import replace
import ctypes
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_program import verify_program
from hepta.hia_program_native import build_program_machine, compile_program_machine, emit_program_machine
from hepta.hia_native_byte_abi import MAX_EXTENT
from tests.test_hia_program import b, branch, c, f, i, jump, ret

ROOT = Path(__file__).resolve().parents[1]
NATIVE = platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}


def byte_program():
    params = [("source", "readbuf"), ("destination", "mutbuf")]
    copy = f("copy_bytes", params, ["u32"], ["read", "write", "trap"], [
        b("entry", params, [
            i("buffer.len", ["source"], [("size", "usize")]),
            i("buffer.len", ["destination"], [("capacity", "usize")]),
            i("compare.le", ["size", "capacity"], [("fits", "bool")]),
            c("zero", "usize", 0),
        ], branch("fits", ("loop", "source", "destination", "size", "zero"), ("short",))),
        b("short", [], [c("error", "u32", 7)], ret("error")),
        b("loop", [("s", "readbuf"), ("d", "mutbuf"), ("n", "usize"), ("at", "usize")], [
            i("compare.lt", ["at", "n"], [("more", "bool")]),
        ], branch("more", ("body", "s", "d", "n", "at"), ("done",))),
        b("body", [("bs", "readbuf"), ("bd", "mutbuf"), ("bn", "usize"), ("ba", "usize")], [
            i("call", ["bs", "ba"], [("byte", "u8")], function="read_byte"),
            i("buffer.store", ["bd", "ba", "byte"]),
            c("one", "usize", 1), i("int.add.checked", ["ba", "one"], [("next", "usize")]),
        ], jump("loop", "bs", "bd", "bn", "next")),
        b("done", [], [c("ok", "u32", 0)], ret("ok")),
    ])
    reader = f("read_byte", [("input", "readbuf"), ("index", "usize")], ["u8"], ["read", "trap"], [
        b("entry", [("input", "readbuf"), ("index", "usize")], [
            i("buffer.load", ["input", "index"], [("v", "u8")]),
        ], ret("v"))])
    status_params = params + [("status", "u32")]
    status = f("echo_status", status_params, ["u32"], [], [b("entry", status_params, [], ret("status"))])
    reads = [("a", "readbuf"), ("z", "readbuf")]
    readonly = f("readonly", reads, ["u32"], [], [b("entry", reads, [c("answer", "u32", 11)], ret("answer"))])
    mixed_params = [("a", "u8"), ("b", "i16"), ("c", "u32"), ("d", "bool"),
                    ("source", "readbuf"), ("e", "u8"), ("destination", "mutbuf"), ("last", "u32")]
    mixed = f("mixed", mixed_params, ["u32"], ["write", "trap"], [
        b("entry", mixed_params, [c("at", "usize", 0), i("buffer.store", ["destination", "at", "e"]),
            i("int.cast", ["a"], [("aa", "u32")], mode="wrap"),
            i("int.cast", ["b"], [("bb", "u32")], mode="wrap"),
            i("int.add.wrap", ["aa", "bb"], [("ab", "u32")]),
            i("int.add.wrap", ["ab", "c"], [("abc", "u32")]),
            i("int.add.wrap", ["abc", "last"], [("sum", "u32")]),
            c("no", "u32", 0), i("select", ["d", "sum", "no"], [("answer", "u32")]),
        ], ret("answer"))])
    return {"schema": "hepta.hia.program.v8", "module": "direct_borrowed_bytes", "functions": [copy, reader, status, readonly, mixed]}


class ByteABIAdmissionTests(unittest.TestCase):
    def test_manifest_is_explicit_and_never_broadens_default_scalar_abi(self):
        program = verify_program(byte_program())
        with self.assertRaisesRegex(ValueError, "entrypoints"):
            emit_program_machine(program)
        image = emit_program_machine(program, foreign_buffer_exports=(("copy_bytes", 4096),))
        self.assertEqual(image.exports, ("copy_bytes",))
        self.assertEqual(image.foreign_buffer_exports, (("copy_bytes", 4096),))
        self.assertIn("borrowed-bytes", image.profile)

    def test_invalid_bounds_types_unknown_and_duplicate_names_fail_closed(self):
        program = verify_program(byte_program())
        values = [[], (("copy_bytes", True),), (("copy_bytes", 0),), (("copy_bytes", MAX_EXTENT + 1),),
                  (("missing", 32),), (("copy_bytes", 32), ("copy_bytes", 32)), (("copy_bytes", 32, 7),)]
        for manifest in values:
            with self.subTest(manifest=manifest), self.assertRaisesRegex(ValueError, "E_HIA_BYTE_ABI"):
                emit_program_machine(program, foreign_buffer_exports=manifest)

    def test_explicit_scalar_contract_and_public_resource_results_stay_closed(self):
        source = byte_program(); source["exports"] = []
        with self.assertRaisesRegex(ValueError, "scalar export contract"):
            emit_program_machine(verify_program(source), foreign_buffer_exports=(("copy_bytes", 32),))
        source = byte_program()
        source["functions"] = [f("owner", [("x", "buffer")], ["u32"], ["alloc"], [
            b("entry", [("x", "buffer")], [i("owner.drop", ["x"]), c("v", "u32", 0)], ret("v"))])]
        with self.assertRaisesRegex(ValueError, "requires loans"):
            emit_program_machine(verify_program(source), foreign_buffer_exports=(("owner", 32),))

    def test_public_loader_hook_name_is_rejected(self):
        source = byte_program()
        source["functions"][2]["name"] = "_init"
        with self.assertRaisesRegex(ValueError, "closed native ABI"):
            emit_program_machine(verify_program(source), foreign_buffer_exports=(("_init", 32),))

    def test_manifest_and_instruction_mutations_cannot_reuse_origin(self):
        program = verify_program(byte_program())
        image = emit_program_machine(program, foreign_buffer_exports=(("copy_bytes", 4096),))
        with tempfile.TemporaryDirectory() as temporary:
            for name, changed in [("extent", replace(image, foreign_buffer_exports=(("copy_bytes", 4097),))),
                                  ("omitted", replace(image, foreign_buffer_exports=()))]:
                with self.subTest(name=name), self.assertRaises(ValueError):
                    compile_program_machine(changed, program=program, output=Path(temporary) / name, kind="object")
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_direct_byte_object_emission_needs_no_llvm_or_subprocess(self):
        script = r'''
import builtins,json,pathlib,subprocess,sys
original=builtins.__import__
def guarded(name,*a,**kw):
    if "llvm" in name.lower(): raise AssertionError(name)
    return original(name,*a,**kw)
builtins.__import__=guarded
def forbidden(*a,**kw): raise AssertionError("process")
subprocess.Popen=forbidden
from hepta.hia_program_native import build_program_machine
r=build_program_machine(json.loads(sys.argv[1]),sys.argv[2],kind="object",foreign_buffer_exports=(("copy_bytes",4096),))
assert r["claims"]["foreign_buffer_entrypoints_exposed"]
assert not any("llvm" in name for name in sys.modules)
'''
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run([sys.executable, "-B", "-c", script, json.dumps(byte_program()), str(Path(temporary) / "p.o")],
                                    cwd=ROOT, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


@unittest.skipUnless(NATIVE and shutil.which("ld"), "Linux x86-64 GNU ld required")
class ByteABINativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="hia-byte-abi-")
        path = Path(cls.directory.name) / "program.so"
        cls.receipt = build_program_machine(byte_program(), path, linker="ld", foreign_buffer_exports=(
            ("copy_bytes", MAX_EXTENT), ("echo_status", MAX_EXTENT), ("readonly", MAX_EXTENT), ("mixed", MAX_EXTENT)))
        cls.lib = ctypes.CDLL(str(path))
        cls.copy = cls.lib.copy_bytes; cls.copy.restype = ctypes.c_uint64
        cls.copy.argtypes = [ctypes.c_void_p, ctypes.c_uint64] * 2
        cls.echo = cls.lib.echo_status; cls.echo.restype = ctypes.c_uint64
        cls.echo.argtypes = [ctypes.c_void_p, ctypes.c_uint64] * 2 + [ctypes.c_uint32]
        cls.readonly = cls.lib.readonly; cls.readonly.restype = ctypes.c_uint64
        cls.readonly.argtypes = [ctypes.c_void_p, ctypes.c_uint64] * 2
        cls.mixed = cls.lib.mixed; cls.mixed.restype = ctypes.c_uint64
        cls.mixed.argtypes = [ctypes.c_uint8, ctypes.c_int16, ctypes.c_uint32, ctypes.c_uint8,
                             ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint8,
                             ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint32]

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def test_real_source_output_buffers_and_surrounding_canaries(self):
        for length in (0, 1, 255, 4097):
            raw = bytes((k * 137 + 23) % 256 for k in range(length))
            source = ctypes.create_string_buffer(b"S" + raw + b"s")
            output = ctypes.create_string_buffer(b"D" + bytes(length) + b"d")
            result = self.copy(ctypes.addressof(source) + 1, length, ctypes.addressof(output) + 1, length)
            self.assertEqual(result, 0)
            self.assertEqual(output.raw[:-1], b"D" + raw + b"d")
            self.assertEqual(source.raw[:-1], b"S" + raw + b"s")

    def test_ordinary_core_error_and_all_u32_status_values_remain_distinct(self):
        source = ctypes.create_string_buffer(b"abcd")
        output = ctypes.create_string_buffer(b"XYZ")
        self.assertEqual(self.copy(source, 4, output, 3), 7)
        self.assertEqual(output.raw, b"XYZ\0")
        for status in (0, 1, 0x7fffffff, 0x80000000, 0xffffffff):
            self.assertEqual(self.echo(None, 0, None, 0, status), status)

    def test_extent_null_and_unsigned_address_wrap_reject_before_access(self):
        output = ctypes.create_string_buffer(b"unmodified")
        cases = [(None, MAX_EXTENT + 1, 1), (1, (1 << 64) - 1, 1), (None, 1, 2),
                 ((1 << 64) - 1, 1, 3), ((1 << 64) - 4, 7, 3)]
        for pointer, length, status in cases:
            before = output.raw
            self.assertEqual(self.copy(pointer, length, output, 10), status << 32)
            self.assertEqual(output.raw, before)
        self.assertEqual(self.echo(None, 0, None, 0, 23), 23)
        self.assertEqual(self.echo((1 << 64) - 1, 0, None, 0, 29), 29)
        self.assertEqual(self.echo(1, MAX_EXTENT, None, 0, 31), 31)

    def test_mutable_overlap_is_rejected_and_adjacent_ranges_are_allowed(self):
        data = ctypes.create_string_buffer(b"abcdefghijklmnop")
        address = ctypes.addressof(data)
        for left, right in ((0, 0), (0, 2), (2, 0)):
            before = data.raw
            self.assertEqual(self.copy(address + left, 6, address + right, 6), 4 << 32)
            self.assertEqual(data.raw, before)
        self.assertEqual(self.copy(address, 8, address + 8, 8), 0)
        self.assertEqual(data.raw[:-1], b"abcdefghabcdefgh")

    def test_readonly_overlap_and_empty_mutable_ranges_are_allowed(self):
        data = ctypes.create_string_buffer(b"abcdefgh")
        address = ctypes.addressof(data)
        self.assertEqual(self.readonly(address, 8, address + 1, 4), 11)
        self.assertEqual(self.echo(address, 8, address + 1, 0, 19), 19)
        self.assertEqual(self.echo(address, 0, address + 1, 4, 17), 17)

    def test_mixed_register_stack_argument_expansion_preserves_narrow_types(self):
        source = ctypes.create_string_buffer(b"source")
        destination = ctypes.create_string_buffer(b"x")
        self.assertEqual(self.mixed(250, -10, 70000, 1, source, 6, 199, destination, 1, 300), 70540)
        self.assertEqual(destination.raw, bytes([199, 0]))

    def test_explicit_v2_machine_plan_preserves_byte_admission_and_native_output(self):
        from tests.test_hia_machine_plan import explicit_plan
        program = verify_program(byte_program())
        plan = explicit_plan(program,
            function_order=list(reversed([fn["name"] for fn in program.as_dict()["functions"]])),
            scratch_registers={"r10": "r11", "r11": "r10"},
            instruction_selection={"move_immediate": "mov32_if_exact", "alu_immediate": "imm8_if_exact"},
            function_alignment=32)
        manifest = (("copy_bytes", 4096),)
        image = emit_program_machine(program, foreign_buffer_exports=manifest, machine_plan=plan)
        canonical = emit_program_machine(program, foreign_buffer_exports=manifest)
        self.assertNotEqual(image.text_bytes, canonical.text_bytes)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "planned.so"
            compile_program_machine(image, program=program, output=output, linker="ld", machine_plan=plan)
            library = ctypes.CDLL(str(output))
            fn = library.copy_bytes; fn.argtypes = [ctypes.c_void_p, ctypes.c_uint64] * 2; fn.restype = ctypes.c_uint64
            source = ctypes.create_string_buffer(bytes(range(256)))
            target = ctypes.create_string_buffer(256)
            self.assertEqual(fn(source, 256, target, 256), 0)
            self.assertEqual(target.raw, source.raw[:256])
            self.assertEqual(fn(source, 256, source, 256), 4 << 32)
            self.assertEqual(fn(None, 1, target, 256), 2 << 32)

    def test_disposable_invocation_owns_copies_and_preserves_costs(self):
        from hepta.hia_native_byte_runner import invoke_byte_program
        output = bytearray(5)
        result = invoke_byte_program(byte_program(), "copy_bytes", [b"hello", output])
        self.assertEqual(result["status"], "returned")
        self.assertEqual(result["arguments"], [b"hello", b"hello"])
        self.assertEqual(output, bytearray(5))
        self.assertTrue(result["termination_confirmed"])
        self.assertGreater(int(result["build_ns"]), 0)
        self.assertGreater(int(result["invocation_ns"]), 0)

    def test_disposable_runner_contains_real_core_traps_and_infinite_loops(self):
        from hepta.hia_native_byte_runner import invoke_byte_program
        params = [("input", "readbuf")]
        trap = {"schema": "hepta.hia.program.v8", "module": "trap", "functions": [
            f("fail", params, ["u32"], ["trap"], [b("entry", params, [], {"op": "trap", "code": "user"})])]}
        result = invoke_byte_program(trap, "fail", [b""], timeout_ms=1000)
        self.assertEqual(result["status"], "trapped")
        self.assertIsNone(result["report"])
        loop = {"schema": "hepta.hia.program.v8", "module": "loop", "functions": [
            f("forever", params, ["u32"], [], [b("entry", params, [], jump("again", "input")),
                b("again", [("loop_input", "readbuf")], [], jump("again", "loop_input"))])]}
        result = invoke_byte_program(loop, "forever", [b""], timeout_ms=150)
        self.assertEqual(result["status"], "budget_exceeded")
        self.assertTrue(result["termination_confirmed"])
        self.assertIsNone(result["report"])

    def test_missing_launch_or_cleanup_evidence_never_claims_confirmed_termination(self):
        from hepta.clang_capture import CaptureFailure, CaptureRejected
        from hepta.hia_native_byte_runner import invoke_byte_program
        no_launch = CaptureRejected("E_CAPTURE_EXEC", "launch unavailable")
        unknown = CaptureRejected("E_CAPTURE_OWNERSHIP", "ownership unavailable")
        cleanup = CaptureRejected("E_CAPTURE_TIMEOUT", "deadline reached")
        cleanup.capture = CaptureFailure(("python",), -9, b"partial", b"", 7, 0)
        cleanup.capture_error = "E_CAPTURE_CLEANUP: reap not confirmed"
        for error, status in ((no_launch, "not_started"), (unknown, "termination_unknown"), (cleanup, "termination_unknown")):
            with self.subTest(status=status), patch("hepta.clang_capture.run_bounded", side_effect=error):
                result = invoke_byte_program(byte_program(), "copy_bytes", [b"a", bytearray(1)])
            self.assertEqual(result["status"], status)
            self.assertFalse(result["leader_termination_confirmed"])
            self.assertFalse(result["termination_confirmed"])
            self.assertIsNone(result["report"])
            if error is cleanup:
                self.assertEqual(result["capture"]["stdout_total_bytes"], 7)
                self.assertTrue(result["capture_error"])

    def test_explicit_v2_machine_plan_preserves_byte_admission_and_native_output(self):
        from tests.test_hia_machine_plan import explicit_plan
        program = verify_program(byte_program())
        plan = explicit_plan(program,
            function_order=list(reversed([fn["name"] for fn in program.as_dict()["functions"]])),
            scratch_registers={"r10": "r11", "r11": "r10"},
            instruction_selection={"move_immediate": "mov32_if_exact", "alu_immediate": "imm8_if_exact"},
            function_alignment=32)
        manifest = (("copy_bytes", 4096),)
        image = emit_program_machine(program, foreign_buffer_exports=manifest, machine_plan=plan)
        canonical = emit_program_machine(program, foreign_buffer_exports=manifest)
        self.assertNotEqual(image.text_bytes, canonical.text_bytes)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "planned.so"
            compile_program_machine(image, program=program, output=output, linker="ld", machine_plan=plan)
            library = ctypes.CDLL(str(output))
            fn = library.copy_bytes; fn.argtypes = [ctypes.c_void_p, ctypes.c_uint64] * 2; fn.restype = ctypes.c_uint64
            source = ctypes.create_string_buffer(bytes(range(256)))
            target = ctypes.create_string_buffer(256)
            self.assertEqual(fn(source, 256, target, 256), 0)
            self.assertEqual(target.raw, source.raw[:256])
            self.assertEqual(fn(source, 256, source, 256), 4 << 32)
            self.assertEqual(fn(None, 1, target, 256), 2 << 32)



if __name__ == "__main__":
    unittest.main()
