"""Adversarial final-image validation; faulty producers cannot validate themselves."""
from __future__ import annotations

import copy
import ctypes
import importlib.util
import json
from pathlib import Path
import platform
import shutil
import struct
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_program import verify_program
from hepta.hia_program_native import emit_program_machine, compile_program_machine
from hepta.hia_machine_x64 import Code
from hepta.hia_safe_core import (build_safe_core, validate_safe_core_image, SafeCoreRejected,
                                  CLAIMS, _profile)
from hepta.hia_safe_core_elf import bind_final_image, _ELF
from hepta.hia_safe_core_x64 import decode
from tests.test_hia_program import arithmetic, b, branch, c, f, i, jump, ret

ROOT = Path(__file__).resolve().parents[1]
AVAILABLE = (platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}
             and shutil.which("ld") is not None and importlib.util.find_spec("z3") is not None)


def guarded_update():
    return json.loads((ROOT / "examples/hia_safe_core/guarded_update.hia.json").read_bytes())


def read_byte():
    params = [("buffer", "readbuf"), ("index", "usize")]
    return {"schema": "hepta.hia.program.v8", "module": "safe_reader", "functions": [
        f("read_byte", params, ["u32"], ["read", "trap"], [b("entry", params, [
            i("buffer.load", ["buffer", "index"], [("byte", "u8")]),
            i("int.cast", ["byte"], [("answer", "u32")], mode="wrap"),
        ], ret("answer"))])]}


@unittest.skipUnless(AVAILABLE, "Linux x86-64, GNU ld and pinned z3-solver are required")
class SafeCoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="hia-safe-core-tests-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.core = verify_program(arithmetic("int.add.wrap", "u32"))
        cls.image = emit_program_machine(cls.core)
        path = cls.root / "reference.so"
        compile_program_machine(cls.image, program=cls.core, output=path, linker="ld")
        cls.data = path.read_bytes()
        cls.report = validate_safe_core_image(cls.core, cls.image, cls.data)
        cls.elf = _ELF(cls.data, 3)

    def newpath(self, name):
        path = self.root / self._testMethodName
        path.mkdir(exist_ok=True)
        return path / name

    def bind(self, data):
        return bind_final_image(self.image.object_bytes, self.image.text_bytes, bytes(data), "calculate")

    def test_all_input_obligations_and_exact_final_bytes_are_bound(self):
        self.assertEqual(self.report["status"], "smt_validated")
        self.assertEqual([o["result"] for o in self.report["obligations"]], ["sat"] + ["unsat"] * 4)
        self.assertEqual(self.report["claims"], CLAIMS)
        self.assertFalse(self.report["claims"]["machine_checked_isa_refinement_proved"])
        self.assertFalse(self.report["claims"]["serialized_receipt_authorizes_execution"])
        self.assertEqual(self.report["image_binding"]["entry_symbol"], "calculate")

    def test_native_wrapping_boundaries_match_independent_math(self):
        report = build_safe_core(arithmetic("int.add.wrap", "u32"), self.newpath("add.so"))
        fn = ctypes.CDLL(report["output"]).calculate
        fn.argtypes, fn.restype = [ctypes.c_uint32, ctypes.c_uint32], ctypes.c_uint32
        values = (0, 1, 127, 255, 65535, 2**31 - 1, 2**31, 2**32 - 1)
        for left in values:
            for right in values:
                self.assertEqual(fn(left, right), (left + right) % 2**32)
        self.case_counts = {"native_arithmetic_pairs": len(values) ** 2}

    def test_checked_add_and_sub_are_proved_at_every_admitted_integer_width(self):
        count = 0
        for typ in ("u8", "u32", "u64", "usize"):
            for operation in ("int.add.checked", "int.sub.checked"):
                with self.subTest(type=typ, op=operation):
                    report = build_safe_core(arithmetic(operation, typ), self.newpath(typ + operation + ".so"))
                    self.assertEqual(report["validation"]["obligations"][-1]["result"], "unsat")
                    count += 1
        self.case_counts = {"all_input_checked_arithmetic_functions": count}

    def test_unsigned_scalar_boolean_bitwise_cast_and_select_models(self):
        params = [("a", "u32"), ("z", "u32"), ("choose", "bool")]
        operations = [
            i("bit.and", ["a", "z"], [("both", "u32")]),
            i("bit.or", ["a", "z"], [("either", "u32")]),
            i("bit.xor", ["both", "either"], [("different", "u32")]),
            i("bit.not", ["different"], [("inverse", "u32")]),
            i("bool.not", ["choose"], [("no", "bool")]),
            i("compare.ge", ["a", "z"], [("ge", "bool")]),
            i("bool.or", ["no", "ge"], [("route", "bool")]),
            i("select", ["route", "different", "inverse"], [("chosen", "u32")]),
            i("int.cast", ["chosen"], [("answer", "u8")], mode="wrap"),
        ]
        core = {"schema": "hepta.hia.program.v8", "module": "selected_scalar", "functions": [
            f("selected", params, ["u8"], [], [b("entry", params, operations, ret("answer"))])]}
        report = build_safe_core(core, self.newpath("selected.so"))
        self.assertTrue(report["ok"])
        fn = ctypes.CDLL(report["output"]).selected
        fn.argtypes, fn.restype = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_bool], ctypes.c_uint8
        for a, z in ((0, 0), (1, 2), (255, 7), (2**32 - 1, 0), (37, 1000)):
            for choose in (False, True):
                different = a ^ z
                expected = different if (not choose or a >= z) else ~different
                self.assertEqual(fn(a, z, choose), expected & 255)

    def test_all_unsigned_conditions_are_checked_on_actual_final_images(self):
        for relation in ("eq", "ne", "lt", "le", "gt", "ge"):
            params = [("a", "u64"), ("z", "u64")]
            core = {"schema": "hepta.hia.program.v8", "module": "comparison", "functions": [
                f("compare", params, ["bool"], [], [b("entry", params, [
                    i("compare." + relation, ["a", "z"], [("r", "bool")])], ret("r"))])]}
            with self.subTest(relation=relation):
                self.assertTrue(build_safe_core(core, self.newpath(relation + ".so"))["ok"])

    def test_borrowed_guarded_update_preserves_all_other_bytes_and_abi_rejections(self):
        report = build_safe_core(guarded_update(), self.newpath("update.so"), foreign_extent=4096)
        self.assertGreater(report["validation"]["model_counts"]["machine_terminal_paths"], 1)
        fn = ctypes.CDLL(report["output"]).update_byte
        fn.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint8, ctypes.c_bool]
        fn.restype = ctypes.c_uint64
        for value in range(256):
            data = ctypes.create_string_buffer(b"L" + bytes([value]) + b"R")
            self.assertEqual(fn(ctypes.addressof(data) + 1, 1, 0, 137, True), (value + 137) & 255)
            self.assertEqual(data.raw, b"L" + bytes([(value + 137) & 255]) + b"R\0")
        data = ctypes.create_string_buffer(b"unchanged")
        original = data.raw
        for active, index in ((False, 0), (True, len(original)), (True, 2**64 - 1)):
            self.assertEqual(fn(data, len(original), index, 99, active), 0)
            self.assertEqual(data.raw, original)
        for pointer, length, status in ((None, 4097, 1), (None, 1, 2), (2**64 - 1, 1, 3)):
            self.assertEqual(fn(pointer, length, 0, 99, True), status << 32)
        self.case_counts = {"native_guarded_updates": 256, "abi_rejections": 3, "no_write_cases": 3}

    def test_readonly_bounds_abort_matches_native_model_without_assuming_in_bounds_inputs(self):
        report = build_safe_core(read_byte(), self.newpath("read.so"), foreign_extent=64)
        self.assertEqual(report["validation"]["obligations"][-1]["result"], "unsat")
        self.assertGreater(report["validation"]["model_counts"]["core_terminal_paths"], 3)

    def test_faulty_add_producer_cannot_revalidate_its_own_wrong_machine_code(self):
        output, queries = self.newpath("wrong.so"), self.newpath("queries")
        with patch.object(Code, "add", Code.sub):
            with self.assertRaises(SafeCoreRejected) as caught:
                build_safe_core(arithmetic("int.add.wrap", "u32"), output, query_directory=queries)
        self.assertFalse(output.exists())
        witness = caught.exception.counterexample
        self.assertEqual(witness["obligation"], "core_to_final_image_return_abort_and_caller_bytes")
        a, b = [value & 0xffffffff for value in witness["abi_words"]]
        self.assertNotEqual((a + b) & 0xffffffff, (a - b) & 0xffffffff)
        retained = list(queries.glob("04-*.smt2"))
        self.assertEqual(len(retained), 1)
        self.assertEqual(json.loads(retained[0].with_suffix(".smt2.result.json").read_bytes())["result"], "sat")

    def test_faulty_equal_extent_guard_produces_a_real_memory_bound_counterexample(self):
        original = Code.jcc
        def wrong(code, condition, target):
            return original(code, "a" if condition == "ae" else condition, target)
        with patch.object(Code, "jcc", wrong):
            with self.assertRaises(SafeCoreRejected) as caught:
                build_safe_core(read_byte(), self.newpath("bad-bounds.so"), foreign_extent=64)
        self.assertEqual(caught.exception.counterexample["obligation"], "machine_memory_access_bounds")
        words = caught.exception.counterexample["abi_words"]
        self.assertEqual(words[1], words[2])

    def test_faulty_wide_foreign_store_is_not_a_byte_store(self):
        with patch.object(Code, "store_u8", Code.store):
            with self.assertRaises(SafeCoreRejected) as caught:
                build_safe_core(guarded_update(), self.newpath("wide-store.so"), foreign_extent=64)
        self.assertEqual(caught.exception.counterexample["obligation"], "machine_memory_access_bounds")

    def test_faulty_callee_saved_register_clobber_is_detected(self):
        original = Code.ret
        def clobber(code):
            code.mov_imm("rbx", 123)
            original(code)
        with patch.object(Code, "ret", clobber):
            with self.assertRaises(SafeCoreRejected) as caught:
                build_safe_core(arithmetic("int.add.wrap", "u32"), self.newpath("clobber.so"))
        self.assertEqual(caught.exception.counterexample["obligation"], "sysv_stack_alignment_and_preservation")

    def test_nonreturning_abort_call_must_still_write_to_the_admitted_stack(self):
        original = Code.call
        def corrupt_stack(code, symbol):
            if symbol == "abort":
                code.mov_imm("rsp", 0)
            return original(code, symbol)
        for name, core, extent in (("scalar", arithmetic("int.add.checked", "u32"), None),
                                   ("borrowed", read_byte(), 64)):
            output = self.newpath(name + "-invalid-abort-stack.so")
            with self.subTest(entry=name), patch.object(Code, "call", corrupt_stack):
                with self.assertRaises(SafeCoreRejected) as caught:
                    build_safe_core(core, output, foreign_extent=extent)
                self.assertFalse(output.exists())
                witness = caught.exception.counterexample
                self.assertEqual(witness["obligation"], "machine_memory_access_bounds")
                if name == "scalar":
                    left, right = (word & 0xffffffff for word in witness["abi_words"])
                    self.assertGreater(left + right, 0xffffffff)
                else:
                    self.assertGreaterEqual(witness["abi_words"][2], witness["abi_words"][1])

    def test_nonreturning_abort_call_cannot_push_beyond_the_declared_stack(self):
        original = Code.call
        def exhaust_stack(code, symbol):
            if symbol == "abort":
                code.mov_imm("rax", 16384)
                code.sub("rsp", "rax")
            return original(code, symbol)
        output = self.newpath("exhausted-abort-stack.so")
        with patch.object(Code, "call", exhaust_stack):
            with self.assertRaisesRegex(ValueError, "bounded displacement of the caller stack"):
                build_safe_core(arithmetic("int.add.checked", "u32"), output)
        self.assertFalse(output.exists())

    def test_final_instruction_byte_change_cannot_reuse_source_or_a_receipt(self):
        changed = bytearray(self.data)
        changed[self.elf.section(".text")["offset"] + 1] ^= 1
        with self.assertRaises(ValueError):
            validate_safe_core_image(self.core, self.image, bytes(changed))
        self.assertEqual(self.report["status"], "smt_validated")  # It remains evidence for the old bytes only.

    def test_final_relocation_target_must_match_exact_symbol_and_plt(self):
        binding = self.report["image_binding"]
        for relocation in binding["relocations"]:
            changed = bytearray(self.data)
            changed[binding["linked_text_file_offset"] + relocation["offset"]] ^= 1
            with self.subTest(symbol=relocation["symbol"]), self.assertRaises(ValueError):
                self.bind(changed)

    def test_plt_indirection_cannot_redirect_to_another_got_slot(self):
        changed = bytearray(self.data)
        changed[self.elf.section(".plt")["offset"] + 18] ^= 8
        with self.assertRaisesRegex(ValueError, "PLT"):
            self.bind(changed)

    def test_loader_metadata_cannot_disable_its_load_binding(self):
        for name in (".dynsym", ".dynstr", ".rela.plt", ".hash", ".gnu.hash", ".gnu.version", ".gnu.version_r"):
            changed = bytearray(self.data)
            section = self.elf.section(name)
            shoff = struct.unpack_from("<Q", changed, 40)[0]
            struct.pack_into("<Q", changed, shoff + section["index"] * 64 + 8,
                             section["flags"] & ~2)
            with self.subTest(section=name), self.assertRaisesRegex(ValueError, "required allocation flag"):
                self.bind(changed)

    def test_loader_metadata_cannot_be_read_from_an_unloaded_benign_copy(self):
        for name in (".dynsym", ".dynstr", ".rela.plt", ".hash", ".gnu.hash", ".gnu.version", ".gnu.version_r"):
            changed = bytearray(self.data)
            section = self.elf.section(name)
            copied_offset = len(changed)
            changed.extend(section["data"])
            shoff = struct.unpack_from("<Q", changed, 40)[0]
            struct.pack_into("<Q", changed, shoff + section["index"] * 64 + 24, copied_offset)
            # The section claims good bytes; the loader still reads these now
            # corrupted original bytes through the untouched PT_LOAD mapping.
            changed[section["offset"]] ^= 1
            with self.subTest(section=name), self.assertRaises(ValueError):
                self.bind(changed)

    def test_partial_page_overlay_cannot_evade_whole_section_mapping_checks(self):
        changed = bytearray(self.data)
        phoff, phsize, phnum = (struct.unpack_from("<Q", changed, 32)[0],
                               struct.unpack_from("<H", changed, 54)[0],
                               struct.unpack_from("<H", changed, 56)[0])
        spare = next(phoff + n * phsize for n in range(phnum)
                     if struct.unpack_from("<I", changed, phoff + n * phsize)[0] == 1 and
                     struct.unpack_from("<Q", changed, phoff + n * phsize + 32)[0] == 0)
        text = self.elf.section(".text")
        struct.pack_into("<IIQQQQQQ", changed, spare, 1, 5, text["offset"] + 16,
                         text["addr"] + 16, text["addr"] + 16, 8, 8, 4096)
        with self.assertRaisesRegex(ValueError, "overlap"):
            self.bind(changed)

    def test_load_alignment_and_permissions_cannot_be_promoted(self):
        phoff = struct.unpack_from("<Q", self.data, 32)[0]
        for field, value in ((48, 8192), (4, 7)):
            changed = bytearray(self.data)
            struct.pack_into("<Q" if field == 48 else "<I", changed, phoff + field, value)
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.bind(changed)

    def test_gnu_hash_bloom_bucket_and_chain_must_resolve_the_export(self):
        section = self.elf.section(".gnu.hash")
        _, _, bloom, _ = struct.unpack_from("<IIII", section["data"])
        for offset in (16, 16 + bloom * 8, section["size"] - 4):
            changed = bytearray(self.data)
            changed[section["offset"] + offset] ^= 1
            with self.subTest(offset=offset), self.assertRaisesRegex(ValueError, "GNU"):
                self.bind(changed)

    def test_sysv_hash_cycles_or_missing_symbols_are_rejected(self):
        section = self.elf.section(".hash")
        count, _ = struct.unpack_from("<II", section["data"])
        changed = bytearray(self.data)
        struct.pack_into("<I", changed, section["offset"] + 8 + count * 4 + 2 * 4, 2)
        with self.assertRaisesRegex(ValueError, "SysV"):
            self.bind(changed)

    def test_abort_symbol_version_cannot_be_rebound(self):
        for name, offset in ((".gnu.version", 2), (".gnu.version_r", 16)):
            changed = bytearray(self.data)
            changed[self.elf.section(name)["offset"] + offset] ^= 1
            with self.subTest(section=name), self.assertRaises(ValueError):
                self.bind(changed)

    def test_loop_call_allocation_and_unsupported_types_are_outside_profile(self):
        loop = {"schema": "hepta.hia.program.v8", "module": "loop", "functions": [
            f("loop", [("a", "u32")], ["u32"], [], [b("entry", [("a", "u32")], [], jump("entry", "a"))])]}
        signed = arithmetic("int.add.wrap", "i32")
        wide = arithmetic("int.mul.wrap", "u32")
        for name, core in (("loop", loop), ("signed", signed), ("multiply", wide)):
            with self.subTest(name=name), self.assertRaises(ValueError):
                build_safe_core(core, self.newpath(name + ".so"))

    def test_missing_solver_never_publishes_a_candidate(self):
        import hepta.hia_safe_core as module
        original = module.importlib.import_module
        def unavailable(name, *args, **kwargs):
            if name == "z3":
                raise ImportError("unavailable")
            return original(name, *args, **kwargs)
        output = self.newpath("unproved.so")
        with patch.object(module.importlib, "import_module", unavailable):
            with self.assertRaisesRegex(SafeCoreRejected, "unavailable"):
                build_safe_core(arithmetic("int.add.wrap", "u32"), output)
        self.assertFalse(output.exists())

    def test_solver_unknown_never_publishes_a_candidate(self):
        import z3
        original = z3.Solver
        class Unknown:
            def __init__(self, *args, **kwargs): self.inner = original(*args, **kwargs)
            def set(self, **kwargs): return self.inner.set(**kwargs)
            def add(self, *args): return self.inner.add(*args)
            def sexpr(self): return self.inner.sexpr()
            def check(self): return z3.unknown
            def reason_unknown(self): return "injected deadline"
        output = self.newpath("unknown.so")
        with patch.object(z3, "Solver", Unknown):
            with self.assertRaisesRegex(SafeCoreRejected, "unknown"):
                build_safe_core(arithmetic("int.add.wrap", "u32"), output)
        self.assertFalse(output.exists())

    def test_saved_smt_queries_replay_with_the_bound_solver(self):
        import z3
        queries = self.newpath("queries")
        report = build_safe_core(arithmetic("int.add.wrap", "u32"), self.newpath("replay.so"), query_directory=queries)
        for row in report["validation"]["obligations"]:
            solver = z3.Solver()
            solver.from_file(str(queries / row["query_file"]))
            self.assertEqual(str(solver.check()), row["result"])


class SafeCoreDecoderTests(unittest.TestCase):
    def test_unsupported_opcode_and_branch_into_an_immediate_are_rejected(self):
        for code in (b"\x0f\x05", b"\xe9\xfc\xff\xff\xff\xc3", b"\x48\xb8\x01"):
            with self.subTest(code=code.hex()), self.assertRaises(ValueError):
                decode(code)


if __name__ == "__main__":
    unittest.main()
