"""Consumer-side proofs use supplied bytes and no producer implementation."""
from __future__ import annotations

from hashlib import sha256
import importlib.util
import json
import ctypes
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_program import verify_program
from hepta.hia_program_native import emit_program_machine, compile_program_machine
from hepta.hia_safe_core import validate_safe_core_artifact, SafeCoreRejected
from hepta.hia_safe_core_elf import _ELF
from hepta.hia_safe_core_x64 import decode, SafeCoreMachineRejected
from hepta.hia_machine_x64 import Code
from hepta.hia_machine_elf import write_elf_object
from tools.check_hia_safe_core import check
from tests.test_hia_program import arithmetic, b, branch, c, f, i, jump, m, ret

ROOT = Path(__file__).resolve().parents[1]
AVAILABLE = (platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}
             and shutil.which("ld") is not None and importlib.util.find_spec("z3") is not None)


class SafeCoreImmutableInputTests(unittest.TestCase):
    def test_native_cnf_proof_wire_preserves_exact_independent_replay(self):
        from hepta.hia_cnf_native import SPARSE_REQUEST
        from hepta.hia_safe_core_x64_decode_native import selected_safe_core_x64_decode

        decoder = selected_safe_core_x64_decode()
        if decoder is None:
            self.skipTest("the cold HIA decoder is required")

        def packet(variables, clauses, tokens, budget=0):
            return struct.pack(f"<5Q{len(tokens)}H", SPARSE_REQUEST, variables,
                               clauses, budget, len(tokens), *tokens)

        expected = (
            b"(set-logic QF_UF)\n"
            b"(declare-fun v1 () Bool)\n(declare-fun v2 () Bool)\n(declare-fun v3 () Bool)\n"
            b"(assert false)\n(assert v1)\n(assert (not v2))\n(assert (or (not v1) v3))\n(check-sat)\n"
        )
        self.assertEqual(decoder.format_proof_query(packet(3, 4, (0, 2, 0, 5, 0, 3, 6, 0))), expected)
        top = decoder.format_proof_query(packet(4096, 1, (8193, 0)))
        self.assertTrue(top.endswith(b"(declare-fun v4096 () Bool)\n(assert (not v4096))\n(check-sat)\n"))
        for malformed in (packet(1, 1, (1, 0)), packet(1, 1, (4, 0)), packet(1, 1, (2,)),
                          packet(1, 2, (2, 0)), packet(1, 1, (2, 0), budget=1)):
            with self.subTest(malformed=malformed), self.assertRaises(ValueError):
                decoder.format_proof_query(malformed)

    def test_imul_register_fields_and_unreviewed_encodings(self):
        for destination in range(16):
            for source in range(16):
                encoded = bytes([0x48 | ((destination >> 3) << 2) | (source >> 3),
                                 0x0f, 0xaf, 0xc0 | ((destination & 7) << 3) | (source & 7)])
                with self.subTest(destination=destination, source=source):
                    instruction = decode(encoded)[0]
                    self.assertEqual((instruction.op, instruction.args, instruction.size),
                                     ("imul", (destination, source), 4))
        for encoded in ("0fafc1", "400fafc1", "660fafc1", "4a0fafc1",
                        "480faf01", "480faf8100000000", "f0480fafc1",
                        "48480fafc1", "480faf", "c30fafc1"):
            with self.subTest(encoded=encoded), self.assertRaises(SafeCoreMachineRejected):
                decode(bytes.fromhex(encoded))

    def test_mutable_buffers_and_bytes_subclasses_are_rejected_before_parsing(self):
        class DerivedBytes(bytes):
            pass

        for mutable in (bytearray(b"ELF"), memoryview(b"ELF"), DerivedBytes(b"ELF")):
            for object_bytes, final_bytes in ((mutable, b"ELF"), (b"ELF", mutable)):
                with self.subTest(type=type(mutable).__name__, object=type(object_bytes).__name__):
                    with patch("hepta.hia_safe_core.verify_program", side_effect=AssertionError("must reject before Core admission")):
                        with self.assertRaisesRegex(SafeCoreRejected, "immutable bytes"):
                            validate_safe_core_artifact({}, object_bytes, final_bytes)


@unittest.skipUnless(AVAILABLE, "Linux x86-64, GNU ld and pinned z3-solver are required")
class SafeCoreArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        retained = os.environ.get("HIA_SAFE_CORE_ARTIFACT_EVIDENCE")
        if retained:
            cls.root = Path(retained)
            cls.root.mkdir(parents=False, exist_ok=False)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix="hia-safe-core-artifact-tests-")
            cls.addClassCleanup(cls.temporary.cleanup)
            cls.root = Path(cls.temporary.name)
        cls.core = verify_program(arithmetic("int.add.wrap", "u32"))
        cls.image = emit_program_machine(cls.core)
        cls.final = cls.root / "reference.so"
        compile_program_machine(cls.image, program=cls.core, output=cls.final, linker="ld")
        cls.data = cls.final.read_bytes()

    def newdir(self):
        path = self.root / self._testMethodName
        path.mkdir()
        return path

    def test_last_identity_check_cannot_publish_a_proof_after_the_deadline(self):
        import hepta.hia_safe_core as checker
        original_identity, original_deadline = checker._solver_identity, checker._Theory.check_time
        identities = []

        def identify(z):
            identity = original_identity(z)
            identities.append(identity)
            return identity

        def deadline(theory):
            if len(identities) >= 2:
                raise SafeCoreRejected("test clock crossed the frozen deadline")
            original_deadline(theory)

        with (patch.object(checker, "_try_native_scalar_artifact", return_value=None),
              patch.object(checker, "_solver_identity", side_effect=identify),
              patch.object(checker._Theory, "check_time", deadline)):
            with self.assertRaises(SafeCoreRejected) as caught:
                validate_safe_core_artifact(self.core, self.image.object_bytes, self.data,
                                           query_directory=self.newdir() / "queries")
        partial = caught.exception.validation
        self.assertFalse(partial["ok"])
        self.assertFalse(partial["complete"])
        self.assertEqual(partial["status"], "unknown")
        self.assertEqual(partial["claims"], {})
        self.assertEqual(len(partial["obligations"]), 5)
        self.assertTrue(all(row["result"] == row["expected"] for row in partial["obligations"]))

    def mutate_pair(self, object_bytes, final_bytes, offset, replacement):
        obj, final = _ELF(object_bytes, 1), _ELF(final_bytes, 3)
        source, linked = bytearray(object_bytes), bytearray(final_bytes)
        for data, elf in ((source, obj), (linked, final)):
            at = elf.section(".text")["offset"] + offset
            data[at:at + len(replacement)] = replacement
        return bytes(source), bytes(linked)

    def wrong_addition(self):
        instructions = decode(self.image.text_bytes)
        offsets = [at for at, ins in instructions.items()
                   if ins.op == "add" and ins.args[:2] == (0, 1)]
        self.assertEqual(len(offsets), 1)
        at = offsets[0]
        self.assertEqual(self.image.text_bytes[at:at + 3], b"\x48\x01\xc8")
        return self.mutate_pair(self.image.object_bytes, self.data, at, b"\x48\x29\xc8")

    def test_native_word_model_proves_signed_unsigned_comparisons_and_conditional_moves(self):
        from hepta.hia_safe_core import _selected_machine_proof
        from tools.qualify_hia_machine_registers import explicit_plan

        if any(component is None for component in _selected_machine_proof()):
            self.skipTest("requires the native HIA x64 decoder and CNF solver")
        real_import = importlib.import_module

        def no_host_solver(name, *args, **kwargs):
            if name == "z3":
                raise AssertionError("the admitted flag semantics reached the hosted checker")
            return real_import(name, *args, **kwargs)

        directory = self.newdir()
        cases = (("u32", "lt", 1), ("i32", "ge", 6), ("u64", "eq", 1))
        for typ, predicate, version in cases:
            for selection in ("none", "cmov", "branch"):
                with self.subTest(typ=typ, predicate=predicate, selection=selection):
                    params = [("left", typ), ("right", typ)]
                    compare = i("compare." + predicate, ("left", "right"), (("choice", "bool"),))
                    ops, returns, result = [compare], ["bool"], "choice"
                    if selection != "none":
                        ops.append(i("select", ("choice", "left", "right"), (("selected", typ),)))
                        returns, result = [typ], "selected"
                    core = verify_program(m(f("compare_words", params, returns, [],
                                              [b("entry", params, ops, ret(result))])))
                    plan = explicit_plan(core, select="cmov_scalar") if selection == "cmov" else None
                    image = emit_program_machine(core, machine_plan=plan)
                    final = directory / (f"{typ}-{selection}.so")
                    compile_program_machine(image, program=core, output=final, linker="ld", machine_plan=plan)
                    text = decode(image.text_bytes, allow_signed=version == 6)
                    flag_op = next((at, op) for at, op in text.items() if op.op == "setcc")
                    self.assertEqual(any(op.op == "cmovne" for op in text.values()), selection == "cmov")
                    self.assertEqual(any(op.op == "jcc" for op in text.values()), selection == "branch")
                    with patch("importlib.import_module", side_effect=no_host_solver):
                        report = validate_safe_core_artifact(core, image.object_bytes, final.read_bytes(),
                                                             profile_version=version)
                        self.assertTrue(report["complete"])
                        self.assertEqual(report["solver"]["version"], "machine-word-circuit-cnf.v1")
                        self.assertEqual(report["model_counts"]["machine_terminal_paths"],
                                         2 if selection == "branch" else 1)
                        at, instruction = flag_op
                        original = image.text_bytes[at:at + instruction.size]
                        changed = original[:2] + bytes([original[2] ^ 1]) + original[3:]
                        obj, supplied = self.mutate_pair(image.object_bytes, final.read_bytes(), at, changed)
                        with self.assertRaises(SafeCoreRejected) as caught:
                            validate_safe_core_artifact(core, obj, supplied, profile_version=version)
                        self.assertEqual(caught.exception.validation["status"], "refuted")

    def test_native_machine_proof_follows_a_core_diamond_and_exact_join_parameters(self):
        from hepta.hia_safe_core import _selected_machine_proof

        if any(component is None for component in _selected_machine_proof()):
            self.skipTest("requires the native HIA x64 decoder and CNF solver")
        real_import = importlib.import_module

        def no_host_solver(name, *args, **kwargs):
            if name == "z3":
                raise AssertionError("a finite Core diamond entered the hosted checker")
            return real_import(name, *args, **kwargs)

        arguments = [("left", "u32"), ("right", "u32")]
        blocks = [
            b("entry", arguments, [i("compare.lt", ("left", "right"), (("condition", "bool"),))],
              branch("condition", ("choose_left", "left"), ("choose_right", "right"))),
            b("join", [("chosen", "u32")], [], ret("chosen")),
            b("choose_left", [("first", "u32")], [], jump("join", "first")),
            b("choose_right", [("second", "u32")], [], jump("join", "second")),
        ]
        core = verify_program(m(f("minimum", arguments, ["u32"], [], blocks)))
        image = emit_program_machine(core)
        final = self.newdir() / "minimum.so"
        compile_program_machine(image, program=core, output=final, linker="ld")
        supplied = final.read_bytes()
        with patch("importlib.import_module", side_effect=no_host_solver):
            report = validate_safe_core_artifact(core, image.object_bytes, supplied)
        self.assertTrue(report["complete"])
        self.assertEqual(report["solver"]["version"], "machine-word-circuit-cnf.v1")
        self.assertEqual(report["model_counts"]["core_terminal_paths"], 2)
        self.assertEqual(report["model_counts"]["machine_terminal_paths"], 2)

    def test_native_machine_partition_replays_distinct_nested_prefixes(self):
        from hepta.hia_safe_core import _selected_machine_proof

        if any(component is None for component in _selected_machine_proof()):
            self.skipTest("requires the native HIA x64 decoder and CNF solver")
        real_import = importlib.import_module

        def no_host_solver(name, *args, **kwargs):
            if name == "z3":
                raise AssertionError("the machine partition entered the hosted checker")
            return real_import(name, *args, **kwargs)

        arguments = [("left", "u8"), ("right", "u8"), ("middle", "u8")]
        blocks = [
            b("entry", arguments, [i("compare.lt", ("left", "right"), (("first", "bool"),))],
              branch("first", ("less", "left", "middle"), ("more", "right", "middle"))),
            b("less", [("low", "u8"), ("less_middle", "u8")],
              [i("compare.lt", ("low", "less_middle"), (("second", "bool"),))],
              branch("second", ("small", "low"), ("small", "less_middle"))),
            b("more", [("high", "u8"), ("more_middle", "u8")],
              [i("compare.le", ("high", "more_middle"), (("third", "bool"),))],
              branch("third", ("large", "more_middle"), ("large", "high"))),
            b("small", [("minimum", "u8")], [], jump("join", "minimum")),
            b("large", [("maximum", "u8")], [], jump("join", "maximum")),
            b("join", [("chosen", "u8")], [], ret("chosen")),
        ]
        core = verify_program(m(f("partition", arguments, ["u8"], [], blocks)))
        image = emit_program_machine(core)
        final = self.newdir() / "partition.so"
        compile_program_machine(image, program=core, output=final, linker="ld")
        supplied = final.read_bytes()
        with patch("importlib.import_module", side_effect=no_host_solver):
            report = validate_safe_core_artifact(core, image.object_bytes, supplied)
        self.assertTrue(report["complete"])
        self.assertEqual(report["solver"]["version"], "machine-word-circuit-cnf.v1")
        self.assertEqual(report["model_counts"]["core_terminal_paths"], 4)
        self.assertEqual(report["model_counts"]["machine_terminal_paths"], 4)

    def test_native_machine_proof_joins_abort_and_return_without_a_host_solver(self):
        from hepta.hia_safe_core import _selected_machine_proof

        if any(component is None for component in _selected_machine_proof()):
            self.skipTest("requires the native HIA x64 decoder and CNF solver")
        real_import = importlib.import_module

        def no_host_solver(name, *args, **kwargs):
            if name == "z3":
                raise AssertionError("the abort partition entered the hosted checker")
            return real_import(name, *args, **kwargs)

        arguments = [("left", "u8"), ("right", "u8")]

        def source(comparison):
            blocks = [
                b("entry", arguments, [i(comparison, ("left", "right"), (("condition", "bool"),))],
                  branch("condition", ("failure",), ("success", "right"))),
                b("success", [("result", "u8")], [], ret("result")),
                b("failure", [], [], {"op": "trap", "code": "user"}),
            ]
            return verify_program(m(f("check", arguments, ["u8"], ["trap"], blocks)))

        core = source("compare.lt")
        image = emit_program_machine(core)
        final = self.newdir() / "conditional-abort.so"
        compile_program_machine(image, program=core, output=final, linker="ld")
        supplied = final.read_bytes()
        with patch("importlib.import_module", side_effect=no_host_solver):
            report = validate_safe_core_artifact(core, image.object_bytes, supplied)
            with self.assertRaises(SafeCoreRejected) as refused:
                validate_safe_core_artifact(source("compare.eq"), image.object_bytes, supplied)
        self.assertTrue(report["complete"])
        self.assertEqual(report["solver"]["version"], "machine-word-circuit-cnf.v1")
        self.assertEqual(report["model_counts"]["machine_terminal_paths"], 2)
        self.assertEqual(refused.exception.validation["status"], "refuted")

    def test_native_machine_defines_arithmetic_flags_for_checked_add_and_subtract(self):
        from hepta.hia_safe_core import _selected_machine_proof

        if any(component is None for component in _selected_machine_proof()):
            self.skipTest("requires the native HIA x64 decoder and CNF solver")
        real_import = importlib.import_module

        def no_host_solver(name, *args, **kwargs):
            if name == "z3":
                raise AssertionError("checked arithmetic entered the hosted checker")
            return real_import(name, *args, **kwargs)

        directory = self.newdir()
        for profile, typ in ((1, "u64"), (6, "i64")):
            for op in ("int.add.checked", "int.sub.checked"):
                with self.subTest(typ=typ, operation=op):
                    core = verify_program(arithmetic(op, typ))
                    image = emit_program_machine(core)
                    final = directory / (typ + "-" + op + ".so")
                    compile_program_machine(image, program=core, output=final, linker="ld")
                    with patch("importlib.import_module", side_effect=no_host_solver):
                        report = validate_safe_core_artifact(core, image.object_bytes, final.read_bytes(),
                                                            profile_version=profile)
                    self.assertTrue(report["complete"])
                    self.assertEqual(report["solver"]["version"], "machine-word-circuit-cnf.v1")
                    self.assertEqual(report["model_counts"]["machine_terminal_paths"], 2)

    def test_native_borrowed_length_proves_the_exact_packed_extent_guard(self):
        from hepta.hia_safe_core import _selected_machine_proof

        if any(component is None for component in _selected_machine_proof()):
            self.skipTest("requires the native HIA x64 decoder and CNF solver")
        real_import = importlib.import_module

        def no_host_solver(name, *args, **kwargs):
            if name == "z3":
                raise AssertionError("the borrowed length proof entered the hosted checker")
            return real_import(name, *args, **kwargs)

        params = [("loan", "readbuf")]
        ops = [i("buffer.len", ("loan",), (("extent", "usize"),)),
               i("int.cast", ("extent",), (("answer", "u32"),), mode="wrap")]
        core = verify_program(m(f("loan_length", params, ["u32"], ["read", "trap"],
                                  [b("entry", params, ops, ret("answer"))])))
        exports = (("loan_length", 64),)
        image = emit_program_machine(core, foreign_buffer_exports=exports)
        final = self.newdir() / "loan-length.so"
        compile_program_machine(image, program=core, output=final, linker="ld")
        supplied = final.read_bytes()
        with patch("importlib.import_module", side_effect=no_host_solver):
            report = validate_safe_core_artifact(core, image.object_bytes, supplied,
                                                 foreign_buffer_exports=exports)
            with self.assertRaises(SafeCoreRejected) as refused:
                validate_safe_core_artifact(core, image.object_bytes, supplied,
                                            foreign_buffer_exports=(("loan_length", 63),))
        self.assertTrue(report["complete"])
        self.assertEqual(report["solver"]["version"], "machine-word-circuit-cnf.v1")
        self.assertEqual(report["foreign_buffer_exports"], [["loan_length", 64]])
        self.assertEqual(refused.exception.validation["status"], "refuted")
        self.assertEqual(refused.exception.counterexample["abi_words"][1], 64)

    def test_native_borrowed_byte_proves_bounds_abort_and_the_exact_return(self):
        from hepta.hia_safe_core import _selected_machine_proof

        if any(component is None for component in _selected_machine_proof()):
            self.skipTest("requires the native HIA x64 decoder and CNF solver")
        real_import = importlib.import_module

        def no_host_solver(name, *args, **kwargs):
            if name == "z3":
                raise AssertionError("the fixed borrowed read entered the hosted checker")
            return real_import(name, *args, **kwargs)

        params = [("loan", "readbuf")]
        directory = self.newdir()
        for index in (0, 7):
            with self.subTest(index=index):
                name = "loan_byte_" + str(index)
                ops = [c("index", "usize", index),
                       i("buffer.load", ("loan", "index"), (("byte", "u8"),)),
                       i("int.cast", ("byte",), (("answer", "u32"),), mode="wrap")]
                core = verify_program(m(f(name, params, ["u32"], ["read", "trap"],
                                          [b("entry", params, ops, ret("answer"))])))
                exports = ((name, 64),)
                image = emit_program_machine(core, foreign_buffer_exports=exports)
                final = directory / (name + ".so")
                compile_program_machine(image, program=core, output=final, linker="ld")
                supplied = final.read_bytes()
                with patch("importlib.import_module", side_effect=no_host_solver):
                    report = validate_safe_core_artifact(core, image.object_bytes, supplied,
                                                         foreign_buffer_exports=exports)
                    with self.assertRaises(SafeCoreRejected) as refused:
                        validate_safe_core_artifact(core, image.object_bytes, supplied,
                                                    foreign_buffer_exports=((name, 63),))
                self.assertTrue(report["complete"])
                self.assertEqual(report["solver"]["version"], "machine-word-circuit-cnf.v1")
                outcomes = {row["name"]: row for row in report["obligations"]}
                bounds = outcomes["machine_memory_access_bounds"]
                self.assertEqual(bounds["result"], "unsat")
                self.assertNotIn("structural_reduction", bounds["native_cnf"])
                self.assertEqual(refused.exception.validation["status"], "refuted")
                witness = refused.exception.counterexample
                self.assertEqual(witness["obligation"], "machine_memory_access_bounds")
                self.assertEqual(witness["abi_words"][1], 64)

    def test_native_borrowed_index_is_proved_for_all_abi_words(self):
        from hepta.hia_safe_core import _selected_machine_proof

        if any(component is None for component in _selected_machine_proof()):
            self.skipTest("requires the native HIA x64 decoder and CNF solver")
        real_import = importlib.import_module

        def no_host_solver(name, *args, **kwargs):
            if name == "z3":
                raise AssertionError("the indexed loan proof entered the hosted checker")
            return real_import(name, *args, **kwargs)

        params = [("loan", "readbuf"), ("index", "usize")]
        ops = [i("buffer.load", ("loan", "index"), (("byte", "u8"),)),
               i("int.cast", ("byte",), (("answer", "u32"),), mode="wrap")]
        core = verify_program(m(f("loan_at", params, ["u32"], ["read", "trap"],
                                  [b("entry", params, ops, ret("answer"))])))
        exports = (("loan_at", 64),)
        image = emit_program_machine(core, foreign_buffer_exports=exports)
        final = self.newdir() / "loan-at.so"
        compile_program_machine(image, program=core, output=final, linker="ld")
        supplied = final.read_bytes()
        with patch("importlib.import_module", side_effect=no_host_solver):
            report = validate_safe_core_artifact(core, image.object_bytes, supplied,
                                                 foreign_buffer_exports=exports)
            with self.assertRaises(SafeCoreRejected) as refused:
                validate_safe_core_artifact(core, image.object_bytes, supplied,
                                            foreign_buffer_exports=(("loan_at", 63),))
        self.assertTrue(report["complete"])
        self.assertEqual(report["solver"]["version"], "machine-word-circuit-cnf.v1")
        self.assertEqual([row["result"] for row in report["obligations"]],
                         ["sat", "unsat", "unsat", "unsat", "unsat"])
        witness = refused.exception.counterexample
        self.assertEqual(witness["obligation"], "machine_memory_access_bounds")
        self.assertEqual(witness["abi_words"][1], 64)
        self.assertLess(witness["abi_words"][2], 64)
        self.assertEqual(witness["caller_byte"]["offset"], witness["abi_words"][2])

    def test_native_borrowed_pair_proves_independent_caller_bytes(self):
        from hepta.hia_safe_core import _selected_machine_proof

        if any(component is None for component in _selected_machine_proof()):
            self.skipTest("requires the native HIA x64 decoder and CNF solver")
        real_import = importlib.import_module

        def no_host_solver(name, *args, **kwargs):
            if name == "z3":
                raise AssertionError("the paired loan proof entered the hosted checker")
            return real_import(name, *args, **kwargs)

        params = [("loan", "readbuf")]
        exports = (("loan_pair", 64),)
        directory = self.newdir()

        def build(operation, *, reverse=False):
            inputs = ("rhs", "lhs") if reverse else ("lhs", "rhs")
            ops = [c("right", "usize", 7),
                   i("buffer.load", ("loan", "right"), (("rhs", "u8"),)),
                   c("left", "usize", 0),
                   i("buffer.load", ("loan", "left"), (("lhs", "u8"),)),
                   i(operation, inputs, (("value", "u8"),)),
                   i("int.cast", ("value",), (("answer", "u32"),), mode="wrap")]
            core = verify_program(m(f("loan_pair", params, ["u32"], ["read", "trap"],
                                      [b("entry", params, ops, ret("answer"))])))
            image = emit_program_machine(core, foreign_buffer_exports=exports)
            final = directory / (operation + ("-reverse" if reverse else "") + ".so")
            compile_program_machine(image, program=core, output=final, linker="ld")
            return core, image.object_bytes, final.read_bytes()

        core, obj, supplied = build("bit.xor")
        and_program, wrong_obj, wrong = build("bit.and")
        with patch("importlib.import_module", side_effect=no_host_solver):
            report = validate_safe_core_artifact(core, obj, supplied, foreign_buffer_exports=exports)
            with self.assertRaises(SafeCoreRejected) as too_wide:
                validate_safe_core_artifact(core, obj, supplied, foreign_buffer_exports=(("loan_pair", 63),))
            with self.assertRaises(SafeCoreRejected) as wrong_value:
                validate_safe_core_artifact(core, wrong_obj, wrong, foreign_buffer_exports=exports)
        self.assertTrue(report["complete"])
        self.assertEqual(report["solver"]["version"], "machine-word-circuit-cnf.v1")
        self.assertEqual(too_wide.exception.counterexample["obligation"], "machine_memory_access_bounds")
        caller_bytes = wrong_value.exception.counterexample["caller_bytes"]
        self.assertEqual([byte["offset"] for byte in caller_bytes], [0, 7])
        left, right = (byte["value"] for byte in caller_bytes)
        self.assertNotEqual(left ^ right, left & right)

        programs = {"bit.and": (and_program, wrong_obj, wrong)}
        for operation in ("bit.and", "bit.or", "int.add.wrap", "int.sub.wrap"):
            with self.subTest(operation=operation):
                if operation not in programs:
                    programs[operation] = build(operation)
                program, primary_object, primary = programs[operation]
                with patch("importlib.import_module", side_effect=no_host_solver):
                    qualified = validate_safe_core_artifact(
                        program, primary_object, primary, foreign_buffer_exports=exports)
                self.assertTrue(qualified["complete"])
                self.assertEqual(qualified["solver"]["version"], "machine-word-circuit-cnf.v1")
        forward_program, _, _ = programs["int.sub.wrap"]
        reverse_program, reverse_object, reverse = build("int.sub.wrap", reverse=True)
        with patch("importlib.import_module", side_effect=no_host_solver):
            result = validate_safe_core_artifact(reverse_program, reverse_object, reverse,
                                                 foreign_buffer_exports=exports)
            with self.assertRaises(SafeCoreRejected) as backwards:
                validate_safe_core_artifact(forward_program, reverse_object, reverse,
                                            foreign_buffer_exports=exports)
        self.assertTrue(result["complete"])
        lhs, rhs = (byte["value"] for byte in backwards.exception.counterexample["caller_bytes"])
        self.assertNotEqual((lhs - rhs) & 255, (rhs - lhs) & 255)

    def test_native_borrowed_write_proves_effects_on_all_terminal_paths(self):
        from hepta.hia_safe_core import _selected_machine_proof

        if any(component is None for component in _selected_machine_proof()):
            self.skipTest("requires the native HIA x64 decoder and CNF solver")
        real_import = importlib.import_module

        def no_host_solver(name, *args, **kwargs):
            if name == "z3":
                raise AssertionError("the mutable loan proof entered the hosted checker")
            return real_import(name, *args, **kwargs)

        exports = (("loan_write", 64),)
        directory = self.newdir()

        def build(indexed, substitute=None):
            params = [("loan", "mutbuf")]
            if indexed:
                params.append(("index", "usize"))
            params.append(("value", "u8"))
            ops = [] if indexed else [c("index", "usize", 7)]
            value = "value"
            if substitute is not None:
                value = "substitute"
                ops.append(c(value, "u8", substitute))
            ops.extend([i("buffer.store", ("loan", "index", value)), c("zero", "u32", 0)])
            core = verify_program(m(f("loan_write", params, ["u32"], ["write", "trap"],
                                      [b("entry", params, ops, ret("zero"))])))
            image = emit_program_machine(core, foreign_buffer_exports=exports)
            final = directory / f"write-{indexed}-{substitute}.so"
            compile_program_machine(image, program=core, output=final, linker="ld")
            return core, image.object_bytes, final.read_bytes()

        for indexed in (False, True):
            with self.subTest(indexed=indexed):
                core, obj, supplied = build(indexed)
                _, wrong_obj, wrong = build(indexed, substitute=17)
                with patch("importlib.import_module", side_effect=no_host_solver):
                    report = validate_safe_core_artifact(core, obj, supplied, foreign_buffer_exports=exports)
                    with self.assertRaises(SafeCoreRejected) as too_wide:
                        validate_safe_core_artifact(core, obj, supplied, foreign_buffer_exports=(("loan_write", 63),))
                    with self.assertRaises(SafeCoreRejected) as wrong_value:
                        validate_safe_core_artifact(core, wrong_obj, wrong, foreign_buffer_exports=exports)
                self.assertTrue(report["complete"])
                self.assertEqual(report["solver"]["version"], "machine-word-circuit-cnf.v1")
                self.assertEqual(too_wide.exception.counterexample["obligation"], "machine_memory_access_bounds")
                witness = wrong_value.exception.counterexample
                words = witness["abi_words"]
                self.assertEqual(witness["obligation"], "core_to_final_image_return_abort_and_caller_bytes")
                self.assertEqual(witness["caller_byte"]["offset"], words[2] if indexed else 7)
                self.assertNotEqual(words[-1] & 255, 17)

    def test_native_read_after_write_distinguishes_pre_and_post_store_memory(self):
        from hepta.hia_safe_core import _selected_machine_proof

        if any(component is None for component in _selected_machine_proof()):
            self.skipTest("requires the native HIA x64 decoder and CNF solver")
        real_import = importlib.import_module

        def no_host_solver(name, *args, **kwargs):
            if name == "z3":
                raise AssertionError("the mutable loan readback entered the hosted checker")
            return real_import(name, *args, **kwargs)

        exports = (("loan_readback", 64),)
        directory = self.newdir()

        def build(indexed, load_first=False):
            params = [("loan", "mutbuf")]
            ops = [] if indexed else [c("index", "usize", 7)]
            if indexed:
                params.append(("index", "usize"))
            params.append(("value", "u8"))
            store = i("buffer.store", ("loan", "index", "value"))
            load = i("buffer.load", ("loan", "index"), (("loaded", "u8"),))
            ops.extend((load, store) if load_first else (store, load))
            ops.append(i("int.cast", ("loaded",), (("result", "u32"),), mode="wrap"))
            core = verify_program(m(f("loan_readback", params, ["u32"], ["read", "write", "trap"],
                                      [b("entry", params, ops, ret("result"))])))
            image = emit_program_machine(core, foreign_buffer_exports=exports)
            final = directory / f"readback-{indexed}-{load_first}.so"
            compile_program_machine(image, program=core, output=final, linker="ld")
            return core, image.object_bytes, final.read_bytes()

        for indexed in (False, True):
            with self.subTest(indexed=indexed):
                core, obj, supplied = build(indexed)
                exchange, wrong_obj, wrong = build(indexed, load_first=True)
                with patch("importlib.import_module", side_effect=no_host_solver):
                    report = validate_safe_core_artifact(core, obj, supplied, foreign_buffer_exports=exports)
                    with self.assertRaises(SafeCoreRejected) as stale:
                        validate_safe_core_artifact(core, wrong_obj, wrong, foreign_buffer_exports=exports)
                    exchange_report = validate_safe_core_artifact(
                        exchange, wrong_obj, wrong, foreign_buffer_exports=exports)
                    with self.assertRaises(SafeCoreRejected) as invented_prior:
                        validate_safe_core_artifact(exchange, obj, supplied, foreign_buffer_exports=exports)
                for checked in (report, exchange_report):
                    self.assertTrue(checked["complete"])
                    self.assertEqual(checked["solver"]["version"], "machine-word-circuit-cnf.v1")
                self.assertEqual(invented_prior.exception.counterexample["obligation"],
                                 "core_to_final_image_return_abort_and_caller_bytes")
                witness = stale.exception.counterexample
                words = witness["abi_words"]
                self.assertEqual(witness["obligation"], "core_to_final_image_return_abort_and_caller_bytes")
                self.assertEqual(witness["caller_byte"]["offset"], words[2] if indexed else 7)
                self.assertNotEqual(witness["caller_byte"]["value"], words[-1] & 255)

    def test_native_write_and_return_length_check_both_observations(self):
        from hepta.hia_safe_core import _selected_machine_proof

        if any(component is None for component in _selected_machine_proof()):
            self.skipTest("requires the native HIA x64 decoder and CNF solver")
        real_import = importlib.import_module

        def no_host_solver(name, *args, **kwargs):
            if name == "z3":
                raise AssertionError("the mutable loan length entered the hosted checker")
            return real_import(name, *args, **kwargs)

        directory = self.newdir()
        exports = (("loan_write_length", 64),)

        def build(indexed, return_length):
            params = [("loan", "mutbuf")]
            position = [] if indexed else [c("index", "usize", 7)]
            if indexed:
                params.append(("index", "usize"))
            params.append(("value", "u8"))
            store = i("buffer.store", ("loan", "index", "value"))
            result = [c("result", "u32", 0)]
            if return_length:
                result = [i("buffer.len", ("loan",), (("length", "usize"),)),
                          i("int.cast", ("length",), (("result", "u32"),), mode="wrap")]
            core = verify_program(m(f("loan_write_length", params, ["u32"], ["read", "write", "trap"],
                                      [b("entry", params, [*position, store, *result], ret("result"))])))
            image = emit_program_machine(core, foreign_buffer_exports=exports)
            final = directory / f"write-length-{indexed}-{return_length}.so"
            compile_program_machine(image, program=core, output=final, linker="ld")
            return core, image.object_bytes, final.read_bytes()

        for indexed in (False, True):
            with self.subTest(indexed=indexed):
                core, obj, valid = build(indexed, True)
                _, wrong_obj, wrong = build(indexed, False)
                with patch("importlib.import_module", side_effect=no_host_solver):
                    report = validate_safe_core_artifact(core, obj, valid, foreign_buffer_exports=exports)
                    with self.assertRaises(SafeCoreRejected) as mismatch:
                        validate_safe_core_artifact(core, wrong_obj, wrong, foreign_buffer_exports=exports)
                self.assertTrue(report["complete"])
                self.assertEqual(report["solver"]["version"], "machine-word-circuit-cnf.v1")
                counterexample = mismatch.exception.counterexample
                self.assertEqual(counterexample["obligation"], "core_to_final_image_return_abort_and_caller_bytes")
                words = counterexample["abi_words"]
                self.assertEqual(counterexample["caller_byte"]["offset"], words[2] if indexed else 7)
                self.assertGreater(words[1], counterexample["caller_byte"]["offset"])

    def test_native_machine_proves_checked_product_overflow_at_full_width(self):
        from hepta.hia_safe_core import _selected_machine_proof

        if any(component is None for component in _selected_machine_proof()):
            self.skipTest("requires the native HIA x64 decoder and CNF solver")
        real_import = importlib.import_module

        def no_host_solver(name, *args, **kwargs):
            if name == "z3":
                raise AssertionError("checked multiplication entered the hosted checker")
            return real_import(name, *args, **kwargs)

        directory = self.newdir()
        for typ, profile in (("u64", 4), ("i64", 6)):
            with self.subTest(typ=typ):
                core = verify_program(arithmetic("int.mul.checked", typ))
                image = emit_program_machine(core)
                final = directory / (typ + "-checked-product.so")
                compile_program_machine(image, program=core, output=final, linker="ld")
                with patch("importlib.import_module", side_effect=no_host_solver):
                    report = validate_safe_core_artifact(core, image.object_bytes, final.read_bytes(),
                                                         profile_version=profile)
                self.assertTrue(report["complete"])
                self.assertEqual(report["solver"]["version"], "machine-word-circuit-cnf.v1")
                self.assertEqual(report["model_counts"]["machine_terminal_paths"], 2)
                self.assertEqual([row["result"] for row in report["obligations"]],
                                 ["sat", "unsat", "unsat", "unsat", "unsat"])

    def test_selected_scalar_elf_proof_checks_actual_bytes_without_host_solver(self):
        import z3
        from hepta.hia_safe_core import _selected_machine_proof

        if any(component is None for component in _selected_machine_proof()):
            self.skipTest("requires the native HIA x64 decoder and CNF solver")
        real_import = importlib.import_module

        def no_host_solver(name, *args, **kwargs):
            if name == "z3":
                raise AssertionError("the hosted checker must not run on this scalar lane")
            return real_import(name, *args, **kwargs)

        directory = self.newdir()
        for typ, op, version in (("u8", "int.mul.wrap", 1), ("u32", "int.sub.wrap", 1),
                                 ("u32", "int.mul.wrap", 1), ("u64", "int.mul.wrap", 1),
                                 ("i32", "int.add.wrap", 6), ("i32", "int.mul.wrap", 6)):
            with self.subTest(type=typ, operation=op):
                core = verify_program(arithmetic(op, typ))
                image = emit_program_machine(core)
                case = typ + "-" + op
                final = directory / (case + ".so")
                compile_program_machine(image, program=core, output=final, linker="ld")
                queries = directory / (case + "-queries")
                with patch("importlib.import_module", side_effect=no_host_solver):
                    proof = validate_safe_core_artifact(
                        core, image.object_bytes, final.read_bytes(), profile_version=version,
                        query_directory=queries)
                self.assertTrue(proof["complete"])
                self.assertEqual(proof["solver"]["version"], "machine-word-circuit-cnf.v1")
                self.assertEqual([row["result"] for row in proof["obligations"]],
                                 ["sat", "unsat", "unsat", "unsat", "unsat"])
                for row in proof["obligations"]:
                    query = (queries / row["query_file"]).read_bytes()
                    self.assertEqual(row["query_sha256"], sha256(query).hexdigest())
                    independent = z3.Solver()
                    independent.from_string(query.decode())
                    self.assertEqual(str(independent.check()), row["result"])
        obj, final = self.wrong_addition()
        queries = directory / "refuted-queries"
        with patch("importlib.import_module", side_effect=no_host_solver), self.assertRaises(SafeCoreRejected) as caught:
            validate_safe_core_artifact(self.core, obj, final, query_directory=queries)
        error = caught.exception
        self.assertEqual(error.validation["status"], "refuted")
        self.assertFalse(error.validation["complete"])
        self.assertEqual(error.validation["subject"]["final_image_sha256"], sha256(final).hexdigest())
        left, right = error.counterexample["abi_words"]
        self.assertNotEqual((left + right) & 0xffffffff, (left - right) & 0xffffffff)
        last = error.validation["obligations"][-1]
        independent = z3.Solver()
        independent.from_string((queries / last["query_file"]).read_text())
        self.assertEqual(independent.check(), z3.sat)

    def custom_leaf(self, code, name="leaf"):
        # Retain the established two-function, two-relocation artifact shape.
        code.ret()
        code.call("abort")
        code.emit(b"\x0f\x0b")
        wrapper = code.offset
        code.push("rbp")
        code.mov_rr("rbp", "rsp")
        code.call("__hia_native_fn_0")
        code.emit(b"\xc9")
        code.ret()
        text, relocations = code.finalize()
        symbols = [{"name": "__hia_native_fn_0", "offset": 0, "size": wrapper, "global": False},
                   {"name": "calculate", "offset": wrapper,
                    "size": len(text) - wrapper, "global": True}]
        obj = write_elf_object(text, symbols, relocations)
        directory = self.root / (self._testMethodName + "-" + name)
        directory.mkdir()
        object_path, final_path = directory / "leaf.o", directory / "leaf.so"
        object_path.write_bytes(obj)
        process = subprocess.run(["ld", "-m", "elf_x86_64", "-shared", "-z", "defs",
            "-z", "noexecstack", "-z", "relro", "-z", "now", "--hash-style=both",
            "--build-id=none", str(object_path), "-lc", "-o", str(final_path)],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        return obj, final_path.read_bytes()

    def test_wrapping_multiplication_is_proved_and_executed_at_all_unsigned_widths(self):
        directory = self.newdir()
        for typ, width in (("u8", 8), ("u32", 32), ("u64", 64), ("usize", 64)):
            with self.subTest(type=typ):
                core = verify_program(arithmetic("int.mul.wrap", typ))
                image = emit_program_machine(core)
                final = directory / (typ + ".so")
                compile_program_machine(image, program=core, output=final, linker="ld")
                (directory / (typ + ".json")).write_bytes(core.canonical_bytes)
                (directory / (typ + ".o")).write_bytes(image.object_bytes)
                proof = validate_safe_core_artifact(core, image.object_bytes, final.read_bytes(),
                    query_directory=directory / (typ + "-queries"))
                (directory / (typ + "-validation.json")).write_text(json.dumps(proof, indent=2) + "\n")
                self.assertTrue(proof["ok"])
                self.assertEqual([row["result"] for row in proof["obligations"]],
                                 ["sat", "unsat", "unsat", "unsat", "unsat"])
                self.assertEqual(proof["subject"]["final_image_sha256"], sha256(final.read_bytes()).hexdigest())
                for key in ("subject", "property", "profile", "assumptions", "checker", "unproved_obligations"):
                    self.assertIn(key, proof)
                function = ctypes.CDLL(str(final)).calculate
                function.argtypes, function.restype = [ctypes.c_uint64, ctypes.c_uint64], ctypes.c_uint64
                mask = (1 << width) - 1
                values = (0, 1, 2, 127, 255, 1 << (width - 1), mask, (1 << 64) - 1)
                for left in values:
                    for right in values:
                        self.assertEqual(function(left, right), (left * right) & mask)
        self.case_counts = {"all_input_wrapping_multiply_functions": 4,
                            "native_wrapping_multiply_calls": 256}

    def test_imul_zero_flag_is_arbitrary_after_a_known_zero_flag(self):
        core = verify_program({"schema": "hepta.hia.program.v8", "module": "flags", "functions": [
            f("calculate", [], ["u64"], [], [b("entry", [], [c("one", "u64", 1)], ret("one"))])]})
        code = Code()
        code.xor("rax", "rax")
        code.imul("rax", "rax")
        code.setcc("e", "rax")
        obj, data = self.custom_leaf(code)
        (self.root / (self._testMethodName + "-core.json")).write_bytes(core.canonical_bytes)
        with self.assertRaises(SafeCoreRejected) as caught:
            validate_safe_core_artifact(core, obj, data,
                query_directory=self.root / (self._testMethodName + "-queries"))
        (self.root / (self._testMethodName + "-validation.json")).write_text(json.dumps(
            caught.exception.validation, indent=2) + "\n")
        self.assertEqual(caught.exception.counterexample["obligation"],
                         "core_to_final_image_return_abort_and_caller_bytes")
        self.assertEqual(caught.exception.validation["obligations"][-1]["result"], "sat")

    def test_joint_product_to_sum_mutation_is_refuted(self):
        core = verify_program(arithmetic("int.mul.wrap", "u32"))
        image = emit_program_machine(core)
        directory = self.newdir()
        final = directory / "product.so"
        compile_program_machine(image, program=core, output=final, linker="ld")
        offsets = [at for at, instruction in decode(image.text_bytes).items()
                   if instruction.op == "imul" and instruction.args == (0, 1)]
        self.assertEqual(len(offsets), 1)
        obj, data = self.mutate_pair(image.object_bytes, final.read_bytes(), offsets[0], b"\x48\x01\xc8\x90")
        (directory / "mutated.o").write_bytes(obj)
        (directory / "mutated.so").write_bytes(data)
        (directory / "core.json").write_bytes(core.canonical_bytes)
        with self.assertRaises(SafeCoreRejected) as caught:
            validate_safe_core_artifact(core, obj, data, query_directory=directory / "queries")
        (directory / "validation.json").write_text(json.dumps(caught.exception.validation, indent=2) + "\n")
        witness = caught.exception.counterexample
        self.assertEqual(witness["obligation"], "core_to_final_image_return_abort_and_caller_bytes")
        left, right = [word & 0xffffffff for word in witness["abi_words"]]
        self.assertNotEqual((left * right) & 0xffffffff, (left + right) & 0xffffffff)

    def test_imul_carry_matches_signed_not_unsigned_truncation(self):
        pairs = ((1 << 63, 1), ((1 << 64) - 1, 1), ((1 << 64) - 1, (1 << 64) - 1),
                 ((1 << 63) - 1, 2), (1 << 63, (1 << 64) - 1), (1 << 63, 2))
        for index, (left, right) in enumerate(pairs):
            signed = lambda word: word - (1 << 64) if word >= 1 << 63 else word
            product = signed(left) * signed(right)
            carry = int(not -(1 << 63) <= product < 1 << 63)
            core = verify_program({"schema": "hepta.hia.program.v8", "module": "carry", "functions": [
                f("calculate", [], ["u64"], [], [b("entry", [], [c("flag", "u64", carry)], ret("flag"))])]})
            code = Code()
            code.mov_imm("rax", left)
            code.mov_imm("rcx", right)
            code.imul("rax", "rcx")
            code.setcc("b", "rax")
            with self.subTest(left=left, right=right, carry=carry):
                obj, data = self.custom_leaf(code, str(index))
                proof = validate_safe_core_artifact(core, obj, data,
                    query_directory=self.root / (self._testMethodName + "-queries-" + str(index)))
                self.assertTrue(proof["ok"])
                (self.root / (self._testMethodName + "-core-" + str(index) + ".json")).write_bytes(core.canonical_bytes)
                (self.root / (self._testMethodName + "-validation-" + str(index) + ".json")).write_text(
                    json.dumps(proof, indent=2) + "\n")
        self.case_counts = {"all_input_constant_imul_carry_functions": len(pairs)}

    def test_exact_supplied_bytes_and_scoped_checker_identity_are_bound(self):
        report = validate_safe_core_artifact(self.core, self.image.object_bytes, self.data)
        self.assertEqual(report["validation_mode"], "independent_supplied_bytes")
        self.assertFalse(report["checker"]["producer_reemission_used"])
        self.assertIsNone(report["backend_implementation_sha256"])
        self.assertEqual(report["subject"]["object_sha256"], sha256(self.image.object_bytes).hexdigest())
        self.assertEqual(report["subject"]["final_image_sha256"], sha256(self.data).hexdigest())
        self.assertEqual(report["subject"]["core_sha256"], self.core.sha256)
        self.assertEqual(report["profile"], "hia.safe-core.unsigned-acyclic-single-borrow.supplied-elf.x86_64.v1")
        self.assertTrue(report["assumptions"])
        self.assertTrue(report["unproved_obligations"])
        self.assertNotIn("hia_program_native.py", report["checker"]["source_identity"])
        self.assertEqual([row["result"] for row in report["obligations"]], ["sat"] + ["unsat"] * 4)

    def test_emission_and_linking_can_be_disabled_during_consumer_validation(self):
        with patch("hepta.hia_program_native.emit_program_machine", side_effect=AssertionError("producer called")), \
             patch("hepta.hia_program_native.compile_program_machine", side_effect=AssertionError("linker called")):
            report = validate_safe_core_artifact(self.core, self.image.object_bytes, self.data)
        self.assertTrue(report["ok"])

    def test_equivalent_noncanonical_instruction_bytes_are_independently_accepted(self):
        core = verify_program({"schema": "hepta.hia.program.v8", "module": "zero", "functions": [
            f("calculate", [], ["u32"], [], [b("entry", [], [c("zero", "u32", 0)], ret("zero"))])]})
        image = emit_program_machine(core)
        directory = self.newdir()
        final = directory / "zero.so"
        compile_program_machine(image, program=core, output=final, linker="ld")
        offsets = [at for at, ins in decode(image.text_bytes).items()
                   if ins.op == "imm" and ins.args == (0, 0) and ins.size == 10]
        self.assertTrue(offsets)
        # MOV RAX,0 -> XOR RAX,RAX + seven NOPs.  This changes flags and bytes;
        # only the independent all-input observation check may accept it.
        obj, data = self.mutate_pair(image.object_bytes, final.read_bytes(), offsets[0],
                                     b"\x48\x31\xc0" + b"\x90" * 7)
        self.assertNotEqual(obj, image.object_bytes)
        report = validate_safe_core_artifact(core, obj, data)
        self.assertTrue(report["ok"])
        self.assertEqual(report["subject"]["object_sha256"], sha256(obj).hexdigest())

    def test_joint_object_and_final_arithmetic_mutation_produces_a_counterexample(self):
        obj, data = self.wrong_addition()
        with self.assertRaises(SafeCoreRejected) as caught:
            validate_safe_core_artifact(self.core, obj, data)
        witness = caught.exception.counterexample
        self.assertEqual(witness["obligation"], "core_to_final_image_return_abort_and_caller_bytes")
        a, b = [word & 0xffffffff for word in witness["abi_words"]]
        self.assertNotEqual((a + b) & 0xffffffff, (a - b) & 0xffffffff)

    def test_final_bytes_cannot_disagree_with_the_supplied_object(self):
        _, data = self.wrong_addition()
        with self.assertRaisesRegex(ValueError, "final text differs"):
            validate_safe_core_artifact(self.core, self.image.object_bytes, data)

    def test_alternate_core_is_not_qualified_by_matching_producer_metadata(self):
        with self.assertRaises(SafeCoreRejected) as caught:
            validate_safe_core_artifact(arithmetic("int.sub.wrap", "u32"), self.image.object_bytes, self.data)
        self.assertIsNotNone(caught.exception.counterexample)

    def test_rejected_command_retains_original_bytes_queries_and_counterexample(self):
        directory = self.newdir()
        obj, data = self.wrong_addition()
        (directory / "input.json").write_bytes(self.core.canonical_bytes)
        (directory / "input.o").write_bytes(obj)
        (directory / "input.so").write_bytes(data)
        report = check(directory / "input.json", directory / "input.o", directory / "input.so", directory / "check")
        self.assertFalse(report["ok"])
        self.assertFalse(report["compiler_invoked"])
        self.assertFalse(report["native_execution_observed"])
        self.assertEqual((directory / "check/candidate.o").read_bytes(), obj)
        self.assertEqual((directory / "check/candidate.so").read_bytes(), data)
        self.assertIsNotNone(report["error"]["counterexample"])
        self.assertEqual(json.loads((directory / "check/queries/04-core_to_final_image_return_abort_and_caller_bytes.smt2.result.json").read_bytes())["result"], "sat")

    def test_pinned_input_mismatch_rejects_before_any_solver_query(self):
        directory = self.newdir()
        (directory / "input.json").write_bytes(self.core.canonical_bytes)
        report = check(directory / "input.json", "unused.o", "unused.so", directory / "check",
                       expected_sha256={"source": "0" * 64})
        self.assertFalse(report["ok"])
        self.assertIn("pinned identity", report["error"]["message"])
        self.assertFalse((directory / "check/queries").exists())

    def test_fresh_consumer_does_not_import_native_producers(self):
        directory = self.newdir()
        (directory / "input.json").write_bytes(self.core.canonical_bytes)
        (directory / "input.o").write_bytes(self.image.object_bytes)
        (directory / "input.so").write_bytes(self.data)
        script = """
import importlib.abc
import json
from pathlib import Path
import sys
blocked = {"hepta.hia_program_native", "hepta.hia_machine_x64", "hepta.hia_machine_elf",
           "hepta.hia_native_byte_abi"}
class RejectProducer(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in blocked:
            raise AssertionError("consumer imported native producer: " + fullname)
        return None
sys.meta_path.insert(0, RejectProducer())
sys.path.insert(0, sys.argv[1])
from tools.check_hia_safe_core import check
root = Path(sys.argv[2])
report = check(root / "input.json", root / "input.o", root / "input.so", root / "check")
print(json.dumps({"ok": report["ok"], "imports": sorted(blocked & set(sys.modules)),
                  "error": report.get("error")}))
raise SystemExit(0 if report["ok"] else 1)
"""
        child = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(ROOT), str(directory)],
                               capture_output=True, text=True, timeout=60)
        self.assertEqual(child.returncode, 0, child.stdout + child.stderr)
        result = json.loads(child.stdout)
        self.assertEqual(result["imports"], [])
        self.assertTrue(result["ok"])


if __name__ == "__main__":
    unittest.main()
