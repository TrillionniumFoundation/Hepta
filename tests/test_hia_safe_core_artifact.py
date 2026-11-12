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
from tests.test_hia_program import arithmetic, b, c, f, ret

ROOT = Path(__file__).resolve().parents[1]
AVAILABLE = (platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}
             and shutil.which("ld") is not None and importlib.util.find_spec("z3") is not None)


class SafeCoreImmutableInputTests(unittest.TestCase):
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

        with patch.object(checker, "_solver_identity", side_effect=identify), patch.object(checker._Theory, "check_time", deadline):
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
