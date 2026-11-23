"""Safe Core v4 independently models complete unsigned products and MUL flags."""
from __future__ import annotations

import ctypes
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_machine_elf import write_elf_object
from hepta.hia_machine_x64 import Code
from hepta.hia_program import verify_program
from hepta.hia_program_native import compile_program_machine, emit_program_machine
from hepta.hia_program_runtime import HIAProgramTrap, execute_program
from hepta.hia_safe_core import (
    ARTIFACT_PROFILE_V4, OPERATIONS_V3, OPERATIONS_V4, PROFILE_V4,
    SafeCoreRejected, WIDTHS_V2, _profile, _Theory, _unsigned_profile_version,
    build_safe_core, validate_safe_core_artifact,
)
from hepta.hia_safe_core_x64 import SafeCoreMachineRejected, decode
from tests.test_hia_program import arithmetic, b, c, f, m, ret
from tests import test_hia_verified_scalar_checked as checked_legacy


MASK64 = (1 << 64) - 1
TYPES = ("u8", "u16", "u32", "u64", "usize")


def constant_core(value):
    return m(f("calculate", [], ["u64"], [], [
        b("entry", [], [c("answer", "u64", value)], ret("answer"))]))


class UnsignedMultiplyDecoderTests(unittest.TestCase):
    def test_every_register_operand_requires_explicit_v4_admission(self):
        for register in range(16):
            encoded = bytes((0x48 | (register >> 3), 0xf7, 0xe0 | (register & 7)))
            with self.subTest(register=register):
                for kwargs in ({}, {"allow_unsigned_multiply": False}, {"allow_variable_shifts": True}):
                    with self.assertRaises(SafeCoreMachineRejected):
                        decode(encoded, **kwargs)
                row = decode(encoded, allow_unsigned_multiply=True)[0]
                self.assertEqual((row.op, row.args, row.size), ("mul", (register,), 3))

    def test_narrow_memory_other_groups_and_nonboolean_admission_fail_closed(self):
        for encoded in (
            "f7e0", "40f7e0", "66f7e0", "6648f7e0", "4af7e0", "4cf7e0",
            "48f7", "48f720", "48f7a000000000", "48f7c0", "48f7d8",
            "48f7e8", "48f7f0", "48f7f8", "48f6e0", "f048f7e0", "4848f7e0",
            "48f7e0e9fcffffff",
        ):
            with self.subTest(encoded=encoded), self.assertRaises(SafeCoreMachineRejected):
                decode(bytes.fromhex(encoded), allow_unsigned_multiply=True)
        for flag in (None, 0, 1, "true"):
            with self.subTest(admission=flag), self.assertRaises(SafeCoreMachineRejected):
                decode(b"\xc3", allow_unsigned_multiply=flag)
        with self.assertRaises(SafeCoreMachineRejected):
            decode(bytes.fromhex("c348f7e0"), allow_variable_shifts=True)


@unittest.skipUnless(checked_legacy.AVAILABLE, "Linux x86-64, GNU ld and pinned Z3 are required")
class UnsignedMultiplyProfileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hia-safe-multiply-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.serial = 0

    def custom(self, code):
        code.ret()
        code.label("abort")
        code.push("rbp")
        code.call("abort")
        code.ud2()
        text, relocations = code.finalize()
        obj = write_elf_object(text, [{"name": "calculate", "offset": 0,
                                      "size": len(text), "global": True}], relocations)
        self.serial += 1
        path = self.root / ("custom-" + str(self.serial) + ".so")
        object_path = path.with_suffix(".o")
        object_path.write_bytes(obj)
        subprocess.run(["ld", "-m", "elf_x86_64", "-shared", "-z", "defs", "-z", "noexecstack",
                        "-z", "relro", "-z", "now", "--hash-style=both", "--build-id=none",
                        str(object_path), "-lc", "-o", str(path)], check=True, capture_output=True, timeout=30)
        return obj, path.read_bytes(), path

    def validate(self, core, obj, final):
        return validate_safe_core_artifact(core, obj, final, profile_version=4)

    def refuted(self, core, obj, final):
        with self.assertRaises(SafeCoreRejected) as caught:
            self.validate(core, obj, final)
        self.assertEqual(caught.exception.validation["status"], "refuted")
        self.assertEqual(caught.exception.counterexample["obligation"],
                         "core_to_final_image_return_abort_and_caller_bytes")
        return caught.exception.counterexample

    def test_gnu_as_independently_encodes_every_admitted_register_operand(self):
        registers = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                     "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")
        assembly = ".intel_syntax noprefix\n.text\n" + "".join("mul " + reg + "\n" for reg in registers)
        object_path, text_path = self.root / "assembled.o", self.root / "assembled.text"
        subprocess.run(["as", "--64", "-o", str(object_path), "-"], input=assembly.encode(),
                       check=True, capture_output=True, timeout=30)
        subprocess.run(["objcopy", "--only-section=.text", "-O", "binary", str(object_path), str(text_path)],
                       check=True, capture_output=True, timeout=30)
        assembled = text_path.read_bytes()
        decoded = decode(assembled, allow_unsigned_multiply=True)
        self.assertEqual([(row.op, row.args, row.size) for row in decoded.values()],
                         [("mul", (number,), 3) for number in range(16)])
        code = Code()
        for register in registers:
            code.mul(register)
        self.assertEqual(code.finalize(), (assembled, []))

    def test_checked_multiply_is_separately_versioned_without_broadening_v1_v2_v3(self):
        self.assertEqual(OPERATIONS_V4 - OPERATIONS_V3, {"int.mul.checked"})
        self.assertEqual(_unsigned_profile_version(verify_program(constant_core(1))), 2)
        self.assertEqual(_unsigned_profile_version(verify_program(arithmetic("int.shl.checked", "u64"))), 3)
        for typ in TYPES:
            checked = verify_program(arithmetic("int.mul.checked", typ))
            self.assertEqual(_unsigned_profile_version(checked), 4)
            self.assertEqual(_profile(checked, profile_version=4)[0]["returns"], [typ])
            for version in (1, 2, 3):
                with self.subTest(type=typ, version=version), self.assertRaises(SafeCoreRejected):
                    _profile(checked, profile_version=version)
        for typ in ("i8", "i16", "i32", "i64", "isize"):
            with self.subTest(signed=typ), self.assertRaises(SafeCoreRejected):
                _profile(verify_program(arithmetic("int.mul.checked", typ)), profile_version=4)
        for version in (True, False, "4", 4.0, 7):
            with self.subTest(version=version), self.assertRaises(SafeCoreRejected):
                _profile(verify_program(constant_core(1)), profile_version=version)

    def test_independent_core_products_match_big_integer_and_vm_boundaries(self):
        import z3
        for typ in TYPES:
            width = WIDTHS_V2[typ]
            mask, dirty = (1 << width) - 1, MASK64 ^ ((1 << width) - 1)
            core = arithmetic("int.mul.checked", typ)
            fn, blocks = _profile(verify_program(core), profile_version=4)
            theory = _Theory(z3, 15000, widths=WIDTHS_V2)
            theory.arguments(fn)
            covered, aborts, result, _ = theory.merge(theory.reference(fn, blocks, None))
            values = (0, 1, 2, (1 << (width // 2)) - 1, 1 << (width // 2),
                      1 << (width - 1), mask, dirty, dirty | 3, MASK64)
            for raw_left in values:
                for raw_right in values:
                    left, right = raw_left & mask, raw_right & mask
                    product = left * right
                    replacements = [(theory.words[0], theory.bv(raw_left)),
                                    (theory.words[1], theory.bv(raw_right))]
                    evaluate = lambda expression: z3.simplify(z3.substitute(expression, *replacements))
                    self.assertTrue(z3.is_true(evaluate(covered)))
                    self.assertEqual(z3.is_true(evaluate(aborts)), product > mask)
                    if product <= mask:
                        self.assertEqual(evaluate(result).as_long(), product)
                        self.assertEqual(execute_program(core, "calculate", [left, right])["result"], product)
                    else:
                        with self.assertRaises(HIAProgramTrap) as caught:
                            execute_program(core, "calculate", [left, right])
                        self.assertEqual(caught.exception.code, "overflow")

    def test_all_five_ordinary_wrappers_prove_and_execute_with_high_half_abort(self):
        for typ in TYPES:
            with self.subTest(type=typ):
                core = arithmetic("int.mul.checked", typ)
                checked = verify_program(core)
                image = emit_program_machine(checked)
                path = self.root / (typ + ".so")
                compile_program_machine(image, program=checked, output=path, linker="ld")
                proof = self.validate(checked, image.object_bytes, path.read_bytes())
                self.assertEqual(proof["profile"], ARTIFACT_PROFILE_V4)
                self.assertEqual(proof["image_binding"]["function_shape"], "internal_with_wrapper")
                self.assertEqual([row["result"] for row in proof["obligations"]], ["sat"] + ["unsat"] * 4)
                function = ctypes.CDLL(str(path)).calculate
                function.argtypes = [ctypes.c_uint64] * 2
                function.restype = ctypes.c_uint64
                width = WIDTHS_V2[typ]; mask = (1 << width) - 1; dirty = MASK64 ^ mask
                self.assertEqual(function(mask | dirty, 1 | dirty), mask)
                self.assertEqual(function(dirty, MASK64), 0)
                checked_legacy.CheckedRegisterTests.aborts(self, path, "calculate", (1 << (width // 2),) * 2)

    def test_canonical_build_keeps_v4_and_previous_artifact_profiles_refuse_mul_bytes(self):
        report = build_safe_core(arithmetic("int.mul.checked", "u16"),
                                 self.root / "canonical.so", profile_version=4)
        self.assertEqual(report["validation"]["profile"], PROFILE_V4)
        code = Code(); code.mov_imm("rax", 7); code.mov_imm("rdx", 11); code.mul("rdx")
        obj, final, _ = self.custom(code)
        for version in (1, 2, 3):
            with self.subTest(version=version), self.assertRaises(SafeCoreMachineRejected):
                validate_safe_core_artifact(constant_core(77), obj, final, profile_version=version)
        self.assertTrue(self.validate(constant_core(77), obj, final)["complete"])

    def test_full_product_reads_old_rax_and_rdx_before_writing_either(self):
        left, other = (1 << 63) + 3, (1 << 62) + 5
        for source in ("rax", "rdx", "r11"):
            with self.subTest(source=source):
                right = left if source == "rax" else other
                product = left * right
                expected = (product & MASK64) ^ (product >> 64)
                code = Code(); code.mov_imm("rax", left)
                code.mov_imm("rdx", other); code.mov_imm("r11", other)
                code.mul(source); code.xor("rax", "rdx")
                obj, final, path = self.custom(code)
                self.assertTrue(self.validate(constant_core(expected), obj, final)["complete"])
                function = ctypes.CDLL(str(path)).calculate
                function.argtypes = []; function.restype = ctypes.c_uint64
                self.assertEqual(function(), expected)

    def test_carry_reports_unsigned_high_half_not_signed_imul_overflow(self):
        for left, right, condition in ((MASK64, 1, "ae"), (1 << 63, 2, "b"),
                                       (0, MASK64, "ae"), (MASK64, MASK64, "b")):
            with self.subTest(left=left, right=right):
                code = Code(); code.mov_imm("rax", left); code.mov_imm("r11", right)
                code.mul("r11"); code.setcc(condition, "rax")
                obj, final, path = self.custom(code)
                self.assertTrue(self.validate(constant_core(1), obj, final)["complete"])
                function = ctypes.CDLL(str(path)).calculate
                function.argtypes = []; function.restype = ctypes.c_uint64
                self.assertEqual(function(), 1)

    def test_undefined_zero_flag_cannot_be_preserved_or_inferred_from_product(self):
        # Each tempting shortcut would incorrectly validate one of these.
        for previous_zero, right in ((False, 0), (True, 1)):
            code = Code(); code.mov_imm("rax", 1); code.mov_imm("r11", right)
            code.alu_imm("cmp", "rax", 1 if previous_zero else 0)
            code.mul("r11"); code.jcc("e", "abort"); code.mov_imm("rax", 17)
            obj, final, _ = self.custom(code)
            with self.subTest(previous_zero=previous_zero, right=right):
                self.refuted(constant_core(17), obj, final)


class UnsignedProductObligationTests(unittest.TestCase):
    def test_exact_product_growth_and_conditional_values(self):
        from hepta.hia_cnf_native import CIRCUIT_REQUEST, SEARCH_PLAN_REQUEST, WORD_PRODUCT_EXCEEDS
        from hepta.hia_core_proof_wire_native import OBLIGATION_SOLVER_REQUEST
        from tests.test_hia_core_workspace_facts_native import vm_run

        source = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/core_obligation_wire.hepta'
        narrow = 32
        wide = 64
        maximum = (1 << narrow) - 1
        nodes = [
            (1, narrow, 0, 0, 0), (1, narrow, 0, 0, 0),    # inputs
            (30, wide, 0, 0, 0), (30, wide, 1, 0, 0),      # zero-extended inputs
            (32, wide, 3, 2, 0), (2, wide, 0, 0, maximum), # exact, reversed product
            (14, 1, 4, 5, 0),                              # unsigned product > threshold
            (2, narrow, 0, 0, maximum),
            (WORD_PRODUCT_EXCEEDS, 1, 0, 1, 7),
            (32, narrow, 0, 1, 0), (30, wide, 9, 0, 0),    # low product
            (2, narrow, 0, 0, 0), (2, wide, 0, 0, 0),
            (11, narrow, 8, 11, 9), (30, wide, 13, 0, 0),  # extend after selection
            (11, wide, 6, 12, 10),                         # extend before selection
            (2, wide, 0, 0, (1 << wide) - 1),
            (WORD_PRODUCT_EXCEEDS, 1, 2, 3, 16),           # always false
            (11, wide, 17, 12, 15),
        ]
        observations = ((8, 6), (14, 18))
        steps = 12345

        def reduce(rows, pairs):
            graph = b''.join(struct.pack('<5Q', *row) for row in rows)
            returns = b''.join(struct.pack('<2Q', *pair) for pair in pairs)
            frame = (struct.pack('<8Q', OBLIGATION_SOLVER_REQUEST, 3, 2, 0, SEARCH_PLAN_REQUEST, steps, 1, 0)
                     + struct.pack('<4Q', CIRCUIT_REQUEST, len(rows), len(pairs), 0) + graph + returns)
            code, response = vm_run(source, frame, 16384, 0)
            if code == 0xfffffffc:
                return None
            self.assertEqual(response[:32], struct.pack('<4Q', CIRCUIT_REQUEST, len(rows), len(pairs), steps))
            self.assertEqual(response[32:32 + len(graph)], graph)
            self.assertEqual(code, 32 + len(graph) + 16 * len(pairs))
            return response[32 + len(graph):]

        self.assertEqual(reduce(nodes, observations), bytes(32))
        # The register allocator tests the high word with SHR/TEST. A different
        # shift, signed shift, or sentinel no longer proves the same overflow.
        shifted = [*nodes, (2, wide, 0, 0, narrow), (37, wide, 4, 19, 0), (8, 1, 20, 12, 0)]
        self.assertEqual(reduce(shifted, ((8, 21),)), bytes(16))
        for index, replacement in ((19, (2, wide, 0, 0, narrow - 1)),
                                   (20, (38, wide, 4, 19, 0)), (21, (7, 1, 20, 12, 0)),
                                   (21, (8, 1, 20, 5, 0))):
            changed = shifted.copy()
            changed[index] = replacement
            self.assertIsNone(reduce(changed, ((8, 21),)))
        # Each change invalidates at least one equality at a concrete input.
        # A pair of observations must stay intact if either one remains open.
        for name, index, replacement in (
            ('threshold', 5, (2, wide, 0, 0, maximum - 1)),
            ('non-strict', 6, (15, 1, 4, 5, 0)),
            ('operand', 4, (32, wide, 2, 2, 0)),
            ('extension', 2, (31, wide, 0, 0, 0)),
            ('overflow limit', 16, (2, wide, 0, 0, maximum - 1)),
            ('conditional', 15, (11, wide, 6, 10, 12)),
        ):
            with self.subTest(name=name):
                changed = nodes.copy()
                changed[index] = replacement
                self.assertIsNone(reduce(changed, observations))
        # At full operand width the wrapping product cannot model exact overflow.
        wrapped = [(op, narrow if width == wide else width, left, right,
                         maximum if index == 16 else immediate)
                   for index, (op, width, left, right, immediate) in enumerate(nodes)]
        self.assertIsNone(reduce(wrapped, observations))
        self.assertIsNone(reduce(nodes, ((9, 10),)))


if __name__ == "__main__":
    unittest.main()
