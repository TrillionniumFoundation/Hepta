"""Independent signed Core/ISA semantics and final ELF refinement for v6."""
from __future__ import annotations

import ctypes
import copy
import importlib.util
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

from hepta.hia_machine_elf import write_elf_object
from hepta.hia_machine_x64 import Code
from hepta.hia_program import integer_range, verify_program
from hepta.hia_program_native import compile_program_machine, emit_program_machine
from hepta.hia_program_runtime import HIAProgramTrap, execute_program
from hepta.hia_safe_core import (
    ARTIFACT_PROFILE_V6, OPERATIONS_V5, OPERATIONS_V6, SafeCoreRejected,
    WIDTHS_V2, WIDTHS_V6, _profile, _Theory, _unsigned_profile_version,
    validate_safe_core_artifact,
)
from hepta.hia_safe_core_x64 import (
    Executor, SafeCoreMachineRejected, _signed_division, decode,
)
from tests.test_hia_program import b, c, f, i, m, ret


MASK64 = (1 << 64) - 1
SIGNED = ("i8", "i16", "i32", "i64", "isize")
UNSIGNED = ("u8", "u16", "u32", "u64", "usize")
AVAILABLE = (platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}
             and shutil.which("ld") is not None and importlib.util.find_spec("z3") is not None)
ARITHMETIC = tuple("int." + name for name in (
    "add.wrap", "sub.wrap", "mul.wrap", "add.checked", "sub.checked", "mul.checked",
    "div.checked", "rem.checked", "neg.checked", "shl.checked", "shr.checked"))


def core_operation(operation, typ, *, destination=None, mode=None):
    unary = operation in ("int.neg.checked", "int.cast", "bit.not")
    params = [("left", typ)] + ([] if unary else [("right", typ)])
    output_type = destination or ("bool" if operation.startswith("compare.") else typ)
    attrs = {"mode": mode} if operation == "int.cast" else {}
    return m(f("calculate", params, [output_type], ["trap"], [
        b("entry", params, [i(operation, [name for name, _ in params], [("answer", output_type)], **attrs)], ret("answer"))]))


def constant_core(value):
    return m(f("calculate", [], ["u64"], [], [b("entry", [], [c("answer", "u64", value)], ret("answer"))]))


def normalize_integer(raw, typ):
    width = WIDTHS_V6[typ]
    raw &= (1 << width) - 1
    return raw - (1 << width) if typ.startswith("i") and raw & (1 << (width - 1)) else raw


def signed_quotient(left, right):
    return (abs(left) // abs(right)) * (-1 if (left < 0) != (right < 0) else 1)


class SignedDecoderTests(unittest.TestCase):
    def test_signed_register_forms_require_explicit_v6_admission(self):
        for register in range(16):
            rex, rm = 0x48 | (register >> 3), register & 7
            cases = ((bytes((rex, 0xf7, 0xd8 | rm)), "neg", (register,)),
                     (bytes((rex, 0xf7, 0xe8 | rm)), "imul_full", (register,)),
                     (bytes((rex, 0xf7, 0xf8 | rm)), "idiv", (register,)),
                     (bytes((rex, 0xc1, 0xf8 | rm, 31)), "sar", (register, 31)),
                     (bytes((rex, 0xd3, 0xf8 | rm)), "sar_cl", (register,)))
            for encoded, op, args in cases:
                with self.subTest(register=register, op=op):
                    for kwargs in ({}, {"allow_variable_shifts": True, "allow_unsigned_multiply": True,
                                         "allow_unsigned_divide": True}):
                        with self.assertRaises(SafeCoreMachineRejected):
                            decode(encoded, **kwargs)
                    row = decode(encoded, allow_signed=True, allow_variable_shifts=True)[0]
                    self.assertEqual((row.op, row.args, row.size), (op, args, len(encoded)))
        with self.assertRaises(SafeCoreMachineRejected):
            decode(bytes.fromhex("4899"))
        self.assertEqual(decode(bytes.fromhex("4899"), allow_signed=True)[0].op, "cqo")

    def test_signed_conditions_are_explicit_and_parity_stays_closed(self):
        for condition in (0, 1, 8, 9, 12, 13, 14, 15):
            branch = bytes((0x0f, 0x80 | condition, 0, 0, 0, 0, 0xc3))
            setcc = bytes((0x40, 0x0f, 0x90 | condition, 0xc0))
            for encoded in (branch, setcc):
                with self.assertRaises(SafeCoreMachineRejected):
                    decode(encoded)
                self.assertEqual(decode(encoded, allow_signed=True)[0].args[0], condition)
        for condition in (10, 11):
            with self.assertRaises(SafeCoreMachineRejected):
                decode(bytes((0x40, 0x0f, 0x90 | condition, 0xc0)), allow_signed=True)

    def test_narrow_memory_prefix_unknown_forms_and_nonboolean_flags_fail_closed(self):
        for encoded in ("99", "4099", "4199", "4999", "4c99", "6699", "664899",
                        "f7f8", "40f7f8", "48f738", "48f7b800000000", "4cf7f8",
                        "4af7f8", "f048f7f8", "4848f7f8", "48d3f0", "48c1f840"):
            with self.subTest(encoded=encoded), self.assertRaises(SafeCoreMachineRejected):
                decode(bytes.fromhex(encoded), allow_signed=True, allow_variable_shifts=True)
        for flag in (None, 0, 1, "true"):
            with self.assertRaises(SafeCoreMachineRejected):
                decode(b"\xc3", allow_signed=flag)
        with self.assertRaises(SafeCoreMachineRejected):
            decode(bytes.fromhex("c34899"))


@unittest.skipUnless(AVAILABLE, "Linux x86-64, GNU ld and pinned Z3 are required")
class SignedCoreModelTests(unittest.TestCase):
    def model(self, core):
        import z3
        fn, blocks = _profile(verify_program(core), profile_version=6)
        theory = _Theory(z3, 60000, widths=WIDTHS_V6)
        theory.arguments(fn)
        return theory, theory.merge(theory.reference(fn, blocks, None))

    def test_new_profile_preserves_all_five_old_type_and_operation_domains(self):
        self.assertEqual(OPERATIONS_V6, OPERATIONS_V5)
        self.assertEqual({key: WIDTHS_V6[key] for key in WIDTHS_V2}, WIDTHS_V2)
        for typ in SIGNED:
            for operation in ARITHMETIC:
                checked = verify_program(core_operation(operation, typ))
                self.assertEqual(_unsigned_profile_version(checked), 6)
                _profile(checked, profile_version=6)
                for version in (1, 2, 3, 4, 5):
                    with self.subTest(type=typ, op=operation, old_profile=version), self.assertRaises(SafeCoreRejected):
                        _profile(checked, profile_version=version)
        for operation, version in (("int.add.wrap", 2), ("int.shl.checked", 3),
                                   ("int.mul.checked", 4), ("int.div.checked", 5)):
            self.assertEqual(_unsigned_profile_version(verify_program(core_operation(operation, "u64"))), version)
        for version in (None, True, 6.0, "6", 7):
            with self.assertRaises(SafeCoreRejected):
                _profile(verify_program(constant_core(0)), profile_version=version)

    def test_signed_model_arithmetic_matches_integer_math_and_existing_vm(self):
        import z3
        for typ in SIGNED:
            lo, hi = integer_range(typ)
            width, mask = WIDTHS_V6[typ], (1 << WIDTHS_V6[typ]) - 1
            dirty = MASK64 ^ mask
            pairs = ((lo, -1), (lo, 0), (lo, 1), (lo, lo), (hi, 1), (hi, -1),
                     (hi, hi), (-7, 3), (-7, -3), (7, -3), (0, 0), (0, hi),
                     (-1, width - 1), (-1, width), (-1, -1), (17, 2))
            for operation in ARITHMETIC:
                core = core_operation(operation, typ)
                theory, (covered, aborted, result, _) = self.model(core)
                for left, right in pairs:
                    args = [left] if operation == "int.neg.checked" else [left, right]
                    values = [((value & mask) | dirty) & MASK64 for value in args]
                    replacements = [(word, theory.bv(value)) for word, value in zip(theory.words, values)]
                    evaluate = lambda expression: z3.simplify(z3.substitute(expression, *replacements))
                    with self.subTest(type=typ, operation=operation, arguments=args):
                        self.assertTrue(z3.is_true(evaluate(covered)))
                        action, mode = operation.split(".")[1:]
                        trap = False
                        if action in ("add", "sub", "mul"):
                            exact = left + right if action == "add" else left - right if action == "sub" else left * right
                            trap = mode == "checked" and not lo <= exact <= hi
                            expected = normalize_integer(exact, typ)
                        elif action == "neg":
                            trap, expected = left == lo, -left
                        elif action in ("div", "rem"):
                            trap = right == 0 or left == lo and right == -1
                            quotient = signed_quotient(left, right) if not trap else 0
                            expected = quotient if action == "div" else left - quotient * right
                        else:
                            trap = not 0 <= right < width
                            expected = (normalize_integer(left << right, typ) if action == "shl" else left >> right) if not trap else 0
                        if trap:
                            self.assertTrue(z3.is_true(evaluate(aborted)))
                            with self.assertRaises(HIAProgramTrap):
                                execute_program(core, "calculate", args)
                        else:
                            self.assertTrue(z3.is_false(evaluate(aborted)))
                            self.assertEqual(evaluate(result).as_long(), expected & MASK64)
                            self.assertEqual(execute_program(core, "calculate", args)["result"], expected)

    def test_all_signed_and_unsigned_cast_pairs_use_mathematical_bounds(self):
        import z3
        for source in SIGNED + UNSIGNED:
            low, high = integer_range(source)
            samples = {low, high, 0, 1, 127, 128, 255, 256, -(1 << 31), -1,
                       1 << 31, (1 << 32) - 1, 1 << 63, (1 << 64) - 1}
            samples = sorted(value for value in samples if low <= value <= high)
            for target in SIGNED + UNSIGNED:
                target_low, target_high = integer_range(target)
                for mode in ("checked", "wrap"):
                    core = core_operation("int.cast", source, destination=target, mode=mode)
                    theory, (covered, aborted, result, _) = self.model(core)
                    for value in samples:
                        source_mask = (1 << WIDTHS_V6[source]) - 1
                        raw = ((value & source_mask) | (MASK64 ^ source_mask)) & MASK64
                        evaluate = lambda expression: z3.simplify(z3.substitute(expression, (theory.words[0], theory.bv(raw))))
                        with self.subTest(source=source, target=target, mode=mode, value=value):
                            self.assertTrue(z3.is_true(evaluate(covered)))
                            expected_abort = mode == "checked" and not target_low <= value <= target_high
                            self.assertEqual(z3.is_true(evaluate(aborted)), expected_abort)
                            if not expected_abort:
                                self.assertEqual(evaluate(result).as_long(), normalize_integer(value, target) & MASK64)

    def test_comparison_bitwise_and_negative_constants_preserve_signed_meaning(self):
        import z3
        operations = ("compare.eq", "compare.ne", "compare.lt", "compare.le", "compare.gt", "compare.ge",
                      "bit.and", "bit.or", "bit.xor", "bit.not")
        for typ in SIGNED:
            lo, hi = integer_range(typ)
            for operation in operations:
                core = core_operation(operation, typ)
                theory, (covered, aborted, result, _) = self.model(core)
                for left, right in ((lo, hi), (hi, lo), (-1, 0), (-1, -1), (-7, 3)):
                    args = [left] if operation == "bit.not" else [left, right]
                    replacements = [(word, theory.bv(value)) for word, value in zip(theory.words, args)]
                    evaluate = lambda expression: z3.simplify(z3.substitute(expression, *replacements))
                    self.assertTrue(z3.is_true(evaluate(covered)))
                    self.assertTrue(z3.is_false(evaluate(aborted)))
                    self.assertEqual(evaluate(result).as_long(), int(execute_program(core, "calculate", args)["result"]) & MASK64)
            document = m(f("calculate", [], [typ], [], [b("entry", [], [c("answer", typ, lo)], ret("answer"))]))
            theory, (_, aborted, result, _) = self.model(document)
            self.assertTrue(z3.is_false(z3.simplify(aborted)))
            self.assertEqual(z3.simplify(result).as_long(), lo & MASK64)

    def test_full_signed_128_bit_dividend_matches_integer_boundaries(self):
        import z3
        words = (0, 1, 2, (1 << 63) - 1, 1 << 63, MASK64)
        for high in words:
            for low in words:
                for divisor in (-(1 << 63), -3, -1, 0, 1, 3, (1 << 63) - 1):
                    word = lambda value: z3.BitVecVal(value, 64)
                    quotient, remainder, admitted = _signed_division(z3, word(high), word(low), word(divisor))
                    dividend = (high << 64) | low
                    if dividend & (1 << 127):
                        dividend -= 1 << 128
                    expected_q = signed_quotient(dividend, divisor) if divisor else None
                    valid = divisor != 0 and -(1 << 63) <= expected_q < (1 << 63)
                    with self.subTest(high=high, low=low, divisor=divisor):
                        self.assertEqual(z3.is_true(admitted), valid)
                        if valid:
                            self.assertEqual(quotient.as_signed_long(), expected_q)
                            self.assertEqual(remainder.as_signed_long(), dividend - expected_q * divisor)


@unittest.skipUnless(AVAILABLE, "Linux x86-64, GNU ld and pinned Z3 are required")
class SignedFinalArtifactTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hia-safe-signed-")
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
        obj = write_elf_object(text, [{"name": "calculate", "offset": 0, "size": len(text), "global": True}], relocations)
        self.serial += 1
        path = self.root / ("custom-" + str(self.serial) + ".so")
        object_path = path.with_suffix(".o")
        object_path.write_bytes(obj)
        subprocess.run(["ld", "-m", "elf_x86_64", "-shared", "-z", "defs", "-z", "noexecstack",
                        "-z", "relro", "-z", "now", "--hash-style=both", "--build-id=none",
                        str(object_path), "-lc", "-o", str(path)], check=True, capture_output=True, timeout=30)
        return obj, path.read_bytes(), path

    def validate(self, core, obj, final):
        return validate_safe_core_artifact(core, obj, final, profile_version=6)

    def assert_refuted(self, core, obj, final, obligation=None):
        with self.assertRaises(SafeCoreRejected) as caught:
            self.validate(core, obj, final)
        self.assertEqual(caught.exception.validation["status"], "refuted")
        if obligation is not None:
            self.assertEqual(caught.exception.counterexample["obligation"], obligation)
        return caught.exception.counterexample

    def test_gnu_as_independently_encodes_all_new_register_operations(self):
        registers = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                     "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")
        assembly = ".intel_syntax noprefix\n.text\ncqo\n"
        expected = [("cqo", ())]
        for number, register in enumerate(registers):
            for mnemonic, decoded_name, suffix in (("neg", "neg", ""), ("imul", "imul_full", ""),
                                                   ("idiv", "idiv", ""), ("sar", "sar", ", 31"),
                                                   ("sar", "sar_cl", ", cl")):
                assembly += mnemonic + " " + register + suffix + "\n"
                expected.append((decoded_name, (number, 31) if decoded_name == "sar" else (number,)))
        path, text = self.root / "signed.o", self.root / "signed.bin"
        subprocess.run(["as", "--64", "-o", str(path), "-"], input=assembly.encode(), check=True, capture_output=True, timeout=30)
        subprocess.run(["objcopy", "--only-section=.text", "-O", "binary", str(path), str(text)], check=True, capture_output=True, timeout=30)
        actual = decode(text.read_bytes(), allow_signed=True, allow_variable_shifts=True)
        self.assertEqual([(row.op, row.args) for row in actual.values()], expected)

    def test_ordinary_signed_arithmetic_wrappers_prove_all_input_refinement(self):
        for typ in SIGNED:
            for operation in ARITHMETIC:
                with self.subTest(type=typ, operation=operation):
                    core = core_operation(operation, typ)
                    checked = verify_program(core)
                    image = emit_program_machine(checked)
                    path = self.root / (typ + operation + ".so")
                    compile_program_machine(image, program=checked, output=path, linker="ld")
                    proof = self.validate(core, image.object_bytes, path.read_bytes())
                    self.assertEqual(proof["profile"], ARTIFACT_PROFILE_V6)
                    self.assertEqual([row["result"] for row in proof["obligations"]], ["sat"] + ["unsat"] * 4)
                    function = ctypes.CDLL(str(path)).calculate
                    count = 1 if operation == "int.neg.checked" else 2
                    function.argtypes = [ctypes.c_uint64] * count
                    function.restype = ctypes.c_uint64
                    args = [-7] if count == 1 else [-7, 2]
                    expected = execute_program(core, "calculate", args)["result"]
                    self.assertEqual(function(*args), expected & MASK64)

    def test_borrowed_write_before_signed_overflow_and_division_is_preserved(self):
        params = [("memory", "mutbuf"), ("left", "i32"), ("right", "i32")]
        for operation in ("int.add.checked", "int.div.checked", "int.rem.checked"):
            core = m(f("calculate", params, ["u32"], ["write", "trap"], [b("entry", params,
                [c("index", "usize", 0), c("byte", "u8", 91), i("buffer.store", ["memory", "index", "byte"]),
                 i(operation, ["left", "right"], [("signed", "i32")]),
                 i("int.cast", ["signed"], [("answer", "u32")], mode="wrap")], ret("answer"))]))
            checked = verify_program(core)
            image = emit_program_machine(checked, foreign_buffer_exports=(("calculate", 64),))
            path = self.root / (operation + ".so")
            compile_program_machine(image, program=checked, output=path, linker="ld")
            proof = validate_safe_core_artifact(core, image.object_bytes, path.read_bytes(),
                profile_version=6, foreign_buffer_exports=image.foreign_buffer_exports)
            self.assertEqual([row["result"] for row in proof["obligations"]], ["sat"] + ["unsat"] * 4)
            mutant = copy.deepcopy(core)
            mutant["functions"][0]["blocks"][0]["ops"][1]["attrs"]["value"] = 92
            bad_checked = verify_program(mutant)
            bad_image = emit_program_machine(bad_checked, foreign_buffer_exports=image.foreign_buffer_exports)
            bad_path = self.root / (operation + "-wrong-store.so")
            compile_program_machine(bad_image, program=bad_checked, output=bad_path, linker="ld")
            with self.assertRaises(SafeCoreRejected) as caught:
                validate_safe_core_artifact(core, bad_image.object_bytes, bad_path.read_bytes(),
                    profile_version=6, foreign_buffer_exports=image.foreign_buffer_exports)
            self.assertEqual(caught.exception.counterexample["obligation"], "core_to_final_image_return_abort_and_caller_bytes")

    def test_fresh_signed_consumer_has_no_native_producer_import(self):
        core = core_operation("int.div.checked", "i16")
        checked = verify_program(core)
        image = emit_program_machine(checked)
        path = self.root / "independent.so"
        compile_program_machine(image, program=checked, output=path, linker="ld")
        source, object_path = self.root / "signed.hepta", self.root / "independent.o"
        source.write_bytes(checked.canonical_bytes)
        object_path.write_bytes(image.object_bytes)
        script = r'''
import importlib.abc, json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
blocked = {'hepta.hia_program_native', 'hepta.hia_machine_x64', 'hepta.hia_machine_elf',
           'hepta.hia_native_byte_abi', 'hepta.hia_verified_scalar'}
class RejectProducer(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in blocked:
            raise AssertionError('native producer import: ' + fullname)
sys.meta_path.insert(0, RejectProducer())
from hepta.hia_safe_core import ARTIFACT_PROFILE_V6, validate_safe_core_artifact
directory = Path(sys.argv[2])
proof = validate_safe_core_artifact(json.loads((directory / 'signed.hepta').read_bytes()),
    (directory / 'independent.o').read_bytes(), (directory / 'independent.so').read_bytes(), profile_version=6)
assert proof['ok'] and proof['complete'] and proof['profile'] == ARTIFACT_PROFILE_V6
assert not blocked.intersection(sys.modules)
'''
        process = subprocess.run([sys.executable, "-I", "-B", "-c", script,
                                  str(Path(__file__).resolve().parents[1]), str(self.root)],
                                 capture_output=True, text=True, timeout=45)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)

    def test_two_operand_imul_overflow_flags_are_exact(self):
        for left, right, overflow in ((-7, 3, False), (-(1 << 63), -1, True),
                                      (1 << 62, 4, True), ((1 << 63) - 1, 1, False)):
            code = Code(); code.mov_imm("rax", left & MASK64); code.mov_imm("rdi", right & MASK64)
            code.imul_rr("rax", "rdi"); code.mov_imm("rax", 0); code.setcc("o", "rax")
            obj, final, path = self.custom(code)
            self.validate(constant_core(int(overflow)), obj, final)
            function = ctypes.CDLL(str(path)).calculate; function.restype = ctypes.c_uint64
            self.assertEqual(function(), int(overflow))

    def test_full_imul_and_idiv_preserve_actual_rdx_rax_aliases(self):
        for low, high, divisor, source in ((MASK64 - 6, MASK64, 3, "r11"),
                                          (MASK64 - 6, MASK64, -7, "rax"),
                                          (MASK64 - 6, MASK64, -1, "rdx"),
                                          (0, 1, 3, "r11")):
            dividend = (high << 64) | low
            if dividend & (1 << 127):
                dividend -= 1 << 128
            quotient = signed_quotient(dividend, divisor)
            remainder = dividend - quotient * divisor
            code = Code(); code.mov_imm("rax", low); code.mov_imm("rdx", high)
            code.mov_imm("r11", divisor & MASK64); code.idiv(source); code.xor("rax", "rdx")
            obj, final, _ = self.custom(code)
            self.validate(constant_core((quotient ^ remainder) & MASK64), obj, final)
        for source in ("rax", "rdx", "r11"):
            code = Code(); code.mov_imm("rax", MASK64 - 6); code.mov_imm("rdx", 3); code.mov_imm("r11", 3)
            code.imul_full(source); code.xor("rax", "rdx")
            value = (-7) * (-7 if source == "rax" else 3)
            high = (value >> 64) & MASK64
            obj, final, _ = self.custom(code)
            self.validate(constant_core((value & MASK64) ^ high), obj, final)

    def test_unchecked_signed_division_faults_cannot_become_successful_returns(self):
        for high, low, divisor in ((0, 1, 0), (MASK64, 1 << 63, -1), (1, 0, 1)):
            code = Code(); code.mov_imm("rax", low); code.mov_imm("rdx", high)
            code.mov_imm("r11", divisor & MASK64); code.idiv("r11"); code.mov_imm("rax", 0)
            obj, final, _ = self.custom(code)
            with self.assertRaises(SafeCoreRejected):
                self.validate(constant_core(0), obj, final)

    def test_arithmetic_shift_zero_count_preserves_flags_and_multibit_of_is_arbitrary(self):
        code = Code(); code.mov_imm("rax", 1 << 63); code.mov_imm("rdi", 1 << 63)
        code.add("rax", "rdi"); code.mov_imm("rax", 7); code.mov_imm("rcx", 64)
        code.shift_cl("sar", "rax"); code.mov_imm("rax", 0); code.setcc("o", "rax")
        obj, final, _ = self.custom(code)
        self.validate(constant_core(1), obj, final)
        for shift in ("shl", "shr", "sar"):
            for variable in (False, True):
                code = Code(); code.mov_imm("rax", MASK64)
                if variable:
                    code.mov_imm("rcx", 2); code.shift_cl(shift, "rax")
                else:
                    getattr(code, shift)("rax", 2)
                code.mov_imm("rax", 0); code.setcc("o", "rax")
                obj, final, _ = self.custom(code)
                self.assert_refuted(constant_core(0), obj, final, "core_to_final_image_return_abort_and_caller_bytes")
                self.assert_refuted(constant_core(1), obj, final, "core_to_final_image_return_abort_and_caller_bytes")

    def test_undefined_multiply_and_divide_signed_flags_are_not_reused(self):
        for operation in ("imul_rr", "imul_full", "mul", "idiv", "div"):
            for condition in (("s",) if operation.startswith("imul") or operation == "mul" else ("s", "o")):
                code = Code(); code.mov_imm("rax", 7); code.mov_imm("rdi", 3); code.mov_imm("rdx", 0)
                if operation == "imul_rr":
                    code.imul_rr("rax", "rdi")
                else:
                    getattr(code, operation)("rdi")
                code.mov_imm("rax", 0); code.setcc(condition, "rax")
                obj, final, _ = self.custom(code)
                self.assert_refuted(constant_core(0), obj, final, "core_to_final_image_return_abort_and_caller_bytes")
                self.assert_refuted(constant_core(1), obj, final, "core_to_final_image_return_abort_and_caller_bytes")


if __name__ == "__main__":
    unittest.main()
