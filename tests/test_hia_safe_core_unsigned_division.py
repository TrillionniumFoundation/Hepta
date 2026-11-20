"""Safe Core v5 checks unsigned DIV, including its complete dividend and #DE."""
from __future__ import annotations

import ctypes
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest

from hepta.hia_machine_x64 import Code
from hepta.hia_program import verify_program
from hepta.hia_program_native import compile_program_machine, emit_program_machine
from hepta.hia_program_runtime import HIAProgramTrap, execute_program
from hepta.hia_safe_core import (
    ARTIFACT_PROFILE_V5, OPERATIONS_V4, OPERATIONS_V5, PROFILE_V5, SafeCoreRejected,
    WIDTHS_V2, _profile, _Theory, _unsigned_profile_version, build_safe_core,
    validate_safe_core_artifact,
)
from hepta.hia_safe_core_x64 import SafeCoreMachineRejected, _unsigned_division, decode
from tests.test_hia_program import arithmetic, b, c, f, i, ret
from tests import test_hia_safe_core_unsigned_multiply as multiply_legacy
from tests import test_hia_verified_scalar_checked as checked_legacy


ROOT = Path(__file__).resolve().parents[1]
MASK64 = (1 << 64) - 1
TYPES = ("u8", "u16", "u32", "u64", "usize")
DIVISIONS = ("int.div.checked", "int.rem.checked")


class UnsignedDivisionDecoderTests(unittest.TestCase):
    def test_every_register_divisor_requires_explicit_v5_admission(self):
        for register in range(16):
            encoded = bytes((0x48 | (register >> 3), 0xf7, 0xf0 | (register & 7)))
            with self.subTest(register=register):
                for kwargs in ({}, {"allow_unsigned_divide": False},
                               {"allow_variable_shifts": True, "allow_unsigned_multiply": True}):
                    with self.assertRaises(SafeCoreMachineRejected):
                        decode(encoded, **kwargs)
                row = decode(encoded, allow_unsigned_divide=True)[0]
                self.assertEqual((row.op, row.args, row.size), ("div", (register,), 3))

    def test_only_reviewed_64_bit_unsigned_register_division_is_admitted(self):
        for encoded in (
            "f7f0", "40f7f0", "66f7f0", "6648f7f0", "4af7f0", "4cf7f0",
            "48f7", "48f730", "48f7b000000000", "48f7e8", "48f7f8",
            "48f6f0", "f048f7f0", "4848f7f0", "48f7f0e9fcffffff",
        ):
            with self.subTest(encoded=encoded), self.assertRaises(SafeCoreMachineRejected):
                decode(bytes.fromhex(encoded), allow_unsigned_divide=True)
        for flag in (None, 0, 1, "true"):
            with self.subTest(admission=flag), self.assertRaises(SafeCoreMachineRejected):
                decode(b"\xc3", allow_unsigned_divide=flag)
        with self.assertRaises(SafeCoreMachineRejected):
            decode(bytes.fromhex("c348f7f0"), allow_unsigned_multiply=True)


@unittest.skipUnless(checked_legacy.AVAILABLE, "Linux x86-64, GNU ld and pinned Z3 are required")
class UnsignedDivisionModelTests(unittest.TestCase):
    def test_dividend_reduction_and_overflow_criterion_have_all_integer_proofs(self):
        # Euclidean division is characterized by N=Q*D+R, 0<=R<D. Prove
        # the two exact reductions used by the independent machine model,
        # and uniqueness of its quotient/remainder, over unbounded integers.
        import z3
        high, low, divisor, quotient, remainder, other_q, other_r = z3.Ints(
            "high low divisor quotient remainder other_q other_r")
        base = 1 << 64
        common = [low >= 0, low < base, divisor >= 1, divisor < base,
                  quotient >= 0, remainder >= 0, remainder < divisor]
        cases = (
            (common + [low == quotient * divisor + remainder], quotient >= base),
            (common + [high >= 0, high < base, high * base + low == quotient * divisor + remainder],
             (high >= divisor) != (quotient >= base)),
            (common + [low == quotient * divisor + remainder, other_q >= 0,
                       other_r >= 0, other_r < divisor, low == other_q * divisor + other_r],
             z3.Or(quotient != other_q, remainder != other_r)),
        )
        for number, (constraints, failure) in enumerate(cases):
            with self.subTest(identity=number):
                solver = z3.Solver(); solver.set(timeout=15000)
                solver.add(*constraints, failure)
                self.assertEqual(solver.check(), z3.unsat)

    def test_full_128_bit_dividend_matches_big_integer_boundaries(self):
        import z3
        values = (0, 1, 2, 3, 1 << 63, MASK64)
        for high in values:
            for low in values:
                for divisor in values:
                    word = lambda value: z3.BitVecVal(value, 64)
                    quotient, remainder, admitted = _unsigned_division(z3, word(high), word(low), word(divisor))
                    total = (high << 64) | low
                    valid = divisor != 0 and total // divisor <= MASK64
                    self.assertEqual(z3.is_true(admitted), valid)
                    if valid:
                        self.assertEqual(quotient.as_long(), total // divisor)
                        self.assertEqual(remainder.as_long(), total % divisor)

    def test_core_quotient_remainder_and_zero_traps_match_vm_and_integer_math(self):
        import z3
        for typ in TYPES:
            width = WIDTHS_V2[typ]; mask = (1 << width) - 1; dirty = MASK64 ^ mask
            for operation in DIVISIONS:
                core = arithmetic(operation, typ)
                fn, blocks = _profile(verify_program(core), profile_version=5)
                theory = _Theory(z3, 15000, widths=WIDTHS_V2); theory.arguments(fn)
                covered, aborted, result, _ = theory.merge(theory.reference(fn, blocks, None))
                for raw_left in (0, 1, 2, 17, mask, dirty, dirty | 17, MASK64):
                    for raw_right in (0, 1, 2, 3, mask, dirty, dirty | 3, MASK64):
                        left, right = raw_left & mask, raw_right & mask
                        replacements = [(theory.words[0], theory.bv(raw_left)),
                                        (theory.words[1], theory.bv(raw_right))]
                        evaluate = lambda expression: z3.simplify(z3.substitute(expression, *replacements))
                        self.assertTrue(z3.is_true(evaluate(covered)))
                        self.assertEqual(z3.is_true(evaluate(aborted)), right == 0)
                        if right:
                            expected = left // right if operation == "int.div.checked" else left % right
                            self.assertEqual(evaluate(result).as_long(), expected)
                            self.assertEqual(execute_program(core, "calculate", [left, right])["result"], expected)
                        else:
                            with self.assertRaises(HIAProgramTrap) as caught:
                                execute_program(core, "calculate", [left, right])
                            self.assertEqual(caught.exception.code, "division_by_zero")


@unittest.skipUnless(checked_legacy.AVAILABLE, "Linux x86-64, GNU ld and pinned Z3 are required")
class UnsignedDivisionProfileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hia-safe-division-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name); self.serial = 0

    def custom(self, code):
        return multiply_legacy.UnsignedMultiplyProfileTests.custom(self, code)

    def validate(self, core, obj, final):
        return validate_safe_core_artifact(core, obj, final, profile_version=5)

    def refuted(self, core, obj, final, obligation="core_to_final_image_return_abort_and_caller_bytes"):
        with self.assertRaises(SafeCoreRejected) as caught:
            self.validate(core, obj, final)
        self.assertEqual(caught.exception.validation["status"], "refuted")
        self.assertEqual(caught.exception.counterexample["obligation"], obligation)
        return caught.exception.counterexample

    def test_v5_is_explicit_and_all_old_core_domains_remain_closed(self):
        self.assertEqual(OPERATIONS_V5 - OPERATIONS_V4, set(DIVISIONS))
        for operation in DIVISIONS:
            for typ in TYPES:
                checked = verify_program(arithmetic(operation, typ))
                self.assertEqual(_unsigned_profile_version(checked), 5)
                self.assertEqual(_profile(checked, profile_version=5)[0]["returns"], [typ])
                for version in (1, 2, 3, 4):
                    with self.subTest(operation=operation, type=typ, version=version), self.assertRaises(SafeCoreRejected):
                        _profile(checked, profile_version=version)
            for typ in ("i8", "i16", "i32", "i64", "isize"):
                with self.subTest(operation=operation, signed=typ), self.assertRaises(SafeCoreRejected):
                    _profile(verify_program(arithmetic(operation, typ)), profile_version=5)
        for version in (True, False, None, "5", 5.0, 0, 6):
            with self.subTest(version=version), self.assertRaises(SafeCoreRejected):
                _profile(verify_program(multiply_legacy.constant_core(1)), profile_version=version)
        for operation, expected in (("int.add.checked", 2), ("int.shr.checked", 3), ("int.mul.checked", 4)):
            self.assertEqual(_unsigned_profile_version(verify_program(arithmetic(operation, "u64"))), expected)

    def test_gnu_as_independently_encodes_every_register_divisor(self):
        registers = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                     "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")
        assembly = ".intel_syntax noprefix\n.text\n" + "".join("div " + reg + "\n" for reg in registers)
        obj, text = self.root / "assembled.o", self.root / "assembled.text"
        subprocess.run(["as", "--64", "-o", str(obj), "-"], input=assembly.encode(),
                       check=True, capture_output=True, timeout=30)
        subprocess.run(["objcopy", "--only-section=.text", "-O", "binary", str(obj), str(text)],
                       check=True, capture_output=True, timeout=30)
        assembled = text.read_bytes()
        decoded = decode(assembled, allow_unsigned_divide=True)
        self.assertEqual([(row.op, row.args, row.size) for row in decoded.values()],
                         [("div", (number,), 3) for number in range(16)])
        code = Code()
        for register in registers:
            code.div(register)
        self.assertEqual(code.finalize(), (assembled, []))

    def test_all_ten_ordinary_wrappers_prove_execute_and_abort_on_normalized_zero(self):
        for typ in TYPES:
            width = WIDTHS_V2[typ]; mask = (1 << width) - 1; dirty = MASK64 ^ mask
            for operation in DIVISIONS:
                with self.subTest(type=typ, operation=operation):
                    checked = verify_program(arithmetic(operation, typ))
                    image = emit_program_machine(checked)
                    path = self.root / (typ + operation + ".so")
                    compile_program_machine(image, program=checked, output=path, linker="ld")
                    proof = self.validate(checked, image.object_bytes, path.read_bytes())
                    self.assertEqual(proof["profile"], ARTIFACT_PROFILE_V5)
                    self.assertEqual([row["result"] for row in proof["obligations"]], ["sat"] + ["unsat"] * 4)
                    function = ctypes.CDLL(str(path)).calculate
                    function.argtypes = [ctypes.c_uint64] * 2; function.restype = ctypes.c_uint64
                    for left, right in ((mask, 1), (mask, 3), (0, mask), (mask, mask), (17, 3)):
                        expected = left // right if operation == "int.div.checked" else left % right
                        self.assertEqual(function(left | dirty, right | dirty), expected)
                    checked_legacy.CheckedRegisterTests.aborts(self, path, "calculate", (17, dirty))

    def test_actual_nonzero_high_dividend_and_rax_alias_are_preserved(self):
        for high, low, divisor, source in ((1, 0, 3, "r11"), (MASK64 - 1, MASK64, MASK64, "r11"),
                                           (1, 7, 7, "rax"), (0, 7, 7, "rax")):
            quotient, remainder = divmod((high << 64) | low, divisor)
            code = Code(); code.mov_imm("rax", low); code.mov_imm("rdx", high)
            code.mov_imm("r11", divisor); code.div(source); code.xor("rax", "rdx")
            obj, final, path = self.custom(code)
            expected = quotient ^ remainder
            with self.subTest(high=high, low=low, source=source):
                proof = self.validate(multiply_legacy.constant_core(expected), obj, final)
                self.assertTrue(proof["complete"])
                function = ctypes.CDLL(str(path)).calculate
                function.argtypes = []; function.restype = ctypes.c_uint64
                self.assertEqual(function(), expected)
                for version in (1, 2, 3, 4):
                    with self.assertRaises(SafeCoreMachineRejected):
                        validate_safe_core_artifact(multiply_legacy.constant_core(expected), obj, final,
                                                    profile_version=version)

    def test_divide_error_and_rdx_alias_are_never_treated_as_core_abort(self):
        script = ("import ctypes,resource,sys; resource.setrlimit(resource.RLIMIT_CORE,(0,0)); "
                  "fn=ctypes.CDLL(sys.argv[1]).calculate; fn.argtypes=[]; fn.restype=ctypes.c_uint64; fn()")
        for high, divisor, source in ((0, 0, "r11"), (1, 1, "r11"), (1, 0, "rdx")):
            code = Code(); code.mov_imm("rax", 7); code.mov_imm("rdx", high)
            code.mov_imm("r11", divisor); code.div(source)
            obj, final, path = self.custom(code)
            with self.subTest(high=high, divisor=divisor, source=source):
                # Every state faults in these constant programs. The existing
                # empty-outcome rule rejects before SMT; this is not a SAT
                # counterexample. Symbolic missing-guard tests separately
                # retain real totality counterexamples and no published image.
                with self.assertRaisesRegex(SafeCoreRejected, "model has no terminal outcome"):
                    self.validate(multiply_legacy.constant_core(7), obj, final)
                process = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(path)],
                                         capture_output=True, timeout=10)
                self.assertEqual(process.returncode, -signal.SIGFPE, process.stderr)

    def test_both_division_flags_are_arbitrary_and_cannot_preserve_prior_values(self):
        for condition, prior in (("b", 0), ("b", 8), ("e", 0), ("e", 7), ("be", 7)):
            code = Code(); code.mov_imm("rax", 7); code.mov_imm("rdx", 0); code.mov_imm("r11", 7)
            code.alu_imm("cmp", "rax", prior); code.div("r11")
            code.mov_imm("rax", 0); code.setcc(condition, "rax")
            obj, final, _ = self.custom(code)
            with self.subTest(condition=condition, prior=prior):
                self.refuted(multiply_legacy.constant_core(0), obj, final)

    def test_borrowed_write_before_division_by_zero_is_preserved(self):
        params = [("memory", "mutbuf"), ("value", "u32"), ("divisor", "u32")]
        for operation in DIVISIONS:
            core = {"schema": "hepta.hia.program.v8", "module": "division_after_store", "functions": [
                f("calculate", params, ["u32"], ["write", "trap"], [b("entry", params,
                    [c("index", "usize", 0), c("byte", "u8", 91), i("buffer.store", ["memory", "index", "byte"]),
                     i(operation, ["value", "divisor"], [("answer", "u32")])], ret("answer"))])]}
            report = build_safe_core(core, self.root / (operation + ".so"), profile_version=5, foreign_extent=64)
            self.assertEqual(report["validation"]["profile"], PROFILE_V5)
            self.assertEqual(report["validation"]["obligations"][-1]["result"], "unsat")

    def test_cli_build_check_and_fresh_consumer_retain_explicit_v5(self):
        source = self.root / "division.core.hepta"
        source.write_bytes(verify_program(arithmetic("int.rem.checked", "u16")).canonical_bytes)
        built, checked = self.root / "build", self.root / "check"
        commands = (
            [str(ROOT / "tools/build_hia_safe_core.py"), "--source", str(source), "--output", str(built)],
            [str(ROOT / "tools/check_hia_safe_core.py"), "--source", str(source), "--object", str(built / "candidate.o"),
             "--image", str(built / "program.so"), "--output", str(checked)],
        )
        for command in commands:
            process = subprocess.run([sys.executable, "-I", "-B", *command, "--profile-version", "5"],
                                     cwd=ROOT, capture_output=True, text=True, timeout=45)
            self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
            self.assertTrue(json.loads(process.stdout)["ok"])
        receipt = json.loads((checked / "attempt.json").read_bytes())
        self.assertEqual(receipt["validation"]["profile"], ARTIFACT_PROFILE_V5)
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
from hepta.hia_safe_core import validate_safe_core_artifact
directory = Path(sys.argv[2])
proof = validate_safe_core_artifact(json.loads((directory / 'core.core.hepta').read_bytes()),
    (directory / 'candidate.o').read_bytes(), (directory / 'program.so').read_bytes(), profile_version=5)
assert proof['ok'] and proof['complete'] and not blocked.intersection(sys.modules)
'''
        process = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(ROOT), str(built)],
                                 capture_output=True, text=True, timeout=45)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)


if __name__ == "__main__":
    unittest.main()
