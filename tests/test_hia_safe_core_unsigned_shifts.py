"""Safe Core v3 keeps unsigned shift checks separate from x86 CL masking."""
from __future__ import annotations

import ctypes
import importlib.util
import json
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest

from hepta.hia_program import verify_program
from hepta.hia_program_native import emit_program_machine, compile_program_machine
from hepta.hia_machine_x64 import Code
from hepta.hia_machine_elf import write_elf_object
from hepta.hia_safe_core import (
    ARTIFACT_PROFILE_V3, OPERATIONS, OPERATIONS_V3, PROFILE_V3,
    SafeCoreRejected, WIDTHS_V2, _profile, _Theory, _unsigned_profile_version,
    build_safe_core, validate_safe_core_artifact,
)
from hepta.hia_safe_core_elf import _ELF, SafeCoreELFRejected
from hepta.hia_safe_core_x64 import decode, SafeCoreMachineRejected
from tests.test_hia_program import b, c, f, i, ret


ROOT = Path(__file__).resolve().parents[1]
MASK64 = (1 << 64) - 1
TYPES = ("u8", "u16", "u32", "u64", "usize")
OPERATORS = ("int.neg.checked", "int.shl.checked", "int.shr.checked")
AVAILABLE = (platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}
             and shutil.which("ld") is not None and importlib.util.find_spec("z3") is not None)


def operation_core(operation, typ="u64"):
    params = [("value", typ)] + ([] if operation == "int.neg.checked" else [("count", typ)])
    return {"schema": "hepta.hia.program.v8", "module": "unsigned_v3", "functions": [
        f("calculate", params, [typ], ["trap"], [b("entry", params,
            [i(operation, [name for name, _ in params], [("answer", typ)])], ret("answer"))])]}


def constant_core(value):
    return {"schema": "hepta.hia.program.v8", "module": "machine_flags", "functions": [
        f("calculate", [], ["u64"], [], [b("entry", [], [c("answer", "u64", value)], ret("answer"))])]}


def identity_core():
    params = [("value", "u64")]
    return {"schema": "hepta.hia.program.v8", "module": "identity", "functions": [
        f("calculate", params, ["u64"], [], [b("entry", params, [], ret("value"))])]}


def constant_count_core(count, direction="shl"):
    params = [("value", "u64")]
    return {"schema": "hepta.hia.program.v8", "module": "fixed_count", "functions": [
        f("calculate", params, ["u64"], ["trap"], [b("entry", params,
            [c("count", "u64", count), i("int." + direction + ".checked",
             ["value", "count"], [("answer", "u64")])], ret("answer"))])]}


class VariableShiftDecoderTests(unittest.TestCase):
    def test_all_register_fields_require_explicit_v3_machine_admission(self):
        for operation, group in (("shl_cl", 4), ("shr_cl", 5)):
            for destination in range(16):
                encoded = bytes((0x48 | (destination >> 3), 0xd3,
                                 0xc0 | (group << 3) | (destination & 7)))
                with self.subTest(operation=operation, destination=destination):
                    with self.assertRaises(SafeCoreMachineRejected):
                        decode(encoded)
                    with self.assertRaises(SafeCoreMachineRejected):
                        decode(encoded, allow_variable_shifts=False)
                    row = decode(encoded, allow_variable_shifts=True)[0]
                    self.assertEqual((row.op, row.args, row.size), (operation, (destination,), 3))

    def test_narrow_memory_prefix_and_unreviewed_group_forms_fail_closed(self):
        for encoded in (
            "d3e0", "40d3e0", "66d3e0", "6648d3e0", "4ad3e0", "4cd3e0",
            "48d3", "48d320", "48d3a000000000", "48d3c0", "48d3d0", "48d3f0",
            "48d3f8", "f048d3e0", "4848d3e0", "48d2e0", "48d3e0e9fcffffff",
        ):
            with self.subTest(encoded=encoded), self.assertRaises(SafeCoreMachineRejected):
                decode(bytes.fromhex(encoded), allow_variable_shifts=True)
        for value in (None, 0, 1, "true"):
            with self.subTest(admission=value), self.assertRaises(SafeCoreMachineRejected):
                decode(b"\xc3", allow_variable_shifts=value)
        with self.assertRaises(SafeCoreMachineRejected):
            decode(bytes.fromhex("c348d3e0"))  # unreachable bytes are also gated


@unittest.skipUnless(AVAILABLE, "Linux x86-64, GNU ld and pinned Z3 are required")
class UnsignedShiftProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="hia-safe-unsigned-shifts-")
        cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name)
        cls.cases = {}
        cls.serial = 0
        for typ in TYPES:
            for operation in OPERATORS:
                checked = verify_program(operation_core(operation, typ))
                image = emit_program_machine(checked)
                stem = typ + "-" + operation
                final = cls.root / (stem + ".so")
                compile_program_machine(image, program=checked, output=final, linker="ld")
                core_path, object_path = cls.root / (stem + ".json"), cls.root / (stem + ".o")
                core_path.write_bytes(checked.canonical_bytes)
                object_path.write_bytes(image.object_bytes)
                cls.cases[typ, operation] = checked, image, final.read_bytes(), core_path, object_path, final

    def custom(self, code):
        """Construct supplied direct ELF bytes with the reviewed abort import."""
        code.ret()
        code.label("abort")
        code.alu_imm("sub", "rsp", 8)
        code.call("abort")
        code.emit(b"\x0f\x0b")
        text, relocations = code.finalize()
        obj = write_elf_object(text, [{"name": "calculate", "offset": 0,
                                      "size": len(text), "global": True}], relocations)
        type(self).serial += 1
        path = self.root / ("custom-" + str(self.serial) + ".so")
        object_path = path.with_suffix(".o")
        object_path.write_bytes(obj)
        subprocess.run(["ld", "-m", "elf_x86_64", "-shared", "-z", "defs", "-z", "noexecstack",
                        "-z", "relro", "-z", "now", "--hash-style=both", "--build-id=none",
                        str(object_path), "-lc", "-o", str(path)], check=True, capture_output=True, timeout=30)
        return obj, path.read_bytes(), path

    def validate(self, core, obj, final, **kwargs):
        return validate_safe_core_artifact(core, obj, final, profile_version=3, **kwargs)

    def mutate(self, typ, operation, changes):
        checked, image, final, *_ = self.cases[typ, operation]
        obj, linked = bytearray(image.object_bytes), bytearray(final)
        for at, replacement in changes:
            self.assertNotEqual(image.text_bytes[at:at + len(replacement)], replacement)
            for data, kind in ((obj, 1), (linked, 3)):
                offset = _ELF(bytes(data), kind).section(".text")["offset"] + at
                data[offset:offset + len(replacement)] = replacement
        return checked, bytes(obj), bytes(linked)

    def refuted(self, core, obj, final):
        with self.assertRaises(SafeCoreRejected) as caught:
            self.validate(core, obj, final)
        self.assertEqual(caught.exception.counterexample["obligation"],
                         "core_to_final_image_return_abort_and_caller_bytes")
        self.assertEqual(caught.exception.validation["obligations"][-1]["result"], "sat")
        self.assertFalse(caught.exception.validation["complete"])
        return caught.exception.counterexample

    def test_new_core_domain_is_explicit_and_does_not_expand_v1_or_v2(self):
        self.assertEqual(OPERATIONS_V3 - OPERATIONS, set(OPERATORS))
        self.assertEqual(_unsigned_profile_version(verify_program(identity_core())), 2)
        for typ in TYPES:
            for operation in OPERATORS:
                checked = self.cases[typ, operation][0]
                self.assertEqual(_unsigned_profile_version(checked), 3)
                self.assertEqual(_profile(checked, profile_version=3)[0]["returns"], [typ])
                for version in (1, 2):
                    with self.subTest(type=typ, operation=operation, version=version), self.assertRaises(SafeCoreRejected):
                        _profile(checked, profile_version=version)
                with self.assertRaises(SafeCoreRejected):
                    _profile(checked)
        for version in (True, False, None, "3", 3.0, 0, 7):
            with self.subTest(version=version), self.assertRaises(SafeCoreRejected):
                _profile(verify_program(identity_core()), profile_version=version)
        with self.assertRaises(SafeCoreRejected):
            _profile(verify_program(operation_core("int.neg.checked", "i64")), profile_version=3)

    def test_independent_reference_matches_unsigned_integer_boundaries(self):
        import z3
        for typ in TYPES:
            width = WIDTHS_V2[typ]; mask = (1 << width) - 1
            dirty = MASK64 ^ mask
            for operation in OPERATORS:
                fn, blocks = _profile(self.cases[typ, operation][0], profile_version=3)
                theory = _Theory(z3, 15000, widths=WIDTHS_V2)
                theory.arguments(fn)
                covered, aborts, result, _ = theory.merge(theory.reference(fn, blocks, None))
                for raw in {0, 1, 1 << (width - 1), mask, dirty, dirty | 1}:
                    counts = (0,) if operation == "int.neg.checked" else {0, 1, width - 1, width, 63, 64, 255, 256, dirty, MASK64}
                    for raw_count in counts:
                        replacements = [(theory.words[0], theory.bv(raw))]
                        if len(theory.words) == 2:
                            replacements.append((theory.words[1], theory.bv(raw_count)))
                        evaluate = lambda expression: z3.simplify(z3.substitute(expression, *replacements))
                        value, count = raw & mask, raw_count & mask
                        bad = value != 0 if operation == "int.neg.checked" else count >= width
                        with self.subTest(type=typ, operation=operation, value=raw, count=raw_count):
                            self.assertTrue(z3.is_true(evaluate(covered)))
                            self.assertEqual(z3.is_true(evaluate(aborts)), bad)
                            if not bad:
                                expected = 0 if operation == "int.neg.checked" else ((value << count) & mask if operation == "int.shl.checked" else value >> count)
                                self.assertEqual(evaluate(result).as_long(), expected)

    def test_all_fifteen_ordinary_wrappers_are_proved_and_execute_dirty_valid_arguments(self):
        for (typ, operation), (checked, image, final, _, _, path) in self.cases.items():
            with self.subTest(type=typ, operation=operation):
                proof = self.validate(checked, image.object_bytes, final)
                self.assertEqual(proof["profile"], ARTIFACT_PROFILE_V3)
                self.assertEqual(proof["image_binding"]["function_shape"], "internal_with_wrapper")
                self.assertEqual([row["result"] for row in proof["obligations"]], ["sat"] + ["unsat"] * 4)
                self.assertFalse(proof["checker"]["producer_reemission_used"])
                library = ctypes.CDLL(str(path)); function = library["calculate"]
                function.argtypes = [ctypes.c_uint64] * (1 if operation == "int.neg.checked" else 2)
                function.restype = ctypes.c_uint64
                width = WIDTHS_V2[typ]; mask = (1 << width) - 1; dirty = MASK64 ^ mask
                if operation == "int.neg.checked":
                    self.assertEqual(function(0), 0)
                    self.assertEqual(function(dirty), 0)
                else:
                    for raw in (0, 1, mask, 1 << (width - 1), dirty | 19):
                        for count in (0, 1, width - 1):
                            expected = ((raw & mask) << count) & mask if operation == "int.shl.checked" else (raw & mask) >> count
                            self.assertEqual(function(raw, count | dirty), expected)
                    if typ == "u8":
                        self.assertEqual(function(197, 256), 197)  # raw count normalizes to zero

    def test_canonical_build_retains_the_explicit_v3_profile(self):
        report = build_safe_core(operation_core("int.shl.checked", "u16"),
                                 self.root / "canonical-v3.so", profile_version=3)
        self.assertEqual(report["validation"]["profile"], PROFILE_V3)
        self.assertEqual(report["validation"]["artifact_input_profile"], ARTIFACT_PROFILE_V3)

    def test_v1_and_v2_artifact_decoders_still_refuse_variable_shifts_for_old_core(self):
        code = Code(); code.mov_rr("rax", "rdi"); code.mov_imm("rcx", 0); code.shift_cl("shl", "rax")
        obj, final, _ = self.custom(code)
        for version in (1, 2):
            with self.subTest(version=version), self.assertRaises(SafeCoreMachineRejected):
                validate_safe_core_artifact(identity_core(), obj, final, profile_version=version)
        with self.assertRaises(SafeCoreMachineRejected):
            validate_safe_core_artifact(identity_core(), obj, final)
        self.assertTrue(self.validate(identity_core(), obj, final)["complete"])

    def test_wrong_shift_direction_has_a_concrete_valid_count_counterexample(self):
        for typ in ("u8", "u64"):
            for operation in ("int.shl.checked", "int.shr.checked"):
                image = self.cases[typ, operation][1]
                at, row = next((at, row) for at, row in decode(image.text_bytes, allow_variable_shifts=True).items()
                               if row.op in ("shl_cl", "shr_cl"))
                raw = bytearray(image.text_bytes[at:at + row.size]); raw[-1] ^= 8
                witness = self.refuted(*self.mutate(typ, operation, [(at, bytes(raw))]))
                mask = (1 << WIDTHS_V2[typ]) - 1
                value, count = (word & mask for word in witness["abi_words"])
                self.assertLess(count, WIDTHS_V2[typ])
                self.assertNotEqual((value << count) & mask, value >> count)

    def test_removing_count_guards_is_refuted_at_every_unsigned_width(self):
        for typ in TYPES:
            for operation in ("int.shl.checked", "int.shr.checked"):
                image = self.cases[typ, operation][1]
                rows = list(decode(image.text_bytes, allow_variable_shifts=True).items())
                at, row = next((at, row) for at, row in rows if row.op == "jcc" and row.args[0] == 3)
                witness = self.refuted(*self.mutate(typ, operation, [(at, b"\x90" * row.size)]))
                self.assertGreaterEqual(witness["abi_words"][1] & ((1 << WIDTHS_V2[typ]) - 1), WIDTHS_V2[typ])

    def test_full_counts_64_and_256_must_abort_even_when_hardware_effective_count_is_zero(self):
        for direction in ("shl", "shr"):
            for count in (64, 256):
                code = Code(); code.mov_rr("rax", "rdi"); code.mov_imm("rcx", count); code.shift_cl(direction, "rax")
                obj, final, _ = self.custom(code)
                self.refuted(constant_count_core(count, direction), obj, final)

    def test_unsigned_negation_cannot_return_nonzero_inputs(self):
        for typ in TYPES:
            image = self.cases[typ, "int.neg.checked"][1]
            at, row = next((at, row) for at, row in decode(image.text_bytes).items()
                           if row.op == "jcc" and row.args[0] == 5)
            witness = self.refuted(*self.mutate(typ, "int.neg.checked", [(at, b"\x90" * row.size)]))
            self.assertNotEqual(witness["abi_words"][0] & ((1 << WIDTHS_V2[typ]) - 1), 0)

    def test_left_shift_discards_value_bits_and_does_not_add_an_overflow_trap(self):
        code = Code(); code.mov_rr("rax", "rdi"); code.mov_imm("rcx", 1)
        code.shift_cl("shl", "rax"); code.jcc("b", "abort")
        obj, final, _ = self.custom(code)
        witness = self.refuted(constant_count_core(1), obj, final)
        self.assertGreaterEqual(witness["abi_words"][0], 1 << 63)

    def test_narrow_left_shift_must_truncate_the_result(self):
        for typ in ("u8", "u16", "u32"):
            width = WIDTHS_V2[typ]; mask = (1 << width) - 1
            code = Code(); code.mov_rr("rax", "rdi"); code.mov_rr("rcx", "rsi")
            code.mov_imm("r10", mask); code.and_("rax", "r10"); code.and_("rcx", "r10")
            code.alu_imm("cmp", "rcx", width); code.jcc("ae", "abort"); code.shift_cl("shl", "rax")
            obj, final, _ = self.custom(code)
            witness = self.refuted(operation_core("int.shl.checked", typ), obj, final)
            value, count = (word & mask for word in witness["abi_words"])
            self.assertLess(count, width)
            self.assertNotEqual((value << count) & MASK64, (value << count) & mask)

    def test_effective_zero_preserves_destination_cf_and_zf(self):
        flag_cases = (("b", 0, 1, 0, 1), ("b", 1, 0, MASK64, 0),
                      ("e", 7, 7, MASK64, 1), ("e", 0, 1, 0, 0))
        for direction in ("shl", "shr"):
            for count in (0, 64, 256):
                code = Code(); code.mov_rr("rax", "rdi"); code.mov_imm("rcx", count); code.shift_cl(direction, "rax")
                obj, final, _ = self.custom(code)
                self.assertTrue(self.validate(identity_core(), obj, final)["complete"])
                for condition, left, right, value, expected in flag_cases:
                    code = Code(); code.mov_imm("r8", left); code.mov_imm("r9", right); code.cmp("r8", "r9")
                    code.mov_imm("rax", value); code.mov_imm("rcx", count); code.shift_cl(direction, "rax")
                    code.setcc(condition, "rax")
                    obj, final, path = self.custom(code)
                    self.assertTrue(self.validate(constant_core(expected), obj, final)["complete"])
                    library = ctypes.CDLL(str(path)); function = library["calculate"]
                    function.argtypes, function.restype = [], ctypes.c_uint64
                    self.assertEqual(function(), expected)

    def test_nonzero_shift_flags_use_last_shifted_bit_and_full_result(self):
        cases = ((1 << 63, 1), (1, 1), (3, 63), (1 << 62, 63),
                 (MASK64, 65), (0, 65), (1, 255), (MASK64, 257))
        for direction in ("shl", "shr"):
            for value, raw_count in cases:
                count = raw_count & 63
                result = ((value << count) & MASK64) if direction == "shl" else value >> count
                carry = (value >> (64 - count if direction == "shl" else count - 1)) & 1
                expected = carry | ((result == 0) << 1)
                code = Code(); code.mov_imm("rax", value); code.mov_imm("rcx", raw_count); code.shift_cl(direction, "rax")
                code.setcc("b", "r10"); code.setcc("e", "r11"); code.shl("r11", 1)
                code.mov_rr("rax", "r10"); code.or_("rax", "r11")
                obj, final, path = self.custom(code)
                self.assertTrue(self.validate(constant_core(expected), obj, final)["complete"])
                library = ctypes.CDLL(str(path)); function = library["calculate"]
                function.argtypes, function.restype = [], ctypes.c_uint64
                self.assertEqual(function(), expected)

    def test_rcx_destination_reads_its_original_cl_before_overwriting_it(self):
        params = [("value", "u64")]
        for direction in ("shl", "shr"):
            core = {"schema": "hepta.hia.program.v8", "module": "shift_alias", "functions": [
                f("calculate", params, ["u64"], ["trap"], [b("entry", params,
                    [i("int." + direction + ".checked", ["value", "value"], [("answer", "u64")])], ret("answer"))])]}
            code = Code(); code.mov_rr("rcx", "rdi"); code.alu_imm("cmp", "rcx", 64); code.jcc("ae", "abort")
            code.shift_cl(direction, "rcx"); code.mov_rr("rax", "rcx")
            obj, final, path = self.custom(code)
            self.assertTrue(self.validate(core, obj, final)["complete"])
            library = ctypes.CDLL(str(path)); function = library["calculate"]
            function.argtypes, function.restype = [ctypes.c_uint64], ctypes.c_uint64
            for value in (0, 1, 2, 7, 31, 63):
                self.assertEqual(function(value), ((value << value) & MASK64) if direction == "shl" else value >> value)

    def test_checked_abort_has_real_native_sigabrt_witnesses(self):
        script = r'''
import ctypes, json, resource, sys
from pathlib import Path
from hepta.hia_safe_core import validate_safe_core_artifact
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
core, obj, final = (Path(value) for value in sys.argv[1:4])
assert validate_safe_core_artifact(json.loads(core.read_text()), obj.read_bytes(), final.read_bytes(), profile_version=3)['complete']
library = ctypes.CDLL(str(final)); fn = library['calculate']
args = [int(value) for value in sys.argv[4:]]
fn.argtypes, fn.restype = [ctypes.c_uint64] * len(args), ctypes.c_uint64
fn(*args)
raise AssertionError('checked operation unexpectedly returned')
'''
        for typ, operation, values in (
            ("u64", "int.shl.checked", (7, 64)), ("u64", "int.shl.checked", (7, 256)),
            ("u64", "int.shr.checked", (7, 64)), ("u64", "int.shr.checked", (7, 256)),
            ("u8", "int.neg.checked", (1,)), ("usize", "int.neg.checked", (MASK64,)),
        ):
            process = subprocess.run([sys.executable, "-B", "-c", script,
                *map(str, self.cases[typ, operation][3:]), *map(str, values)],
                cwd=ROOT, capture_output=True, text=True, timeout=45)
            self.assertEqual(process.returncode, -signal.SIGABRT, process.stdout + process.stderr)

    def test_borrowed_memory_effect_before_checked_shift_is_preserved_on_abort(self):
        params = [("memory", "mutbuf"), ("value", "u32"), ("count", "u32")]
        core = {"schema": "hepta.hia.program.v8", "module": "shift_after_store", "functions": [
            f("calculate", params, ["u32"], ["write", "trap"], [b("entry", params,
                [c("index", "usize", 0), c("byte", "u8", 91), i("buffer.store", ["memory", "index", "byte"]),
                 i("int.shl.checked", ["value", "count"], [("answer", "u32")])], ret("answer"))])]}
        report = build_safe_core(core, self.root / "borrowed-v3.so", profile_version=3, foreign_extent=64)
        self.assertEqual(report["validation"]["profile"], PROFILE_V3)
        self.assertEqual(report["validation"]["obligations"][-1]["result"], "unsat")

    def test_fresh_v3_consumer_imports_no_native_producer(self):
        script = r'''
import importlib.abc, json, sys
from pathlib import Path
blocked = {'hepta.hia_program_native', 'hepta.hia_machine_x64', 'hepta.hia_machine_elf',
           'hepta.hia_native_byte_abi', 'hepta.hia_verified_scalar'}
class RejectProducer(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in blocked:
            raise AssertionError('producer import during independent v3 validation: ' + fullname)
sys.meta_path.insert(0, RejectProducer())
from hepta.hia_safe_core import validate_safe_core_artifact
proof = validate_safe_core_artifact(json.loads(Path(sys.argv[1]).read_text()),
    Path(sys.argv[2]).read_bytes(), Path(sys.argv[3]).read_bytes(), profile_version=3)
assert proof['complete'] and not blocked.intersection(sys.modules)
print(json.dumps({'ok': proof['ok'], 'profile': proof['profile'], 'producer_imported': False}))
'''
        process = subprocess.run([sys.executable, "-B", "-c", script,
            *map(str, self.cases["u16", "int.shl.checked"][3:])],
            cwd=ROOT, capture_output=True, text=True, timeout=45)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertEqual(json.loads(process.stdout), {"ok": True, "profile": ARTIFACT_PROFILE_V3, "producer_imported": False})

    def test_final_only_shift_change_cannot_reuse_object_identity(self):
        checked, image, data, *_ = self.cases["u64", "int.shl.checked"]
        at = next(at for at, row in decode(image.text_bytes, allow_variable_shifts=True).items() if row.op == "shl_cl")
        changed = bytearray(data)
        changed[_ELF(data, 3).section(".text")["offset"] + at + 2] ^= 8
        with self.assertRaises(SafeCoreELFRejected):
            self.validate(checked, image.object_bytes, bytes(changed))


if __name__ == "__main__":
    unittest.main()
