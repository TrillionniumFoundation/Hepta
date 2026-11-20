"""Signed final-byte refinement: independent arithmetic, traps and ABI controls.

Native comparisons use Python integer arithmetic and explicit two's-complement
conversion. The noncanonical leaves are supplied directly as machine bytes;
their admission never depends on reproducing the register producer's output.
"""
from __future__ import annotations

import ctypes
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_machine_elf import write_elf_object
from hepta.hia_machine_x64 import Code
from hepta.hia_safe_core import SafeCoreRejected, validate_safe_core_artifact
from hepta.hia_verified_kernel import build_verified_kernel, select_verified_kernel
from hepta.hia_verified_kernel_load import load_verified_scalar_kernel
from hepta.hia_verified_scalar import build_verified_scalar, emit_verified_scalar
from tests.test_hia_program import arithmetic, b, c, f, i, m, ret
from tests import test_hia_verified_scalar_checked as legacy


SIGNED = (("i8", 8), ("i16", 16), ("i32", 32), ("i64", 64), ("isize", 64))
UNSIGNED = (("u8", 8), ("u16", 16), ("u32", 32), ("u64", 64), ("usize", 64))
WORD_MASK = (1 << 64) - 1


def signed(value, width):
    value &= (1 << width) - 1
    return value - (1 << width) if value & (1 << (width - 1)) else value


def raw(value):
    return value & WORD_MASK


def divide(left, right):
    quotient = abs(left) // abs(right)
    return -quotient if (left < 0) != (right < 0) else quotient


def unary(operation, typ):
    params = [("value", typ)]
    return m(f("calculate", params, [typ], ["trap"], [b("entry", params, [
        i(operation, ["value"], [("answer", typ)]),
    ], ret("answer"))]))


def cast(source, target, mode):
    params = [("value", source)]
    return m(f("convert", params, [target], ["trap"], [b("entry", params, [
        i("int.cast", ["value"], [("answer", target)], mode=mode),
    ], ret("answer"))]))


def constant_binary(operation, left, right, typ="i64"):
    return m(f("calculate", [], [typ], ["trap"], [b("entry", [], [
        c("left", typ, left), c("right", typ, right),
        i(operation, ["left", "right"], [("answer", typ)]),
    ], ret("answer"))]))


def live_arithmetic(operation, left="a", right="b"):
    params = [(name, "i64") for name in "abcdef"]
    operations = [c("k", "i64", -7),
                  i(operation, [left, right], [("value", "i64")])]
    result = "value"
    for number, name in enumerate("abcdefk"):
        output = "sum" + str(number)
        operations.append(i("int.add.wrap", [result, name], [(output, "i64")]))
        result = output
    return m(f("calculate", params, ["i64"], ["trap"], [b("entry", params, operations, ret(result))]))


@unittest.skipUnless(legacy.AVAILABLE, "Linux x86-64, GNU ld and pinned Z3 are required")
class SignedRegisterTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hia-signed-register-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.serial = 0

    def build(self, core):
        self.serial += 1
        path = self.root / (str(self.serial) + ".so")
        image = emit_verified_scalar(core)
        report = build_verified_scalar(core, path, image=image)
        self.assertEqual(image.core_profile_version, 6)
        self.assertEqual(report["core_profile_version"], 6)
        self.assertTrue(report["validation"]["complete"])
        self.assertEqual([row["result"] for row in report["validation"]["obligations"]],
                         ["sat", "unsat", "unsat", "unsat", "unsat"])
        self.assertEqual(report["hot_stack_bytes"], 0)
        function = getattr(ctypes.CDLL(str(path)), image.export)
        function.argtypes = [ctypes.c_uint64] * len(core["functions"][0]["params"])
        function.restype = ctypes.c_uint64
        return image, path, report, function

    def aborts(self, path, export, values):
        legacy.CheckedRegisterTests.aborts(self, path, export, tuple(map(raw, values)))

    def custom_leaf(self, core, body, name):
        """Package supplied machine bytes; no scalar producer is consulted."""
        code = Code()
        code.emit(bytes.fromhex(body))
        code.push("rbp")
        code.call("abort")
        code.ud2()
        text, relocations = code.finalize()
        export = core["functions"][0]["name"]
        object_bytes = write_elf_object(text, [{"name": export, "offset": 0,
                                               "size": len(text), "global": True}], relocations)
        object_path, final_path = self.root / (name + ".o"), self.root / (name + ".so")
        object_path.write_bytes(object_bytes)
        result = subprocess.run(["ld", "-m", "elf_x86_64", "-shared", "-z", "defs",
            "-z", "noexecstack", "-z", "relro", "-z", "now", "--hash-style=both",
            "--build-id=none", str(object_path), "-lc", "-o", str(final_path)],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return object_bytes, final_path.read_bytes()

    def rejected_leaf(self, core, body, name, *, obligation=None):
        object_bytes, final_bytes = self.custom_leaf(core, body, name)
        with self.assertRaises(SafeCoreRejected) as caught:
            validate_safe_core_artifact(core, object_bytes, final_bytes, profile_version=6)
        self.assertEqual(caught.exception.validation["status"], "refuted")
        self.assertIsNotNone(caught.exception.counterexample)
        self.assertFalse(caught.exception.validation["complete"])
        if obligation is not None:
            self.assertEqual(caught.exception.counterexample["obligation"], obligation)
        return caught.exception.counterexample

    def test_wrapping_add_sub_multiply_use_signed_results_at_all_widths(self):
        for typ, width in SIGNED:
            lo, hi, mask = -(1 << (width - 1)), (1 << (width - 1)) - 1, (1 << width) - 1
            values = (lo, lo + 1, -7, -1, 0, 1, 3, hi)
            for operation in ("int.add.wrap", "int.sub.wrap", "int.mul.wrap"):
                with self.subTest(type=typ, operation=operation):
                    _, _, _, function = self.build(arithmetic(operation, typ))
                    for left in values:
                        for right in values:
                            answer = (left + right if operation == "int.add.wrap" else
                                      left - right if operation == "int.sub.wrap" else left * right)
                            expected = raw(signed(answer, width))
                            self.assertEqual(function(raw(left), raw(right)), expected)
                            # Opposite high-bit patterns cannot affect a narrow input.
                            self.assertEqual(function(left & mask, (right & mask) | (WORD_MASK ^ mask)), expected)

    def test_checked_add_subtract_cover_signed_min_max_and_native_abort(self):
        for typ, width in SIGNED:
            lo, hi = -(1 << (width - 1)), (1 << (width - 1)) - 1
            mask = (1 << width) - 1
            for operation in ("int.add.checked", "int.sub.checked"):
                with self.subTest(type=typ, operation=operation):
                    _, path, _, function = self.build(arithmetic(operation, typ))
                    pairs = ((lo, 0), (hi, 0), (-7, 3), (7, -3), (-1, 1), (0, 0))
                    for left, right in pairs:
                        expected = left + right if operation == "int.add.checked" else left - right
                        self.assertEqual(function(raw(left), raw(right)), raw(expected))
                        self.assertEqual(function(left & mask, right & mask), raw(expected))
                    invalid = ((hi, 1), (lo, -1), (lo, lo)) if operation == "int.add.checked" else (
                        (lo, 1), (hi, -1), (hi, lo))
                    for values in invalid:
                        self.aborts(path, "calculate", values)

    def test_checked_multiply_keeps_signed_high_half_and_each_width_boundary(self):
        for typ, width in SIGNED:
            lo, hi = -(1 << (width - 1)), (1 << (width - 1)) - 1
            with self.subTest(type=typ):
                _, path, _, function = self.build(arithmetic("int.mul.checked", typ))
                for left, right in ((0, lo), (lo, 0), (lo, 1), (hi, 1), (-7, 3), (-7, -3), (3, hi // 3)):
                    self.assertEqual(function(raw(left), raw(right)), raw(left * right))
                for values in ((lo, -1), (hi, 2), (lo, 2), (hi, hi)):
                    self.aborts(path, "calculate", values)

    def test_division_and_remainder_truncate_toward_zero_and_trap_min_over_minus_one(self):
        for typ, width in SIGNED:
            lo, hi = -(1 << (width - 1)), (1 << (width - 1)) - 1
            mask = (1 << width) - 1
            for operation in ("int.div.checked", "int.rem.checked"):
                with self.subTest(type=typ, operation=operation):
                    _, path, _, function = self.build(arithmetic(operation, typ))
                    pairs = ((-7, 3), (7, -3), (-7, -3), (7, 3), (lo, 1), (lo, 3),
                             (hi, -1), (-1, lo), (0, -1), (lo, lo), (1, hi))
                    for left, right in pairs:
                        quotient = divide(left, right)
                        expected = quotient if operation == "int.div.checked" else left - quotient * right
                        self.assertEqual(function(raw(left), raw(right)), raw(expected))
                        self.assertEqual(function(left & mask, right & mask), raw(expected))
                    self.aborts(path, "calculate", (lo, -1))
                    self.aborts(path, "calculate", (1, 0))
                    if width == 8:
                        # Exhaust all valid i8 pairs; negative remainders differ
                        # from Python's % rule, hence the explicit quotient.
                        for left in range(-128, 128):
                            for right in range(-128, 128):
                                if right == 0 or (left == -128 and right == -1):
                                    continue
                                quotient = divide(left, right)
                                answer = quotient if operation == "int.div.checked" else left - quotient * right
                                self.assertEqual(function(raw(left), raw(right)), raw(answer))

    def test_negation_and_arithmetic_shift_cover_negative_values_and_all_counts(self):
        for typ, width in SIGNED:
            lo, hi = -(1 << (width - 1)), (1 << (width - 1)) - 1
            _, path, _, function = self.build(unary("int.neg.checked", typ))
            for value in (lo + 1, -7, -1, 0, 1, hi):
                self.assertEqual(function(raw(value)), raw(-value))
            self.aborts(path, "calculate", (lo,))
            for operation in ("int.shl.checked", "int.shr.checked"):
                with self.subTest(type=typ, operation=operation):
                    _, path, _, function = self.build(arithmetic(operation, typ))
                    for value in (lo, lo + 1, -8, -1, 0, 1, hi):
                        for count in range(width):
                            expected = signed(value << count, width) if operation == "int.shl.checked" else value >> count
                            self.assertEqual(function(raw(value), count), raw(expected))
                    for count in (-1, lo, width, width + 1):
                        self.aborts(path, "calculate", (-7, count))

    def test_signed_comparisons_and_bitwise_operations_keep_bool_and_integer_abis(self):
        relations = {"eq": lambda a, b: a == b, "ne": lambda a, b: a != b,
                     "lt": lambda a, b: a < b, "le": lambda a, b: a <= b,
                     "gt": lambda a, b: a > b, "ge": lambda a, b: a >= b}
        for typ, width in SIGNED:
            lo, hi = -(1 << (width - 1)), (1 << (width - 1)) - 1
            params = [("a", typ), ("z", typ)]
            for relation, reference in relations.items():
                with self.subTest(type=typ, relation=relation):
                    core = m(f("compare", params, ["bool"], [], [b("entry", params, [
                        i("compare." + relation, ["a", "z"], [("answer", "bool")]),
                    ], ret("answer"))]))
                    _, _, _, function = self.build(core)
                    for left, right in ((lo, hi), (hi, lo), (-1, 0), (0, -1), (lo, lo), (hi, hi)):
                        self.assertEqual(function(raw(left), raw(right)), int(reference(left, right)))
            for operation in ("bit.and", "bit.or", "bit.xor"):
                _, _, _, function = self.build(arithmetic(operation, typ))
                for left, right in ((lo, -1), (lo, hi), (-7, 3), (hi, -1)):
                    value = left & right if operation == "bit.and" else left | right if operation == "bit.or" else left ^ right
                    self.assertEqual(function(raw(left), raw(right)), raw(signed(value, width)))
            _, _, _, function = self.build(unary("bit.not", typ))
            for value in (lo, -1, 0, hi):
                self.assertEqual(function(raw(value)), raw(signed(~value, width)))

    def test_checked_and_wrapping_casts_cover_signedness_and_width_crossings(self):
        pairs = [(left, right) for left in SIGNED for right in SIGNED]
        pairs += [(left, right) for left, right in zip(SIGNED, UNSIGNED)]
        pairs += [(right, left) for left, right in zip(SIGNED, UNSIGNED)]
        pairs += [(("i8", 8), ("u64", 64)), (("u8", 8), ("i64", 64)),
                  (("u64", 64), ("i8", 8)), (("i64", 64), ("u8", 8))]
        for (source, source_width), (target, target_width) in pairs:
            source_signed, target_signed = source.startswith("i"), target.startswith("i")
            low = -(1 << (source_width - 1)) if source_signed else 0
            high = (1 << (source_width - int(source_signed))) - 1
            target_low = -(1 << (target_width - 1)) if target_signed else 0
            target_high = (1 << (target_width - int(target_signed))) - 1
            values = {low, high, 0, 1}
            if source_signed:
                values.add(-1)
            for boundary in (target_low - 1, target_low, target_high, target_high + 1):
                if low <= boundary <= high:
                    values.add(boundary)
            for mode in ("checked", "wrap"):
                with self.subTest(source=source, target=target, mode=mode):
                    _, path, _, function = self.build(cast(source, target, mode))
                    for value in sorted(values):
                        if mode == "checked" and not target_low <= value <= target_high:
                            self.aborts(path, "convert", (value,))
                            continue
                        answer = (signed(value, target_width) if target_signed
                                  else value & ((1 << target_width) - 1))
                        self.assertEqual(function(raw(value)), raw(answer))
                        self.assertEqual(function(value & ((1 << source_width) - 1)), raw(answer))

    def test_live_rcx_rax_rdx_and_repeated_operands_are_preserved(self):
        values = (-23, 3, -5, 2, 13, -17)
        known = dict(zip("abcdef", values)); known["k"] = -7
        cases = [(operation, left, right) for operation in ("int.div.checked", "int.rem.checked", "int.mul.checked")
                 for left, right in (("a", "b"), ("a", "c"), ("c", "a"), ("c", "c"),
                                     ("k", "a"), ("a", "k"), ("k", "c"), ("c", "k"), ("k", "k"))]
        cases += [(operation, left, right) for operation in ("int.shl.checked", "int.shr.checked")
                  for left, right in (("a", "b"), ("d", "b"), ("a", "d"), ("b", "b"), ("d", "d"))]
        for operation, left, right in cases:
            with self.subTest(operation=operation, left=left, right=right):
                _, _, _, function = self.build(live_arithmetic(operation, left, right))
                a, z = known[left], known[right]
                quotient = divide(a, z)
                value = (quotient if operation == "int.div.checked" else a - quotient * z
                         if operation == "int.rem.checked" else a * z if operation == "int.mul.checked"
                         else signed(a << z, 64) if operation == "int.shl.checked" else a >> z)
                self.assertEqual(function(*map(raw, values)), raw(value + sum(known.values())))

    def test_dead_checked_results_retain_overflow_and_shift_traps(self):
        cases = [(arithmetic("int.mul.checked", "i8"), (127, 2)),
                 (arithmetic("int.div.checked", "i64"), (-(1 << 63), -1)),
                 (arithmetic("int.rem.checked", "i64"), (1, 0)),
                 (arithmetic("int.shr.checked", "i16"), (-1, -1)),
                 (unary("int.neg.checked", "i32"), (-(1 << 31),))]
        for core, arguments in cases:
            block = core["functions"][0]["blocks"][0]
            typ = core["functions"][0]["returns"][0]
            block["ops"].append(c("returned", typ, -23)); block["term"] = ret("returned")
            with self.subTest(operation=block["ops"][0]["op"]):
                _, path, _, _ = self.build(core)
                self.aborts(path, "calculate", arguments)

    def test_select_preserves_sign_extension_and_normalizes_dirty_boolean_words(self):
        for typ, width in SIGNED:
            params = [("condition", "bool"), ("yes", typ), ("no", typ)]
            core = m(f("choose", params, [typ], [], [b("entry", params, [
                i("select", ["condition", "yes", "no"], [("answer", typ)]),
            ], ret("answer"))]))
            with self.subTest(type=typ):
                _, _, _, function = self.build(core)
                low = -(1 << (width - 1))
                for condition in (0, 1, 2, 3, WORD_MASK - 1, WORD_MASK):
                    self.assertEqual(function(condition, raw(low), 7), raw(low if condition & 1 else 7))

    def test_signed_profile_composes_unsigned_arithmetic_with_checked_boundary_casts(self):
        params = [("value", "i16"), ("factor", "u64"), ("count", "u64")]
        core = m(f("compose", params, ["i8"], ["trap"], [b("entry", params, [
            i("int.cast", ["value"], [("unsigned", "u64")], mode="checked"),
            i("int.mul.checked", ["unsigned", "factor"], [("product", "u64")]),
            i("int.shr.checked", ["product", "count"], [("shifted", "u64")]),
            i("int.cast", ["shifted"], [("answer", "i8")], mode="checked"),
        ], ret("answer"))]))
        _, path, _, function = self.build(core)
        self.assertEqual(function(14, 7, 2), 24)
        self.assertEqual(function(0x1234000e, 7, 2), 24)
        for values in ((-1, 1, 0), (32767, WORD_MASK, 0), (1, 1, 64), (128, 1, 0)):
            self.aborts(path, "compose", values)

    def test_noncanonical_handwritten_signed_leaf_is_proved_without_reemission(self):
        params = [("value", "i64")]
        core = m(f("calculate", params, ["i64"], ["trap"], [b("entry", params, [
            c("one", "i64", 1), i("int.shr.checked", ["value", "one"], [("answer", "i64")]),
        ], ret("answer"))]))
        # MOV RAX,RDI; SAR RAX,1; RET. There is no parameter-count guard
        # because this independent Core function has a constant valid count.
        obj, final = self.custom_leaf(core, "4889f848c1f801c3", "handwritten-sar")
        with patch("hepta.hia_verified_scalar.emit_verified_scalar", side_effect=AssertionError("producer called")):
            proof = validate_safe_core_artifact(core, obj, final, profile_version=6)
        self.assertTrue(proof["complete"])
        self.assertFalse(proof["checker"]["producer_reemission_used"])
        for version in (1, 2, 3, 4, 5):
            with self.subTest(old_profile=version), self.assertRaises(SafeCoreRejected):
                validate_safe_core_artifact(core, obj, final, profile_version=version)

    def test_independent_wrong_signed_comparison_and_zero_extension_are_refuted(self):
        params = [("a", "i64"), ("z", "i64")]
        comparison = m(f("calculate", params, ["bool"], [], [b("entry", params, [
            i("compare.lt", ["a", "z"], [("answer", "bool")]),
        ], ret("answer"))]))
        # MOV RAX,0; CMP RDI,RSI; SETB AL; RET: unsigned instead of signed.
        self.rejected_leaf(comparison, "48b800000000000000004839f7400f92c0c3", "unsigned-comparison")
        params = [("value", "i8")]
        identity = m(f("calculate", params, ["i8"], [], [b("entry", params, [], ret("value"))]))
        # MOV RAX,RDI; AND RAX,255; RET: narrow signed result lacks extension.
        self.rejected_leaf(identity, "4889f84881e0ff000000c3", "zero-extended-i8")

    def test_logical_right_shift_and_unguarded_negation_have_counterexamples(self):
        params = [("value", "i64")]
        shift = m(f("calculate", params, ["i64"], ["trap"], [b("entry", params, [
            c("one", "i64", 1), i("int.shr.checked", ["value", "one"], [("answer", "i64")]),
        ], ret("answer"))]))
        self.rejected_leaf(shift, "4889f848c1e801c3", "logical-shift")
        witness = self.rejected_leaf(unary("int.neg.checked", "i64"),
                                     "4889f848f7d8c3", "unguarded-negation")
        self.assertEqual(witness["abi_words"], [1 << 63])

    def test_signed_division_uses_actual_sign_extension_and_reports_hardware_fault_paths(self):
        # MOV RAX,-7; MOV RSI,3; XOR RDX,RDX; DIV RSI; RET: numeric mismatch.
        unsigned_div = "48b8f9ffffffffffffff48be03000000000000004831d248f7f6c3"
        self.rejected_leaf(constant_binary("int.div.checked", -7, 3), unsigned_div, "unsigned-divide")
        # Same source inputs, but IDIV with zero high half is also wrong.
        self.rejected_leaf(constant_binary("int.div.checked", -7, 3),
                           unsigned_div.replace("48f7f6", "48f7fe"), "missing-cqo")
        # MOV RAX,RDI; CQO; IDIV RSI; RET has no zero/MIN guard. A #DE
        # must not be silently equated with the declared libc abort outcome.
        self.rejected_leaf(arithmetic("int.div.checked", "i64"), "4889f8489948f7fec3", "unguarded-idiv",
                           obligation="all_inputs_reach_a_terminal_model_outcome")

    def test_saved_register_mutation_is_rejected_even_when_arithmetic_matches(self):
        core = constant_binary("int.add.wrap", -7, 3)
        # MOV RAX,-4; NEG RBX; RET: result right, callee-saved RBX wrong.
        self.rejected_leaf(core, "48b8fcffffffffffffff48f7dbc3", "corrupt-rbx",
                           obligation="sysv_stack_alignment_and_preservation")

    def test_missing_signed_guards_and_abort_stack_damage_publish_nothing(self):
        cases = [(arithmetic("int.add.checked", "i64"), "missing-add-guard"),
                 (arithmetic("int.shr.checked", "i16"), "missing-count-guard"),
                 (cast("i64", "u64", "checked"), "missing-negative-cast-guard")]
        for core, name in cases:
            output = self.root / (name + ".so")
            with self.subTest(case=name), patch.object(Code, "jcc", lambda *args: None):
                with self.assertRaises(SafeCoreRejected) as caught:
                    build_verified_scalar(core, output)
                self.assertEqual(caught.exception.validation["status"], "refuted")
                self.assertFalse(output.exists())
        output = self.root / "bad-abort-stack.so"
        with patch.object(Code, "push", lambda *args: None), self.assertRaises(SafeCoreRejected) as caught:
            build_verified_scalar(unary("int.neg.checked", "i64"), output)
        self.assertFalse(output.exists())
        self.assertEqual(caught.exception.counterexample["obligation"], "sysv_stack_alignment_and_preservation")

    def test_auto_selection_and_sealed_loading_preserve_signed_raw_abi(self):
        core = arithmetic("int.shr.checked", "i16")
        checked, strategy, selected, _ = select_verified_kernel(core)
        self.assertEqual(strategy, "scalar")
        self.assertEqual(selected.core_profile_version, 6)
        path = self.root / "public-selected.so"
        report = build_verified_kernel(core, path)
        self.assertEqual(report["selected_strategy"], "scalar")
        loaded = load_verified_scalar_kernel(checked, selected.object_bytes, path.read_bytes())
        self.assertTrue(loaded.mapping_admission["sealed_image_and_loaded_symbol_bound"])
        self.assertEqual(loaded.parameter_types, ("i16", "i16"))
        self.assertEqual(loaded.return_type, "i16")
        self.assertEqual(loaded.function(0x12345678fff8, 2), raw(-2))
        self.assertEqual(loaded.function(raw(-32768), 15), raw(-1))


if __name__ == "__main__":
    unittest.main()
