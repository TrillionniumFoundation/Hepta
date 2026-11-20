"""Checked unsigned division/remainder preserve registers, guards and final bytes."""
from __future__ import annotations

import ctypes
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_machine_x64 import Code
from hepta.hia_program import verify_program
from hepta.hia_safe_core import ARTIFACT_PROFILE_V5, SafeCoreRejected, validate_safe_core_artifact
from hepta.hia_safe_core_x64 import decode
from hepta.hia_verified_kernel import build_verified_kernel, select_verified_kernel
from hepta.hia_verified_kernel_load import load_verified_scalar_kernel
from hepta.hia_verified_scalar import (
    PROFILE, PROFILE_V3, PROFILE_V4, PROFILE_V5, VerifiedScalarRejected,
    build_verified_scalar, emit_verified_scalar,
)
from tests.test_hia_program import arithmetic, b, c, f, i, m, ret
from tests.test_hia_verified_scalar import multiply_add
from tests import test_hia_verified_scalar_checked as checked_legacy
from tests import test_hia_verified_scalar_multiply as multiply_legacy
from tools.build_hia_verified_kernel import build as build_attempt


WIDTHS = (("u8", 8), ("u16", 16), ("u32", 32), ("u64", 64), ("usize", 64))
DIVISIONS = ("int.div.checked", "int.rem.checked")


def live_division(operation, left="a", right="b", *, pressure=False):
    core = multiply_legacy.live_multiply(left, right, pressure=pressure)
    core["functions"][0]["name"] = "live_division"
    for instruction in core["functions"][0]["blocks"][0]["ops"]:
        if instruction["op"] == "int.mul.checked":
            instruction["op"] = operation
    return core


def constant_division(operation, left=17, right=3, typ="u64"):
    return m(f("calculate", [], [typ], ["trap"], [b("entry", [], [
        c("left", typ, left), c("right", typ, right),
        i(operation, ["left", "right"], [("answer", typ)]),
    ], ret("answer"))]))


@unittest.skipUnless(checked_legacy.AVAILABLE, "Linux x86-64, GNU ld and pinned Z3 are required")
class CheckedDivisionRegisterTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hia-register-division-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name); self.serial = 0

    def build(self, core, *, abort_stack=16):
        self.serial += 1
        path = self.root / (str(self.serial) + ".so")
        image = emit_verified_scalar(core)
        result = build_verified_scalar(core, path, image=image)
        self.assertEqual((image.profile, image.core_profile_version), (PROFILE_V5, 5))
        self.assertEqual(result["validation"]["profile"], ARTIFACT_PROFILE_V5)
        self.assertEqual([row["result"] for row in result["validation"]["obligations"]], ["sat"] + ["unsat"] * 4)
        self.assertEqual(result["hot_stack_bytes"], 0)
        self.assertEqual(result["maximum_observed_stack_bytes"], abort_stack)
        function = getattr(ctypes.CDLL(str(path)), image.export)
        function.argtypes = [ctypes.c_uint64] * len(core["functions"][0]["params"])
        function.restype = ctypes.c_uint64
        return image, path, result, function

    def aborts(self, path, export, values):
        checked_legacy.CheckedRegisterTests.aborts(self, path, export, values)

    def refuted(self, core, name, mutation):
        return checked_legacy.CheckedRegisterTests.refuted(self, core, name, mutation)

    def test_all_widths_cover_canonical_values_dirty_inputs_and_native_zero_abort(self):
        for typ, width in WIDTHS:
            mask, dirty = (1 << width) - 1, ((1 << 64) - 1) ^ ((1 << width) - 1)
            for operation in DIVISIONS:
                with self.subTest(type=typ, operation=operation):
                    _, path, _, function = self.build(arithmetic(operation, typ))
                    for left, right in ((0, 1), (mask, 1), (mask, 2), (mask, mask),
                                        (17, 3), (1, mask), (1 << (width - 1), 3)):
                        expected = left // right if operation == "int.div.checked" else left % right
                        self.assertEqual(function(left, right), expected)
                        self.assertEqual(function(left | dirty, right | dirty), expected)
                    self.aborts(path, "calculate", (mask, 0))
                    self.aborts(path, "calculate", (mask, dirty))
                    if typ == "u8":
                        for left in range(256):
                            for right in range(1, 256):
                                expected = left // right if operation == "int.div.checked" else left % right
                                self.assertEqual(function(left, right), expected)

    def test_live_rax_rdx_and_all_six_arguments_survive_every_operand_alias(self):
        values = (23, 3, 5, 11, 13, 17)
        inputs = dict(zip("abcdef", values)); inputs["k"] = 7
        for operation in DIVISIONS:
            for left, right in (("a", "b"), ("a", "c"), ("c", "a"), ("c", "c"),
                                ("k", "a"), ("a", "k"), ("k", "c"), ("c", "k"), ("k", "k")):
                with self.subTest(operation=operation, left=left, right=right):
                    _, _, _, function = self.build(live_division(operation, left, right),
                                                   abort_stack=0 if right == "k" else 16)
                    result = (inputs[left] // inputs[right] if operation == "int.div.checked"
                              else inputs[left] % inputs[right])
                    self.assertEqual(function(*values), result + sum(inputs.values()))

    def test_dying_divisors_in_implicit_registers_are_moved_before_clobber(self):
        for operation in DIVISIONS:
            for left, right in (("k", "c"), ("c", "k"), ("k", "k"), ("c", "c")):
                params = [(name, "u64") for name in "abc"]
                core = m(f("calculate", params, ["u64"], ["trap"], [b("entry", params, [
                    c("k", "u64", 7), i(operation, [left, right], [("answer", "u64")]),
                ], ret("answer"))]))
                with self.subTest(operation=operation, left=left, right=right):
                    _, path, _, function = self.build(core, abort_stack=0 if right == "k" else 16)
                    value = {"k": 7, "c": 11}
                    expected = value[left] // value[right] if operation == "int.div.checked" else value[left] % value[right]
                    self.assertEqual(function(19, 23, 11), expected)
                    if right == "c":
                        self.aborts(path, "calculate", (19, 23, 0))

    def test_v5_composes_division_remainder_multiply_and_variable_shift(self):
        params = [(name, "u64") for name in ("a", "b", "count", "kept")]
        core = m(f("calculate", params, ["u64"], ["trap"], [b("entry", params, [
            i("int.div.checked", ["a", "b"], [("quotient", "u64")]),
            i("int.mul.checked", ["quotient", "b"], [("product", "u64")]),
            i("int.rem.checked", ["a", "b"], [("remainder", "u64")]),
            i("int.add.wrap", ["product", "remainder"], [("total", "u64")]),
            i("int.shl.checked", ["total", "count"], [("shifted", "u64")]),
            i("int.add.wrap", ["shifted", "kept"], [("answer", "u64")]),
        ], ret("answer"))]))
        _, path, _, function = self.build(core)
        self.assertEqual(function(17, 3, 2, 11), 79)
        self.aborts(path, "calculate", (17, 0, 2, 11))
        self.aborts(path, "calculate", (17, 3, 64, 11))

    def test_full_register_pressure_refuses_before_proof_and_checked_v5_fallback_proves(self):
        for operation in DIVISIONS:
            core = live_division(operation, pressure=True)
            with self.assertRaisesRegex(VerifiedScalarRejected, "DIV needs a free"):
                emit_verified_scalar(core)
            _, selected, image, _ = select_verified_kernel(core)
            self.assertEqual(selected, "checked"); self.assertIsNone(image)
            path = self.root / (operation + ".so")
            result = build_verified_kernel(core, path)
            self.assertEqual(result["selected_strategy"], "checked")
            self.assertEqual(result["validation"]["profile"], "hia.safe-core.unsigned-acyclic-single-borrow.x86_64.v5")
            function = ctypes.CDLL(str(path)).live_division
            function.argtypes = [ctypes.c_uint64] * 6; function.restype = ctypes.c_uint64
            values = (23, 3, 5, 11, 13, 17)
            expected = 23 // 3 if operation == "int.div.checked" else 23 % 3
            self.assertEqual(function(*values), expected + sum(values) + 7 + 11 + 13)
            self.aborts(path, "live_division", (23, 0, 5, 11, 13, 17))

    def test_dead_results_still_abort_on_zero_divisors(self):
        for operation in DIVISIONS:
            core = arithmetic(operation, "u64")
            block = core["functions"][0]["blocks"][0]
            block["ops"].append(c("returned", "u64", 23)); block["term"] = ret("returned")
            _, path, _, function = self.build(core)
            self.assertEqual(function(17, 3), 23)
            self.aborts(path, "calculate", (0, 0))

    def test_missing_inverted_and_wrong_zero_guards_have_counterexamples(self):
        jump, test = Code.jcc, Code.test
        def no_zero(code, condition, target):
            if condition != "e":
                jump(code, condition, target)
        def inverted(code, condition, target):
            jump(code, "ne" if condition == "e" else condition, target)
        def compare_one(code, left, right):
            code.alu_imm("cmp", left, 1) if left == right else test(code, left, right)
        for operation in DIVISIONS:
            for name, mutation in (("missing", patch.object(Code, "jcc", no_zero)),
                                   ("inverted", patch.object(Code, "jcc", inverted)),
                                   ("wrong-zero", patch.object(Code, "test", compare_one))):
                with self.subTest(operation=operation, mutation=name):
                    witness = self.refuted(arithmetic(operation, "u64"), operation + name, mutation)
                    self.assertEqual(witness["obligation"], "all_inputs_reach_a_terminal_model_outcome")

    def test_missing_or_poisoned_high_word_cannot_be_assumed_zero(self):
        xor = Code.xor
        for operation in DIVISIONS:
            params = [(name, "u64") for name in ("a", "b", "high")]
            core = m(f("calculate", params, ["u64"], ["trap"], [b("entry", params, [
                i(operation, ["a", "b"], [("answer", "u64")]),
            ], ret("answer"))]))
            for name, replacement in (("missing", None), ("poisoned", 1)):
                def broken(code, destination, source, replacement=replacement):
                    if destination == source == "rdx":
                        if replacement is not None:
                            code.mov_imm("rdx", replacement)
                    else:
                        xor(code, destination, source)
                witness = self.refuted(core, operation + name, patch.object(Code, "xor", broken))
                self.assertEqual(witness["obligation"], "all_inputs_reach_a_terminal_model_outcome")
                self.assertNotEqual(witness["abi_words"][1], 0)
                high = witness["abi_words"][2] if replacement is None else replacement
                self.assertGreaterEqual(high, witness["abi_words"][1])

    def test_wrong_divisor_result_register_and_nonzero_high_word_are_refuted(self):
        divide, xor, move = Code.div, Code.xor, Code.mov_rr
        def high_one(code, destination, source):
            if destination == source == "rdx":
                code.mov_imm("rdx", 1)
            else:
                xor(code, destination, source)
        def lose_remainder(code, destination, source):
            if (destination, source) != ("rax", "rdx"):
                move(code, destination, source)
        def wrong_quotient(code, source):
            divide(code, source); code.mov_rr("rax", "rdx")
        for operation in DIVISIONS:
            mutations = [("divisor", patch.object(Code, "div", lambda code, source: divide(code, "rax"))),
                         ("high-one", patch.object(Code, "xor", high_one))]
            mutations.append(("result-register", patch.object(Code, "div", wrong_quotient)
                              if operation == "int.div.checked" else patch.object(Code, "mov_rr", lose_remainder)))
            for name, mutation in mutations:
                witness = self.refuted(constant_division(operation), operation + name, mutation)
                self.assertEqual(witness["obligation"], "core_to_final_image_return_abort_and_caller_bytes")

    def test_live_register_saves_and_abort_alignment_are_independently_proved(self):
        move = Code.mov_rr
        for register in ("rax", "rdx"):
            def broken(code, destination, source, target=register):
                if source == target and destination in ("r10", "r11"):
                    code.mov_imm(destination, 0)
                else:
                    move(code, destination, source)
            self.refuted(live_division("int.div.checked"), "lost-" + register, patch.object(Code, "mov_rr", broken))
        witness = self.refuted(arithmetic("int.rem.checked", "u64"), "unaligned-abort",
                               patch.object(Code, "push", lambda *args: None))
        self.assertEqual(witness["obligation"], "sysv_stack_alignment_and_preservation")

    def test_old_profiles_keep_their_bytes_and_v5_consumption_does_not_reemit(self):
        core = arithmetic("int.div.checked", "u64")
        image, path, _, _ = self.build(core)
        instructions = [row for at, row in decode(image.text_bytes, allow_unsigned_divide=True).items()
                        if at < image.hot_text_bytes]
        self.assertEqual([row.op for row in instructions], ["test", "jcc", "mov", "xor", "div", "ret"])
        with patch("hepta.hia_verified_scalar.emit_verified_scalar", side_effect=AssertionError("producer called")):
            self.assertTrue(validate_safe_core_artifact(core, image.object_bytes, path.read_bytes(), profile_version=5)["complete"])
        old = emit_verified_scalar(multiply_add())
        self.assertEqual((old.profile, old.core_profile_version, old.hot_text_bytes), (PROFILE, 2, 11))
        self.assertEqual(old.text_bytes[:11], bytes.fromhex("480faffe4801d74889f8c3"))
        self.assertEqual(emit_verified_scalar(arithmetic("int.shr.checked", "u64")).profile, PROFILE_V3)
        product = emit_verified_scalar(arithmetic("int.mul.checked", "u64"))
        self.assertEqual((product.profile, product.core_profile_version), (PROFILE_V4, 4))
        self.assertEqual(product.text_bytes[:product.hot_text_bytes], bytes.fromhex("4889f848f7e60f8201000000c3"))
        for version in (2, 3, 4, True, "5", 5.0):
            with self.subTest(version=version), self.assertRaises(VerifiedScalarRejected):
                build_verified_scalar(core, self.root / "forged.so", image=replace(image, core_profile_version=version))

    def test_loader_revalidates_both_operations_and_attempt_records_v5(self):
        import hepta.hia_verified_kernel_load as loader
        for operation in DIVISIONS:
            core = arithmetic(operation, "u32")
            image, path, _, _ = self.build(core)
            with patch.object(loader, "validate_safe_core_artifact", wraps=loader.validate_safe_core_artifact) as validate:
                first = load_verified_scalar_kernel(core, image.object_bytes, path.read_bytes())
                first.validation["ok"] = False; first.function.argtypes = []
                second = load_verified_scalar_kernel(core, image.object_bytes, path.read_bytes())
            self.assertEqual([call.kwargs["profile_version"] for call in validate.call_args_list], [5, 5])
            self.assertEqual(second.validation["profile"], ARTIFACT_PROFILE_V5)
            self.assertTrue(second.validation["ok"]); self.assertIsNot(first.function, second.function)
            expected = 17 // 3 if operation == "int.div.checked" else 17 % 3
            self.assertEqual(second.function(0xffffffff00000011, 0xffffffff00000003), expected)
        source = self.root / "remainder.hepta"
        source.write_bytes(verify_program(core).canonical_bytes)
        result = build_attempt(source, self.root / "attempt")
        self.assertTrue(result["ok"], result.get("error"))
        self.assertEqual(result["selected_strategy"], "scalar")
        self.assertEqual(result["result"]["validation"]["profile"], ARTIFACT_PROFILE_V5)
        selection = json.loads((self.root / "attempt/selection.json").read_bytes())
        self.assertEqual(selection["core_profile_version"], 5)


if __name__ == "__main__":
    unittest.main()
