"""Unsigned checked register multiplication preserves full products and SSA state."""
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
from hepta.hia_safe_core import ARTIFACT_PROFILE_V4, SafeCoreRejected, validate_safe_core_artifact
from hepta.hia_safe_core_x64 import decode
from hepta.hia_verified_kernel import build_verified_kernel, select_verified_kernel
from hepta.hia_verified_kernel_load import load_verified_scalar_kernel
from hepta.hia_verified_scalar import (
    PROFILE, PROFILE_V3, PROFILE_V4, VerifiedScalarRejected,
    build_verified_scalar, emit_verified_scalar,
)
from tests.test_hia_program import arithmetic, b, c, f, i, m, ret
from tests.test_hia_verified_scalar import multiply_add
from tests import test_hia_verified_scalar_checked as checked_legacy
from tools.build_hia_verified_kernel import build as build_attempt


WIDTHS = (("u8", 8), ("u16", 16), ("u32", 32), ("u64", 64), ("usize", 64))


def live_multiply(left="a", right="b", *, pressure=False):
    params = [(name, "u64") for name in "abcdef"]
    constants = (("k", 7), ("x", 11), ("y", 13)) if pressure else (("k", 7),)
    operations = [c(name, "u64", value) for name, value in constants]
    operations.append(i("int.mul.checked", [left, right], [("product", "u64")]))
    result = "product"
    for number, name in enumerate([*"abcdef", *[name for name, _ in constants]]):
        output = "total" + str(number)
        operations.append(i("int.add.wrap", [result, name], [(output, "u64")]))
        result = output
    return m(f("live_multiply", params, ["u64"], ["trap"], [b("entry", params, operations, ret(result))]))


@unittest.skipUnless(checked_legacy.AVAILABLE, "Linux x86-64, GNU ld and pinned Z3 are required")
class CheckedMultiplyRegisterTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hia-register-multiply-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.serial = 0

    def build(self, core, *, abort_stack=16):
        self.serial += 1
        path = self.root / (str(self.serial) + ".so")
        image = emit_verified_scalar(core)
        result = build_verified_scalar(core, path, image=image)
        self.assertEqual((image.profile, image.core_profile_version), (PROFILE_V4, 4))
        self.assertEqual(result["validation"]["profile"], ARTIFACT_PROFILE_V4)
        self.assertEqual([row["result"] for row in result["validation"]["obligations"]],
                         ["sat"] + ["unsat"] * 4)
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

    def test_every_width_preserves_canonical_returns_dirty_high_bits_and_overflow_abort(self):
        for typ, width in WIDTHS:
            with self.subTest(type=typ):
                _, path, _, function = self.build(arithmetic("int.mul.checked", typ))
                mask, dirty = (1 << width) - 1, ((1 << 64) - 1) ^ ((1 << width) - 1)
                half = (1 << (width // 2)) - 1
                for left, right in ((0, mask), (mask, 0), (1, mask), (mask, 1),
                                    (half, half), (3, mask // 3), (7, 11)):
                    self.assertEqual(function(left, right), left * right)
                    self.assertEqual(function(left | dirty, right | dirty), left * right)
                for left, right in ((mask, 2), (1 << (width // 2),) * 2, (mask, mask)):
                    self.aborts(path, "calculate", (left, right))
                if typ == "u8":
                    for left in range(256):
                        for right in range(256):
                            if left * right <= 255:
                                self.assertEqual(function(left, right), left * right)

    def test_implicit_outputs_preserve_all_live_arguments_and_rax_rdx_operand_aliases(self):
        values = (3, 2, 5, 11, 13, 17)
        inputs = dict(zip("abcdef", values)); inputs["k"] = 7
        for left, right in (("a", "b"), ("a", "c"), ("c", "a"), ("c", "c"),
                            ("k", "a"), ("a", "k"), ("k", "c"), ("c", "k"), ("k", "k")):
            with self.subTest(left=left, right=right):
                _, _, _, function = self.build(live_multiply(left, right),
                                               abort_stack=0 if left == right == "k" else 16)
                self.assertEqual(function(*values), inputs[left] * inputs[right] + sum(inputs.values()))

    def test_dying_rax_and_rdx_operands_are_read_before_the_multiply_clobbers_them(self):
        for left, right in (("k", "c"), ("c", "k"), ("k", "k"), ("c", "c")):
            params = [(name, "u64") for name in "abc"]
            core = m(f("calculate", params, ["u64"], ["trap"], [b("entry", params, [
                c("k", "u64", 7), i("int.mul.checked", [left, right], [("answer", "u64")]),
            ], ret("answer"))]))
            with self.subTest(left=left, right=right):
                _, _, _, function = self.build(core, abort_stack=0 if left == right == "k" else 16)
                expected = {"k": 7, "c": 11}
                self.assertEqual(function(19, 23, 11), expected[left] * expected[right])

    def test_checked_multiply_then_shift_uses_v4_without_losing_v3_count_traps(self):
        params = [(name, "u64") for name in ("a", "b", "count", "kept")]
        core = m(f("calculate", params, ["u64"], ["trap"], [b("entry", params, [
            i("int.mul.checked", ["a", "b"], [("product", "u64")]),
            i("int.shl.checked", ["product", "count"], [("shifted", "u64")]),
            i("int.add.wrap", ["shifted", "kept"], [("answer", "u64")]),
        ], ret("answer"))]))
        _, path, _, function = self.build(core)
        self.assertEqual(function(3, 7, 2, 11), 95)
        self.aborts(path, "calculate", (3, 7, 64, 11))
        self.aborts(path, "calculate", (1 << 63, 2, 0, 11))

    def test_full_register_pressure_refuses_before_proof_and_checked_v4_fallback_works(self):
        core = live_multiply(pressure=True)
        with self.assertRaisesRegex(VerifiedScalarRejected, "MUL needs a free"):
            emit_verified_scalar(core)
        _, selected, image, _ = select_verified_kernel(core)
        self.assertEqual(selected, "checked"); self.assertIsNone(image)
        path = self.root / "fallback.so"
        result = build_verified_kernel(core, path)
        self.assertEqual(result["selected_strategy"], "checked")
        self.assertEqual(result["validation"]["profile"],
                         "hia.safe-core.unsigned-acyclic-single-borrow.x86_64.v4")
        function = ctypes.CDLL(str(path)).live_multiply
        function.argtypes = [ctypes.c_uint64] * 6; function.restype = ctypes.c_uint64
        self.assertEqual(function(3, 2, 5, 11, 13, 17), 88)
        self.aborts(path, "live_multiply", (1 << 63, 2, 5, 11, 13, 17))

    def test_dead_checked_product_still_traps_even_when_low_word_is_zero(self):
        core = arithmetic("int.mul.checked", "u64")
        block = core["functions"][0]["blocks"][0]
        block["ops"].append(c("returned", "u64", 23)); block["term"] = ret("returned")
        _, path, _, function = self.build(core)
        self.assertEqual(function(0, (1 << 64) - 1), 23)
        self.aborts(path, "calculate", (1 << 32, 1 << 32))

    def test_missing_inverted_or_destroyed_carry_checks_are_refuted(self):
        core = arithmetic("int.mul.checked", "u64")
        jump, multiply = Code.jcc, Code.mul
        def no_carry(code, condition, target):
            if condition != "b":
                jump(code, condition, target)
        def invert_carry(code, condition, target):
            jump(code, "ae" if condition == "b" else condition, target)
        def clobber_carry(code, source):
            multiply(code, source); code.xor("rdx", "rdx")
        for name, mutation in (
            ("missing", patch.object(Code, "jcc", no_carry)),
            ("inverted", patch.object(Code, "jcc", invert_carry)),
            ("clobbered", patch.object(Code, "mul", clobber_carry)),
        ):
            with self.subTest(mutation=name):
                self.refuted(core, name, mutation)

    def test_full_symbolic_hard_mutants_reject_without_publishing_incomplete_proofs(self):
        # A 64x64 nonlinear SAT query may exhaust the fixed proof budget.
        # Both a counterexample and UNKNOWN must reject, with no publication;
        # this gate does not mislabel the latter as a completed refutation.
        multiply = Code.mul
        for name, mutation in (
            ("signed-full", patch.object(Code, "mul", lambda code, source: code.imul("rax", source))),
            ("wrong-operand-full", patch.object(Code, "mul", lambda code, source: multiply(code, "rax"))),
        ):
            path = self.root / (name + ".so")
            with self.subTest(mutation=name), mutation, self.assertRaises(SafeCoreRejected) as caught:
                build_verified_scalar(arithmetic("int.mul.checked", "u64"), path,
                                      query_directory=self.root / (name + "-queries"))
            self.assertFalse(path.exists())
            self.assertFalse(caught.exception.validation["complete"])
            self.assertFalse(caught.exception.validation["ok"])
            self.assertIn(caught.exception.validation["status"], ("refuted", "unknown"))
            if caught.exception.validation["status"] == "refuted":
                self.assertIsNotNone(caught.exception.counterexample)

    def test_signed_and_wrong_operand_mutants_have_independent_constant_counterexamples(self):
        multiply = Code.mul
        for name, left, right, mutation in (
            ("signed-constant", (1 << 64) - 1, 2,
             patch.object(Code, "mul", lambda code, source: code.imul("rax", source))),
            ("wrong-operand-constant", 3, 7,
             patch.object(Code, "mul", lambda code, source: multiply(code, "rax"))),
        ):
            core = m(f("calculate", [], ["u64"], ["trap"], [b("entry", [], [
                c("a", "u64", left), c("z", "u64", right),
                i("int.mul.checked", ["a", "z"], [("answer", "u64")]),
            ], ret("answer"))]))
            with self.subTest(mutation=name):
                self.refuted(core, name, mutation)

    def test_narrow_product_cannot_be_truncated_before_its_range_check(self):
        original = Code.alu_imm
        def truncated(code, operation, register, value):
            if (operation, register, value) == ("cmp", "rax", 255):
                original(code, "and", "rax", 255)
            original(code, operation, register, value)
        witness = self.refuted(arithmetic("int.mul.checked", "u8"), "narrow-truncated",
                               patch.object(Code, "alu_imm", truncated))
        left, right = [word & 255 for word in witness["abi_words"]]
        self.assertGreater(left * right, 255)

    def test_live_implicit_register_saves_and_abort_alignment_are_proved(self):
        original = Code.mov_rr
        for register in ("rax", "rdx"):
            def broken(code, destination, source, target=register):
                if source == target and destination in ("r10", "r11"):
                    code.mov_imm(destination, 0)
                else:
                    original(code, destination, source)
            self.refuted(live_multiply(), "lost-" + register, patch.object(Code, "mov_rr", broken))
        witness = self.refuted(arithmetic("int.mul.checked", "u64"), "unaligned-abort",
                               patch.object(Code, "push", lambda *args: None))
        self.assertEqual(witness["obligation"], "sysv_stack_alignment_and_preservation")

    def test_independent_consumer_never_reemits_and_old_scalar_profiles_keep_their_bytes(self):
        core = arithmetic("int.mul.checked", "u64")
        image, path, _, _ = self.build(core)
        instructions = [row for at, row in decode(image.text_bytes, allow_unsigned_multiply=True).items()
                        if at < image.hot_text_bytes]
        self.assertEqual([row.op for row in instructions], ["mov", "mul", "jcc", "ret"])
        with patch("hepta.hia_verified_scalar.emit_verified_scalar", side_effect=AssertionError("producer called")):
            proof = validate_safe_core_artifact(core, image.object_bytes, path.read_bytes(), profile_version=4)
        self.assertFalse(proof["checker"]["producer_reemission_used"])
        old = emit_verified_scalar(multiply_add())
        self.assertEqual((old.profile, old.core_profile_version, old.hot_text_bytes), (PROFILE, 2, 11))
        self.assertEqual(old.text_bytes[:11], bytes.fromhex("480faffe4801d74889f8c3"))
        shift = emit_verified_scalar(arithmetic("int.shr.checked", "u64"))
        self.assertEqual((shift.profile, shift.core_profile_version), (PROFILE_V3, 3))
        for version in (2, 3, True, "4", 4.0):
            with self.subTest(version=version), self.assertRaises(VerifiedScalarRejected):
                build_verified_scalar(core, self.root / "forged.so", image=replace(image, core_profile_version=version))

    def test_sealed_loader_and_retained_attempt_select_and_freshly_validate_v4(self):
        import hepta.hia_verified_kernel_load as loader
        core = arithmetic("int.mul.checked", "u32")
        image, path, _, _ = self.build(core)
        with patch.object(loader, "validate_safe_core_artifact", wraps=loader.validate_safe_core_artifact) as validate:
            first = load_verified_scalar_kernel(core, image.object_bytes, path.read_bytes())
            first.validation["ok"] = False; first.function.argtypes = []
            second = load_verified_scalar_kernel(core, image.object_bytes, path.read_bytes())
        self.assertEqual([call.kwargs["profile_version"] for call in validate.call_args_list], [4, 4])
        self.assertTrue(second.validation["ok"])
        self.assertEqual(second.validation["profile"], ARTIFACT_PROFILE_V4)
        self.assertIsNot(first.function, second.function)
        self.assertEqual(second.function(0xffffffff00000007, 0xffffffff0000000b), 77)
        self.assertEqual(first.mapping_admission["inode"], second.mapping_admission["inode"])
        source = self.root / "multiply.hepta"
        source.write_bytes(verify_program(core).canonical_bytes)
        result = build_attempt(source, self.root / "attempt")
        self.assertTrue(result["ok"], result.get("error"))
        self.assertEqual(result["selected_strategy"], "scalar")
        self.assertEqual(result["result"]["validation"]["profile"], ARTIFACT_PROFILE_V4)
        selection = json.loads((self.root / "attempt/selection.json").read_bytes())
        self.assertEqual(selection["core_profile_version"], 4)


if __name__ == "__main__":
    unittest.main()
