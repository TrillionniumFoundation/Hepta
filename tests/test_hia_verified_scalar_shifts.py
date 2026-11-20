"""Checked unsigned shifts keep CL, live registers and aborts in the proof."""
from __future__ import annotations

import ctypes
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_machine_x64 import Code
from hepta.hia_program import verify_program
from hepta.hia_safe_core import ARTIFACT_PROFILE_V2, ARTIFACT_PROFILE_V3, SafeCoreRejected
from hepta.hia_verified_kernel import build_verified_kernel, select_verified_kernel
from hepta.hia_verified_kernel_load import load_verified_scalar_kernel
from hepta.hia_verified_scalar import (PROFILE, PROFILE_V3, VerifiedScalarRejected,
                                       build_verified_scalar, emit_verified_scalar)
from tests import test_hia_verified_scalar_checked as checked_legacy
from tests.test_hia_program import arithmetic, b, c, f, i, m, ret
from tests.test_hia_verified_scalar import multiply_add
from tools.build_hia_verified_kernel import build as build_attempt


WIDTHS = (("u8", 8), ("u16", 16), ("u32", 32), ("u64", 64), ("usize", 64))


def negate(typ):
    params = [("value", typ)]
    return m(f("negate", params, [typ], ["trap"], [b("entry", params, [
        i("int.neg.checked", ["value"], [("result", typ)]),
    ], ret("result"))]))


def live_shift(left="a", count="b", *, pressure=False):
    params = [(name, "u64") for name in "abcdef"]
    operations = [c(name, "u64", value) for name, value in (("x", 1), ("y", 2), ("z", 3))] if pressure else []
    operations.append(i("int.shl.checked", [left, count], [("shifted", "u64")]))
    result = "shifted"
    for index, name in enumerate("abcdef" + ("xyz" if pressure else "")):
        output = "total" + str(index)
        operations.append(i("int.add.wrap", [result, name], [(output, "u64")]))
        result = output
    return m(f("live_shift", params, ["u64"], ["trap"], [b("entry", params, operations, ret(result))]))


@unittest.skipUnless(checked_legacy.AVAILABLE, "Linux x86-64, GNU ld and pinned Z3 are required")
class CheckedShiftRegisterTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hia-register-shifts-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.serial = 0

    def build(self, core, *, sealed=False):
        self.serial += 1
        path = self.root / (str(self.serial) + ".so")
        image = emit_verified_scalar(core)
        report = build_verified_scalar(core, path, image=image)
        self.assertEqual(image.profile, PROFILE_V3)
        self.assertEqual(image.core_profile_version, 3)
        self.assertEqual(report["core_profile_version"], 3)
        self.assertEqual(report["validation"]["profile"], ARTIFACT_PROFILE_V3)
        self.assertEqual([row["result"] for row in report["validation"]["obligations"]],
                         ["sat", "unsat", "unsat", "unsat", "unsat"])
        self.assertEqual(report["hot_stack_bytes"], 0)
        self.assertEqual(report["maximum_observed_stack_bytes"], 16)
        if sealed:
            loaded = load_verified_scalar_kernel(core, image.object_bytes, path.read_bytes())
            self.assertTrue(loaded.mapping_admission["sealed_image_and_loaded_symbol_bound"])
            function = loaded.function
        else:
            function = getattr(ctypes.CDLL(str(path)), image.export)
            function.argtypes = [ctypes.c_uint64] * len(core["functions"][0]["params"])
            function.restype = ctypes.c_uint64
        return image, path, report, function

    def aborts(self, path, export, values):
        checked_legacy.CheckedRegisterTests.aborts(self, path, export, values)

    def refuted(self, core, name, mutation):
        return checked_legacy.CheckedRegisterTests.refuted(self, core, name, mutation)

    def test_shifts_cover_every_valid_count_and_dirty_parameter_bits_at_each_width(self):
        for typ, width in WIDTHS:
            mask = (1 << width) - 1
            dirty = ((1 << 64) - 1) ^ mask
            for operation in ("int.shl.checked", "int.shr.checked"):
                with self.subTest(type=typ, operation=operation):
                    _, path, _, function = self.build(arithmetic(operation, typ))
                    for value in {0, 1, 3, mask, mask >> 1, 1 << (width - 1)}:
                        for count in range(width):
                            expected = ((value << count) & mask if operation == "int.shl.checked" else value >> count)
                            self.assertEqual(function(value, count), expected)
                            self.assertEqual(function(value | dirty, count | dirty), expected)
                    for count in (width, 64, mask):
                        self.aborts(path, "calculate", (mask, count))
                    if width == 8:
                        self.assertEqual(function(mask, 256), mask)
                    else:
                        self.aborts(path, "calculate", (mask, 256))

    def test_unsigned_negation_only_returns_zero_after_input_normalization(self):
        for typ, width in WIDTHS:
            with self.subTest(type=typ):
                _, path, _, function = self.build(negate(typ))
                mask = (1 << width) - 1
                self.assertEqual(function(0), 0)
                self.assertEqual(function(((1 << 64) - 1) ^ mask), 0)
                for value in (1, mask):
                    self.aborts(path, "negate", (value,))

    def test_cl_assignment_preserves_live_fourth_argument_and_operand_aliases(self):
        values = (3, 2, 7, 1, 13, 17)
        for left, count in (("a", "b"), ("d", "b"), ("a", "d"), ("b", "b"), ("d", "d")):
            with self.subTest(left=left, count=count):
                _, _, _, function = self.build(live_shift(left, count))
                result = (values["abcdef".index(left)] << values["abcdef".index(count)]) + sum(values)
                self.assertEqual(function(*values), result)

    def test_consecutive_shifts_preserve_a_live_count_after_cl_reassignment(self):
        params = [("a", "u64"), ("b", "u64"), ("c", "u64"), ("d", "u64")]
        core = m(f("shifts", params, ["u64"], ["trap"], [b("entry", params, [
            i("int.shl.checked", ["a", "b"], [("first", "u64")]),
            i("int.shr.checked", ["c", "first"], [("second", "u64")]),
            i("int.add.wrap", ["second", "b"], [("with_count", "u64")]),
            i("int.add.wrap", ["with_count", "d"], [("result", "u64")]),
        ], ret("result"))]))
        _, _, _, function = self.build(core)
        self.assertEqual(function(2, 1, 16, 11), 13)
        self.assertEqual(function(0, 0, 16, 11), 27)

    def test_full_register_pressure_refuses_before_proof_and_checked_v3_fallback_works(self):
        core = live_shift(pressure=True)
        with self.assertRaisesRegex(VerifiedScalarRejected, "CL shift needs a free"):
            emit_verified_scalar(core)
        _, selected, image, refusals = select_verified_kernel(core)
        self.assertEqual(selected, "checked")
        self.assertIsNone(image)
        self.assertEqual({row["strategy"] for row in refusals}, {"scalar", "simd"})
        output = self.root / "checked.so"
        result = build_verified_kernel(core, output)
        self.assertEqual(result["selected_strategy"], "checked")
        self.assertEqual(result["validation"]["profile"],
                         "hia.safe-core.unsigned-acyclic-single-borrow.x86_64.v3")
        function = ctypes.CDLL(str(output)).live_shift
        function.argtypes = [ctypes.c_uint64] * 6
        function.restype = ctypes.c_uint64
        self.assertEqual(function(3, 2, 7, 11, 13, 17), 71)
        self.aborts(output, "live_shift", (3, 64, 7, 11, 13, 17))

    def test_dead_shift_and_negation_results_still_enforce_their_traps(self):
        for core, invalid in ((arithmetic("int.shl.checked", "u64"), (7, 64)), (negate("u64"), (1,))):
            block = core["functions"][0]["blocks"][0]
            block["ops"].append(c("returned", "u64", 23))
            block["term"] = ret("returned")
            _, path, _, function = self.build(core)
            self.assertEqual(function(*([0] * len(invalid))), 23)
            self.aborts(path, core["functions"][0]["name"], invalid)

    def test_missing_or_masked_count_guard_and_wrong_shift_are_refuted(self):
        core = arithmetic("int.shl.checked", "u64")
        original_jump, original_alu, original_shift = Code.jcc, Code.alu_imm, Code.shift_cl
        def missing(code, condition, target):
            if condition != "ae":
                original_jump(code, condition, target)
        def mask_before_check(code, op, register, value):
            if (op, register, value) == ("cmp", "rcx", 64):
                original_alu(code, "and", "rcx", 63)
            original_alu(code, op, register, value)
        mutations = (
            ("missing", patch.object(Code, "jcc", missing)),
            ("masked", patch.object(Code, "alu_imm", mask_before_check)),
            ("direction", patch.object(Code, "shift_cl", lambda code, op, dst: original_shift(code, "shr", dst))),
            ("fixed", patch.object(Code, "shift_cl", lambda code, op, dst: code.shift(op, dst, 1))),
        )
        for name, mutation in mutations:
            with self.subTest(mutation=name):
                witness = self.refuted(core, name, mutation)
                self.assertEqual(witness["obligation"], "core_to_final_image_return_abort_and_caller_bytes")

    def test_cl_relocation_cannot_clobber_the_live_fourth_argument(self):
        original = Code.mov_rr
        def corrupt_save(code, destination, source):
            if source == "rcx":
                code.mov_imm(destination, 0)
            else:
                original(code, destination, source)
        self.refuted(live_shift("d", "b"), "clobber-rcx", patch.object(Code, "mov_rr", corrupt_save))

    def test_negation_guard_cannot_be_removed(self):
        original = Code.jcc
        def missing(code, condition, target):
            if condition != "ne":
                original(code, condition, target)
        self.refuted(negate("u64"), "missing-negation-guard", patch.object(Code, "jcc", missing))

    def test_image_profile_version_cannot_be_forged_and_legacy_profile_stays_v2(self):
        core = arithmetic("int.shl.checked", "u64")
        image = emit_verified_scalar(core)
        for version in (2, True, "3", 3.0):
            with self.subTest(version=version), self.assertRaises(VerifiedScalarRejected):
                build_verified_scalar(core, self.root / "forged.so", image=replace(image, core_profile_version=version))
        old = emit_verified_scalar(multiply_add())
        self.assertEqual((old.profile, old.core_profile_version, old.hot_text_bytes), (PROFILE, 2, 11))
        self.assertEqual(old.text_bytes[:11], bytes.fromhex("480faffe4801d74889f8c3"))
        old_result = build_verified_scalar(multiply_add(), self.root / "old.so", image=old)
        self.assertEqual(old_result["validation"]["profile"], ARTIFACT_PROFILE_V2)

    def test_sealed_loader_selects_v3_fresh_and_rechecks_cached_callables(self):
        import hepta.hia_verified_kernel_load as loader
        core = arithmetic("int.shr.checked", "u16")
        image, path, _, _ = self.build(core)
        with patch.object(loader, "validate_safe_core_artifact", wraps=loader.validate_safe_core_artifact) as validate:
            first = load_verified_scalar_kernel(core, image.object_bytes, path.read_bytes())
            first.validation["ok"] = False
            first.function.argtypes = []
            second = load_verified_scalar_kernel(core, image.object_bytes, path.read_bytes())
        self.assertEqual(validate.call_count, 2)
        self.assertEqual([call.kwargs["profile_version"] for call in validate.call_args_list], [3, 3])
        self.assertIsNot(first.function, second.function)
        self.assertTrue(second.validation["ok"])
        self.assertEqual(second.validation["profile"], ARTIFACT_PROFILE_V3)
        self.assertEqual(second.parameter_types, ("u16", "u16"))
        self.assertEqual(second.function(0xffffffffffff8000, 0xffffffffffff000f), 1)
        self.assertEqual(first.mapping_admission["inode"], second.mapping_admission["inode"])

    def test_standard_retained_attempt_selects_and_records_profile_v3(self):
        source = self.root / "shift.hepta"
        source.write_bytes(verify_program(arithmetic("int.shl.checked", "u32")).canonical_bytes)
        destination = self.root / "attempt"
        result = build_attempt(source, destination)
        self.assertTrue(result["ok"], result.get("error"))
        self.assertEqual(result["selected_strategy"], "scalar")
        self.assertEqual(result["result"]["validation"]["profile"], ARTIFACT_PROFILE_V3)
        selection = json.loads((destination / "selection.json").read_bytes())
        self.assertEqual(selection["core_profile_version"], 3)
        self.assertEqual(sha256((destination / "candidate.o").read_bytes()).hexdigest(),
                         result["result"]["object_sha256"])


if __name__ == "__main__":
    unittest.main()
