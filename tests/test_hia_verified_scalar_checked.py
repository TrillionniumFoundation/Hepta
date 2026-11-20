"""Checked register arithmetic is proved on final bytes, including its traps."""
from __future__ import annotations

import ctypes
import importlib.util
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_machine_x64 import Code
from hepta.hia_safe_core import SafeCoreRejected, validate_safe_core_artifact
from hepta.hia_safe_core_x64 import decode
from hepta.hia_verified_kernel import build_verified_kernel
from hepta.hia_verified_scalar import VerifiedScalarRejected, build_verified_scalar, emit_verified_scalar
from tests.test_hia_program import arithmetic, b, c, f, i, m, ret


AVAILABLE = (platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}
             and shutil.which("ld") is not None and importlib.util.find_spec("z3") is not None)
WIDTHS = (("u8", 8), ("u16", 16), ("u32", 32), ("u64", 64), ("usize", 64))


def cast(source, target):
    params = [("value", source)]
    return m(f("convert", params, [target], ["trap"], [b("entry", params, [
        i("int.cast", ["value"], [("result", target)], mode="checked"),
    ], ret("result"))]))


@unittest.skipUnless(AVAILABLE, "Linux x86-64, GNU ld and pinned Z3 are required")
class CheckedRegisterTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hia-checked-register-tests-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.serial = 0

    def build(self, core):
        self.serial += 1
        path = self.root / ("kernel-" + str(self.serial) + ".so")
        image = emit_verified_scalar(core)
        report = build_verified_scalar(core, path, image=image)
        self.assertTrue(report["validation"]["ok"] and report["validation"]["complete"])
        self.assertEqual([row["result"] for row in report["validation"]["obligations"]],
                         ["sat", "unsat", "unsat", "unsat", "unsat"])
        self.assertEqual(report["hot_stack_bytes"], 0)
        function = getattr(ctypes.CDLL(str(path)), image.export)
        function.argtypes = [ctypes.c_uint64] * len(core["functions"][0]["params"])
        function.restype = ctypes.c_uint64
        return image, path, report, function

    def aborts(self, path, export, values):
        script = ("import ctypes,resource,sys; resource.setrlimit(resource.RLIMIT_CORE,(0,0)); "
                  "fn=getattr(ctypes.CDLL(sys.argv[1]),sys.argv[2]); "
                  "fn.argtypes=[ctypes.c_uint64]*(len(sys.argv)-3); fn.restype=ctypes.c_uint64; "
                  "fn(*[int(value) for value in sys.argv[3:]])")
        process = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(path), export,
                                  *map(str, values)], capture_output=True, timeout=10)
        self.assertEqual(process.returncode, -signal.SIGABRT, process.stderr)

    def refuted(self, core, name, mutation):
        path = self.root / (name + ".so")
        with mutation, self.assertRaises(SafeCoreRejected) as caught:
            build_verified_scalar(core, path, query_directory=self.root / (name + "-queries"))
        self.assertIsNotNone(caught.exception.counterexample)
        self.assertFalse(path.exists())
        self.assertEqual(caught.exception.validation["status"], "refuted")
        return caught.exception.counterexample

    def test_all_unsigned_widths_preserve_return_and_abort_with_dirty_high_bits(self):
        for typ, width in WIDTHS:
            mask = (1 << width) - 1
            dirty = ((1 << 64) - 1) ^ mask
            for operation in ("int.add.checked", "int.sub.checked"):
                with self.subTest(type=typ, operation=operation):
                    _, path, report, function = self.build(arithmetic(operation, typ))
                    self.assertEqual(report["maximum_observed_stack_bytes"], 16)
                    if operation == "int.add.checked":
                        pairs = ((0, 0), (mask, 0), (mask - 1, 1), (1, 1), (dirty, 1))
                        self.aborts(path, "calculate", (mask, 1))
                    else:
                        pairs = ((0, 0), (mask, mask), (mask, 1), (1, 0), (dirty | mask, 1))
                        self.aborts(path, "calculate", (0, 1))
                    for left, right in pairs:
                        expected = ((left & mask) + (right & mask) if operation == "int.add.checked"
                                    else (left & mask) - (right & mask))
                        self.assertEqual(function(left, right), expected)

    def test_checked_casts_cover_all_unsigned_source_target_width_pairs(self):
        for source, source_width in WIDTHS:
            for target, target_width in WIDTHS:
                with self.subTest(source=source, target=target):
                    _, path, report, function = self.build(cast(source, target))
                    limit = (1 << min(source_width, target_width)) - 1
                    dirty = ((1 << 64) - 1) ^ ((1 << source_width) - 1)
                    for value in (0, 1, limit):
                        self.assertEqual(function(value), value)
                        self.assertEqual(function(dirty | value), value)
                    self.assertEqual(report["maximum_observed_stack_bytes"],
                                     16 if source_width > target_width else 0)
                    if source_width > target_width:
                        self.aborts(path, "convert", (1 << target_width,))

    def test_checked_subtraction_does_not_reuse_live_left_via_dying_right(self):
        params = [("a", "u64"), ("b", "u64")]
        core = m(f("difference", params, ["u64"], ["trap"], [b("entry", params, [
            i("int.sub.checked", ["a", "b"], [("d", "u64")]),
            i("int.add.wrap", ["d", "a"], [("result", "u64")]),
        ], ret("result"))]))
        _, path, _, function = self.build(core)
        self.assertEqual(function(13, 7), 19)
        self.assertEqual(function(0xffffffffffffffff, 0), 0xfffffffffffffffe)
        self.aborts(path, "difference", (7, 13))

    def test_repeated_operand_alias_and_dead_checked_result_still_trap(self):
        params = [("a", "u32"), ("kept", "u64")]
        core = m(f("dead_result", params, ["u64"], ["trap"], [b("entry", params, [
            i("int.add.checked", ["a", "a"], [("unused", "u32")]),
        ], ret("kept"))]))
        _, path, _, function = self.build(core)
        self.assertEqual(function(17, 0xfedcba9876543210), 0xfedcba9876543210)
        self.aborts(path, "dead_result", (0x80000000, 7))

    def test_u32_guard_scratch_preserves_all_other_live_values(self):
        params = [(name, "u64") for name in ("a", "b", "c", "d", "e", "f")]
        operations = [c("k0", "u64", 13), c("k1", "u64", 17),
                      i("int.cast", ["a"], [("narrow", "u32")], mode="checked"),
                      i("int.cast", ["narrow"], [("wide", "u64")], mode="wrap")]
        result = "wide"
        for number, name in enumerate(("b", "c", "d", "e", "f", "k0", "k1")):
            output = "r" + str(number)
            operations.append(i("int.add.wrap", [result, name], [(output, "u64")]))
            result = output
        core = m(f("pressure", params, ["u64"], ["trap"], [b("entry", params, operations, ret(result))]))
        _, path, _, function = self.build(core)
        self.assertEqual(function(5, 7, 11, 19, 23, 29), 124)
        self.aborts(path, "pressure", (1 << 32, 7, 11, 19, 23, 29))
        original = Code.mov_rr

        def overwrite_live(code, destination, source):
            original(code, "rsi" if destination == "r11" else destination, source)

        self.refuted(core, "scratch-clobber", patch.object(Code, "mov_rr", overwrite_live))

    def test_full_register_pressure_refuses_instead_of_clobber_or_spill(self):
        params = [(name, "u64") for name in ("a", "b", "c", "d", "e", "f")]
        operations = [c("k" + str(n), "u64", n + 1) for n in range(3)]
        operations += [i("int.cast", ["a"], [("narrow", "u32")], mode="checked"),
                       i("int.cast", ["narrow"], [("wide", "u64")], mode="wrap")]
        result = "wide"
        for number, name in enumerate(("b", "c", "d", "e", "f", "k0", "k1", "k2")):
            output = "r" + str(number)
            operations.append(i("int.add.wrap", [result, name], [(output, "u64")]))
            result = output
        core = m(f("pressure", params, ["u64"], ["trap"], [b("entry", params, operations, ret(result))]))
        with self.assertRaisesRegex(VerifiedScalarRejected, "free caller-saved register budget"):
            emit_verified_scalar(core)
        report = build_verified_kernel(core, self.root / "checked-fallback.so")
        self.assertEqual(report["selected_strategy"], "checked")
        self.assertTrue(report["validation"]["complete"])

    def test_removed_overflow_and_checked_cast_guards_have_sat_counterexamples(self):
        programs = [arithmetic(operation, typ) for operation in ("int.add.checked", "int.sub.checked")
                    for typ, _ in WIDTHS]
        programs += [cast("u64", typ) for typ in ("u8", "u16", "u32")]
        for number, core in enumerate(programs):
            with self.subTest(index=number):
                witness = self.refuted(core, "no-guard-" + str(number), patch.object(Code, "jcc", lambda *args: None))
                self.assertEqual(witness["obligation"], "core_to_final_image_return_abort_and_caller_bytes")

    def test_truncation_before_range_check_is_refuted(self):
        original = Code.alu_imm

        def truncate_first(code, operation, destination, value):
            if operation == "cmp" and value == 255:
                original(code, "and", destination, 255)
            original(code, operation, destination, value)

        self.refuted(arithmetic("int.add.checked", "u8"), "truncate-first",
                     patch.object(Code, "alu_imm", truncate_first))

    def test_inverted_carry_and_misaligned_abort_are_refuted(self):
        original = Code.jcc
        self.refuted(arithmetic("int.add.checked", "u64"), "inverted-carry",
                     patch.object(Code, "jcc", lambda code, condition, target: original(code, "ae", target)))
        witness = self.refuted(arithmetic("int.sub.checked", "u64"), "bad-abort-stack",
                               patch.object(Code, "push", lambda *args: None))
        self.assertEqual(witness["obligation"], "sysv_stack_alignment_and_preservation")

    def test_independent_consumer_does_not_reemit_checked_register_code(self):
        core = arithmetic("int.add.checked", "u64")
        image, path, _, _ = self.build(core)
        instructions = [row for offset, row in decode(image.text_bytes).items() if offset < image.hot_text_bytes]
        self.assertEqual([row.op for row in instructions], ["add", "jcc", "mov", "ret"])
        with patch("hepta.hia_verified_scalar.emit_verified_scalar", side_effect=AssertionError("producer called")):
            report = validate_safe_core_artifact(core, image.object_bytes, path.read_bytes(), profile_version=2)
        self.assertTrue(report["complete"])
        self.assertFalse(report["checker"]["producer_reemission_used"])

    def test_scalar_linker_fifo_or_symlink_is_rejected_before_solver(self):
        original = self.root / "caller-input"
        original.write_bytes(b"preserve these caller bytes")
        for kind, body in (("fifo", "os.mkfifo(sys.argv[-1])"),
                           ("symlink", "os.symlink(" + repr(str(original)) + ",sys.argv[-1])")):
            with self.subTest(kind=kind):
                linker = self.root / (kind + "-linker")
                linker.write_text("#!" + sys.executable + "\nimport os,sys\n"
                                  "if '--version' in sys.argv:\n"
                                  "    print('GNU ld test wrapper')\n    raise SystemExit(0)\n"
                                  + body + "\n")
                linker.chmod(0o700)
                output = self.root / (kind + ".so")
                with patch("hepta.hia_verified_scalar.validate_safe_core_artifact",
                           side_effect=AssertionError("nonregular output reached the solver")):
                    with self.assertRaises(VerifiedScalarRejected):
                        build_verified_scalar(arithmetic("int.add.checked", "u64"), output, linker=str(linker))
                self.assertFalse(output.exists())
        self.assertEqual(original.read_bytes(), b"preserve these caller bytes")


if __name__ == "__main__":
    unittest.main()
