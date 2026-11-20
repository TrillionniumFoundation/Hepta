"""Register kernels retain independent all-input final-image validation."""
from __future__ import annotations

import ctypes
from dataclasses import replace
import importlib.util
import platform
import shutil
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hepta.hia_machine_x64 import Code
from hepta.hia_safe_core import SafeCoreRejected, validate_safe_core_artifact
from hepta.hia_safe_core_elf import SafeCoreELFRejected, _ELF, bind_final_artifact
from hepta.hia_safe_core_x64 import decode
from hepta.hia_verified_scalar import VerifiedScalarRejected, build_verified_scalar, emit_verified_scalar
import hepta.hia_verified_scalar as scalar
from tests.test_hia_program import arithmetic, b, c, f, i, m, ret


AVAILABLE = (platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}
             and shutil.which("ld") is not None and importlib.util.find_spec("z3") is not None)


def multiply_add(typ="u64"):
    params = [("a", typ), ("b", typ), ("c", typ)]
    return m(f("multiply_add", params, [typ], [], [b("entry", params, [
        i("int.mul.wrap", ["a", "b"], [("product", typ)]),
        i("int.add.wrap", ["product", "c"], [("answer", typ)]),
    ], ret("answer"))]))


class RegisterProducerTests(unittest.TestCase):
    def test_u64_multiply_add_has_four_hot_instructions_and_no_stack_or_calls(self):
        image = emit_verified_scalar(multiply_add())
        instructions = list(decode(image.text_bytes[:image.hot_text_bytes]).values())
        self.assertEqual([ins.op for ins in instructions], ["imul", "add", "mov", "ret"])
        self.assertEqual(image.hot_text_bytes, 11)
        self.assertEqual(image, emit_verified_scalar(multiply_add()))

    def test_unmodeled_signed_checked_multiplication_is_explicitly_rejected(self):
        with self.assertRaisesRegex(VerifiedScalarRejected, "exactly one scalar entry/return"):
            emit_verified_scalar(arithmetic("int.mul.checked", "i64"))

    def test_pressure_refuses_instead_of_silently_spilling(self):
        params = [("a", "u64")]
        operations = [c("k" + str(n), "u64", n) for n in range(10)]
        result = "a"
        for n in range(10):
            operations.append(i("int.add.wrap", [result, "k" + str(n)], [("r" + str(n), "u64")]))
            result = "r" + str(n)
        document = m(f("pressure", params, ["u64"], [], [b("entry", params, operations, ret(result))]))
        with self.assertRaisesRegex(VerifiedScalarRejected, "register budget"):
            emit_verified_scalar(document)

    def test_loader_hook_name_is_rejected_before_linkage(self):
        document = multiply_add()
        document["functions"][0]["name"] = "_init"
        with self.assertRaisesRegex(VerifiedScalarRejected, "loader"):
            emit_verified_scalar(document)


@unittest.skipUnless(AVAILABLE, "Linux x86-64, GNU ld and pinned Z3 are required")
class VerifiedRegisterKernelTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hia-verified-scalar-tests-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def build(self, core, name="kernel"):
        image = emit_verified_scalar(core)
        path = self.root / (name + ".so")
        report = build_verified_scalar(core, path)
        return image, path, report

    def test_all_input_multiply_add_at_every_supported_unsigned_width(self):
        for typ, width in (("u8", 8), ("u16", 16), ("u32", 32), ("u64", 64), ("usize", 64)):
            with self.subTest(type=typ):
                image, path, report = self.build(multiply_add(typ), typ)
                self.assertTrue(report["ok"])
                self.assertEqual([row["result"] for row in report["validation"]["obligations"]],
                                 ["sat", "unsat", "unsat", "unsat", "unsat"])
                self.assertEqual(report["validation"]["image_binding"]["function_shape"], "direct_entry")
                self.assertEqual(report["validation"]["model_counts"]["maximum_observed_stack_bytes"], 0)
                self.assertEqual(report["wrapper_calls"], 0)
                fn = ctypes.CDLL(str(path)).multiply_add
                fn.argtypes, fn.restype = [ctypes.c_uint64] * 3, ctypes.c_uint64
                values = (0, 1, 2, 255, 65535, 2**32 - 1, 2**63, 2**64 - 1)
                mask = (1 << width) - 1
                for a in values:
                    for b_ in values:
                        for c_ in values:
                            self.assertEqual(fn(a, b_, c_), (a * b_ + c_) & mask)

    def test_bitwise_cast_boolean_comparison_and_select(self):
        params = [("a", "u64"), ("b", "u64"), ("choice", "bool")]
        ops = [
            i("bit.xor", ["a", "b"], [("xor", "u64")]),
            i("bit.not", ["xor"], [("not", "u64")]),
            i("bool.not", ["choice"], [("no", "bool")]),
            i("compare.lt", ["a", "b"], [("less", "bool")]),
            i("bool.or", ["no", "less"], [("cond", "bool")]),
            i("select", ["cond", "xor", "not"], [("chosen", "u64")]),
            i("int.cast", ["chosen"], [("answer", "u16")], mode="wrap"),
        ]
        core = m(f("choose", params, ["u16"], [], [b("entry", params, ops, ret("answer"))]))
        _, path, _ = self.build(core)
        fn = ctypes.CDLL(str(path)).choose
        fn.argtypes, fn.restype = [ctypes.c_uint64] * 3, ctypes.c_uint64
        for a, b_ in ((0, 0), (1, 2), (2, 1), (2**64 - 1, 0), (37, 1000)):
            for choice in (0, 1, 2, 3, 2**64 - 1):
                expected = (a ^ b_) if not (choice & 1) or a < b_ else ~(a ^ b_)
                self.assertEqual(fn(a, b_, choice), expected & 65535)

    def test_noncommutative_right_operand_cannot_be_reused_early(self):
        params = [("a", "u64"), ("b", "u64")]
        core = m(f("reuse", params, ["u64"], [], [b("entry", params, [
            i("int.sub.wrap", ["a", "b"], [("difference", "u64")]),
            i("int.add.wrap", ["difference", "a"], [("answer", "u64")]),
        ], ret("answer"))]))
        _, path, _ = self.build(core)
        fn = ctypes.CDLL(str(path)).reuse
        fn.argtypes, fn.restype = [ctypes.c_uint64] * 2, ctypes.c_uint64
        self.assertEqual(fn(13, 7), 19)

    def test_proof_consumer_does_not_call_the_register_producer(self):
        core = multiply_add()
        image, path, _ = self.build(core)
        with patch("hepta.hia_verified_scalar.emit_verified_scalar", side_effect=AssertionError("producer called")):
            report = validate_safe_core_artifact(core, image.object_bytes, path.read_bytes(), profile_version=2)
        self.assertTrue(report["ok"])
        self.assertFalse(report["checker"]["producer_reemission_used"])

    def test_add_to_sub_mutation_yields_a_counterexample_and_no_publication(self):
        path = self.root / "wrong.so"
        with patch.object(Code, "add", Code.sub):
            with self.assertRaises(SafeCoreRejected) as caught:
                build_verified_scalar(multiply_add(), path, query_directory=self.root / "queries")
        witness = caught.exception.counterexample
        self.assertEqual(witness["obligation"], "core_to_final_image_return_abort_and_caller_bytes")
        a, b_, c_ = witness["abi_words"]
        self.assertNotEqual((a * b_ + c_) & (2**64 - 1), (a * b_ - c_) & (2**64 - 1))
        self.assertFalse(path.exists())

    def test_saved_register_clobber_is_refuted_before_publication(self):
        original = Code.ret

        def clobber(code):
            code.mov_imm("rbx", 1)
            original(code)

        path = self.root / "clobber.so"
        with patch.object(Code, "ret", clobber), self.assertRaises(SafeCoreRejected) as caught:
            build_verified_scalar(multiply_add(), path)
        self.assertEqual(caught.exception.counterexample["obligation"], "sysv_stack_alignment_and_preservation")
        self.assertFalse(path.exists())

    def test_direct_export_extent_and_relocation_are_bound(self):
        image, path, _ = self.build(multiply_add())
        obj = _ELF(image.object_bytes, 1)
        symbol_table = obj.section(".symtab")
        modified = bytearray(image.object_bytes)
        for index, symbol in enumerate(obj.symbols(".symtab")):
            if symbol["name"] == image.export:
                struct.pack_into("<Q", modified, symbol_table["offset"] + index * 24 + 16, symbol["size"] - 1)
        with self.assertRaisesRegex(SafeCoreELFRejected, "partition"):
            bind_final_artifact(bytes(modified), path.read_bytes(), image.export)
        modified = bytearray(image.object_bytes)
        relocation = obj.section(".rela.text")
        struct.pack_into("<q", modified, relocation["offset"] + 16, -3)
        with self.assertRaisesRegex(SafeCoreELFRejected, "E8"):
            bind_final_artifact(bytes(modified), path.read_bytes(), image.export)

    def test_changed_checker_is_rejected_before_publication(self):
        path = self.root / "changed.so"
        with patch.object(scalar, "_checker_source_identity", return_value={}):
            with self.assertRaisesRegex(VerifiedScalarRejected, "checker changed"):
                build_verified_scalar(multiply_add(), path)
        self.assertFalse(path.exists())

    def test_changed_checker_after_publication_withdraws_the_owned_output(self):
        path = self.root / "changed-after.so"
        identity = scalar._checker_source_identity()
        original = scalar.publish_verified

        def publish(*args):
            result = original(*args)
            identity.clear()
            return result

        with patch.object(scalar, "_checker_source_identity", side_effect=lambda: dict(identity)), \
                patch.object(scalar, "publish_verified", side_effect=publish):
            with self.assertRaisesRegex(VerifiedScalarRejected, "checker changed"):
                build_verified_scalar(multiply_add(), path)
        self.assertFalse(path.exists())

    def test_incomplete_consumer_result_never_publishes(self):
        path = self.root / "incomplete.so"
        with patch.object(scalar, "validate_safe_core_artifact", return_value={"ok": False, "complete": False}):
            with self.assertRaisesRegex(VerifiedScalarRejected, "did not complete"):
                build_verified_scalar(multiply_add(), path)
        self.assertFalse(path.exists())

    def test_selected_immutable_image_is_not_emitted_again(self):
        core = multiply_add()
        image = emit_verified_scalar(core)
        with patch.object(scalar, "emit_verified_scalar", side_effect=AssertionError("second emission")):
            result = build_verified_scalar(core, self.root / "selected.so", image=image)
        self.assertEqual(result["object_sha256"], result["validation"]["subject"]["object_sha256"])

    def test_selected_text_must_equal_the_exact_object_text(self):
        core = multiply_add()
        image = emit_verified_scalar(core)
        forged = replace(image, text_bytes=b"\xc3")
        path = self.root / "forged-text.so"
        with self.assertRaisesRegex(VerifiedScalarRejected, "text or export"):
            build_verified_scalar(core, path, image=forged)
        self.assertFalse(path.exists())
