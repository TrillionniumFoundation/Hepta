"""Independent short-reduction composition and endpoint-fast mutation controls."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_safe_core_elf import _ELF, SafeCoreELFRejected
from hepta.hia_verified_simd import emit_verified_simd, simd_kernel_program
from hepta.hia_verified_simd_check import (
    BOUNDED_REDUCTION_PROFILES, COPY_FAST_ENDPOINT_PROFILES, VerifiedSIMDRejected,
    decode_simd, validate_verified_simd_artifact,
)


AVAILABLE = (platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}
             and shutil.which("ld") is not None and importlib.util.find_spec("z3") is not None)


class BoundedReductionDecoderTests(unittest.TestCase):
    def test_gpr_to_xmm_move_decodes_direction_width_and_required_avx(self):
        examples = (
            ("c4c1f96ec9", "vgpr_to_xmm", (1, 9)),
            ("c4e1f96ec8", "vgpr_to_xmm", (1, 0)),
            ("c4c1f97ec9", "vmovq", (9, 1)),
            ("c5e9f60f", "vpsadbw_mem", (128, 1, 2, 7, 0)),
            ("c5f9eb07", "vpor_mem", (128, 0, 0, 7, 0)),
        )
        for encoded, operation, operands in examples:
            with self.subTest(encoded=encoded):
                rows = decode_simd(bytes.fromhex(encoded))
                self.assertEqual(len(rows), 1)
                self.assertEqual((rows[0].op, rows[0].args, rows[0].cpu_features),
                                 (operation, operands, ("avx",)))
                self.assertEqual(rows[0].size, len(bytes.fromhex(encoded)))

    def test_reserved_vmovq_and_memory_forms_fail_closed(self):
        for encoded in (
            "c4c1f96e", "c4c1fd6ec9", "c4c1796ec9", "c4c1f16ec9",
            "c4c2f96ec9", "c441f96ec9", "c481f96ec9", "c4c1f96e0f",
            "c5f96ec9", "62f1fd086ec9", "66c4c1f96ec9",
            "4d8b0f", "4c8b0c", "4c0fb74f02", "448b4f04",
        ):
            with self.subTest(encoded=encoded), self.assertRaises(VerifiedSIMDRejected):
                decode_simd(bytes.fromhex(encoded))


@unittest.skipUnless(AVAILABLE, "Linux x86-64, GNU ld and pinned z3 are required")
class BoundedReductionCheckerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="hia-bounded-tail-check-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.cases = {}
        for isa in ("avx2", "avx512"):
            for kind in ("sum_u8", "all_zero_u8", "copy_u8"):
                core = simd_kernel_program(kind)
                image = emit_verified_simd(core, isa=isa)
                obj = cls.root / (kind + isa + ".o")
                final = obj.with_suffix(".so")
                obj.write_bytes(image.object_bytes)
                subprocess.run(["ld", "-m", "elf_x86_64", "-shared", "-z", "defs", "-z", "noexecstack",
                    "-z", "relro", "-z", "now", "--hash-style=both", "--build-id=none",
                    str(obj), "-lc", "-o", str(final)], check=True, capture_output=True, timeout=30)
                data = final.read_bytes()
                proof = validate_verified_simd_artifact(core, image.object_bytes, data)
                cls.cases[isa, kind] = core, image, data, proof

    def rows(self, isa, kind):
        return decode_simd(self.cases[isa, kind][1].text_bytes)

    def raw(self, isa, kind, row):
        return self.cases[isa, kind][1].text_bytes[row.pc:row.pc + row.size]

    def reject(self, isa, kind, changes, obligation=None):
        core, image, linked, _ = self.cases[isa, kind]
        obj, final = bytearray(image.object_bytes), bytearray(linked)
        for row, changed in changes:
            self.assertEqual(len(changed), row.size)
            self.assertNotEqual(changed, self.raw(isa, kind, row))
            for data, elf_kind in ((obj, 1), (final, 3)):
                offset = _ELF(bytes(data), elf_kind).section(".text")["offset"] + row.pc
                data[offset:offset + row.size] = changed
        with self.assertRaises(VerifiedSIMDRejected) as caught:
            validate_verified_simd_artifact(core, bytes(obj), bytes(final))
        if obligation:
            self.assertIsNotNone(caught.exception.counterexample)
            self.assertEqual(caught.exception.counterexample["obligation"], obligation)
            self.assertFalse(caught.exception.validation["ok"])
            self.assertFalse(caught.exception.validation["complete"])
        return caught.exception

    def word(self, isa, kind, width):
        rows = self.rows(isa, kind)
        start = next(i for i, r in enumerate(rows) if r.op == "copy_load" and r.args == (width * 8, 9, 7, 0))
        size = 5 if kind == "sum_u8" and width != 1 else 2
        return rows[start:start + size]

    def narrow_horizontal(self, isa, kind):
        rows = self.rows(isa, kind)
        start = next(i for i, r in enumerate(rows) if r.op == "vmovq" and r.args == (0, 0))
        return rows[start:start + 4]

    def test_new_profiles_have_all_cross_stage_and_nonoverlap_obligations(self):
        for (isa, kind), (_, _, _, proof) in self.cases.items():
            bits = 256 if isa == "avx2" else 512
            copy = kind == "copy_u8"
            with self.subTest(isa=isa, kind=kind):
                self.assertEqual(proof["profile"], (COPY_FAST_ENDPOINT_PROFILES if copy else BOUNDED_REDUCTION_PROFILES)[bits])
                self.assertEqual(len(proof["obligations"]), (21 if isa == "avx2" else 23) if copy else 22)
                self.assertEqual([r["result"] for r in proof["obligations"]],
                                 ["sat"] + ["unsat"] * (len(proof["obligations"]) - 1))
                self.assertFalse(proof["checker"]["producer_reemission_used"])
                self.assertTrue(proof["fresh_cpu_probe_required"])
                names = {r["name"] for r in proof["obligations"]}
                if copy:
                    self.assertEqual(proof["model_counts"]["copy_tail"], "endpoints-fast")
                    self.assertIn("endpoint_1_byte_effects_and_frame", names)
                else:
                    self.assertEqual(proof["model_counts"]["reduce_tail"], "bounded")
                    self.assertEqual(proof["model_counts"]["narrow_cleanup_width"], 16)
                    self.assertEqual(proof["model_counts"]["bounded_word_widths"], [8, 4, 2, 1])
                    self.assertTrue(proof["claims"]["bounded_reduction_tail_effects_checked"])
                    self.assertTrue({"decoded_short_entry_partition", "range_and_decreasing_variant_16",
                        "short_accumulator_initiation_and_frame", "wide_to_narrow_reduction_and_frame",
                        "narrow_vector_induction_and_frame", "narrow_horizontal_reduction_and_frame",
                        "bounded_word_partition_bounds_and_no_overlap", "reduction_prefix_suffix_partition"} <= names)
                    self.assertTrue({"bounded_word_" + str(w) + "_semantics_and_frame" for w in (8, 4, 2, 1)} <= names)
                features = {"avx"} | ({"avx2"} if not copy else set())
                if isa == "avx512": features.add("avx512f")
                if isa == "avx512" and kind == "sum_u8": features.add("avx512bw")
                self.assertEqual(proof["required_cpu_features"], sorted(features))

    def test_short_bypass_must_initialize_both_accumulators_and_enter_at_the_guard(self):
        for isa in ("avx2", "avx512"):
            for kind in ("sum_u8", "all_zero_u8"):
                rows = self.rows(isa, kind)
                width = 32 if isa == "avx2" else 64
                guard = next(i for i, r in enumerate(rows) if r.op == "alu_imm" and r.args == ("cmp", 10, width))
                branch = rows[guard + 1]
                narrow = next(r for r in rows if r.op == "alu_imm" and r.args == ("cmp", 10, 16))
                raw = bytearray(self.raw(isa, kind, branch)); raw[-4:] = struct.pack("<i", narrow.pc - branch.pc - branch.size)
                self.reject(isa, kind, [(branch, bytes(raw))])
                for row in [r for r in rows if r.op == "vpxor" and r.args[0] == 128]:
                    raw = bytearray(self.raw(isa, kind, row)); raw[-1] ^= 1
                    self.reject(isa, kind, [(row, bytes(raw))])

    def test_wide_fold_cannot_duplicate_a_half(self):
        for isa in ("avx2", "avx512"):
            for kind in ("sum_u8", "all_zero_u8"):
                row = next(r for r in self.rows(isa, kind) if r.op == "vextract" and r.args[0] == 256)
                raw = bytearray(self.raw(isa, kind, row)); raw[-1] = 0
                self.reject(isa, kind, [(row, bytes(raw))], "wide_to_narrow_reduction_and_frame")

    def test_correct_fold_value_cannot_pollute_the_persistent_zero_register(self):
        for isa in ("avx2", "avx512"):
            for kind in ("sum_u8", "all_zero_u8"):
                rows = self.rows(isa, kind)
                index = next(i for i, r in enumerate(rows) if r.op == "vextract" and r.args[0] == 256)
                extract, combine = rows[index:index + 2]
                first = bytearray(self.raw(isa, kind, extract)); first[-2] = (first[-2] & 0xf8) | 2
                second = bytearray(self.raw(isa, kind, combine)); second[-1] = (second[-1] & 0xf8) | 2
                self.reject(isa, kind, [(extract, bytes(first)), (combine, bytes(second))],
                            "wide_to_narrow_reduction_and_frame")

    def test_narrow_cleanup_wrong_data_operation_is_refuted(self):
        for isa in ("avx2", "avx512"):
            for kind in ("sum_u8", "all_zero_u8"):
                row = next(r for r in self.rows(isa, kind) if r.op.endswith("_mem") and r.args[0] == 128)
                raw = bytearray(self.raw(isa, kind, row)); raw[2] = 0xeb if kind == "sum_u8" else 0xef
                self.reject(isa, kind, [(row, bytes(raw))], "narrow_vector_induction_and_frame")

    def test_narrow_horizontal_correct_result_cannot_destroy_word_tail_zero(self):
        for isa in ("avx2", "avx512"):
            for kind in ("sum_u8", "all_zero_u8"):
                _, shift, move, _ = self.narrow_horizontal(isa, kind)
                first = bytearray(self.raw(isa, kind, shift)); first[1] = (first[1] & 0x87) | (13 << 3)
                second = bytearray(self.raw(isa, kind, move)); second[-1] = (second[-1] & 0xc7) | (2 << 3)
                self.reject(isa, kind, [(shift, bytes(first)), (move, bytes(second))],
                            "narrow_horizontal_reduction_and_frame")

    def test_word_accumulator_mutations_have_real_smt_counterexamples(self):
        for isa in ("avx2", "avx512"):
            for kind in ("sum_u8", "all_zero_u8"):
                for width in (8, 4, 2, 1):
                    row = self.word(isa, kind, width)[-1]
                    raw = bytearray(self.raw(isa, kind, row)); raw[1] = 0x29 if kind == "sum_u8" else 0x21
                    self.reject(isa, kind, [(row, bytes(raw))], "bounded_word_" + str(width) + "_semantics_and_frame")

    def test_correct_word_sum_cannot_pollute_the_next_word_zero_register(self):
        for isa in ("avx2", "avx512"):
            _, _, sad, move, _ = self.word(isa, "sum_u8", 8)
            first = bytearray(self.raw(isa, "sum_u8", sad)); first[-1] = (first[-1] & 0xc7) | (2 << 3)
            second = bytearray(self.raw(isa, "sum_u8", move)); second[-1] = (second[-1] & 0xc7) | (2 << 3)
            self.reject(isa, "sum_u8", [(sad, bytes(first)), (move, bytes(second))],
                        "bounded_word_8_semantics_and_frame")

    def test_word_transfer_uses_actual_source_register_and_return_frame(self):
        for isa in ("avx2", "avx512"):
            block = self.word(isa, "sum_u8", 4)
            transfer = block[1]
            raw = bytearray(self.raw(isa, "sum_u8", transfer)); raw[-1] = (raw[-1] & 0xf8) | 3
            self.reject(isa, "sum_u8", [(transfer, bytes(raw))], "bounded_word_4_semantics_and_frame")
            move = block[3]
            raw = bytearray(self.raw(isa, "sum_u8", move)); raw[-1] = (raw[-1] & 0xf8) | 4
            self.reject(isa, "sum_u8", [(move, bytes(raw))], "bounded_word_4_semantics_and_frame")

    def test_word_guards_widths_and_stride_changes_cannot_overread_or_overlap(self):
        for isa in ("avx2", "avx512"):
            for kind in ("sum_u8", "all_zero_u8"):
                rows = self.rows(isa, kind)
                for width in (8, 4, 2):
                    index = next(i for i, r in enumerate(rows) if r.op == "alu_imm" and r.args == ("cmp", 10, width))
                    guard, branch = rows[index:index + 2]
                    raw = bytearray(self.raw(isa, kind, guard)); raw[-1] -= 1
                    self.reject(isa, kind, [(guard, bytes(raw))])
                    raw = bytearray(self.raw(isa, kind, branch)); raw[1] = 0x86
                    self.reject(isa, kind, [(branch, bytes(raw))])
                    pointer = next(r for r in rows if r.op == "alu_imm" and r.args == ("add", 7, width))
                    raw = bytearray(self.raw(isa, kind, pointer)); raw[-1] = width // 2
                    self.reject(isa, kind, [(pointer, bytes(raw))])
                load = self.word(isa, kind, 4)[0]
                raw = bytearray(self.raw(isa, kind, load)); raw[0] = 0x4c
                self.reject(isa, kind, [(load, bytes(raw))])
                load = self.word(isa, kind, 2)[0]
                raw = bytearray(self.raw(isa, kind, load)); raw[2] = 0xb6
                self.reject(isa, kind, [(load, bytes(raw))])

    def test_single_byte_remainder_still_checks_actual_data_and_frame(self):
        for isa in ("avx2", "avx512"):
            rows = self.rows(isa, "copy_u8")
            index = next(i for i, r in enumerate(rows) if r.op == "copy_load" and r.args[0] == 8)
            store = rows[index + 1]
            raw = bytearray(self.raw(isa, "copy_u8", store)); raw[-1] = (raw[-1] & 0xc7) | (3 << 3)
            self.reject(isa, "copy_u8", [(store, bytes(raw))], "endpoint_1_byte_effects_and_frame")

    def test_fast_single_byte_branch_cannot_admit_a_larger_endpoint(self):
        for isa in ("avx2", "avx512"):
            rows = self.rows(isa, "copy_u8")
            index = next(i for i, r in enumerate(rows) if r.op == "alu_imm" and r.args == ("cmp", 10, 1))
            guard, branch = rows[index:index + 2]
            load = next(r for r in rows if r.op == "copy_load" and r.args[0] == 16)
            raw = bytearray(self.raw(isa, "copy_u8", branch)); raw[-4:] = struct.pack("<i", load.pc - branch.pc - branch.size)
            self.reject(isa, "copy_u8", [(branch, bytes(raw))])
            raw = bytearray(self.raw(isa, "copy_u8", guard)); raw[-1] = 2
            self.reject(isa, "copy_u8", [(guard, bytes(raw))])
            raw = bytearray(self.raw(isa, "copy_u8", branch)); raw[1] = 0x86
            self.reject(isa, "copy_u8", [(branch, bytes(raw))])

    def test_new_profiles_validate_supplied_bytes_without_producer_authority(self):
        with patch("hepta.hia_verified_simd.emit_verified_simd", side_effect=AssertionError("producer invoked")), \
             patch("hepta.hia_verified_simd_wide.emit_wide_simd", side_effect=AssertionError("producer invoked")):
            for kind in ("sum_u8", "all_zero_u8", "copy_u8"):
                core, image, final, _ = self.cases["avx512", kind]
                self.assertTrue(validate_verified_simd_artifact(core, image.object_bytes, final)["complete"])
        core, image, final, _ = self.cases["avx512", "sum_u8"]
        changed = bytearray(final)
        row = self.word("avx512", "sum_u8", 4)[-1]
        changed[_ELF(final, 3).section(".text")["offset"] + row.pc + 1] = 0x29
        with self.assertRaises(SafeCoreELFRejected):
            validate_verified_simd_artifact(core, image.object_bytes, bytes(changed))


if __name__ == "__main__":
    unittest.main()
