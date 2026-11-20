"""Supplied-byte AVX2/AVX-512 verification without executing wide instructions."""
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
    WIDE_PROFILES, VerifiedSIMDRejected, decode_simd, validate_verified_simd_artifact,
)


AVAILABLE = (platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}
             and shutil.which("ld") is not None and importlib.util.find_spec("z3") is not None)


class WideDecoderTests(unittest.TestCase):
    def test_independent_prefix_operand_and_feature_decoding(self):
        # Intel-defined fields, including reversed ModRM roles for extract
        # and VEX.vvvv as the VPSRLDQ destination, are checked independently.
        examples = (
            ("c5edf60f", "vpsadbw_mem", (256, 1, 2, 7, 0), ("avx2",)),
            ("c5e5d4d9", "vpaddq", (256, 3, 3, 1), ("avx2",)),
            ("c5d5eb6f60", "vpor_mem", (256, 5, 5, 7, 96), ("avx2",)),
            ("c5fe6f4a20", "vload", (256, 1, 2, 32), ("avx",)),
            ("c5fe7f4f60", "vstore", (256, 7, 96, 1), ("avx",)),
            ("62f16d48f64f03", "vpsadbw_mem", (512, 1, 2, 7, 192), ("avx512bw", "avx512f")),
            ("62f1d548eb6f03", "vpor_mem", (512, 5, 5, 7, 192), ("avx512f",)),
            ("62f1fe487f4f03", "vstore", (512, 7, 192, 1), ("avx512f",)),
            ("62f3fd483bc101", "vextract", (512, 256, 1, 0, 1), ("avx512f",)),
            ("c4e37d39c101", "vextract", (256, 128, 1, 0, 1), ("avx2",)),
            ("c5f9d4c1", "vpaddq", (128, 0, 0, 1), ("avx",)),
            ("c5f973d808", "vpsrldq", (128, 0, 0, 8), ("avx",)),
            ("c4c1f97ec1", "vmovq", (9, 0), ("avx",)),
            ("c5f877", "vzeroupper", (), ("avx",)),
        )
        for encoded, op, args, features in examples:
            with self.subTest(encoded=encoded):
                rows = decode_simd(bytes.fromhex(encoded))
                self.assertEqual(len(rows), 1)
                self.assertEqual((rows[0].op, rows[0].args, rows[0].cpu_features),
                                 (op, args, features))
                self.assertEqual(rows[0].size, len(bytes.fromhex(encoded)))

    def test_signed_disp8_tuple_scale_and_unscaled_disp32(self):
        examples = (
            ("c5fe6f4aff", (256, 1, 2, -1)),
            ("62f1fe486f4aff", (512, 1, 2, -64)),
            ("62f1fe486f4a80", (512, 1, 2, -8192)),
            ("62f1fe486f4a7f", (512, 1, 2, 8128)),
            ("62f1fe486f8a40000000", (512, 1, 2, 64)),
            ("62f1fe486f8affffffff", (512, 1, 2, -1)),
        )
        for encoded, args in examples:
            with self.subTest(encoded=encoded):
                self.assertEqual(decode_simd(bytes.fromhex(encoded))[0].args, args)

    def test_unreviewed_prefixes_masks_registers_and_addressing_fail_closed(self):
        bad = (
            "c5", "c4e3", "62f1fd", "62f1fe486f4a", "62f1fe486f8a400000",
            "c57defc0", "c5bdefc0", "c5f66f0a", "c5fb6f0a", "c5fe6f0c",
            "c5fe6f0d00000000", "c5fe6f0b", "c5fe6fca", "f3c5fe6f0a",
            "62f1fe496f0a", "62f1fe586f0a", "62f1fec86f0a", "62f1fe286f0a",
            "62f1fa486f0a", "62e1fe486f0a", "62f1fe406f0a", "62f17e486f0a",
            "62f16d48d4c1", "62f1ed48f60f", "c4e3fd39c101", "c4e37d39c102",
            "62f3f5483bc101", "c4e1f17ec0", "c5fd73d808", "c5f973d008",
            "c5fc77", "c5f977", "c4e17877",
        )
        for encoded in bad:
            with self.subTest(encoded=encoded), self.assertRaises(VerifiedSIMDRejected):
                decode_simd(bytes.fromhex(encoded))


@unittest.skipUnless(AVAILABLE, "Linux x86-64, GNU ld and pinned z3 are required")
class WideSIMDCheckerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="hia-wide-simd-check-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.cases = {}
        for isa in ("avx2", "avx512"):
            for kind in ("sum_u8", "all_zero_u8", "copy_u8"):
                core = simd_kernel_program(kind)
                image = emit_verified_simd(core, isa=isa, **({"copy_tail": "byte"} if kind == "copy_u8" else {"reduce_tail": "byte"}))
                obj, final = cls.root / (kind + isa + ".o"), cls.root / (kind + isa + ".so")
                obj.write_bytes(image.object_bytes)
                linked = subprocess.run([
                    "ld", "-m", "elf_x86_64", "-shared", "-z", "defs", "-z", "noexecstack",
                    "-z", "relro", "-z", "now", "--hash-style=both", "--build-id=none",
                    str(obj), "-lc", "-o", str(final),
                ], capture_output=True, text=True, timeout=30)
                if linked.returncode:
                    raise AssertionError(linked.stderr)
                final_bytes = final.read_bytes()
                proof = validate_verified_simd_artifact(core, image.object_bytes, final_bytes)
                cls.cases[isa, kind] = core, image, final_bytes, proof

    def rows(self, isa, kind):
        return decode_simd(self.cases[isa, kind][1].text_bytes)

    def bytes_of(self, isa, kind, row):
        return self.cases[isa, kind][1].text_bytes[row.pc:row.pc + row.size]

    def modified(self, isa, kind, changes):
        core, image, final_bytes, _ = self.cases[isa, kind]
        obj, linked = bytearray(image.object_bytes), bytearray(final_bytes)
        for row, replacement in changes:
            self.assertEqual(len(replacement), row.size)
            self.assertNotEqual(self.bytes_of(isa, kind, row), replacement)
            for data, elf_kind in ((obj, 1), (linked, 3)):
                at = _ELF(bytes(data), elf_kind).section(".text")["offset"] + row.pc
                data[at:at + row.size] = replacement
        return core, bytes(obj), bytes(linked)

    def reject(self, isa, kind, changes, obligation=None):
        args = self.modified(isa, kind, changes)
        with self.assertRaises(VerifiedSIMDRejected) as caught:
            validate_verified_simd_artifact(*args)
        if obligation is not None:
            self.assertIsNotNone(caught.exception.counterexample)
            self.assertEqual(caught.exception.counterexample["obligation"], obligation)
            self.assertFalse(caught.exception.validation["ok"])
        return caught.exception

    def changed_opcode(self, isa, kind, row, opcode):
        data = bytearray(self.bytes_of(isa, kind, row))
        data[4 if data[0] == 0x62 else 2 if data[0] == 0xc5 else 3] = opcode
        return bytes(data)

    def merge_rows(self, isa, kind):
        rows = self.rows(isa, kind)
        width = 32 if isa == "avx2" else 64
        bulk = next(j for j, r in enumerate(rows) if r.op == "alu_imm" and r.args == ("cmp", 10, width * 4))
        start = rows[bulk + 1].args[1]
        vector = next(r.pc for r in rows if r.op == "alu_imm" and r.args == ("cmp", 10, width))
        result = [r for r in rows if start <= r.pc < vector]
        self.assertEqual(len(result), 3)
        return result

    def test_all_six_profiles_have_complete_induction_and_exact_features(self):
        for (isa, kind), (_, _, _, report) in self.cases.items():
            with self.subTest(isa=isa, kind=kind):
                bits = 256 if isa == "avx2" else 512
                expected = {"avx"}
                if kind != "copy_u8": expected.add("avx2")
                if isa == "avx512": expected.add("avx512f")
                if isa == "avx512" and kind == "sum_u8": expected.add("avx512bw")
                self.assertEqual(report["profile"], WIDE_PROFILES[bits])
                self.assertEqual(report["target_isa"], isa)
                self.assertEqual(report["required_cpu_features"], sorted(expected))
                self.assertEqual(report["required_xcr0_mask"], 6 if isa == "avx2" else 230)
                self.assertTrue(report["fresh_cpu_probe_required"])
                self.assertEqual([o["result"] for o in report["obligations"]],
                                 ["sat"] + ["unsat"] * (11 if kind == "copy_u8" else 13))
                names = {o["name"] for o in report["obligations"]}
                self.assertTrue({"range_and_decreasing_variant_" + str(n)
                                 for n in (bits // 2, bits // 8, 1)} <= names)
                if kind != "copy_u8":
                    self.assertTrue({"wide_accumulator_initiation", "wide_accumulator_merge_and_frame",
                                     "wide_horizontal_reduction"} <= names)
                self.assertEqual(report["model_counts"]["vector_width"], bits // 8)
                self.assertEqual(report["model_counts"]["superblock_width"], bits // 2)
                self.assertEqual(report["model_counts"]["reduction_accumulators"], 0 if kind == "copy_u8" else 4)
                self.assertFalse(report["claims"]["serialized_receipt_authorizes_execution"])
                self.assertIn("hia_verified_simd_wide_x64.py", report["checker"]["source_identity"])

    def test_consumer_never_reemits_and_accepts_equivalent_supplied_merge_order(self):
        with patch("hepta.hia_verified_simd.emit_verified_simd", side_effect=AssertionError("producer invoked")), \
             patch("hepta.hia_verified_simd_wide.emit_wide_simd", side_effect=AssertionError("wide producer invoked")):
            for isa in ("avx2", "avx512"):
                for kind in ("sum_u8", "all_zero_u8"):
                    merge = self.merge_rows(isa, kind)
                    changed = [(merge[0], self.bytes_of(isa, kind, merge[2])),
                               (merge[2], self.bytes_of(isa, kind, merge[0]))]
                    report = validate_verified_simd_artifact(*self.modified(isa, kind, changed))
                    self.assertTrue(report["ok"])
                    self.assertNotEqual(report["subject"]["object_sha256"],
                                        self.cases[isa, kind][3]["subject"]["object_sha256"])

    def test_every_accumulator_and_persistent_zero_are_initialized(self):
        for isa in ("avx2", "avx512"):
            for kind in ("sum_u8", "all_zero_u8"):
                rows = [r for r in self.rows(isa, kind) if r.op == "vpxor"]
                self.assertEqual([r.args[1] for r in rows], [0, 2, 3, 4, 5])
                for row in rows:
                    with self.subTest(isa=isa, kind=kind, register=row.args[1]):
                        self.reject(isa, kind, [(row, self.changed_opcode(isa, kind, row, 0xdb))])

    def test_folded_reads_use_real_signed_tuple_scaled_offsets(self):
        for isa in ("avx2", "avx512"):
            for kind in ("sum_u8", "all_zero_u8"):
                row = [r for r in self.rows(isa, kind) if r.op.endswith("_mem")][1]
                for displacement in (0, 2 if isa == "avx512" else 64, 0xff):
                    raw = bytearray(self.bytes_of(isa, kind, row)); raw[-1] = displacement
                    with self.subTest(isa=isa, kind=kind, displacement=displacement):
                        self.reject(isa, kind, [(row, bytes(raw))])

    def test_sum_wrong_accumulation_produces_universal_counterexample(self):
        for isa in ("avx2", "avx512"):
            row = [r for r in self.rows(isa, "sum_u8") if r.op == "vpaddq"][3]
            self.reject(isa, "sum_u8", [(row, self.changed_opcode(isa, "sum_u8", row, 0xfb))],
                        "wide_bulk_sum_induction")

    def test_zero_xor_and_and_do_not_preserve_the_all_zero_predicate(self):
        for isa in ("avx2", "avx512"):
            row = [r for r in self.rows(isa, "all_zero_u8") if r.op == "vpor_mem"][3]
            for opcode in (0xef, 0xdb):
                self.reject(isa, "all_zero_u8", [(row, self.changed_opcode(isa, "all_zero_u8", row, opcode))],
                            "wide_bulk_zero_scan_induction")

    def test_all_four_copy_chunks_and_exact_stored_register_are_required(self):
        for isa in ("avx2", "avx512"):
            stores = [r for r in self.rows(isa, "copy_u8") if r.op == "vstore"]
            row = stores[3]
            raw = bytearray(self.bytes_of(isa, "copy_u8", row)); raw[-1] = 2 if isa == "avx512" else 64
            self.reject(isa, "copy_u8", [(row, bytes(raw))])
            raw = bytearray(self.bytes_of(isa, "copy_u8", row)); raw[-2] = (raw[-2] & 0xc7) | (3 << 3)
            self.reject(isa, "copy_u8", [(row, bytes(raw))], "wide_bulk_copy_byte_semantics")

    def test_merge_is_semantically_checked_and_cannot_be_bypassed(self):
        for isa in ("avx2", "avx512"):
            for kind in ("sum_u8", "all_zero_u8"):
                merge = self.merge_rows(isa, kind)
                raw = bytearray(self.bytes_of(isa, kind, merge[-1])); raw[-1] = (raw[-1] & 0xf8) | 4
                self.reject(isa, kind, [(merge[-1], bytes(raw))], "wide_accumulator_merge_and_frame")
                branch = next(r for r in self.rows(isa, kind) if r.op == "jcc" and r.args[1] == merge[0].pc)
                raw = bytearray(self.bytes_of(isa, kind, branch))
                raw[-4:] = struct.pack("<i", merge[-1].pc + merge[-1].size - branch.pc - branch.size)
                self.reject(isa, kind, [(branch, bytes(raw))])

    def test_narrowing_zeroes_upper_bits_and_horizontal_extract_is_semantic(self):
        for isa in ("avx2", "avx512"):
            for kind in ("sum_u8", "all_zero_u8"):
                extracts = [r for r in self.rows(isa, kind) if r.op == "vextract"]
                for row in extracts:
                    raw = bytearray(self.bytes_of(isa, kind, row)); raw[-1] = 0
                    self.reject(isa, kind, [(row, bytes(raw))], "wide_horizontal_reduction")
                if isa == "avx512":
                    # Extract into ymm0 destroys its complete former zmm0,
                    # including upper bits. A decoder that retained those
                    # bits could incorrectly bless a subsequent reduction.
                    row = extracts[0]
                    raw = bytearray(self.bytes_of(isa, kind, row)); raw[-2] &= 0xf8
                    self.reject(isa, kind, [(row, bytes(raw))], "wide_horizontal_reduction")

    def test_horizontal_shift_and_gpr_frame_are_checked(self):
        for isa in ("avx2", "avx512"):
            row = next(r for r in self.rows(isa, "sum_u8") if r.op == "vpsrldq")
            raw = bytearray(self.bytes_of(isa, "sum_u8", row)); raw[-1] = 0
            self.reject(isa, "sum_u8", [(row, bytes(raw))], "wide_horizontal_reduction")
            row = next(r for r in self.rows(isa, "sum_u8") if r.op == "vmovq" and r.args[0] == 0)
            raw = bytearray(self.bytes_of(isa, "sum_u8", row)); raw[-1] = (raw[-1] & 0xf8) | 3
            self.reject(isa, "sum_u8", [(row, bytes(raw))])

    def test_vector_cleanup_and_tail_cannot_skip_their_guards(self):
        for isa in ("avx2", "avx512"):
            width = 32 if isa == "avx2" else 64
            for kind in ("sum_u8", "all_zero_u8", "copy_u8"):
                rows = self.rows(isa, kind)
                guard = next(r for r in rows if r.op == "alu_imm" and r.args == ("cmp", 10, width))
                raw = bytearray(self.bytes_of(isa, kind, guard)); raw[-1] -= 1
                self.reject(isa, kind, [(guard, bytes(raw))])
                cleanup = next(r for r in rows if r.op == "vzeroupper")
                self.reject(isa, kind, [(cleanup, bytes.fromhex("c5fc77"))])
                branch = next(r for r in rows if r.op == "jcc" and r.pc > guard.pc and
                              r.args[0] == 2)
                raw = bytearray(self.bytes_of(isa, kind, branch))
                raw[-4:] = struct.pack("<i", cleanup.pc + cleanup.size - branch.pc - branch.size)
                self.reject(isa, kind, [(branch, bytes(raw))])

    def test_final_only_change_cannot_reuse_verified_object(self):
        for isa in ("avx2", "avx512"):
            core, image, final, _ = self.cases[isa, "sum_u8"]
            data = bytearray(final)
            row = next(r for r in self.rows(isa, "sum_u8") if r.op == "vpaddq")
            at = _ELF(final, 3).section(".text")["offset"] + row.pc
            data[at:at + row.size] = self.changed_opcode(isa, "sum_u8", row, 0xfb)
            with self.assertRaises(SafeCoreELFRejected):
                validate_verified_simd_artifact(core, image.object_bytes, bytes(data))


if __name__ == "__main__":
    unittest.main()
