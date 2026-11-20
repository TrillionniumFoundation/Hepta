"""Universal endpoint-copy coverage, overlap, decoding and frame controls."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_safe_core_elf import _ELF, SafeCoreELFRejected
from hepta.hia_verified_simd import emit_verified_simd, simd_kernel_program
from hepta.hia_verified_simd_check import (
    COPY_ENDPOINT_PROFILES, WIDE_PROFILES, VerifiedSIMDRejected,
    decode_simd, validate_verified_simd_artifact,
)


AVAILABLE = (platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}
             and shutil.which("ld") is not None and importlib.util.find_spec("z3") is not None)


class EndpointDecoderTests(unittest.TestCase):
    def test_exact_scalar_widths_and_vex128_are_independently_decoded(self):
        examples = (
            ("4c8b0a", "copy_load", (64, 9, 2, 0)),
            ("4c8b1a", "copy_load", (64, 11, 2, 0)),
            ("4c890f", "copy_store", (64, 7, 0, 9)),
            ("4c891f", "copy_store", (64, 7, 0, 11)),
            ("448b0a", "copy_load", (32, 9, 2, 0)),
            ("448b1a", "copy_load", (32, 11, 2, 0)),
            ("44890f", "copy_store", (32, 7, 0, 9)),
            ("44891f", "copy_store", (32, 7, 0, 11)),
            ("4c0fb70a", "copy_load", (16, 9, 2, 0)),
            ("4c0fb71a", "copy_load", (16, 11, 2, 0)),
            ("6644890f", "copy_store", (16, 7, 0, 9)),
            ("6644891f", "copy_store", (16, 7, 0, 11)),
            ("4c0fb60a", "copy_load", (8, 9, 2, 0)),
            ("44880f", "copy_store", (8, 7, 0, 9)),
            ("c5fa6f0a", "vload", (128, 1, 2, 0)),
            ("c5fa7f17", "vstore", (128, 7, 0, 2)),
            ("c5fe6f12", "vload", (256, 2, 2, 0)),
        )
        for encoded, op, args in examples:
            with self.subTest(encoded=encoded):
                rows = decode_simd(bytes.fromhex(encoded))
                self.assertEqual(len(rows), 1)
                self.assertEqual((rows[0].op, rows[0].args), (op, args))
                self.assertEqual(rows[0].size, len(bytes.fromhex(encoded)))
                self.assertEqual(rows[0].cpu_features, ("avx",) if op.startswith("v") else ())

    def test_reserved_prefix_address_and_operand_forms_still_fail_closed(self):
        for encoded in (
            "4c8b", "448b", "4c0fb7", "664489", "4c8b0c", "4c8b0d00000000",
            "4c8b4a08", "6644894f02", "664c890f", "664489cf", "4d8b0a",
            "4c0fb74a02", "4c0fb70c", "44880d00000000", "c5fb6f0a",
            "c5f26f0a", "c57a6f0a", "c5fa6f0c", "c5fa6fca",
        ):
            with self.subTest(encoded=encoded), self.assertRaises(VerifiedSIMDRejected):
                decode_simd(bytes.fromhex(encoded))


@unittest.skipUnless(AVAILABLE, "Linux x86-64, GNU ld and pinned z3 are required")
class EndpointCopyCheckerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="hia-endpoint-copy-check-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.core = simd_kernel_program("copy_u8")
        cls.cases = {}
        for isa in ("avx2", "avx512"):
            for tail in ("byte", "endpoints"):
                image = emit_verified_simd(cls.core, isa=isa, copy_tail=tail)
                obj = cls.root / (isa + tail + ".o")
                final = obj.with_suffix(".so")
                obj.write_bytes(image.object_bytes)
                subprocess.run(["ld", "-m", "elf_x86_64", "-shared", "-z", "defs", "-z", "noexecstack",
                    "-z", "relro", "-z", "now", "--hash-style=both", "--build-id=none",
                    str(obj), "-lc", "-o", str(final)], check=True, capture_output=True, timeout=30)
                data = final.read_bytes()
                proof = validate_verified_simd_artifact(cls.core, image.object_bytes, data)
                cls.cases[isa, tail] = image, data, proof

    def rows(self, isa):
        return decode_simd(self.cases[isa, "endpoints"][0].text_bytes)

    def endpoint(self, isa, width):
        rows = self.rows(isa)
        if width == 1:
            start = next(i for i, row in enumerate(rows) if row.op == "copy_load" and row.args[0] == 8)
            return rows[start:start + 2]
        guard = next(i for i, row in enumerate(rows) if row.op == "alu_imm" and row.args == ("cmp", 10, width))
        return rows[guard + 2:guard + 9]

    def raw(self, isa, row):
        return self.cases[isa, "endpoints"][0].text_bytes[row.pc:row.pc + row.size]

    def reject(self, isa, changes, obligation=None):
        image, data, _ = self.cases[isa, "endpoints"]
        obj, final = bytearray(image.object_bytes), bytearray(data)
        for row, changed in changes:
            self.assertEqual(len(changed), row.size)
            self.assertNotEqual(changed, self.raw(isa, row))
            for buffer, elf_kind in ((obj, 1), (final, 3)):
                at = _ELF(bytes(buffer), elf_kind).section(".text")["offset"] + row.pc
                buffer[at:at + row.size] = changed
        with self.assertRaises(VerifiedSIMDRejected) as caught:
            validate_verified_simd_artifact(self.core, bytes(obj), bytes(final))
        if obligation:
            self.assertIsNotNone(caught.exception.counterexample)
            self.assertEqual(caught.exception.counterexample["obligation"], obligation)
        return caught.exception

    def test_new_profiles_prove_all_suffix_bytes_and_retain_old_byte_profile(self):
        for isa in ("avx2", "avx512"):
            bits = 256 if isa == "avx2" else 512
            widths = [16, 8, 4, 2, 1] if isa == "avx2" else [32, 16, 8, 4, 2, 1]
            _, _, old = self.cases[isa, "byte"]
            image, _, report = self.cases[isa, "endpoints"]
            self.assertEqual(old["profile"], WIDE_PROFILES[bits])
            self.assertEqual(len(old["obligations"]), 12)
            self.assertFalse(old["claims"]["overlapping_endpoint_copy_effects_checked"])
            self.assertEqual(report["profile"], COPY_ENDPOINT_PROFILES[bits])
            self.assertEqual(len(report["obligations"]), 21 if isa == "avx2" else 23)
            self.assertEqual([o["result"] for o in report["obligations"]],
                             ["sat"] + ["unsat"] * (len(report["obligations"]) - 1))
            names = {o["name"] for o in report["obligations"]}
            self.assertTrue({"endpoint_dispatch_partition", "copy_prefix_suffix_partition",
                             "copy_source_preserved_between_iterations"} <= names)
            for width in widths:
                self.assertTrue({"endpoint_" + str(width) + suffix for suffix in
                                 ("_bounds_and_exact_coverage", "_byte_effects_and_frame")} <= names)
            self.assertEqual(report["model_counts"]["endpoint_widths"], widths)
            self.assertEqual(report["model_counts"]["loop_backedges"], 2)
            self.assertTrue(report["claims"]["overlapping_endpoint_copy_effects_checked"])
            self.assertEqual(report["required_cpu_features"], ["avx"] if isa == "avx2" else ["avx", "avx512f"])
            self.assertEqual(emit_verified_simd(self.core, isa=isa, copy_tail="endpoints").text_bytes, image.text_bytes)

    def test_batched_bulk_store_of_the_wrong_chunk_is_refuted(self):
        for isa in ("avx2", "avx512"):
            row = [r for r in self.rows(isa) if r.op == "vstore"][2]
            raw = bytearray(self.raw(isa, row))
            raw[-2] = (raw[-2] & 0xc7) | (4 << 3)
            self.reject(isa, [(row, bytes(raw))], "wide_bulk_copy_byte_semantics")

    def test_overlapping_endpoint_writes_must_use_the_correct_source_byte(self):
        for isa in ("avx2", "avx512"):
            widths = [16, 8, 4, 2] if isa == "avx2" else [32, 16, 8, 4, 2]
            for width in widths:
                row = self.endpoint(isa, width)[-1]
                raw = bytearray(self.raw(isa, row))
                # Reusing the first loaded block for the last store happens
                # to work when remaining == width. The universal obligation
                # must find a different remaining count in the overlap range.
                raw[-1] = (raw[-1] & 0xc7) | (1 << 3)
                error = self.reject(isa, [(row, bytes(raw))], "endpoint_" + str(width) + "_byte_effects_and_frame")
                match = re.search(r"endpoint_remaining\s*=\s*(\d+)", error.counterexample["model"])
                self.assertIsNotNone(match)
                self.assertTrue(width < int(match.group(1)) < 2 * width)

    def test_delta_off_by_one_negative_and_pointer_mixups_are_rejected(self):
        for isa in ("avx2", "avx512"):
            for width in (16, 8, 4, 2):
                block = self.endpoint(isa, width)
                for amount in (width - 1, width + 1, 0xff):
                    raw = bytearray(self.raw(isa, block[1])); raw[-1] = amount
                    self.reject(isa, [(block[1], bytes(raw))])
                raw = bytearray(self.raw(isa, block[2])); raw[-1] = (raw[-1] & 0xf8) | 7
                self.reject(isa, [(block[2], bytes(raw))])

    def test_level_guards_cannot_admit_short_accesses_or_skip_valid_levels(self):
        for isa in ("avx2", "avx512"):
            rows = self.rows(isa)
            for width in (16, 8, 4, 2):
                index = next(i for i, r in enumerate(rows) if r.op == "alu_imm" and r.args == ("cmp", 10, width))
                guard, branch = rows[index], rows[index + 1]
                raw = bytearray(self.raw(isa, guard)); raw[-1] -= 1
                self.reject(isa, [(guard, bytes(raw))])
                raw = bytearray(self.raw(isa, branch)); raw[1] = 0x86
                self.reject(isa, [(branch, bytes(raw))])

    def test_narrow_load_store_width_and_frame_mutations_are_rejected(self):
        for isa in ("avx2", "avx512"):
            block = self.endpoint(isa, 4)
            for row in (block[0], block[4]):
                raw = bytearray(self.raw(isa, row)); raw[0] = 0x4c
                self.reject(isa, [(row, bytes(raw))])
            row = self.endpoint(isa, 16)[0]
            raw = bytearray(self.raw(isa, row)); raw[1] |= 4
            self.reject(isa, [(row, bytes(raw))])
            row = self.endpoint(isa, 8)[0]
            raw = bytearray(self.raw(isa, row)); raw[-1] = (raw[-1] & 0xc7)
            self.reject(isa, [(row, bytes(raw))])
            row = self.endpoint(isa, 1)[1]
            raw = bytearray(self.raw(isa, row)); raw[-1] = (raw[-1] & 0xc7) | (3 << 3)
            self.reject(isa, [(row, bytes(raw))], "endpoint_1_byte_effects_and_frame")

    def test_zero_and_endpoint_branches_must_reach_the_common_vzeroupper(self):
        for isa in ("avx2", "avx512"):
            rows = self.rows(isa)
            cleanup = next(r for r in rows if r.op == "vzeroupper")
            done = next(r for r in rows if r.op == "ret")
            branches = [r for r in rows if r.op in ("jcc", "jmp") and r.args[-1] == cleanup.pc]
            self.assertGreater(len(branches), 1)
            for row in (branches[0], branches[-1]):
                raw = bytearray(self.raw(isa, row)); raw[-4:] = struct.pack("<i", done.pc - row.pc - row.size)
                self.reject(isa, [(row, bytes(raw))])
            self.reject(isa, [(cleanup, bytes.fromhex("c5fc77"))])

    def test_supplied_final_bytes_are_checked_without_producer_authority(self):
        image, data, _ = self.cases["avx512", "endpoints"]
        with patch("hepta.hia_verified_simd.emit_verified_simd", side_effect=AssertionError("producer invoked")), \
             patch("hepta.hia_verified_simd_wide.emit_wide_simd", side_effect=AssertionError("wide producer invoked")):
            self.assertTrue(validate_verified_simd_artifact(self.core, image.object_bytes, data)["complete"])
        changed = bytearray(data)
        at = _ELF(data, 3).section(".text")["offset"]
        changed[at] ^= 1
        with self.assertRaises(SafeCoreELFRejected):
            validate_verified_simd_artifact(self.core, image.object_bytes, bytes(changed))


if __name__ == "__main__":
    unittest.main()
