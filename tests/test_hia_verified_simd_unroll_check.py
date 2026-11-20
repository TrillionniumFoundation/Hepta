"""Adversarial final-byte controls for the four-vector SSE2 loop."""
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

from hepta.hia_safe_core_elf import _ELF
from hepta.hia_verified_simd import emit_verified_simd, simd_kernel_program
from hepta.hia_verified_simd_check import (
    PROFILE, UNROLLED_PROFILE, VerifiedSIMDRejected, decode_simd,
    validate_verified_simd_artifact,
)


AVAILABLE = (platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}
             and shutil.which("ld") is not None and importlib.util.find_spec("z3") is not None)


class DisplacedVectorDecoderTests(unittest.TestCase):
    def test_displacements_are_signed_and_preserve_memory_roles(self):
        examples = (
            ("f30f6f0f", "load128", (1, 7, 0)),
            ("f30f6f4f10", "load128", (1, 7, 16)),
            ("f30f6f4ff0", "load128", (1, 7, -16)),
            ("f30f6f8f30000000", "load128", (1, 7, 48)),
            ("f30f6f8fe0ffffff", "load128", (1, 7, -32)),
            ("f30f7f4f30", "store128", (7, 48, 1)),
            ("f30f7f8f20000000", "store128", (7, 32, 1)),
            ("f30f6f4a20", "load128", (1, 2, 32)),
        )
        for encoded, operation, arguments in examples:
            with self.subTest(encoded=encoded):
                rows = decode_simd(bytes.fromhex(encoded))
                self.assertEqual(len(rows), 1)
                self.assertEqual((rows[0].op, rows[0].args), (operation, arguments))
                self.assertEqual(rows[0].size, len(bytes.fromhex(encoded)))

    def test_truncated_indexed_rip_and_register_forms_stay_outside_profile(self):
        for encoded in (
            "f30f6f4f", "f30f6f8f300000", "f30f7f8f",
            "f30f6f4c0710", "f30f6f0d00000000", "f30f6fcf",
            "f3490f6f4f10", "f30f6f4e10",
        ):
            with self.subTest(encoded=encoded), self.assertRaises(VerifiedSIMDRejected):
                decode_simd(bytes.fromhex(encoded))


@unittest.skipUnless(AVAILABLE, "Linux x86-64, GNU ld and pinned z3 are required")
class UnrolledSIMDCheckerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="hia-unrolled-simd-check-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.cases = {}
        for kind in ("sum_u8", "all_zero_u8", "copy_u8"):
            core = simd_kernel_program(kind)
            image = emit_verified_simd(core, unroll=4)
            obj, final = cls.root / (kind + ".o"), cls.root / (kind + ".so")
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
            cls.cases[kind] = (core, image, final_bytes, proof)

    def bulk_rows(self, kind):
        rows = decode_simd(self.cases[kind][1].text_bytes)
        start = next(j for j, row in enumerate(rows)
                     if row.op == "alu_imm" and row.args == ("cmp", 10, 64))
        stop = next(j for j in range(start + 1, len(rows))
                    if rows[j].op == "alu_imm" and rows[j].args == ("cmp", 10, 16))
        return rows[start:stop], rows[stop].pc

    def mutate(self, kind, changes, *, obligation=None):
        core, image, final_bytes, _ = self.cases[kind]
        object_bytes, linked_bytes = bytearray(image.object_bytes), bytearray(final_bytes)
        for row, new_bytes in changes:
            self.assertEqual(len(new_bytes), row.size)
            self.assertNotEqual(image.text_bytes[row.pc:row.pc + row.size], new_bytes)
            for data, elf_kind in ((object_bytes, 1), (linked_bytes, 3)):
                offset = _ELF(bytes(data), elf_kind).section(".text")["offset"] + row.pc
                data[offset:offset + row.size] = new_bytes
        with self.assertRaises(VerifiedSIMDRejected) as caught:
            validate_verified_simd_artifact(core, bytes(object_bytes), bytes(linked_bytes))
        if obligation is not None:
            self.assertIsNotNone(caught.exception.counterexample)
            self.assertEqual(caught.exception.counterexample["obligation"], obligation)
            self.assertFalse(caught.exception.validation["ok"])
        return caught.exception

    def bytes_of(self, kind, row):
        return self.cases[kind][1].text_bytes[row.pc:row.pc + row.size]

    def test_all_four_symbolic_chunks_are_proved_before_vector_and_scalar_tails(self):
        for kind, (_, _, _, report) in self.cases.items():
            with self.subTest(kind=kind):
                self.assertEqual(report["profile"], UNROLLED_PROFILE)
                self.assertNotEqual(report["profile"], PROFILE)
                self.assertEqual([o["result"] for o in report["obligations"]],
                                 ["sat"] + ["unsat"] * 11)
                self.assertIn("range_and_decreasing_variant_64",
                              [o["name"] for o in report["obligations"]])
                self.assertEqual(report["model_counts"]["vector_unroll"], 4)
                self.assertEqual(report["model_counts"]["superblock_width"], 64)
                self.assertEqual(report["model_counts"]["vector_width"], 16)
                self.assertEqual(report["model_counts"]["loop_backedges"], 3)
                self.assertEqual(report["model_counts"]["range_admission_sites"], 1)
                bulk, _ = self.bulk_rows(kind)
                self.assertEqual([r.args[2] for r in bulk if r.op == "load128"],
                                 [0, 16, 32, 48])
                if kind == "copy_u8":
                    self.assertEqual([r.args[1] for r in bulk if r.op == "store128"],
                                     [0, 16, 32, 48])

    def test_consumer_uses_supplied_bytes_without_reemitting(self):
        core, image, final_bytes, _ = self.cases["sum_u8"]
        with patch("hepta.hia_verified_simd.emit_verified_simd",
                   side_effect=AssertionError("producer invoked by consumer")):
            self.assertTrue(validate_verified_simd_artifact(core, image.object_bytes, final_bytes)["ok"])

    def test_short_bulk_guard_cannot_authorize_four_vector_loads(self):
        for kind in self.cases:
            bulk, _ = self.bulk_rows(kind)
            row = bulk[0]
            original = self.bytes_of(kind, row)
            self.assertEqual(original[-1], 64)
            with self.subTest(kind=kind):
                self.mutate(kind, [(row, original[:-1] + bytes([63]))])

    def test_bulk_pointer_and_remaining_strides_are_exact(self):
        for kind in self.cases:
            bulk, _ = self.bulk_rows(kind)
            updates = [r for r in bulk if r.op == "alu_imm" and
                       r.args[0] in ("add", "sub") and r.args[2] == 64]
            self.assertEqual(len(updates), 3 if kind == "copy_u8" else 2)
            for row in updates:
                with self.subTest(kind=kind, update=row.args):
                    original = self.bytes_of(kind, row)
                    self.mutate(kind, [(row, original[:-1] + bytes([63]))])

    def test_bulk_backedge_cannot_skip_the_remaining_superblocks(self):
        for kind in self.cases:
            bulk, vector_pc = self.bulk_rows(kind)
            row = bulk[-1]
            self.assertEqual(row.op, "jmp")
            changed = b"\xe9" + struct.pack("<i", vector_pc - (row.pc + row.size))
            with self.subTest(kind=kind):
                self.mutate(kind, [(row, changed)])

    def test_second_load_cannot_repeat_precede_or_exceed_the_guarded_range(self):
        for kind in self.cases:
            bulk, _ = self.bulk_rows(kind)
            row = next(r for r in bulk if r.op == "load128" and r.args[2] == 16)
            self.assertEqual(row.size, 5)
            for displacement in (0, 0xf0, 64):
                with self.subTest(kind=kind, displacement=displacement):
                    original = self.bytes_of(kind, row)
                    self.mutate(kind, [(row, original[:-1] + bytes([displacement]))])

    def test_copy_destination_offsets_cannot_duplicate_or_escape(self):
        bulk, _ = self.bulk_rows("copy_u8")
        row = next(r for r in bulk if r.op == "store128" and r.args[1] == 48)
        for displacement in (32, 64, 0xf0):
            with self.subTest(displacement=displacement):
                original = self.bytes_of("copy_u8", row)
                self.mutate("copy_u8", [(row, original[:-1] + bytes([displacement]))])

    def test_later_sum_chunk_subtraction_has_a_concrete_counterexample(self):
        bulk, _ = self.bulk_rows("sum_u8")
        row = [r for r in bulk if r.op == "paddq"][2]
        original = self.bytes_of("sum_u8", row)
        self.assertEqual(original[:3], bytes.fromhex("660fd4"))
        self.mutate("sum_u8", [(row, bytes.fromhex("660ffb") + original[3:])],
                    obligation="bulk_sum_induction")

    def test_zero_scan_cancellation_in_the_fourth_chunk_is_refuted(self):
        bulk, _ = self.bulk_rows("all_zero_u8")
        row = [r for r in bulk if r.op == "por"][3]
        original = self.bytes_of("all_zero_u8", row)
        self.assertEqual(original[:3], bytes.fromhex("660feb"))
        self.mutate("all_zero_u8", [(row, bytes.fromhex("660fef") + original[3:])],
                    obligation="bulk_zero_scan_induction")

    def test_last_sum_chunk_must_restore_the_zero_register_for_following_loops(self):
        bulk, _ = self.bulk_rows("sum_u8")
        sad = [r for r in bulk if r.op == "psadbw"][-1]
        add = [r for r in bulk if r.op == "paddq"][-1]
        self.assertEqual(self.bytes_of("sum_u8", sad), bytes.fromhex("660ff6ca"))
        self.assertEqual(self.bytes_of("sum_u8", add), bytes.fromhex("660fd4c1"))
        self.mutate("sum_u8", [(sad, bytes.fromhex("660ff6d1")),
                              (add, bytes.fromhex("660fd4c2"))],
                    obligation="bulk_sum_induction")

    def test_fourth_copy_chunk_cannot_store_an_arbitrary_caller_register(self):
        bulk, _ = self.bulk_rows("copy_u8")
        row = [r for r in bulk if r.op == "store128"][3]
        original = self.bytes_of("copy_u8", row)
        self.assertEqual(original, bytes.fromhex("f30f7f4f30"))
        self.mutate("copy_u8", [(row, bytes.fromhex("f30f7f4730"))],
                    obligation="bulk_copy_byte_semantics")


if __name__ == "__main__":
    unittest.main()
