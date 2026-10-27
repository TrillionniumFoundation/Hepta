"""The instruction search is finite, model-proved, and bound to exact bytes."""
from __future__ import annotations

import copy
import importlib.util
import os
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_program import verify_program
from hepta.hia_translation_validation import validate_translation
from hepta.hia_x86_search import (
    X86SearchRejected, _elf_layout, affine_program, assembly_source, build_candidate,
    enumerate_candidates, exported_code, inspect_candidate_artifact, search_affine_candidates,
)

HAS_Z3 = importlib.util.find_spec("z3") is not None
CLANG = os.environ.get("HEPTA_CLANG", "clang-20")
HAS_NATIVE = HAS_Z3 and shutil.which(CLANG) is not None


def lea(offset):
    return next(c for c in enumerate_candidates() if c["recipe"] == [{"op": "lea", "imm": offset}])


class ClosedGrammarTests(unittest.TestCase):
    def test_complete_grammar_has_146_unique_stable_recipes(self):
        candidates = enumerate_candidates()
        self.assertEqual(len(candidates), 146)
        self.assertEqual(len({c["id"] for c in candidates}), 146)
        self.assertEqual(candidates, enumerate_candidates())
        for candidate in candidates:
            self.assertEqual(len(bytes.fromhex(candidate["expected_code_hex"])), candidate["encoded_bytes"])
            self.assertTrue(candidate["expected_code_hex"].endswith("c3"))
            verify_program(candidate["program"])
            self.assertNotIn("proved", candidate)

    def test_explicit_signed_immediate_encodings_and_zero_displacement(self):
        self.assertEqual(lea(12)["expected_code_hex"], "488d470cc3")
        self.assertEqual(lea(-12)["expected_code_hex"], "488d47f4c3")
        self.assertEqual(lea(0)["expected_code_hex"], "488d07c3")
        multiplication = next(c for c in enumerate_candidates() if c["recipe"] ==
                              [{"op": "imul", "imm": -1}, {"op": "add", "imm": -12}])
        self.assertEqual(multiplication["expected_code_hex"], "486bc7ff4883c0f4c3")

    def test_input_cannot_supply_assembly_registers_memory_calls_or_stack_mutation(self):
        for instruction in ({"op": "call", "imm": 12}, {"op": "push"}, {"op": "load", "imm": 12},
                            {"op": "lea", "imm": 12, "destination": "rbx"}, {"op": "lea", "imm": True},
                            {"op": "lea", "imm": "12(%rdi); call evil"}):
            candidate = lea(12)
            candidate["recipe"][0] = instruction
            with self.subTest(instruction=instruction), self.assertRaises(X86SearchRejected):
                assembly_source(candidate)

    def test_serialized_proved_flag_and_altered_model_or_bytes_never_authorize(self):
        for mutation in ("proved", "program", "id", "expected_code_hex", "encoded_bytes"):
            candidate = lea(12)
            if mutation == "program":
                candidate[mutation] = affine_program(11)
            elif mutation == "proved":
                candidate[mutation] = True
            elif mutation == "encoded_bytes":
                candidate[mutation] = 4
            else:
                candidate[mutation] = "fake"
            with self.subTest(field=mutation), self.assertRaises(X86SearchRejected):
                assembly_source(candidate)

    def test_baseline_offset_is_bounded_and_not_boolean(self):
        for offset in (-17, 17, True, 1.0, "12"):
            with self.subTest(offset=offset), self.assertRaises(X86SearchRejected):
                affine_program(offset)


@unittest.skipUnless(HAS_Z3, "optional z3-solver is not installed")
class ModelProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.search = search_affine_candidates()

    def test_all_146_models_decided_and_minimum_is_exactly_five_bytes(self):
        result = self.search
        self.assertTrue(result["finite_minimum_encoded_bytes_proved"], result)
        self.assertEqual(result["candidate_count"], 146)
        self.assertEqual(result["decided_count"], 146)
        self.assertEqual(result["accepted_count"], 7)
        self.assertEqual(result["minimum_encoded_bytes"], 5)
        self.assertEqual(result["selected_candidate"], lea(12))
        self.assertFalse(result["claims"]["global_optimality_established"])
        wrong = [row for row in result["candidates"] if row["proof"]["status"] == "disproved"]
        self.assertEqual(len(wrong), 139)
        self.assertTrue(all(row["proof"]["counterexample"] is not None for row in wrong))

    def test_one_unknown_denies_finite_minimum_even_when_best_candidate_is_proved(self):
        call_count = 0
        def one_unknown(*args, **kwargs):
            nonlocal call_count
            result = validate_translation(*args, **kwargs)
            call_count += 1
            if call_count == 1:
                result["status"] = "unknown"
                result["reason"] = "test_injected_solver_timeout"
            return result
        with patch("hepta.hia_x86_search.validate_translation", side_effect=one_unknown):
            result = search_affine_candidates()
        self.assertEqual(call_count, 146)
        self.assertEqual(result["decided_count"], 145)
        self.assertFalse(result["finite_minimum_encoded_bytes_proved"])
        self.assertIsNone(result["minimum_encoded_bytes"])
        self.assertEqual(result["selected_candidate"], lea(12))

    def test_safe_but_wrong_native_recipe_rejected_before_compiler_launch(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "bad.so"
            with patch("hepta.hia_x86_search.run_bounded") as launch:
                with self.assertRaisesRegex(X86SearchRejected, "not freshly proved"):
                    build_candidate(affine_program(12), lea(11), destination, clang="not-a-compiler")
                launch.assert_not_called()
            self.assertFalse(destination.exists())

    def test_otherwise_fresh_proof_must_bind_profile_scope_and_every_input_digest(self):
        good = validate_translation(affine_program(12), lea(12)["program"], function="calculate")
        for field in ("schema", "profile", "scope", "before_sha256", "after_sha256",
                      "before_input_sha256", "after_input_sha256"):
            bad = copy.deepcopy(good)
            bad[field] = "wrong"
            with self.subTest(field=field), patch("hepta.hia_x86_search.validate_translation", return_value=bad):
                with self.assertRaisesRegex(X86SearchRejected, "does not bind"):
                    build_candidate(affine_program(12), lea(12), "/tmp/never-created-x86.so", clang="not-a-compiler")


@unittest.skipUnless(HAS_NATIVE, "requires actual Clang20+ and z3-solver")
class ActualNativeByteGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="hia-x86-test-")
        cls.candidate = lea(12)
        cls.path = Path(cls.temporary.name) / "candidate.so"
        cls.receipt = build_candidate(affine_program(), cls.candidate, cls.path, clang=CLANG)
        cls.data = cls.path.read_bytes()

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_real_assembler_exact_entry_bytes_and_native_boundary_outputs(self):
        inspection = inspect_candidate_artifact(self.data, self.candidate)
        self.assertEqual(inspection["code_hex"], "488d470cc3")
        self.assertEqual(inspection["encoded_bytes"], 5)
        self.assertTrue(inspection["imports_relocations_initializers_absent"])
        from tools.qualify_hia_x86_search import PROTOCOL, _edge_sample
        result = _edge_sample(self.path, self.receipt["artifact_sha256"], PROTOCOL["edge_inputs"])
        self.assertEqual(result["status"], "observed", result)

    def test_corrupted_code_cannot_reuse_valid_candidate_or_artifact_receipt(self):
        body = exported_code(self.data)
        bad = bytearray(self.data)
        bad[body["file_offset"] + 3] = 11  # x+11 is safe but wrong.
        with self.assertRaisesRegex(X86SearchRejected, "differ from the closed encoder"):
            inspect_candidate_artifact(bytes(bad), self.candidate)

    def test_loader_offset_and_hidden_extra_executable_bytes_are_rejected(self):
        phoff = int.from_bytes(self.data[32:40], "little")
        phnum = int.from_bytes(self.data[56:58], "little")
        target = next(phoff + 56 * i for i in range(phnum)
                      if struct.unpack_from("<II", self.data, phoff + 56 * i) == (1, 5))
        for field, delta in ((8, 4096), (32, 1)):
            bad = bytearray(self.data)
            value = struct.unpack_from("<Q", bad, target + field)[0]
            struct.pack_into("<Q", bad, target + field, value + delta)
            if field == 32:
                struct.pack_into("<Q", bad, target + 40, value + delta)
            with self.subTest(field=field), self.assertRaises(ValueError):
                inspect_candidate_artifact(bytes(bad), self.candidate)

    def test_nonallocated_shadow_symbol_table_cannot_hide_different_loader_entry(self):
        sections, _, _ = _elf_layout(self.data)
        symbols = next(s for s in sections if s["type"] == 11)
        bad = bytearray(self.data)
        shadow_offset = len(bad)
        # The section inspector sees an innocent appended copy. The loader's
        # DT_SYMTAB still addresses the original mapped table, now set to +1.
        bad.extend(self.data[symbols["offset"]:symbols["offset"] + symbols["size"]])
        shoff = int.from_bytes(self.data[40:48], "little")
        header = shoff + symbols["index"] * 64
        struct.pack_into("<Q", bad, header + 8, 0)  # Remove SHF_ALLOC.
        struct.pack_into("<Q", bad, header + 24, shadow_offset)
        original_value = symbols["offset"] + 24 + 8
        struct.pack_into("<Q", bad, original_value,
                         struct.unpack_from("<Q", bad, original_value)[0] + 1)
        with self.assertRaisesRegex(X86SearchRejected, "authority tables must be allocated"):
            inspect_candidate_artifact(bytes(bad), self.candidate)

    def test_hash_bucket_cannot_make_loader_read_outside_checked_dynamic_symbols(self):
        sections, _, _ = _elf_layout(self.data)
        table = next(s for s in sections if s["type"] == 0x6FFFFFF6)
        bad = bytearray(self.data)
        buckets, _, bloom_size, _ = struct.unpack_from("<IIII", bad, table["offset"])
        bucket_start = table["offset"] + 16 + bloom_size * 8
        occupied = next(bucket_start + 4 * i for i in range(buckets)
                        if struct.unpack_from("<I", bad, bucket_start + 4 * i)[0] == 1)
        struct.pack_into("<I", bad, occupied, 3)
        with self.assertRaisesRegex(X86SearchRejected, "outside the checked symbol inventory"):
            inspect_candidate_artifact(bytes(bad), self.candidate)

    def test_dynamic_initializer_and_other_public_symbol_type_are_rejected(self):
        sections, segments, _ = _elf_layout(self.data)
        dynamic = next(p for p in segments if p["type"] == 2)
        at = next(at for at in range(dynamic["offset"], dynamic["offset"] + dynamic["filesz"], 16)
                  if struct.unpack_from("<Q", self.data, at)[0] == 30)
        bad = bytearray(self.data)
        struct.pack_into("<Q", bad, at, 12)  # DT_INIT is code execution outside the model.
        with self.assertRaisesRegex(X86SearchRejected, "unreviewed or duplicate dynamic"):
            inspect_candidate_artifact(bytes(bad), self.candidate)
        symbols = next(s for s in sections if s["type"] == 11)
        bad = bytearray(self.data)
        bad[symbols["offset"] + 24 + 4] = 0x1A  # STT_GNU_IFUNC, invokes resolver.
        with self.assertRaises(ValueError):
            inspect_candidate_artifact(bytes(bad), self.candidate)

    def test_existing_artifact_is_not_overwritten(self):
        with self.assertRaisesRegex(X86SearchRejected, "new file"):
            build_candidate(affine_program(), self.candidate, self.path, clang=CLANG)
        self.assertEqual(self.path.read_bytes(), self.data)


if __name__ == "__main__":
    unittest.main()
