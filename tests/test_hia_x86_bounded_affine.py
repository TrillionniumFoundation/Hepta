"""Wider affine targets reuse the original exhaustive grammar and native gate."""
from __future__ import annotations

import copy
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_program import verify_program
from hepta.hia_program_llvm import build_program_native
from hepta.hia_translation_validation import validate_translation
from hepta.hia_x86_search import (
    BOUNDED_AFFINE_PROFILE, BOUNDED_AFFINE_SCHEMA, GRAMMAR, PROFILE, SCHEMA,
    X86SearchRejected, affine_program, bounded_affine_program, build_candidate,
    enumerate_candidates, exported_code, inspect_candidate_artifact,
    search_affine_candidates, search_bounded_affine_candidates,
)
from tools.qualify_hia_ndu_search import expected_checksum as legacy_checksum
from tools.qualify_hia_x86_bounded_affine import (
    CASES, PROTOCOL, _native_case, edge_sample, expected_checksum, freeze_selections,
)
from tools.qualify_hia_x86_search import PROTOCOL as LEGACY_PROTOCOL

HAS_Z3 = importlib.util.find_spec("z3") is not None
CLANG = os.environ.get("HEPTA_CLANG", "clang-20")
HAS_NATIVE = HAS_Z3 and shutil.which(CLANG) is not None


def digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def multiply_add(multiplier, offset):
    return next(c for c in enumerate_candidates() if c["recipe"] == [
        {"op": "imul", "imm": multiplier}, {"op": "add", "imm": offset}])


class TargetDomainTests(unittest.TestCase):
    def test_target_bounds_and_exact_integer_types(self):
        for multiplier in (-2, 5, True, 2.0, "2"):
            with self.subTest(multiplier=multiplier), self.assertRaises(X86SearchRejected):
                bounded_affine_program(multiplier, 12)
        for offset in (-17, 17, True, 12.0, "12"):
            with self.subTest(offset=offset), self.assertRaises(X86SearchRejected):
                bounded_affine_program(2, offset)
        for a in (-1, 0, 1, 2, 3, 4):
            for b in (-16, 0, 16):
                verify_program(bounded_affine_program(a, b))

    def test_negative_coefficients_use_explicit_u64_wrapping_literals(self):
        program = verify_program(bounded_affine_program(-1, -12)).as_dict()
        operations = program["functions"][0]["blocks"][0]["ops"]
        self.assertEqual(operations[0]["attrs"]["value"], (1 << 64) - 1)
        self.assertEqual(operations[2]["attrs"]["value"], (1 << 64) - 12)
        self.assertEqual([op["op"] for op in operations],
                         ["const", "int.mul.wrap", "const", "int.add.wrap"])

    def test_legacy_grammar_corpus_and_frozen_protocol_are_unchanged(self):
        # Hashes captured at the pre-extension b504e18 source snapshot.
        self.assertEqual(digest(GRAMMAR),
                         "800d76ce8dea791dac8be7088fc54b27f55185f589c98b4cb0a0b72b534deb30")
        self.assertEqual(digest(enumerate_candidates()),
                         "a284e5fad214d2e1ad2a9575d50e90c4972243c06f3c177f16ce17ca9fcb5014")
        self.assertEqual(digest(LEGACY_PROTOCOL),
                         "a718fbc700d78fe84c2ddabf1ff0f94908c937ccf35fbc10d81bca3ab36614df")
        self.assertNotEqual(PROTOCOL["schema"], LEGACY_PROTOCOL["schema"])

    def test_checksum_agrees_with_constant_and_legacy_formula_oracles(self):
        mask = (1 << 64) - 1
        for n in (0, 1, 17):
            for a, b in CASES:
                with self.subTest(n=n, a=a, b=b):
                    reference = (a * legacy_checksum(n, 23) + n * (b - 12 * a)) & mask
                    self.assertEqual(expected_checksum(n, 23, a, b), reference)
                    if a == 0:
                        self.assertEqual(reference, n * b & mask)

    def test_invalid_timeout_is_rejected_before_any_solver(self):
        for timeout in (0, 60001, True, 1.0):
            with self.subTest(timeout=timeout), patch("hepta.hia_x86_search.validate_translation") as solver:
                with self.assertRaises(X86SearchRejected):
                    search_bounded_affine_candidates(2, 12, timeout_ms=timeout)
                solver.assert_not_called()


@unittest.skipUnless(HAS_Z3, "optional z3-solver is not installed")
class BoundedAffineProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.searches = {(a, b): search_bounded_affine_candidates(a, b) for a, b in CASES}
        cls.empty = search_bounded_affine_candidates(2, 1)

    def test_all_ten_targets_have_146_decided_proofs_and_a_nine_byte_minimum(self):
        for (a, b), result in self.searches.items():
            with self.subTest(a=a, b=b):
                self.assertEqual(result["schema"], BOUNDED_AFFINE_SCHEMA)
                self.assertEqual(result["target_profile"], BOUNDED_AFFINE_PROFILE)
                self.assertEqual(result["profile"], PROFILE)
                self.assertEqual(result["multiplier"], a)
                self.assertEqual(result["offset"], b)
                self.assertEqual(result["candidate_count"], 146)
                self.assertEqual(result["decided_count"], 146)
                self.assertEqual(result["accepted_count"], 1)
                self.assertTrue(result["finite_minimum_encoded_bytes_proved"])
                self.assertEqual(result["minimum_encoded_bytes"], 9)
                self.assertEqual(result["selected_candidate"], multiply_add(a, b))
                wrong = [r for r in result["candidates"] if r["proof"]["status"] == "disproved"]
                self.assertEqual(len(wrong), 145)
                self.assertTrue(all(r["proof"]["counterexample"] is not None for r in wrong))
                for claim in ("native_backend_refinement_proved", "serialized_receipt_authorizes_execution",
                              "runtime_optimality_established", "global_optimality_established"):
                    self.assertFalse(result["claims"][claim])

    def test_legacy_api_keeps_original_schema_fields_and_minimum(self):
        legacy = search_affine_candidates()
        extended = search_bounded_affine_candidates(1, 12)
        self.assertEqual(legacy["schema"], SCHEMA)
        self.assertNotIn("multiplier", legacy)
        self.assertNotIn("target_profile", legacy)
        self.assertEqual(set(extended) - set(legacy), {"multiplier", "target_profile"})
        self.assertEqual(legacy["baseline"], verify_program(affine_program()).as_dict())
        self.assertEqual(legacy["candidate_count"], 146)
        self.assertEqual(legacy["decided_count"], 146)
        self.assertEqual(legacy["accepted_count"], 7)
        self.assertEqual(legacy["minimum_encoded_bytes"], 5)
        self.assertEqual(extended["selected_candidate"], legacy["selected_candidate"])
        self.assertEqual(extended["claims"], legacy["claims"])

    def test_unrepresented_affine_target_has_no_minimum_certificate(self):
        self.assertEqual(self.empty["candidate_count"], 146)
        self.assertEqual(self.empty["decided_count"], 146)
        self.assertEqual(self.empty["accepted_count"], 0)
        self.assertIsNone(self.empty["selected_candidate"])
        self.assertIsNone(self.empty["minimum_encoded_bytes"])
        self.assertFalse(self.empty["finite_minimum_encoded_bytes_proved"])

    def test_one_unknown_keeps_all_outcomes_but_denies_certificate_and_qualification(self):
        calls = 0
        def one_unknown(*args, **kwargs):
            nonlocal calls
            receipt = validate_translation(*args, **kwargs)
            calls += 1
            if calls == 1:
                receipt["status"] = "unknown"
                receipt["reason"] = "test_injected_solver_timeout"
            return receipt
        with patch("hepta.hia_x86_search.validate_translation", side_effect=one_unknown):
            result = search_bounded_affine_candidates(2, -12)
        self.assertEqual(calls, 146)
        self.assertEqual(result["decided_count"], 145)
        self.assertIsNotNone(result["selected_candidate"])
        self.assertIsNone(result["minimum_encoded_bytes"])
        self.assertFalse(result["finite_minimum_encoded_bytes_proved"])
        self._assert_refused_before_native(result, 2, -12)

    def _assert_refused_before_native(self, result, a, b):
        protocol = copy.deepcopy(PROTOCOL)
        protocol["targets"] = [{"multiplier": a, "offset": b}]
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            with patch("tools.qualify_hia_x86_bounded_affine.search_bounded_affine_candidates", return_value=result), \
                    patch("tools.qualify_hia_x86_bounded_affine.build_candidate") as build, \
                    patch("tools.qualify_hia_x86_bounded_affine.build_program_native") as llvm:
                with self.assertRaisesRegex(RuntimeError, "cannot authorize native"):
                    freeze_selections(folder, protocol)
                build.assert_not_called()
                llvm.assert_not_called()
            receipt = json.loads((folder / "SELECTIONS.json").read_bytes())
            self.assertFalse(receipt["selections"][0]["complete"])
            self.assertEqual(receipt["native_observations_consumed"], 0)
            self.assertEqual(json.loads((folder / "case-00/complete-search.json").read_bytes()), result)

    def test_empty_search_is_retained_and_denies_native_qualification(self):
        self._assert_refused_before_native(self.empty, 2, 1)

    def test_every_target_selection_is_frozen_without_native_observations(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            with patch("tools.qualify_hia_x86_bounded_affine.search_bounded_affine_candidates",
                       side_effect=lambda a, b, **_: self.searches[a, b]), \
                    patch("tools.qualify_hia_x86_bounded_affine.native_sample") as measure:
                records, receipt_hash = freeze_selections(folder, PROTOCOL)
                measure.assert_not_called()
            self.assertEqual(len(records), 10)
            self.assertEqual(receipt_hash, sha256((folder / "SELECTIONS.json").read_bytes()).hexdigest())
            receipt = json.loads((folder / "SELECTIONS.json").read_bytes())
            self.assertEqual(receipt["native_observations_consumed"], 0)
            self.assertTrue(all(row["complete"] for row in receipt["selections"]))
            for row in receipt["selections"]:
                raw = (folder / f"case-{row['case']:02d}/complete-search.json").read_bytes()
                self.assertEqual(sha256(raw).hexdigest(), row["search_sha256"])
            self.assertFalse(list(folder.rglob("*.so")))

    def test_affine_candidate_for_different_target_fails_fresh_proof_before_compiler(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "never.so"
            with patch("hepta.hia_x86_search.run_bounded") as compiler:
                with self.assertRaisesRegex(X86SearchRejected, "not freshly proved"):
                    build_candidate(bounded_affine_program(3, 12), multiply_add(2, 12), output,
                                    clang="not-a-compiler")
                compiler.assert_not_called()
            self.assertFalse(output.exists())


@unittest.skipUnless(HAS_NATIVE, "requires actual Clang20+ and z3-solver")
class BoundedAffineNativeTests(unittest.TestCase):
    def test_all_ten_targets_build_through_existing_byte_gate_and_run_native_edges(self):
        with tempfile.TemporaryDirectory(prefix="hia-bounded-affine-") as temporary:
            for index, (a, b) in enumerate(CASES):
                with self.subTest(a=a, b=b):
                    path = Path(temporary) / f"case-{index}.so"
                    candidate = multiply_add(a, b)
                    receipt = build_candidate(bounded_affine_program(a, b), candidate, path, clang=CLANG)
                    inspection = inspect_candidate_artifact(path.read_bytes(), candidate)
                    self.assertEqual(inspection["code_hex"], candidate["expected_code_hex"])
                    self.assertEqual(inspection["encoded_bytes"], 9)
                    self.assertTrue(inspection["imports_relocations_initializers_absent"])
                    result = edge_sample(path, receipt["artifact_sha256"], PROTOCOL["edge_inputs"], a, b)
                    self.assertEqual(result["status"], "observed", result)

    def test_actual_llvm_can_use_shorter_code_outside_the_frozen_grammar(self):
        with tempfile.TemporaryDirectory(prefix="hia-affine-llvm-") as temporary:
            path = Path(temporary) / "llvm.so"
            receipt = build_program_native(bounded_affine_program(0, 12), path, clang=CLANG)
            actual = exported_code(path.read_bytes())
            self.assertLess(actual["encoded_bytes"], 9)
            self.assertNotIn(actual["code_hex"], {c["expected_code_hex"] for c in enumerate_candidates()})
            result = edge_sample(path, receipt["artifact_sha256"], PROTOCOL["edge_inputs"], 0, 12)
            self.assertEqual(result["status"], "observed", result)

    def test_failed_timing_is_retained_without_retry_or_positive_case_result(self):
        search = search_bounded_affine_candidates(0, 12)
        with tempfile.TemporaryDirectory(prefix="hia-affine-failure-") as temporary:
            folder = Path(temporary)
            record = {"case": 0, "multiplier": 0, "offset": 12, "search": search, "folder": str(folder)}
            # Use real compiler, fresh proof and native edges. Only the timing
            # child is fault-injected; its failed evidence must remain visible.
            with patch("tools.qualify_hia_x86_bounded_affine.native_sample",
                       return_value={"status": "failed", "error": "injected_child_failure"}) as measure:
                result = _native_case(record, PROTOCOL, CLANG, folder / "unused-driver", "unused-hash")
            self.assertFalse(result["ok"])
            self.assertEqual(measure.call_count, 14)
            self.assertEqual(len(result["samples"]), 14)
            self.assertTrue(all(row["status"] == "failed" for row in result["samples"]))
            self.assertIn("failed samples cannot be trimmed", result["error"])
            self.assertEqual(json.loads((folder / "NATIVE.json").read_bytes()), result)


if __name__ == "__main__":
    unittest.main()
