"""Bind induction and modular proofs to the actual release object and controls."""
from __future__ import annotations

from copy import deepcopy
import ctypes
from hashlib import sha256
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_guarded_optimization import propose_guarded_reduction
from hepta.hia_narrowing import (
    propose_guarded_narrowing, verify_guarded_narrowing,
    build_guarded_narrowed_native,
)
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_program_source import lower_source
from hepta.hia_optimization import OptimizationRejected
from tools.qualify_hia_native_ndu import build, checksum, driver, source_inventory
from tools.qualify_hia_release_parity import specification

ROOT = Path(__file__).resolve().parents[1]
PROFILE = "verified-reduction-narrowed-release-v1"
CLANG = os.environ.get("CLANG", "clang")
RUSTC = os.environ.get("RUSTC", "rustc")


class GuardedNarrowedReleaseProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = lower_source((ROOT / "benchmarks/hia_native_ndu/kernel.hepta").read_text())
        cls.proposal = propose_guarded_narrowing(cls.base, maximum=32, include_induction=True)

    def test_legacy_reduction_default_is_unchanged_and_option_is_exact_bool(self):
        legacy = propose_guarded_narrowing(self.base, maximum=32)
        self.assertEqual(legacy["guarded"], propose_guarded_reduction(self.base, maximum=32))
        self.assertEqual(len(legacy["guarded"]["changes"]), 1)
        self.assertEqual(len(self.proposal["guarded"]["changes"]), 3)
        for invalid in (0, 1, None, "true"):
            with self.subTest(value=invalid), self.assertRaises(OptimizationRejected):
                propose_guarded_narrowing(self.base, maximum=32, include_induction=invalid)

    def test_three_induction_obligations_and_modular_proof_share_actual_intermediate(self):
        report = verify_guarded_narrowing(self.base, self.proposal)
        self.assertEqual(report["status"], "verified", report["reason"])
        guard, narrow = [row["proof"] for row in report["stages"]]
        obligations = [row for row in guard["obligations"] if row["kind"] == "removed_check_cannot_trap"]
        self.assertEqual(len(obligations), 3)
        self.assertTrue(all(row["result"] == "unsat" for row in obligations))
        self.assertEqual(guard["candidate_sha256"], narrow["base_sha256"])
        self.assertEqual(narrow["base_sha256"], report["intermediate_sha256"])
        self.assertEqual(narrow["candidate_sha256"], report["candidate_sha256"])
        self.assertTrue(report["claims"]["independent_stage_proofs_bound"])
        self.assertFalse(report["claims"]["backend_refinement_proved"])
        self.assertFalse(report["claims"]["performance_qualified"])

    def test_both_guard_sides_and_allocator_refusal_preserve_vm_observables(self):
        candidate = verify_program(self.proposal["narrowing"]["candidate_core"])
        for length in (0, 1, 15, 31, 32, 33, 71):
            for seed in (0, 255, 2**32-1):
                for fail_at in (None, 1):
                    with self.subTest(length=length, seed=seed, fail_at=fail_at):
                        before = execute_program(self.base, "calculate", [length, seed], allocation_fail_at=fail_at)
                        after = execute_program(candidate, "calculate", [length, seed], allocation_fail_at=fail_at)
                        self.assertEqual(before["result"], after["result"])
                        self.assertEqual(before["resources"], after["resources"])

    def test_substituting_a_different_intermediate_cannot_reuse_valid_stage_proof(self):
        forged = deepcopy(self.proposal)
        forged["narrowing"]["base_sha256"] = self.base.sha256
        report = verify_guarded_narrowing(self.base, forged)
        self.assertEqual(report["status"], "rejected")
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "never.o"
            with patch("hepta.hia_program_llvm.build_program_native", side_effect=AssertionError("compiled unbound chain")):
                with self.assertRaises((OptimizationRejected, ValueError)):
                    build_guarded_narrowed_native(self.base, forged, output, kind="object")
            self.assertFalse(output.exists())

    def test_new_profile_preserves_frozen_cohorts_costs_and_thresholds(self):
        original = specification("verified-reduction-release-v1")
        new = specification(PROFILE)
        self.assertEqual({key: value for key, value in original.items() if key != "build_profile"},
                         {key: value for key, value in new.items() if key != "build_profile"})
        inventory = source_inventory()
        for path in ("hepta/hia_narrowing.py", "hepta/hia_guarded_optimization.py", "hepta/hia_inductive.py"):
            self.assertEqual(inventory[path], sha256((ROOT / path).read_bytes()).hexdigest())


@unittest.skipUnless(shutil.which(CLANG) and shutil.which(RUSTC), "actual Clang and Rust toolchains required")
class GuardedNarrowedReleaseNativeTests(unittest.TestCase):
    def test_actual_release_builder_checks_both_proofs_object_and_allocator(self):
        with tempfile.TemporaryDirectory() as folder:
            directory, report = Path(folder), {}
            products = build(directory, str(Path(shutil.which(CLANG)).resolve()),
                             str(Path(shutil.which(RUSTC)).resolve()), report,
                             build_profile=PROFILE)
            proof = report["hia_guarded_compilation"]
            self.assertTrue(report["build_profile"]["hia_verified_reduction"])
            self.assertTrue(report["build_profile"]["hia_verified_modular_narrowing"])
            self.assertEqual(proof["verification"]["candidate_sha256"], proof["native"]["core_sha256"])
            self.assertEqual(proof["native"]["artifact_sha256"], sha256((directory / "hia.o").read_bytes()).hexdigest())
            guard, narrow = [stage["proof"] for stage in proof["verification"]["stages"]]
            self.assertEqual(len(guard["changes"]), 3)
            self.assertEqual(guard["candidate_sha256"], narrow["base_sha256"])
            with driver(directory / "driver", directory / "native-regression.jsonl") as child:
                child.load("hia", products)
                for length in (0, 1, 16, 64, 256, 4096, 65536):
                    for seed in (0, 255, 2**32-1):
                        for fail in (0, 1):
                            # The driver checks full allocator/free/refusal
                            # observations against an independent byte formula.
                            row = child.measure("hia", length, seed, 1, 1, fail=fail)
                            self.assertEqual(row["observed"], 1001 if fail and length else checksum(length, seed))
            self.assertTrue(all(stream.closed for stream in (
                child.process.stdin, child.process.stdout, child.process.stderr)))
            with self.assertRaisesRegex(ValueError, "native child failed"):
                with driver(directory / "driver", directory / "terminated-driver.jsonl") as terminated:
                    terminated.process.kill()
                    terminated.process.wait(timeout=5)
            self.assertTrue(all(stream.closed for stream in (
                terminated.process.stdin, terminated.process.stdout, terminated.process.stderr)))
            library = ctypes.CDLL(str(directory / "hia.so"))
            try:
                library.calculate.argtypes = (ctypes.c_size_t, ctypes.c_uint32)
                library.calculate.restype = ctypes.c_uint64
                # Outside the optimization guard, the complete checked
                # fallback still executes. These are correctness-only probes.
                for length in (65537, 70001):
                    for seed in (0, 2**32-1):
                        self.assertEqual(library.calculate(length, seed), checksum(length, seed))
            finally:
                import _ctypes
                _ctypes.dlclose(library._handle)


if __name__ == "__main__":
    unittest.main()
