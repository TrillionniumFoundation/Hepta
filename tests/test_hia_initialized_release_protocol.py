"""Prospective registration and synthetic acceptance audits; no timing run."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest

from hepta.hia_narrowing import propose_guarded_narrowing
from hepta.hia_program import verify_program
from hepta.hia_program_source import lower_source
from tools.qualify_hia_release_parity import (
    INITIALIZED_RUST_PGO_PROFILE, INITIALIZED_PROTOCOL, _require_initialized_artifact,
    _validate_release_registration, assess, specification,
)
from tools.hia_rust_pgo import PROFILE as PGO, training_registration


class InitializedReleaseProtocolTests(unittest.TestCase):
    def test_original_v1_v2_registration_bytes_keep_their_preregistered_digests(self):
        expected = {"verified-reduction-narrowed-release-v1": "80156b0bbf9e80def9dad5ec59e7aecdd36673740a20c1dc4465f0ac19b3013e",
                    PGO: "76fdb12545dff614b1cacd015251994832f7e03f01710bed0639d180ee435f6d"}
        for profile, digest in expected.items():
            raw = json.dumps(specification(profile), sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
            self.assertEqual(sha256(raw).hexdigest(), digest)

    def test_new_single_registration_keeps_training_budget_and_strong_controls(self):
        old, new = specification(PGO), specification(INITIALIZED_RUST_PGO_PROFILE)
        self.assertEqual(new, json.loads(INITIALIZED_PROTOCOL.read_text()))
        self.assertEqual(new["schema"], "hepta.hia.release-parity.protocol.v3")
        self.assertEqual(new["holdout_sizes"], [3, 17, 65, 259, 1031, 4099, 16387, 65519])
        self.assertEqual(new["holdout_seeds"], [1597, 2633, 4261])
        for key in ("training_sizes", "training_seeds", "batch_calls", "samples", "warmup_calls",
                    "backends", "performance_gate", "correctness_sizes", "correctness_seeds"):
            self.assertEqual(old[key], new[key])
        self.assertFalse(set(old["holdout_sizes"]) & set(new["holdout_sizes"]))
        self.assertFalse(set(old["holdout_seeds"]) & set(new["holdout_seeds"]))
        self.assertEqual(new["rust_pgo"], training_registration())
        self.assertTrue({"lto=fat", "codegen-units=1", "opt-level=3"} <= set(new["rust_pgo"]["rust_flags"]))
        _validate_release_registration(new)

    def test_frozen_denominators_are_the_actual_complete_cross_product(self):
        spec = specification(INITIALIZED_RUST_PGO_PROFILE)
        requests = len(spec["backends"]) * sum(len(spec[p + "_sizes"]) * len(spec[p + "_seeds"]) for p in ("training", "holdout"))
        cohort = spec["timing_cohort"]
        self.assertEqual((requests, requests * spec["samples"], requests * spec["samples"] * spec["batch_calls"]),
                         (cohort["timing_requests"], cohort["timed_batches"], cohort["timed_kernel_calls"]))
        self.assertEqual((requests, cohort["runs_on_final_frozen_source"]), (132, 1))
        self.assertEqual(len(spec["backends"]) * len(spec["correctness_sizes"]) * (len(spec["correctness_seeds"]) + 1), 192)

    def test_changed_axis_or_weakened_initialization_registration_refuses(self):
        for change in ("axis", "coverage", "timing_count"):
            spec = specification(INITIALIZED_RUST_PGO_PROFILE)
            if change == "axis":
                spec["holdout_sizes"][0] += 1
            elif change == "coverage":
                spec["initialization_coverage"]["require_all_local_allocations_covered"] = False
            else:
                spec["timing_cohort"]["timed_kernel_calls"] = 1
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "E_RELEASE_COHORT"):
                _validate_release_registration(spec)

    def test_single_new_holdout_p99_spike_remains_a_negative(self):
        spec = specification(INITIALIZED_RUST_PGO_PROFILE)
        rows = [{"phase": phase, "backend": backend, "n": n, "seed": seed,
                 "calls": spec["batch_calls"], "samples": spec["samples"], "times_ns": [100] * spec["samples"]}
                for phase in ("training", "holdout") for backend in spec["backends"]
                for n in spec[phase + "_sizes"] for seed in spec[phase + "_seeds"]]
        self.assertTrue(assess(rows, spec)["performance_gate_passed"])
        next(row for row in rows if row["phase"] == "holdout" and row["backend"] == "hia")["times_ns"][-1] = 121
        result = assess(rows, spec)
        self.assertFalse(result["performance_gate_passed"])
        self.assertFalse(result["holdout_gate_passed"])
        self.assertEqual(len(result["comparisons"]), 33)
        self.assertFalse(result["broad_rust_performance_parity_established"])

    def test_actual_core_reverified_before_synthetic_object_inventory_is_accepted(self):
        root = Path(__file__).resolve().parents[1]
        base = lower_source((root / "benchmarks/hia_native_ndu/kernel.hepta").read_text())
        proposal = propose_guarded_narrowing(base, maximum=65536, include_induction=True)
        core = verify_program(proposal["narrowing"]["candidate_core"])
        spec = specification(INITIALIZED_RUST_PGO_PROFILE)
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / "hia.optimized.core.json").write_bytes(core.canonical_bytes)
            # Synthetic report inventory tests only this acceptance boundary.
            # Native malloc execution is independently tested in initialization tests.
            report = {"hia_compilation": {"core_sha256": core.sha256,
                                          "binary_inventory": {"undefined": ["malloc", "free", "abort"]}}}
            _require_initialized_artifact(folder, report, spec)
            self.assertTrue(report["initialization_artifact_qualified"])
            for imports in (["calloc", "malloc", "free"], ["calloc", "free"], ["free"]):
                invalid = deepcopy(report)
                invalid["hia_compilation"]["binary_inventory"]["undefined"] = imports
                with self.subTest(imports=imports), self.assertRaisesRegex(ValueError, "E_RELEASE_INITIALIZATION"):
                    _require_initialized_artifact(folder, invalid, spec)
            invalid = deepcopy(report)
            invalid["hia_compilation"]["core_sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "E_RELEASE_INITIALIZATION"):
                _require_initialized_artifact(folder, invalid, spec)


if __name__ == "__main__":
    unittest.main()
