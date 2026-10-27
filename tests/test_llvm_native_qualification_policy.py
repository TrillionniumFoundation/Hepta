"""Frozen performance gate controls, without collecting any native timings."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from hepta.pipeline import compiler_hash
from tools import qualify_llvm_native as qualifier
from tools import performance_observation as observation
from tools.qualify_llvm_native import KERNELS, PROTOCOL, evaluate_samples, validate_report


def samples(ratio=1.0):
    return [{"kernel": kernel, "group": group, "backend": backend,
             "elapsed_ns": 100_000_000 if backend == "rust" else int(100_000_000 * ratio),
             "checksum": 12345}
            for kernel in KERNELS for group in range(PROTOCOL["paired_groups"])
            for backend in ("rust", "llvm")]


class LLVMNativeQualificationPolicyTests(unittest.TestCase):
    def test_diagnostics_leave_frozen_workload_and_protocol_bytes_unchanged(self):
        receipt = qualifier.ROOT / "evidence/P6_LLVM_NATIVE_V2_FIRST_RUN_20261025.json"
        frozen = json.loads(receipt.read_text())
        self.assertEqual(qualifier.PROTOCOL, frozen["protocol"])
        self.assertEqual(qualifier.sha(qualifier.wire(qualifier.PROTOCOL).encode()), frozen["protocol_sha256"])
        self.assertEqual(qualifier.sha(qualifier.SOURCE.encode()), frozen["source_sha256"])
        self.assertEqual(qualifier.sha(qualifier.DRIVER.encode()), frozen["driver_source_sha256"])

    def test_comparable_correct_stable_samples_pass(self):
        result = evaluate_samples(samples(1.0))
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "passed")

    def test_observed_regression_is_retained_and_fails_frozen_threshold(self):
        result = evaluate_samples(samples(1.25))
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "performance_failed")
        self.assertGreaterEqual(len(result["performance_threshold_failures"]), 4)
        self.assertEqual(result["summary"]["signed_walk"]["paired_time_ratios"], [1.25] * 7)

    def test_fast_but_too_short_measurements_do_not_qualify(self):
        data = samples()
        for row in data:
            row["elapsed_ns"] = 1_000_000
        result = evaluate_samples(data)
        self.assertEqual(result["status"], "measurement_inconclusive")
        self.assertFalse(result["ok"])

    def test_noisy_samples_are_retained_and_marked_inconclusive(self):
        data = samples()
        times = [60_000_000, 70_000_000, 80_000_000, 100_000_000,
                 120_000_000, 130_000_000, 140_000_000]
        for row in data:
            row["elapsed_ns"] = times[row["group"]]
        result = evaluate_samples(data)
        self.assertEqual(result["status"], "measurement_inconclusive")
        self.assertEqual(len(result["measurement_quality_failures"]), 6)
        self.assertEqual(result["summary"]["unsigned_walk"]["implementations"]["llvm"]["samples_ns"], times)

    def test_missing_duplicate_malformed_and_mismatching_samples_fail_closed(self):
        data = samples()
        wrong_checksum = deepcopy(data)
        wrong_checksum[-1]["checksum"] += 1
        nan_time = deepcopy(data)
        nan_time[0]["elapsed_ns"] = float("nan")
        for bad in (data[:-1], data + [data[0]], wrong_checksum, nan_time):
            with self.subTest(length=len(bad)):
                with self.assertRaises(ValueError):
                    evaluate_samples(bad)


class LLVMNativeReportValidationTests(unittest.TestCase):
    """Synthetic validator fixtures are never execution or performance evidence."""

    @classmethod
    def setUpClass(cls):
        receipt = Path(__file__).resolve().parents[1] / "evidence/P6_LLVM_NATIVE_V2_FIRST_RUN_20261025.json"
        cls.observed_inconclusive = json.loads(receipt.read_text())
        # Reuse retained build structure, then replace *all* elapsed values
        # with explicitly synthetic stable samples. This exercises acceptance
        # without running a compiler, executing native code or collecting time.
        cls.synthetic = deepcopy(cls.observed_inconclusive)
        cls.synthetic["qualifier_sha256"] = qualifier.digest(qualifier.__file__)
        cls.synthetic["process_observer_sha256"] = observation.source_sha256()
        cls.synthetic["compiler_tree_sha256"] = compiler_hash()
        cls.synthetic["reference_validation"]["compiler_sha256"] = compiler_hash()
        cls.synthetic["ok"], cls.synthetic["status"] = True, "passed"
        cls.synthetic["claims"]["host_scalar32_performance_gate_passed"] = True
        for row in cls.synthetic["raw_samples"]:
            row["elapsed_ns"] = 100_000_000
        # Explicit synthetic diagnostic fixtures, never historical observations.
        # No attempt is made to invent missing telemetry for the old run.
        cls.synthetic["process_observations"] = []
        directory = Path(cls.synthetic["reference_validation"]["path"]).parent
        for row in cls.synthetic["raw_samples"]:
            index = row["sample_index"]
            child = {"status": "observed", "counters": dict.fromkeys(observation.RUSAGE_FIELDS, 0), "error": None}
            linux = {}
            for name, path in observation.LINUX_FILES.items():
                absent = {"path": path, "status": "unavailable", "raw": None, "raw_sha256": None,
                          "counters": None, "error": {"type": "SyntheticFixtureUnavailable", "errno": None}}
                linux[name] = {"before": deepcopy(absent), "after": deepcopy(absent),
                               "status": "unavailable", "delta": None, "decreased_counters": []}
            cls.synthetic["process_observations"].append({"schema": observation.SCHEMA,
                "scope": dict(observation.SCOPE), "sample": {key: row[key] for key in ("sample_index", "group", "kernel", "backend")},
                "command": [str(directory / "driver"), str(directory / (row["backend"] + ".so")), row["kernel"],
                            str(PROTOCOL["kernel_iterations"]), str(PROTOCOL["native_calls_per_sample"]),
                            str(PROTOCOL["warmup_calls_per_process"])],
                "state": "complete", "capture_exception": None,
                "clock": {"start_monotonic_ns": index * 200_000_000,
                          "end_monotonic_ns": index * 200_000_000 + 100_000_000, "wall_ns": 100_000_000},
                "children": {"before": deepcopy(child), "after": deepcopy(child), "status": "observed",
                             "delta": dict.fromkeys(observation.RUSAGE_FIELDS, 0), "decreased_counters": []},
                "linux": linux})
        cls.synthetic["evaluation"] = evaluate_samples(cls.synthetic["raw_samples"])

    def test_complete_synthetic_data_passes_and_can_bind_candidate_commit(self):
        with patch.object(qualifier, "run", side_effect=AssertionError("native command forbidden")), \
             patch.object(qualifier, "compile_rust", side_effect=AssertionError("native build forbidden")), \
             patch.object(qualifier.ctypes, "CDLL", side_effect=AssertionError("native loading forbidden")):
            validate_report(deepcopy(self.synthetic), expected_git_commit=self.synthetic["git_commit"])
        with self.assertRaisesRegex(ValueError, "candidate commit"):
            validate_report(deepcopy(self.synthetic), expected_git_commit="0" * 40)

    def test_outer_success_cannot_override_archived_inconclusive_samples(self):
        data = deepcopy(self.synthetic)
        data["raw_samples"] = deepcopy(self.observed_inconclusive["raw_samples"])
        data["evaluation"] = evaluate_samples(data["raw_samples"])
        self.assertEqual(data["evaluation"]["status"], "measurement_inconclusive")
        with self.assertRaisesRegex(ValueError, "measurement-quality"):
            validate_report(data)
        data["evaluation"] = deepcopy(self.synthetic["evaluation"])
        with self.assertRaisesRegex(ValueError, "evaluation was altered"):
            validate_report(data)

    def test_identity_build_and_scope_tampering_reject(self):
        def changed(path, value):
            data = deepcopy(self.synthetic)
            parent = data
            for part in path[:-1]:
                parent = parent[part]
            parent[path[-1]] = value
            return data

        mutations = [
            (["protocol", "maximum_relative_mad"], 0.5),
            (["protocol_sha256"], "0" * 64),
            (["source_sha256"], "0" * 64),
            (["driver_source_sha256"], "0" * 64),
            (["qualifier_sha256"], "0" * 64),
            (["process_observer_sha256"], "0" * 64),
            (["compiler_tree_sha256"], "0" * 64),
            (["generated_rust_sha256"], "0" * 64),
            (["llvm_ir_sha256"], "0" * 64),
            (["native_receipts", "rust_library", "check_only"], True),
            (["native_receipts", "rust_library", "flags"], ["opt-level=3", "overflow-checks=no"]),
            (["native_receipts", "rust_object", "artifact_sha256"], "0" * 64),
            (["native_receipts", "llvm_library", "claims", "ssa_cfg_origin_rechecked"], False),
            (["native_receipts", "llvm_object", "ssa_sha256"], "0" * 64),
            (["artifacts", "llvm_library", "sha256"], "0" * 64),
            (["claims", "whole_language_performance_qualified"], True),
            (["claims", "host_scalar32_performance_gate_passed"], 1),
            (["reference_validation", "checks", "rust_borrows_types"], "not_run"),
            (["environment", "selected_cpu"], True),
            (["compile_wall_seconds", "rust_object"], float("nan")),
        ]
        for path, value in mutations:
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    validate_report(changed(path, value))

    def test_missing_or_modified_oracle_and_raw_samples_reject(self):
        for mutation in (
            lambda r: r["correctness"]["cases"].pop(),
            lambda r: r["correctness"].update(case_count=185, native_calls=370),
            lambda r: r["correctness"]["cases"][0].update(expected=1),
            lambda r: r["raw_samples"].pop(),
            lambda r: r["raw_samples"].reverse(),
            lambda r: r["raw_samples"][0].update(group=False),
            lambda r: r["raw_samples"][0].update(elapsed_ns=True),
            lambda r: r["raw_samples"][0].update(checksum=True),
            lambda r: r["raw_samples"][0].update(clock_resolution_ns=0),
            lambda r: r["raw_samples"][0].update(sample_index=1),
            lambda r: r["process_observations"].pop(),
            lambda r: r["process_observations"].reverse(),
            lambda r: r["process_observations"][0]["scope"].update(native_elapsed_replaced=True),
            lambda r: r["process_observations"][0]["children"]["delta"].update(user_cpu_ns=-1),
        ):
            data = deepcopy(self.synthetic)
            mutation(data)
            with self.assertRaises(ValueError):
                validate_report(data)

    def test_recomputed_performance_failure_still_rejects(self):
        data = deepcopy(self.synthetic)
        for row in data["raw_samples"]:
            if row["backend"] == "llvm":
                row["elapsed_ns"] = 125_000_000
        data["evaluation"] = evaluate_samples(data["raw_samples"])
        self.assertEqual(data["evaluation"]["status"], "performance_failed")
        with self.assertRaisesRegex(ValueError, "raw native samples fail"):
            validate_report(data)


if __name__ == "__main__":
    unittest.main()
