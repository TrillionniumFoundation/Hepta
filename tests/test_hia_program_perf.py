"""Standalone performance evidence regressions; no timing samples are run."""
from __future__ import annotations

import os
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_program_llvm import HIAProgramLLVM, HIAProgramLLVMRejected
from tools import qualify_hia_program_perf as q


CLANG = os.environ.get("CLANG", "/usr/lib/llvm-20/bin/clang")


class StandalonePerformancePolicyTests(unittest.TestCase):
    def test_interference_observations_never_censor_or_repair_noisy_samples(self):
        samples = [{"elapsed_ns": 1000, "process_cpu_ns": cpu, "voluntary_context_switches": 0,
                    "involuntary_context_switches": switches, "minor_page_faults": 1,
                    "major_page_faults": 0} for cpu, switches in ((250, 50), (1001, 0))]
        result = q.interference_summary(samples)
        self.assertEqual(result["sample_count"], 2)
        self.assertEqual(result["cpu_to_wall_ratio"], {"minimum": 0.25, "median": 0.6255, "maximum": 1.001})
        self.assertEqual(result["totals"]["involuntary_context_switches"], 50)
        self.assertEqual(result["samples_excluded"], 0)
        self.assertFalse(result["acceptance_thresholds_adjusted"])
        for field in ("process_cpu_ns", "involuntary_context_switches"):
            changed = [{**samples[0], field: True}]
            with self.assertRaises(ValueError):
                q.interference_summary(changed)

    def test_requested_artifacts_are_exactly_retained_after_a_failed_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "attempt"
            report = {}
            payload = b"not a rebuilt substitute\x00native bytes"
            with self.assertRaisesRegex(RuntimeError, "actual attempted failure"):
                with q.artifact_workspace(destination, report) as workspace:
                    (workspace / "measured.so").write_bytes(payload)
                    raise RuntimeError("actual attempted failure")
            self.assertEqual((destination / "measured.so").read_bytes(), payload)
            manifest_bytes = (destination / "artifact-retention.json").read_bytes()
            manifest = json.loads(manifest_bytes)
            self.assertEqual(manifest["files"], {"measured.so": {"bytes": len(payload), "sha256": q.sha(payload)}})
            self.assertEqual(report["artifact_retention"]["manifest_sha256"], q.sha(manifest_bytes))
            self.assertEqual(report["artifact_retention"]["files"], manifest["files"])

    def test_retention_rejects_existing_directory_without_replacing_files(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)
            sentinel = destination / "unchanged"
            sentinel.write_text("existing evidence")
            report = {}
            with self.assertRaisesRegex(ValueError, "must be new"):
                with q.artifact_workspace(destination, report):
                    self.fail("existing directory admitted")
            self.assertEqual(sentinel.read_text(), "existing evidence")
            self.assertNotIn("artifact_retention", report)
            self.assertFalse((destination / "artifact-retention.json").exists())

    def test_frozen_workload_and_thresholds_are_unchanged_and_c_is_not_claimed(self):
        self.assertEqual(len(q.sample_order()), 63)
        for key in ("paired_groups", "native_calls_per_sample", "warmup_calls_per_process",
                    "kernel_buffer_sizes", "minimum_sample_seconds", "maximum_sample_seconds",
                    "maximum_relative_mad", "maximum_geometric_mean_paired_time_ratio",
                    "maximum_kernel_paired_time_ratio", "ordering", "outlier_policy"):
            self.assertEqual(q.PROTOCOL[key], q.ORIGINAL_PROTOCOL[key])
        self.assertEqual(q.PROTOCOL["c_backend_scope"],
                         "no C correctness or performance backend is executed by this qualification")

    def test_unrelated_compiler_failure_is_not_a_successful_origin_control(self):
        ir = HIAProgramLLVM("  call void @free(ptr %data) nobuiltin\n", "0" * 64, "0" * 64, "0" * 64, ("two_alloc",))
        observation = {}
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(q, "compile_program_llvm", side_effect=[{"ok": True},
                    HIAProgramLLVMRejected("E_HIA_PROGRAM_STALE: implementation changed")]):
                with patch.object(q, "execute", side_effect=AssertionError("native mutant must not run")):
                    with self.assertRaisesRegex(ValueError, "unrelated"):
                        q.observe(ir, None, Path(directory), CLANG, observation=observation)
        self.assertEqual(observation["status"], "running")
        self.assertNotIn("rehashed_llvm_rejected", observation)


@unittest.skipUnless(shutil.which(CLANG), "actual Clang required")
class StandalonePerformanceFailureCaptureTests(unittest.TestCase):
    def test_actual_native_abort_is_captured_without_terminating_qualification(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            source, library = folder / "abort.c", folder / "abort.so"
            source.write_text("#include <stdint.h>\n#include <stddef.h>\n#include <stdlib.h>\n"
                              "uint64_t full_lifecycle(size_t n,uint32_t seed){(void)n;(void)seed;abort();}\n")
            q.successful(q.execute([CLANG, "-shared", "-fPIC", str(source), "-o", str(library)]))
            observation = {}
            with self.assertRaises(q.NativeCommandFailed) as rejected:
                q.check_correctness({name: library for name in q.BACKENDS}, observation=observation)
            self.assertEqual(rejected.exception.record["returncode"], -6)
            self.assertEqual(observation["process"], rejected.exception.record)
            self.assertEqual(observation["status"], "running")
            self.assertEqual(observation["observations"], [])


if __name__ == "__main__":
    unittest.main()
