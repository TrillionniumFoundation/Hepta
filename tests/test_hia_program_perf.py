"""Standalone performance evidence regressions; no timing samples are run."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_program_llvm import HIAProgramLLVM, HIAProgramLLVMRejected
from tools import qualify_hia_program_perf as q


CLANG = os.environ.get("CLANG", "/usr/lib/llvm-20/bin/clang")


class StandalonePerformancePolicyTests(unittest.TestCase):
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
