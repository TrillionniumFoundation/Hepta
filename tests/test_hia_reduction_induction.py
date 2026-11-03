"""The general two-workload pipeline independently proves each counted step."""
from __future__ import annotations

from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

from hepta.hia_optimization import OptimizationRejected
from hepta.hia_program_runtime import execute_program
from hepta.hia_program_source import lower_source
from hepta.hia_reduction import (propose_reduction_pipeline, reduction_program,
                                verify_reduction_pipeline, build_reduction_native)

ROOT = Path(__file__).resolve().parents[1]


class ReductionInductionTests(unittest.TestCase):
    def test_linear_and_affine_each_have_three_independently_proved_changes(self):
        for workload in ("linear", "affine"):
            base = lower_source((ROOT / "benchmarks/hia_reduction_release" /
                                 (workload + ".hepta")).read_text())
            with self.subTest(workload=workload):
                legacy = propose_reduction_pipeline(base, maximum=16)
                proposal = propose_reduction_pipeline(base, maximum=16,
                                                      include_induction=True)
                self.assertEqual(len(legacy["guarded"]["changes"]), 1)
                self.assertEqual(len(proposal["guarded"]["changes"]), 3)
                report = verify_reduction_pipeline(base, proposal)
                self.assertEqual(report["status"], "verified", report)
                guard = report["proofs"]["guarded_reduction"]
                removed = {(row["block"], row["operation"])
                           for row in guard["obligations"]
                           if row["kind"] == "removed_check_cannot_trap"
                           and row["result"] == "unsat"}
                declared = {(row["block"], row["operation"])
                            for row in proposal["guarded"]["changes"]}
                self.assertEqual(removed, declared)
                self.assertEqual(report["input_assumptions"], [])
                self.assertFalse(report["claims"]["backend_refinement_proved"])

    def test_both_load_shapes_preserve_guard_sides_and_allocation_refusal(self):
        for workload in ("linear", "affine"):
            base = lower_source((ROOT / "benchmarks/hia_reduction_release" /
                                 (workload + ".hepta")).read_text())
            proposal = propose_reduction_pipeline(base, maximum=16,
                                                  include_induction=True)
            candidate = reduction_program(base, proposal)
            for length in (0, 1, 15, 16, 17, 41):
                for seed in (0, 255, 2**32 - 1):
                    for fail_at in (None, 1):
                        with self.subTest(workload=workload, n=length,
                                          seed=seed, fail_at=fail_at):
                            before = execute_program(base, "calculate", [length, seed],
                                                     allocation_fail_at=fail_at)
                            after = execute_program(candidate, "calculate", [length, seed],
                                                    allocation_fail_at=fail_at)
                            oracle = sum(((i + seed) if workload == "linear"
                                          else (i * seed + 17)) % 256
                                         for i in range(length))
                            self.assertEqual(after["result"],
                                             1001 if fail_at and length else oracle)
                            self.assertEqual(before["result"], after["result"])
                            self.assertEqual(before["resources"], after["resources"])

    def test_induction_option_is_explicit_and_cannot_change_entry_facts(self):
        source = (ROOT / "benchmarks/hia_reduction_release/affine.hepta").read_text()
        base = lower_source(source)
        for invalid in (0, 1, None, "true"):
            with self.subTest(value=invalid), self.assertRaises(OptimizationRejected):
                propose_reduction_pipeline(base, include_induction=invalid)
        wrong_initial = lower_source(source.replace("let mut total:u64=0;",
                                                    "let mut total:u64=1;"))
        report = verify_reduction_pipeline(
            wrong_initial,
            propose_reduction_pipeline(wrong_initial, include_induction=True))
        self.assertEqual(report["status"], "rejected", report)


CLANG = os.environ.get("HEPTA_TEST_CLANG", os.environ.get("CLANG", "clang"))


@unittest.skipUnless(shutil.which(CLANG), "actual Clang 20+ required")
class ReductionInductionNativeTests(unittest.TestCase):
    def test_native_two_workloads_guard_sides_and_allocator_trace(self):
        from tools.qualify_hia_reduction_release import child_driver
        metrics = ROOT / "benchmarks/hia_native_ndu"
        fixtures = ROOT / "benchmarks/hia_reduction_release"
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            for source, output, flags in (
                    (metrics / "metrics.c", directory / "metrics.o", ["-c", "-fPIC"]),
                    (metrics / "probe_exports.c", directory / "probe_exports.o", ["-c", "-fPIC"]),
                    (fixtures / "driver.c", directory / "driver", ["-ldl"])):
                result = subprocess.run([CLANG, "-O3", "-I", str(metrics), str(source), *flags, "-o", str(output)],
                                        capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stderr)
            wraps = ["-Wl,--wrap=" + name for name in ("malloc", "calloc", "realloc", "free")]
            for workload in ("linear", "affine"):
                base = lower_source((fixtures / (workload + ".hepta")).read_text())
                proposal = propose_reduction_pipeline(base, maximum=16, include_induction=True)
                obj, library = directory / (workload + ".o"), directory / (workload + ".so")
                receipt = build_reduction_native(base, proposal, obj, clang=CLANG, kind="object")
                self.assertTrue(receipt["claims"]["final_artifact_bound"])
                result = subprocess.run([CLANG, "-shared", str(obj), str(directory / "metrics.o"),
                    str(directory / "probe_exports.o"), *wraps, "-o", str(library)],
                    capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stderr)
                with child_driver(directory / "driver", directory / (workload + ".jsonl")) as child:
                    child.load("hia_reduction", {"hia_reduction": {"path": str(library)}})
                    for n in (0, 1, 15, 16, 17, 41, 257):
                        for seed in (0, 255, 2**32 - 1):
                            for fail in (0, 1):
                                # The driver independently checks checksum, exact
                                # allocation/refusal/free sequence and live bytes.
                                child.measure(workload, "hia_reduction", n, seed, 1, 1, fail=fail)


if __name__ == "__main__":
    unittest.main()
