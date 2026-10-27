"""Native observations keep exact outcomes, failed attempts and paired timing."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import sys
import tempfile
import unittest

from hepta.hia_program import VerifiedProgram, verify_program
from hepta.hia_swap_opt import rewrite_byte_swap
from tools.hia_ndu_measure import DRIVER_SOURCE, _events, _process, measure_pair


ROOT = Path(__file__).resolve().parents[1]
CLANG = os.environ.get("CLANG") or shutil.which("clang-20") or shutil.which("clang")
NATIVE = bool(CLANG and platform.system() == "Linux" and platform.machine() in {"x86_64", "amd64"})


def pair():
    baseline = verify_program((ROOT / "examples/hia_ndu/byte_swap.json").read_bytes())
    return baseline, rewrite_byte_swap(baseline).program


class NativePairAdmissionTests(unittest.TestCase):
    def test_invalid_budgets_and_scalar_inputs_reject_before_native_calls(self):
        baseline, candidate = pair()
        invalid = [{"samples": 14}, {"samples": 16}, {"samples": True}, {"samples": 65},
                   {"iterations": 0}, {"iterations": True}, {"iterations": 1_000_001},
                   {"timeout": 0}, {"timeout": 61}, {"timeout": True}, {"samples": float("nan")}]
        for kwargs in invalid:
            with self.subTest(kwargs=kwargs):
                result = measure_pair(baseline, candidate, "swap_candidate", [[5, 0, 4, 0]], **kwargs)
                self.assertFalse(result["ok"])
                self.assertEqual(result["native"], {})
                self.assertEqual(result["processes"], [])
                json.dumps(result, allow_nan=False)
        for cases in ([], [[5, 0, 4]], [[5, 0, 4, True]], [[5, 0, 4, -1]], [[5, 0, 4, 1 << 64]], [[5,0,4,0]] * 65):
            with self.subTest(cases=cases[:1]):
                result = measure_pair(baseline, candidate, "swap_candidate", cases)
                self.assertFalse(result["ok"])
                self.assertEqual(result["native"], {})
        result = measure_pair(baseline, candidate, "swap_candidate", [[5,0,4,0]] * 64,
                              samples=63, iterations=1_000_000)
        self.assertFalse(result["ok"])
        self.assertEqual(result["native"], {})

    def test_forged_verified_program_and_wrong_entry_do_not_become_native_authority(self):
        baseline, candidate = pair()
        for value, entry in ((VerifiedProgram(b"{}"), "swap_candidate"), (candidate, "missing")):
            result = measure_pair(baseline, value, entry, [[5, 0, 4, 0]])
            self.assertFalse(result["ok"])
            self.assertEqual(result["native"], {})

    def test_changed_output_and_trapping_case_keep_the_failed_observation(self):
        baseline, candidate = pair()
        changed = candidate.as_dict()
        operation = next(op for op in changed["functions"][0]["blocks"][0]["ops"]
                         if op["op"] == "const" and op["out"][0]["name"] == "byte4")
        operation["attrs"]["value"] = 99
        result = measure_pair(baseline, verify_program(changed), "swap_candidate", [[5, 0, 4, 0]])
        self.assertFalse(result["ok"])
        row = result["correctness"]["interpreter_cases"][0]
        self.assertEqual(row["baseline"]["result"], 55)
        self.assertEqual(row["candidate"]["result"], 99)
        self.assertEqual(result["native"], {})
        trapped = measure_pair(baseline, candidate, "swap_candidate", [[5, 0, 5, 0]])
        self.assertFalse(trapped["ok"])
        self.assertEqual(trapped["diagnostics"][0]["code"], "bounds")
        self.assertEqual(trapped["correctness"]["interpreter_cases"][0]["arguments"], [5, 0, 5, 0])


@unittest.skipUnless(NATIVE, "Actual Clang20+ Linux x86-64 is required")
class NativePairExecutionTests(unittest.TestCase):
    def test_actual_native_pair_checks_every_case_and_retains_uncensored_clocks(self):
        baseline, candidate = pair()
        cases = [[5, 0, 4, 0], [5, 0, 4, 4], [5, 2, 2, 2], [5, 1, 3, 1]]
        expected = [55, 11, 33, 44]
        result = measure_pair(baseline, candidate, "swap_candidate", cases,
                              clang=CLANG, samples=15, iterations=1000)
        self.assertTrue(result["ok"], result["diagnostics"])
        self.assertEqual(result["counts"]["calls_per_sample"], 4000)
        self.assertEqual(result["counts"]["timed_calls_total"], 120000)
        self.assertEqual(len(result["correctness"]["native_cases"]), 8)
        for row in result["correctness"]["native_cases"]:
            self.assertEqual(row["actual"], expected[row["case"]])
        self.assertEqual(len(result["raw_samples"]), 15)
        for index, row in enumerate(result["raw_samples"]):
            self.assertEqual(row["pair"], index)
            self.assertEqual(row["order"], ["baseline", "candidate"] if index % 2 == 0 else ["candidate", "baseline"])
            for role in ("baseline", "candidate"):
                self.assertGreater(row[role + "_ns"], 0)
                self.assertGreaterEqual(row[role + "_cpu_ns"], 0)
                self.assertEqual(row[role + "_checksum"], 143000)
        self.assertEqual(result["summary"]["samples_excluded"], 0)
        for role, core in (("baseline", baseline), ("candidate", candidate)):
            values = [row[role + "_ns"] for row in result["raw_samples"]]
            median = statistics.median(values)
            self.assertEqual(result["summary"][role + "_median_ns"], median)
            self.assertEqual(result["summary"][role + "_mad_ns"], statistics.median(abs(value-median) for value in values))
            self.assertEqual(result["native"][role]["core_sha256"], core.sha256)
            self.assertGreater(result["native"][role]["artifact_bytes"], 0)
            self.assertFalse(Path(result["native"][role]["output"]).exists())
            replay = verify_program(result["reproduction"][role]["canonical_core"])
            self.assertEqual(replay.sha256, core.sha256)
        self.assertEqual(result["driver"]["source_sha256"], hashlib.sha256(DRIVER_SOURCE.encode()).hexdigest())
        self.assertGreater(result["costs"]["total_ns"], sum(value for key,value in result["costs"].items() if key != "total_ns"))
        self.assertFalse(any(result["claims"].values()))
        json.dumps(result, allow_nan=False)

    def test_same_total_checksum_cannot_hide_wrong_individual_native_results(self):
        # This deliberately wrong native implementation swaps two results whose
        # sum remains 33. Per-case comparison must reject before timed sampling.
        with tempfile.TemporaryDirectory(prefix="hepta-ndu-negative-") as temp:
            directory = Path(temp)
            source = directory / "wrong.c"
            source.write_text("#include <stddef.h>\n#include <stdint.h>\n"
                "uint8_t probe(size_t a,size_t b,size_t c,size_t d){(void)a;(void)c;(void)d;return b?11:22;}\n")
            driver_source = directory / "driver.c"
            driver_source.write_text(DRIVER_SOURCE)
            report = {"processes": [], "correctness": {"native_cases": []}}
            library, driver = directory / "wrong.so", directory / "driver"
            build = _process(report, "test_fixture", [CLANG, "-shared", "-fPIC", source, "-o", library], directory)
            self.assertEqual(build["returncode"], 0, build)
            build = _process(report, "test_driver", [CLANG, "-std=c11", "-O3", driver_source, "-ldl", "-o", driver], directory)
            self.assertEqual(build["returncode"], 0, build)
            native = _process(report, "native_measurement", [driver, library, library, "probe", "15", "1000"], directory,
                              stdin="2\n5 0 4 0 11\n5 1 4 0 22\n")
            self.assertEqual(native["returncode"], 90)
            _events(report, native)
            self.assertEqual(report["raw_samples"], [])
            self.assertEqual(report["correctness"]["native_cases"][0]["actual"], 22)
            self.assertEqual(report["correctness"]["native_cases"][0]["expected"], 11)
            self.assertEqual(report["raw_events"][-1]["code"], "native_case_mismatch")


class NativePairFailureRetentionTests(unittest.TestCase):
    def test_real_timeout_retains_an_incomplete_pair_and_stderr(self):
        payload = {"kind": "sample", "pair": 0, "position": 0, "backend": "baseline",
                   "elapsed_ns": 123, "process_cpu_ns": 120, "checksum": 7, "expected_checksum": 7}
        child = ("import sys,time; print(" + repr(json.dumps(payload)) + ",flush=True); "
                 "print('bounded failure prefix',file=sys.stderr,flush=True);time.sleep(5)")
        report = {"processes": [], "correctness": {"native_cases": []}}
        with tempfile.TemporaryDirectory() as directory:
            row = _process(report, "native_measurement", [sys.executable, "-u", "-c", child], Path(directory), timeout=1)
        self.assertEqual(row["capture_error"], "E_CAPTURE_TIMEOUT")
        self.assertIn("bounded failure prefix", row["stderr"])
        _events(report, row)
        self.assertEqual(report["raw_events"], [payload])
        self.assertEqual(report["raw_samples"], [{"pair": 0, "order": ["baseline"],
                         "baseline_ns": 123, "baseline_cpu_ns": 120, "baseline_checksum": 7}])


if __name__ == "__main__":
    unittest.main()
