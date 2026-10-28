"""Benchmark admission/failure controls; synthetic metrics are never evidence."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import qualify_hia_narrowing_bench as bench


def synthetic_rows(profile):
    rows = []
    bulk = {k: bench.timed_checksum(k, protocol=profile) for k in profile["kernels"]}
    tails = {k: bench.tail_checksum(k, "holdout", profile) for k in profile["kernels"]}
    for index, (group, kernel, backend) in enumerate(bench.sample_order(profile, bench.BACKENDS)):
        rows.append({"sample_index": index, "group": group, "kernel": kernel, "backend": backend,
            "status": "measured", "elapsed_ns": 32_000_000, "process_cpu_ns": 31_900_000,
            "outer_wall_ns": 40_000_000, "process_peak_rss_kib": 2000,
            "batch_ns": [1_000_000] * profile["batches"], "mapping_verified": True,
            "checksum": bulk[kernel], "tail_checksum": tails[kernel],
            "request_ns": [1000] * profile["request_tail_probes"],
            "clock_ns": [20] * profile["clock_overhead_probes"]})
    return rows


class BenchmarkGateTests(unittest.TestCase):
    def test_tail_regression_fails_when_bulk_throughput_still_passes(self):
        profile = bench.protocol()
        rows = synthetic_rows(profile)
        self.assertTrue(bench.evaluate(rows, profile)["noninferiority_passed"])
        for row in rows:
            if row["backend"] == "hia_narrowed":
                row["request_ns"][-4:] = [2000] * 4
        result = bench.evaluate(rows, profile)
        self.assertTrue(result["quality_passed"])
        self.assertFalse(result["noninferiority_passed"])
        self.assertFalse(result["strong_noninferiority_passed"])
        self.assertTrue(all(c["paired_time_ratio_upper95"] == 1 for c in result["comparisons"]))
        self.assertTrue(all(c["empirical_p99_request_ratio"] == 2 for c in result["comparisons"]))

    def test_missing_failed_unmapped_and_wrong_tail_answers_are_not_excluded(self):
        profile = bench.protocol()
        for attack in ("missing", "failed", "mapping", "checksum", "clock"):
            rows = synthetic_rows(profile)
            if attack == "missing":
                rows.pop()
            elif attack == "failed":
                rows[0]["status"] = "failed"
            elif attack == "mapping":
                rows[0]["mapping_verified"] = False
            elif attack == "checksum":
                rows[0]["tail_checksum"] ^= 1
            else:
                rows[0]["clock_ns"][0] = 0
            result = bench.evaluate(rows, profile)
            self.assertFalse(result["quality_passed"], attack)
            self.assertFalse(result["noninferiority_passed"], attack)
            self.assertEqual(result["samples_excluded"], 0)

    @unittest.skipUnless(importlib.util.find_spec("z3"), "pinned Z3 required for registration")
    def test_registration_rejects_source_and_environment_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "registration.json"
            registered = bench.registration(path, {"clang": "/bin/true"})
            with patch.object(bench, "bindings", return_value={"forged.py": "0" * 64}):
                with self.assertRaisesRegex(ValueError, "source/protocol changed"):
                    bench.require_registration(path, {"clang": "/bin/true"})
            changed = {**registered["environment"], "LD_PRELOAD": "/untrusted.so"}
            with patch.object(bench, "environment_identity", return_value=changed):
                with self.assertRaisesRegex(ValueError, "environment changed"):
                    bench.require_registration(path, {"clang": "/bin/true"})


@unittest.skipUnless(shutil.which(os.environ.get("CLANG", "clang")), "native Clang required")
class BenchmarkNativeDriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temporary.name)
        cls.clang = os.environ.get("CLANG", "clang")
        profile = bench.protocol()
        header = bench.workload_header(profile)
        header += "#define REQUEST_TAIL_PROBES 257\n#define CLOCK_OVERHEAD_PROBES 65\n"
        (cls.directory / "workload.h").write_text(header)
        shutil.copyfile(bench.STUDY / "driver.c", cls.directory / "driver.c")
        cls.driver, cls.library = cls.directory / "driver", cls.directory / "fixture.so"
        subprocess.run([cls.clang, "-std=c11", "-Wall", "-Wextra", "-Werror", "-O3",
                        str(cls.directory / "driver.c"), "-ldl", "-o", str(cls.driver)], check=True,
                       capture_output=True, text=True, timeout=30)
        source = "#include <stdint.h>\n#include <stddef.h>\nuint64_t full_lifecycle(size_t n, uint32_t s) {return n*13+s;}\nuint64_t packet_xor(size_t n,uint32_t s){return n^s;}\n"
        subprocess.run([cls.clang, "-std=c11", "-O3", "-shared", "-fPIC", "-x", "c", "-", "-o", str(cls.library)],
                       input=source, check=True, capture_output=True, text=True, timeout=30)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_real_case_mode_validates_sealed_loaded_mapping_without_performance_samples(self):
        observed = bench.sealed_driver(self.driver, self.library, ["full_lifecycle", "case", "17", "4294967295"])
        self.assertEqual(observed["returncode"], 0, observed)
        self.assertEqual(observed["observation"]["actual"], 17 * 13 + 4294967295)
        self.assertTrue(observed["observation"]["mapping_verified"])
        self.assertEqual(observed["sealed_image_sha256"], bench.identity(self.library)["sha256"])
        self.assertNotIn("elapsed_ns", observed["observation"])

    def test_unsealed_real_file_is_refused_before_loading(self):
        descriptor = os.open(self.library, os.O_RDONLY)
        try:
            attempted = subprocess.run([str(self.driver), str(descriptor), "full_lifecycle", "case", "1", "2"],
                pass_fds=(descriptor,), capture_output=True, text=True, timeout=10)
            self.assertEqual(attempted.returncode, 22)
            self.assertEqual(attempted.stdout, "")
        finally:
            os.close(descriptor)

    def test_original_path_mutation_after_snapshot_cannot_replace_executed_image(self):
        original_execute = bench.execute
        original_bytes = self.library.read_bytes()

        def mutate_then_execute(*args, **kwargs):
            self.library.write_bytes(b"corrupt replacement must not execute")
            return original_execute(*args, **kwargs)

        try:
            with patch.object(bench, "execute", side_effect=mutate_then_execute):
                observed = bench.sealed_driver(self.driver, self.library, ["packet_xor", "case", "31", "77"])
            self.assertEqual(observed["observation"]["actual"], 31 ^ 77)
            self.assertEqual(observed["sealed_image_sha256"], bench.sha(original_bytes))
            self.assertNotEqual(observed["sealed_image_sha256"], bench.identity(self.library)["sha256"])
        finally:
            self.library.write_bytes(original_bytes)


if __name__ == "__main__":
    unittest.main()
