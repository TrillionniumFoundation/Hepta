"""Regression checks for the new fixed strong-baseline experiment policy."""
from copy import deepcopy
import math
import sys
import unittest

from tools import qualify_hia_optimizer_bench as q


def observations():
    rows = []
    for index, (group, kernel, backend) in enumerate(q.sample_order()):
        rows.append({"group": group, "kernel": kernel, "backend": backend, "sample_index": index,
                     "status": "measured", "elapsed_ns": 32_000_000, "process_cpu_ns": 31_500_000,
                     "process_peak_rss_kib": 4096, "outer_wall_ns": 36_000_000,
                     "batch_ns": [1_000_000] * q.PROTOCOL["batches"], "checksum": q.timed_checksum(kernel)})
    return rows


class OptimizerBenchmarkPolicyTests(unittest.TestCase):
    def test_independent_periodic_oracle_matches_direct_byte_computation(self):
        for size in (0, 1, 255, 256, 257, 1021):
            for seed in (0, 19, 255, 256, 2**31, 2**32 - 1):
                full = sum((i + seed) & 255 for i in range(size))
                packet = sum((((i * 13 + seed) & 255) ^ ((i + (seed ^ 90)) & 255)) for i in range(size))
                self.assertEqual(q.oracle("full_lifecycle", size, seed), full)
                self.assertEqual(q.oracle("packet_xor", size, seed), packet)
        for bad in (-1, 65537, True):
            with self.assertRaises(ValueError):
                q.oracle("packet_xor", bad, 0)

    def test_training_and_holdout_never_share_sizes_or_seeds(self):
        self.assertFalse(set(q.PROTOCOL["training_sizes"]) & set(q.PROTOCOL["holdout_sizes"]))
        self.assertFalse(set(q.PROTOCOL["training_seeds"]) & set(q.PROTOCOL["holdout_seeds"]))
        for kernel in q.KERNELS:
            self.assertNotEqual(q.timed_checksum(kernel, "train"), q.timed_checksum(kernel, "holdout"))
        self.assertIn("#define HOLDOUT_SIZE_COUNT 8", q.workload_header())
        self.assertIn("#define TRAIN_SEED_COUNT 4", q.workload_header())

    def test_all_backends_are_paired_and_order_is_fixed(self):
        order = q.sample_order()
        self.assertEqual(len(order), 84)
        self.assertEqual(len(set(order)), 84)
        for group in range(q.PROTOCOL["groups"]):
            for kernel in q.KERNELS:
                names = [b for g, k, b in order if g == group and k == kernel]
                self.assertEqual(set(names), set(q.BACKENDS))
                offset = (group + q.KERNELS.index(kernel)) % len(q.BACKENDS)
                expected = list(q.BACKENDS[offset:] + q.BACKENDS[:offset])
                self.assertEqual(names, expected[::-1] if group % 2 else expected)

    def test_missing_reordered_failed_or_forged_samples_cannot_pass(self):
        original = observations()
        valid = q.evaluate_samples(original)
        self.assertTrue(valid["quality_passed"])
        self.assertTrue(valid["noninferiority_passed"])
        for mode in ("missing", "reordered", "failed", "checksum", "bool_time", "batch_total"):
            rows = deepcopy(original)
            if mode == "missing": rows.pop()
            elif mode == "reordered": rows[0], rows[1] = rows[1], rows[0]
            elif mode == "failed": rows[0]["status"] = "timeout"
            elif mode == "checksum": rows[0]["checksum"] += 1
            elif mode == "bool_time": rows[0]["elapsed_ns"] = True
            elif mode == "batch_total": rows[0]["batch_ns"][0] = rows[0]["elapsed_ns"]
            with self.subTest(mode=mode):
                result = q.evaluate_samples(rows)
                self.assertFalse(result["quality_passed"])
                self.assertFalse(result["noninferiority_passed"])
                self.assertEqual(result["samples_excluded"], 0)

    def test_slow_hia_fails_noninferiority_without_being_relabelled_bad_data(self):
        rows = observations()
        for row in rows:
            if row["backend"] == "hia":
                row["elapsed_ns"] *= 2
                row["batch_ns"] = [v * 2 for v in row["batch_ns"]]
        result = q.evaluate_samples(rows)
        self.assertTrue(result["quality_passed"])
        self.assertFalse(result["noninferiority_passed"])
        self.assertEqual(len(result["comparisons"]), 10)
        for comparison in result["comparisons"]:
            self.assertAlmostEqual(comparison["paired_time_geomean_ratio"], 2)
            self.assertAlmostEqual(comparison["paired_time_ratio_upper95"], 2)
            self.assertFalse(comparison["noninferiority_thresholds_passed"])

    def test_tail_and_memory_regressions_are_independent_of_mean_time(self):
        for field in ("batch_ns", "process_peak_rss_kib"):
            rows = observations()
            for row in rows:
                if row["backend"] == "hia":
                    if field == "batch_ns":
                        row[field] = [980_000] * 29 + [1_200_000] * 2
                    else:
                        row[field] *= 2
            result = q.evaluate_samples(rows)
            self.assertTrue(result["quality_passed"])
            self.assertFalse(result["noninferiority_passed"])
            self.assertTrue(all(math.isclose(c["paired_time_geomean_ratio"], 1) for c in result["comparisons"]))

    def test_native_process_failure_retains_both_output_streams(self):
        record = q.execute([sys.executable, "-c", "import sys;print('actual output');print('actual failure',file=sys.stderr);sys.exit(7)"])
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["returncode"], 7)
        self.assertIn("actual output", record["stdout"])
        self.assertIn("actual failure", record["stderr"])
        self.assertGreater(record["wall_ns"], 0)
        with self.assertRaises(ValueError):
            q.successful(record)


if __name__ == "__main__":
    unittest.main()
