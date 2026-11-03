"""Campaign integrity and cost accounting, independent of timing outcomes."""
import copy
import unittest

from tools.qualify_hia_reduction_release import ARMS,assess,amortization,checksum,specification


class ReductionReleaseTests(unittest.TestCase):
    def cohort(self):
        spec=specification()
        rows=[{"workload":workload,"phase":phase,"backend":arm,"n":n,"seed":seed,
               "calls":spec["batch_calls"],"times_ns":[64]*spec["samples"]}
              for workload in spec["workloads"] for phase in ("regression","holdout")
              for n in spec[phase+"_sizes"] for seed in spec["seeds"] for arm in ARMS]
        return spec,rows

    def test_frozen_historical_registration_rejects_empty_or_relaxed_campaign(self):
        spec, rows = self.cohort()
        mutations = (("workloads", []), ("holdout_sizes", []), ("seeds", []),
                     ("samples", 1), ("schema", "unknown"),
                     ("performance_gate", {"median_ratio_maximum": 100,
                                           "p95_ratio_maximum": 100}))
        for key, value in mutations:
            changed = copy.deepcopy(spec)
            changed[key] = value
            with self.subTest(field=key), self.assertRaises(ValueError):
                assess([] if key == "workloads" else rows, changed)

    def test_registration_does_not_equate_boolean_and_integer(self):
        spec, rows = self.cohort()
        spec["regression_sizes"][0] = False
        with self.assertRaises(ValueError):
            assess(rows, spec)

    def test_periodic_oracle_matches_direct_arbitrary_seeds_and_tails(self):
        for workload in ("linear","affine"):
            for n in (0,1,255,256,257,509,4097):
                for seed in (0,1,2,255,256,4294967295):
                    direct=sum(((i+seed) if workload=="linear" else (i*seed+17))%256 for i in range(n))
                    self.assertEqual(checksum(workload,n,seed),direct)

    def test_missing_duplicate_or_trimmed_observation_cannot_pass(self):
        spec,rows=self.cohort()
        result=assess(rows,spec)
        self.assertTrue(result["all_rust_gate_passed"])
        self.assertEqual(result["rust_comparisons_total"],60)
        for invalid in (rows[:-1],rows+[rows[0]]):
            with self.assertRaises(ValueError): assess(invalid,spec)
        invalid=copy.deepcopy(rows);invalid[0]["times_ns"]=[64,64]
        with self.assertRaises(ValueError): assess(invalid,spec)

    def test_one_negative_length_is_retained_in_full_gate(self):
        spec,rows=self.cohort()
        for row in rows:
            if row["backend"]=="hia_reduction" and row["n"]==0:
                row["times_ns"]=[128]*spec["samples"]
        result=assess(rows,spec)
        self.assertFalse(result["all_rust_gate_passed"])
        self.assertTrue(result["independent_holdout_passed"])

    def test_full_cost_selects_best_rust_at_each_horizon(self):
        spec,rows=self.cohort()
        for row in rows:
            row["times_ns"]=[{"hia_checked":256,"hia_reduction":64,"rust_release":192,"rust_byte_release":128}[row["backend"]]]*spec["samples"]
        report={"protocol":spec,"assessment":assess(rows,spec),
            "backend_build_wall_ns":{w:{"hia_checked":20,"hia_reduction":10000,"rust_release":1,"rust_byte_release":1000} for w in spec["workloads"]},
            "loads":[{"workload":w,"backend":arm,"load_ns":0} for w in spec["workloads"] for arm in ARMS]}
        value=amortization(report)[0]
        self.assertEqual(value["horizons"][0]["rust_reference"],"rust_release")
        self.assertEqual(value["horizons"][-1]["rust_reference"],"rust_byte_release")
        self.assertEqual(value["break_even_calls"],9000)
        self.assertGreater(value["horizons"][0]["hia_total_ns"],value["horizons"][0]["rust_total_ns"])


if __name__=="__main__": unittest.main()
