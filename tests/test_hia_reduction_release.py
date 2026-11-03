"""Campaign integrity and cost accounting, independent of timing outcomes."""
import copy
import unittest

from tools.qualify_hia_reduction_release import ARMS,METRIC_NAMES,ReductionDriver,assess,amortization,checksum,specification


class ReductionReleaseTests(unittest.TestCase):
    def cohort(self):
        spec=specification()
        rows=[{"workload":workload,"phase":phase,"backend":arm,"n":n,"seed":seed,
               "calls":spec["batch_calls"],"samples":spec["samples"], "elapsed_ns":64*spec["samples"],
               "times_ns":[64]*spec["samples"]}
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

    def test_observed_work_requires_exact_native_integer_identity(self):
        for field in ("n", "seed", "calls", "samples"):
            for mutation in ("missing", "float", "boolean", "wrong"):
                spec, rows = self.cohort()
                row = rows[0]
                if mutation == "missing":
                    row.pop(field)
                elif mutation == "float":
                    row[field] = float(row[field])
                elif mutation == "boolean":
                    row[field] = bool(row[field])
                else:
                    row[field] += 1
                with self.subTest(field=field, mutation=mutation), self.assertRaises(ValueError):
                    assess(rows, spec)

    def test_elapsed_total_and_sample_vector_must_reconcile(self):
        for mutation in ("missing", "zero", "float", "mismatch", "boolean_sample",
                         "negative_sample", "overflow_sample", "tuple_samples"):
            spec, rows = self.cohort()
            row = rows[0]
            if mutation == "missing":
                row.pop("elapsed_ns")
            elif mutation == "zero":
                row["elapsed_ns"] = 0
            elif mutation == "float":
                row["elapsed_ns"] = float(row["elapsed_ns"])
            elif mutation == "mismatch":
                row["elapsed_ns"] -= 1
            elif mutation == "tuple_samples":
                row["times_ns"] = tuple(row["times_ns"])
            else:
                row["times_ns"][0] = {"boolean_sample": True, "negative_sample": -1,
                                       "overflow_sample": 2**64}[mutation]
                row["elapsed_ns"] = sum(row["times_ns"])
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                assess(rows, spec)

    def test_driver_rejects_wrong_work_even_for_zero_length_checksums(self):
        # Every zero-length batch has checksum zero, regardless of its call
        # count. Bind the echoed work rather than relying on that checksum.
        valid = {"id": ARMS.index("hia_reduction"), "n": 0, "seed": 17,
                 "calls": 64, "samples": 3, "times_ns": [10, 10, 10],
                 "elapsed_ns": 30, "cold_value": 0, "batch_checksum": 0,
                 "observed": 0, "metrics": [0] * len(METRIC_NAMES)}
        driver = object.__new__(ReductionDriver)
        driver.ask = lambda command: copy.deepcopy(valid)
        self.assertEqual(driver.measure("linear", "hia_reduction", 0, 17, 64, 3)["calls"], 64)
        for field, value in (("calls", 1), ("samples", 1), ("id", True),
                             ("n", False), ("elapsed_ns", 29)):
            changed = copy.deepcopy(valid)
            changed[field] = value
            driver.ask = lambda command: copy.deepcopy(changed)
            with self.subTest(field=field), self.assertRaises(ValueError):
                driver.measure("linear", "hia_reduction", 0, 17, 64, 3)

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
                row["elapsed_ns"]=sum(row["times_ns"])
        result=assess(rows,spec)
        self.assertFalse(result["all_rust_gate_passed"])
        self.assertTrue(result["independent_holdout_passed"])

    def test_full_cost_selects_best_rust_at_each_horizon(self):
        spec,rows=self.cohort()
        for row in rows:
            row["times_ns"]=[{"hia_checked":256,"hia_reduction":64,"rust_release":192,"rust_byte_release":128}[row["backend"]]]*spec["samples"]
            row["elapsed_ns"]=sum(row["times_ns"])
        report={"protocol":spec,"assessment":assess(rows,spec),
            "backend_build_wall_ns":{w:{"hia_checked":20,"hia_reduction":10000,"rust_release":1,"rust_byte_release":1000} for w in spec["workloads"]},
            "loads":[{"workload":w,"backend":arm,"load_ns":0} for w in spec["workloads"] for arm in ARMS]}
        value=amortization(report)[0]
        self.assertEqual(value["horizons"][0]["rust_reference"],"rust_release")
        self.assertEqual(value["horizons"][-1]["rust_reference"],"rust_byte_release")
        self.assertEqual(value["break_even_calls"],9000)
        self.assertGreater(value["horizons"][0]["hia_total_ns"],value["horizons"][0]["rust_total_ns"])


if __name__=="__main__": unittest.main()
