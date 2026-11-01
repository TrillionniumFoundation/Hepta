"""Campaign integrity and cost accounting, independent of timing outcomes."""
import copy
import unittest

from tools.qualify_hia_reduction_release import ARMS,assess,amortization,checksum,specification


class ReductionReleaseTests(unittest.TestCase):
    def cohort(self):
        spec=specification()
        spec.update(workloads=["linear"],regression_sizes=[0],holdout_sizes=[509],seeds=[17],samples=3)
        rows=[{"workload":"linear","phase":phase,"backend":arm,"n":n,"seed":17,
               "calls":64,"times_ns":[64,64,64]} for phase in ("regression","holdout")
              for n in spec[phase+"_sizes"] for arm in ARMS]
        return spec,rows

    def test_periodic_oracle_matches_direct_arbitrary_seeds_and_tails(self):
        for workload in ("linear","affine"):
            for n in (0,1,255,256,257,509,4097):
                for seed in (0,1,2,255,256,4294967295):
                    direct=sum(((i+seed) if workload=="linear" else (i*seed+17))%256 for i in range(n))
                    self.assertEqual(checksum(workload,n,seed),direct)

    def test_missing_duplicate_or_trimmed_observation_cannot_pass(self):
        spec,rows=self.cohort()
        self.assertTrue(assess(rows,spec)["all_rust_gate_passed"])
        for invalid in (rows[:-1],rows+[rows[0]]):
            with self.assertRaises(ValueError): assess(invalid,spec)
        invalid=copy.deepcopy(rows);invalid[0]["times_ns"]=[64,64]
        with self.assertRaises(ValueError): assess(invalid,spec)

    def test_one_negative_length_is_retained_in_full_gate(self):
        spec,rows=self.cohort()
        for row in rows:
            if row["backend"]=="hia_reduction" and row["n"]==0:
                row["times_ns"]=[128,128,128]
        result=assess(rows,spec)
        self.assertFalse(result["all_rust_gate_passed"])
        self.assertTrue(result["independent_holdout_passed"])

    def test_full_cost_selects_best_rust_at_each_horizon(self):
        spec,rows=self.cohort()
        for row in rows:
            row["times_ns"]=[{"hia_checked":256,"hia_reduction":64,"rust_release":192,"rust_byte_release":128}[row["backend"]]]*3
        report={"protocol":spec,"assessment":assess(rows,spec),
            "backend_build_wall_ns":{"linear":{"hia_checked":20,"hia_reduction":10000,"rust_release":1,"rust_byte_release":1000}},
            "loads":[{"workload":"linear","backend":arm,"load_ns":0} for arm in ARMS]}
        value=amortization(report)[0]
        self.assertEqual(value["horizons"][0]["rust_reference"],"rust_release")
        self.assertEqual(value["horizons"][-1]["rust_reference"],"rust_byte_release")
        self.assertEqual(value["break_even_calls"],9000)
        self.assertGreater(value["horizons"][0]["hia_total_ns"],value["horizons"][0]["rust_total_ns"])


if __name__=="__main__": unittest.main()
