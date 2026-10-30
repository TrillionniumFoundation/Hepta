"""The new finite tail gate cannot be waived by mean or request-tail success."""
import copy
import unittest
from tools.qualify_hia_round4_bench import require_batch_p99


class Round4TailGateTests(unittest.TestCase):
    def result(self):
        return {"quality_passed": True, "comparisons": [
            {"kernel": kernel, "baseline": baseline, "noninferiority_thresholds_passed": True,
             "empirical_p99_batch_ratio": 0.9}
            for kernel in ("full_lifecycle", "packet_xor") for baseline in
            ("hia_original", "hia_guarded", "rust_o3_lto", "c_o3_lto", "cpp_o3_lto", "c_pgo_lto", "cpp_pgo_lto")]}

    def test_tail_regression_fails_otherwise_passing_comparison(self):
        value=self.result()
        value["comparisons"][4]["empirical_p99_batch_ratio"]=1.698142
        checked=require_batch_p99(value,1.10)
        self.assertFalse(checked["noninferiority_passed"])
        self.assertFalse(checked["strong_noninferiority_passed"])
        self.assertFalse(checked["comparisons"][4]["batch_p99_gate_passed"])

    def test_unknown_nonfinite_or_boolean_tail_never_passes(self):
        for ratio in (None,False,float("nan"),float("inf"),-1,0):
            value=self.result()
            value["comparisons"][2]["empirical_p99_batch_ratio"]=ratio
            self.assertFalse(require_batch_p99(value,1.10)["noninferiority_passed"])

    def test_incomplete_or_wrong_quality_inventory_remains_rejected(self):
        value=self.result()
        self.assertTrue(require_batch_p99(copy.deepcopy(value),1.10)["noninferiority_passed"])
        value["quality_passed"]=False
        self.assertFalse(require_batch_p99(copy.deepcopy(value),1.10)["noninferiority_passed"])
        value["quality_passed"]=True
        value["comparisons"].pop()
        self.assertFalse(require_batch_p99(value,1.10)["noninferiority_passed"])


if __name__ == "__main__":unittest.main()
