from copy import deepcopy
import unittest

from tools.qualify_hia_native_ndu import (
    batch_checksum, checksum, digest, finalize_acceptance, first_ready, fixed_ready,
    observed_model, percentile, protocol,
)


class NativeEconomicsContractTests(unittest.TestCase):
    def test_independent_periodic_oracle_covers_u32_wrap_and_empty(self):
        for n in (0, 1, 17, 255, 256, 4096, 65536):
            for seed in (0, 255, 256, (1 << 32)-1):
                self.assertEqual(checksum(n, seed), sum((i+seed) & 255 for i in range(n)))
        self.assertEqual(batch_checksum(7, (1 << 32)-2, 4),
                         sum(checksum(7, seed & ((1 << 32)-1)) for seed in range((1 << 32)-2, (1 << 32)+2)))

    def test_future_episode_values_are_not_policy_features_or_identity(self):
        spec = protocol()
        training = {name:{"latency_ns":{str(n):1000+n for n in spec["sizes"]},
                          "preparation_ns":5000,"resident_bytes":4096} for name in spec["backends"]}
        products = {name:{"sha256":digest(name)} for name in spec["backends"]}
        first = observed_model(training,products,spec,64,4,set(),1,0)
        changed = deepcopy(spec)
        changed["episodes"] = [{"sizes":[65536]*4,"seeds":[99]*4}]
        second = observed_model(training,products,changed,64,4,set(),1,0)
        self.assertEqual(first,second)
        self.assertEqual(first["baseline"]["latency_ns"],[1064]*4)
        self.assertFalse(first["observations"][0]["future_workload_visible"])

    def test_observed_change_and_spent_resources_change_successor(self):
        spec=protocol()
        training={name:{"latency_ns":{str(n):n for n in spec["sizes"]},
                        "preparation_ns":9,"resident_bytes":1024} for name in spec["backends"]}
        products={name:{"sha256":digest(name)} for name in spec["backends"]}
        a=observed_model(training,products,spec,64,4,set(),1,0)
        b=observed_model(training,products,spec,4096,3,{"hia"},2,100)
        self.assertEqual(b["initial_ready"],["hia"])
        self.assertEqual(b["budget_ns"],a["budget_ns"]-100)
        self.assertEqual(b["baseline"]["latency_ns"],[4096]*3)
        with self.assertRaises(ValueError): observed_model(training,products,spec,65,3,set(),1,0)

    def test_complete_ties_are_explicit_and_tail_samples_are_not_trimmed(self):
        reference={"winners":[{"schedule":[["rust"],["rust"]]},
                              {"schedule":[["cpp"],["cpp"]]}]}
        self.assertEqual(first_ready(reference,set()),{"cpp"})
        self.assertEqual(first_ready({"winners":[]},{"hia"}),{"hia"})
        self.assertEqual(percentile([1]*19+[1000],.95),1)
        self.assertEqual(percentile([1]*19+[1000],.99),1000)

    def test_source_drift_or_incomplete_execution_withdraws_positive_acceptance(self):
        for status, unchanged in (("failed", True), ("completed", False), ("completed", None)):
            report = {"status": status, "source_unchanged": unchanged,
                      "acceptance": {"performance_gate_passed": True,
                                     "service_scope_net_ndu_benefit_established": True}}
            finalize_acceptance(report)
            self.assertFalse(report["acceptance_observation_valid"])
            self.assertNotIn("acceptance", report)
        valid = {"status": "completed", "source_unchanged": True, "acceptance": {"performance_gate_passed": False}}
        finalize_acceptance(valid)
        self.assertTrue(valid["acceptance_observation_valid"])
        self.assertFalse(valid["acceptance"]["performance_gate_passed"])

    def test_fixed_policy_rejects_an_input_that_exposes_future_episodes(self):
        with self.assertRaisesRegex(ValueError, "exclude future"):
            fixed_ready({}, protocol())
        selected = {"variants": [], "resident_quota_bytes": 0, "sizes": [64], "baseline": "c"}
        self.assertEqual(fixed_ready({"c": {"latency_ns": {"64": 100}}}, selected), set())


if __name__ == "__main__":
    unittest.main()
