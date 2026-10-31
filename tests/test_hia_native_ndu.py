from copy import deepcopy
import unittest

from tools.qualify_hia_native_ndu import (
    batch_checksum, checksum, digest, finalize_acceptance, first_ready, fixed_ready,
    native_first_action, observed_model, percentile, protocol,
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

    @staticmethod
    def native_fixture(schedules):
        states = {"empty": {"ready": []}, "cpp": {"ready": ["cpp"]},
                  "rust": {"ready": ["rust"]}, "both": {"ready": ["cpp", "rust"]}}
        plans = {}
        for index, schedule in enumerate(schedules):
            actions, source = [], "empty"
            for target in schedule:
                actions.append({"source": source, "target": target, "status": "verified"})
                source = target
            plans[f"plan-{index}"] = {"verified": True, "actions": actions}
        return ({"plans": plans, "stateful_binding": {"states": states}},
                {"authority": "DENY_ALL", "safety_certificate": False,
                 "advisory_candidate_id": None, "pareto_candidate_ids": list(plans)})

    def test_whole_path_tie_preserves_a_common_preparation_action(self):
        bundle, response = self.native_fixture([["cpp", "cpp"], ["cpp"]])
        before = deepcopy(response)
        result = native_first_action(bundle, response, set())
        self.assertEqual(result["chosen_ready"], ["cpp"])
        self.assertEqual(result["status"], "unanimous_first_action")
        self.assertTrue(result["stopped_until_size_change"])
        self.assertFalse(result["whole_path_selected"])
        self.assertFalse(result["safety_certificate"])
        self.assertEqual(response, before)

    def test_conflicting_pareto_first_actions_do_not_pick_an_arbitrary_path(self):
        bundle, response = self.native_fixture([["cpp"], ["rust"]])
        result = native_first_action(bundle, response, set())
        self.assertEqual(result["chosen_ready"], [])
        self.assertEqual(result["status"], "abstain_no_common_first_action")
        self.assertFalse(result["stopped_until_size_change"])
        self.assertEqual(result["pareto_first_ready_sets"], [["cpp"], ["rust"]])

    def test_a_common_first_action_does_not_erase_later_preparation_work(self):
        bundle, response = self.native_fixture([["cpp", "both"], ["cpp"]])
        result = native_first_action(bundle, response, set())
        self.assertEqual(result["chosen_ready"], ["cpp"])
        self.assertFalse(result["stopped_until_size_change"])

    def test_abstention_unbound_and_unadmitted_paths_never_acquire_authority(self):
        bundle, response = self.native_fixture([["cpp"]])
        response["pareto_candidate_ids"].append("abstain")
        self.assertEqual(native_first_action(bundle, response, set())["chosen_ready"], [])
        response["pareto_candidate_ids"] = ["absent"]
        with self.assertRaisesRegex(ValueError, "absent from the bound plan"):
            native_first_action(bundle, response, set())
        response["pareto_candidate_ids"] = ["plan-0"]
        bundle["plans"]["plan-0"]["verified"] = False
        with self.assertRaisesRegex(ValueError, "lacks admitted"):
            native_first_action(bundle, response, set())
        response["authority"] = "ALLOW"
        with self.assertRaisesRegex(ValueError, "cannot acquire execution authority"):
            native_first_action(bundle, response, set())

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
