from copy import deepcopy
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch
import unittest

from tools.qualify_hia_native_ndu import (
    batch_checksum, checksum, digest, evaluate, execute_policies, finalize_acceptance, first_ready, fixed_ready,
    native_first_action, observed_model, percentile, protocol,
)


class NativeEconomicsContractTests(unittest.TestCase):
    def test_zero_native_calls_cannot_be_reported_as_incremental_ndu_benefit(self):
        spec = protocol()
        report = {"training_summary": {name: {str(n): {"median": 1, "p95": 1, "p99": 1}
                   for n in spec["sizes"]} for name in spec["backends"]},
                  "policy_runs": [{"episode": index, "arm": arm,
                                   "service_total_ns": 1 if arm == "native_ndu" else 2,
                                   "native_invocations": 0}
                                  for index in range(len(spec["episodes"])) for arm in spec["policy_arms"]]}
        zero = evaluate(report, spec)
        self.assertTrue(zero["service_scope_gated_policy_benefit_established"])
        self.assertFalse(zero["service_scope_net_ndu_benefit_established"])
        self.assertFalse(zero["whole_lifecycle_net_ndu_benefit_established"])
        for row in report["policy_runs"]:
            if row["arm"] == "native_ndu":
                row["native_invocations"] = 1
                row["service_total_ns"] = 3
        invoked_loss = evaluate(report, spec)
        self.assertEqual(invoked_loss["native_policy_invocations"], len(spec["episodes"]))
        self.assertFalse(invoked_loss["service_scope_net_ndu_benefit_established"])
        self.assertFalse(invoked_loss["native_invocation_count_alone_proves_benefit"])

    def test_future_controller_estimates_are_bound_without_future_episode_leakage(self):
        spec = protocol()
        training = {name: {"latency_ns": {str(n): 1000 + n for n in spec["sizes"]},
                           "preparation_ns": 5000, "resident_bytes": 4096} for name in spec["backends"]}
        products = {name: {"sha256": digest(name)} for name in spec["backends"]}
        a = observed_model(training, products, spec, 64, 4, set(), 1, 0,
                           future_decision_cost_ns=12345)
        altered = deepcopy(spec)
        altered["episodes"] = [{"sizes": [65536] * 4, "seeds": [99] * 4}]
        b = observed_model(training, products, altered, 64, 4, set(), 1, 0,
                           future_decision_cost_ns=12345)
        self.assertEqual(a, b)
        self.assertEqual(a["future_decision_cost_ns"], 12345)
        self.assertTrue(a["schema"].endswith(".v2"))
        for invalid in (True, -1, 1.5):
            with self.assertRaises(ValueError):
                observed_model(training, products, spec, 64, 4, set(), 1, 0,
                               future_decision_cost_ns=invalid)

    def test_no_savings_gate_precedes_native_startup_and_retains_actual_controller_costs(self):
        # This is a control-flow refusal unit test, not native timing evidence.
        spec = protocol()
        spec["episodes"] = [{"sizes": [64], "seeds": [123]}]
        training = {name: {"latency_ns": {str(n): 1000 for n in spec["sizes"]},
                           "preparation_ns": 5000, "resident_bytes": 4096} for name in spec["backends"]}
        products = {name: {"sha256": digest(name), "path": name} for name in spec["backends"]}
        report = {"controller_calibration": {"status": "passed", "training_sha256": digest(training),
            "sha256": digest("unit-calibration"), "native_startup_ns": 8000, "native_shutdown_ns": 2000,
            "estimates_ns": {"exact_dp": 1000, "greedy": 1000, "native_ndu": 1000}}}

        class UnitDriver:
            def __init__(self):
                self.loaded = set()
            def load(self, name, unused):
                self.loaded.add(name)
                return {"transport_outer_ns": 1, "load_outer_ns": 1}
            def measure(self, *unused):
                return {"transport_outer_ns": 1}
            def mapping(self, unused):
                return {"backing_resident_bytes": 4096}

        @contextmanager
        def unit_driver(*unused):
            yield UnitDriver()

        with patch("tools.qualify_hia_native_ndu.driver", unit_driver), \
             patch("hepta.hia_ndu_session.NduSession.for_stream_profile",
                   side_effect=AssertionError("skip must precede native startup")) as start:
            execute_policies(Path("/unused-unit-fixture"), products, training, report, spec, "unused", "unused")
        start.assert_not_called()
        self.assertEqual(len(report["policy_runs"]), 4)
        for row in report["policy_runs"]:
            self.assertEqual(row["status"], "passed")
            self.assertEqual(row["native_invocations"], 0)
            self.assertEqual(row["ndu_startup_ns"], 0)
            self.assertGreater(row["service_total_ns"], 0)
            self.assertGreater(row["steps"][0]["controller_ns"], 0)
            if row["arm"] != "fixed":
                self.assertEqual(row["steps"][0]["decision"]["status"], "skip_controller_keep_incumbent")
                self.assertFalse(row["steps"][0]["invocation_gate"]["invoke"])

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
        valid = {"status": "completed", "source_unchanged": True, "runtime_inputs_unchanged": True,
                 "acceptance": {"performance_gate_passed": False}}
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
