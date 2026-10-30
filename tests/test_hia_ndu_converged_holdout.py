"""Cost accounting rejects missing/negative work and discloses unknown lifetime cost."""
import unittest
from tools.qualify_hia_ndu_converged_holdout import cost_report, protocol


class ProspectiveNduCostTests(unittest.TestCase):
    def fixture(self):
        arms=protocol()["arms"]
        return {"setup_accounting":{"native_build_cost":{"wall_ns":100},"controller_setup_ns":{a:3 for a in arms}},
                "shared_setup_wall_ns":5,"standalone_total_cost_ns":{a:200 if a.startswith("ndu") else 80 for a in arms},
                "episodes":[{"arm":a} for a in arms for _ in range(2)],
                "all_episodes_completed":True,"all_outputs_correct":True,"all_actual_budgets_passed":True}

    def test_outer_build_replaces_inner_once_and_reuse_does_not_erase_it(self):
        cost=cost_report(self.fixture(),build_outer_ns=120,wrapper_overhead_ns=7,retained_bytes=11)
        self.assertEqual(cost["standalone_with_original_build_total_ns"]["ndu"],227)
        self.assertEqual(cost["already_built_marginal_total_ns"]["ndu"],107)
        self.assertEqual(cost["standalone_with_original_build_total_ns"]["q32-dp"],87)
        self.assertEqual(cost["native_net_savings_ns"]["ndu"]["q32-dp"],-140)
        self.assertFalse(cost["measured_scope_net_gain"])
        self.assertFalse(cost["all_lifetime_costs_known"])
        self.assertIsNone(cost["unknown_costs"]["human_work_ns"])

    def test_fake_negative_overhead_or_missing_original_build_is_not_credit(self):
        for build,overhead in ((99,7),(120,-1)):
            with self.assertRaises(ValueError):
                cost_report(self.fixture(),build_outer_ns=build,wrapper_overhead_ns=overhead,retained_bytes=11)

    def test_failed_episode_and_unknown_lifetime_cannot_pass_broad_claim(self):
        result=self.fixture()
        result["all_episodes_completed"]=False
        result["standalone_total_cost_ns"]={a:101 if a.startswith("ndu") else 10000 for a in protocol()["arms"]}
        cost=cost_report(result,build_outer_ns=100,wrapper_overhead_ns=0,retained_bytes=0)
        self.assertFalse(cost["measured_scope_net_gain"])
        self.assertFalse(cost["complete_lifetime_net_gain_proved"])
        self.assertFalse(cost["strongest_cross_language_static_baseline_beaten"])


if __name__ == "__main__":
    unittest.main()
