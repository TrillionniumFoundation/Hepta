"""Adversarial accounting fixtures, never native timing or NDU-gain evidence."""
from copy import deepcopy
import unittest





class NativeCohortAdmissionTests(unittest.TestCase):


    def test_every_failed_cancelled_or_unfinished_registered_attempt_blocks_acceptance(self):
        for status in ("failed", "cancelled", "timed_out", "running", None, True):
            with self.subTest(status=status):
                self.rejects(lambda r, s: r["policy_runs"][3].update(status=status))

    def test_missing_extra_or_unregistered_rows_are_not_dropped(self):
        for mutate in (
            lambda r, s: r["policy_runs"].pop(),
            lambda r, s: r["policy_runs"].append(dict(r["policy_runs"][0], arm="unregistered")),
            lambda r, s: r["policy_runs"].__setitem__(1, deepcopy(r["policy_runs"][0])),
            lambda r, s: r["policy_runs"][0].update(episode=len(s["episodes"])),
            lambda r, s: r["policy_runs"][0].update(episode=True),
            lambda r, s: r["policy_runs"][0].update(arm="unregistered"),
        ):
            with self.subTest(mutation=mutate):
                self.rejects(mutate)

    def test_empty_episode_or_weakened_control_registration_cannot_pass_vacuously(self):
        for mutate in (
            lambda r, s: s.update(episodes=[]),
            lambda r, s: s["policy_arms"].pop(),
            lambda r, s: s["policy_arms"].__setitem__(0, "greedy"),
            lambda r, s: s["episodes"][0].update(sizes=[], seeds=[]),
            lambda r, s: s["economic_gate"].update(all_semantic_and_resource_checks_required=False),
            lambda r, s: s["economic_gate"].update(native_ndu_service_total_must_be_less_than_every_control_in_every_episode=False),
        ):
            with self.subTest(mutation=mutate):
                self.rejects(mutate)

    def test_unknown_boolean_negative_or_noninteger_cost_cannot_be_a_saving(self):
        for name in ("actual_total_ns", "service_total_ns", "independent_audit_ns"):
            for invalid in (None, True, -1, 1.5, float("nan"), float("inf")):
                with self.subTest(field=name, value=invalid):
                    self.rejects(lambda r, s: r["policy_runs"][3].update({name: invalid}))
        for name in ("actual_total_ns", "service_total_ns"):
            self.rejects(lambda r, s: r["policy_runs"][3].update({name: 0}))

    def test_audit_subtraction_must_match_original_disjoint_costs(self):
        for mutate in (
            lambda r, s: r["policy_runs"][3].update(service_total_ns=1),
            lambda r, s: r["policy_runs"][3].update(actual_total_ns=1),
            lambda r, s: r["policy_runs"][3].update(independent_audit_ns=1),
            lambda r, s: r["policy_runs"][3]["steps"][0].update(independent_audit_ns=10000),
            lambda r, s: r["policy_runs"][3]["steps"][0].update(controller_ns=10000),
        ):
            with self.subTest(mutation=mutate):
                self.rejects(mutate)

    def test_every_registered_request_has_one_matching_step(self):
        for mutate in (
            lambda r, s: r["policy_runs"][0]["steps"].pop(),
            lambda r, s: r["policy_runs"][0]["steps"][0].update(index=True),
            lambda r, s: r["policy_runs"][0]["steps"][0].update(seed=0),
            lambda r, s: r["policy_runs"][0]["steps"][0].update(observed_size=0),
        ):
            with self.subTest(mutation=mutate):
                self.rejects(mutate)

    def test_native_count_needs_matching_retained_responses_and_closed_session(self):
        for mutate in (
            lambda r, s: r["policy_runs"][3].update(native_invocations=True),
            lambda r, s: r["policy_runs"][3].update(native_invocations=-1),
            lambda r, s: r["policy_runs"][3].update(native_invocations=2),
            lambda r, s: r["policy_runs"][3]["steps"][0].pop("response"),
            lambda r, s: r["policy_runs"][3]["steps"][0].update(response=None),
            lambda r, s: r["policy_runs"][3].pop("ndu_session"),
            lambda r, s: r["policy_runs"][3]["ndu_session"].update(requests=2),
            lambda r, s: r["policy_runs"][3]["ndu_session"].update(closed=False),
            lambda r, s: r["policy_runs"][3]["ndu_session"].update(cleanup_errors=["uncertain"]),
            lambda r, s: r["policy_runs"][3]["ndu_session"].update(request_costs_ns=[]),
            lambda r, s: r["policy_runs"][0].update(native_invocations=1),
        ):
            with self.subTest(mutation=mutate):
                self.rejects(mutate)

    def test_training_statistics_and_registered_limits_must_be_positive_finite_numbers(self):
        for invalid in (None, True, -1, 0, float("nan"), float("inf")):
            with self.subTest(value=invalid):
                self.rejects(lambda r, s: r["training_summary"]["cpp"][str(s["sizes"][0])].update(median=invalid))
                self.rejects(lambda r, s: s["performance_gate"].update(hia_tail_ratio_maximum=invalid))






if __name__ == "__main__":
    unittest.main()
