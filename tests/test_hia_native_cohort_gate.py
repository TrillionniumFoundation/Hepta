"""Adversarial accounting fixtures, never native timing or NDU-gain evidence."""
from copy import deepcopy
import unittest

from tools.qualify_hia_native_ndu import evaluate, finalize_acceptance, protocol


def cohort_fixture(*, native_calls=1, ndu_cost=100, control_cost=200, controller_profile="full-model-v3"):
    """An explicitly authored complete matrix for testing result admission only."""
    spec = protocol(controller_profile)
    rows = []
    for episode_index, episode in enumerate(spec["episodes"]):
        for arm in spec["policy_arms"]:
            calls = native_calls if arm == "native_ndu" else 0
            steps = [{"index": index, "observed_size": size, "seed": seed,
                      "controller_ns": 1, "independent_audit_ns": 2}
                     for index, (size, seed) in enumerate(zip(episode["sizes"], episode["seeds"]))]
            for step in steps[:calls]:
                step["response"] = {"authored_accounting_fixture": True}
            service = ndu_cost if arm == "native_ndu" else control_cost
            audit = sum(step["independent_audit_ns"] for step in steps)
            row = {"episode": episode_index, "arm": arm, "status": "passed",
                   "steps": steps, "service_total_ns": service,
                   "actual_total_ns": service + audit, "independent_audit_ns": audit,
                   "native_invocations": calls}
            if calls:
                row["ndu_session"] = {"requests": calls, "closed": True,
                                      "request_costs_ns": [1] * calls, "cleanup_errors": []}
            rows.append(row)
    stats = {name: {str(n): {"median": 100, "p95": 100, "p99": 100}
                   for n in spec["sizes"]} for name in spec["backends"]}
    return {"training_summary": stats, "policy_runs": rows}, spec


class NativeCohortAdmissionTests(unittest.TestCase):
    def rejects(self, mutate):
        report, spec = cohort_fixture()
        mutate(report, spec)
        with self.assertRaisesRegex(ValueError, "E_HIA_NATIVE_ECONOMICS"):
            evaluate(report, spec)

    def test_duplicate_row_cannot_overwrite_an_original_losing_native_attempt(self):
        report, spec = cohort_fixture()
        original = next(row for row in report["policy_runs"] if row["arm"] == "native_ndu")
        fast_duplicate = deepcopy(original)
        original["service_total_ns"] = 400
        original["actual_total_ns"] = 400 + original["independent_audit_ns"]
        report["policy_runs"].append(fast_duplicate)
        with self.assertRaisesRegex(ValueError, "E_HIA_NATIVE_ECONOMICS"):
            evaluate(report, spec)

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

    def test_complete_negative_and_zero_invocation_cohorts_keep_their_original_meaning(self):
        report, spec = cohort_fixture(ndu_cost=300)
        before = deepcopy(report)
        result = evaluate(report, spec)
        self.assertFalse(result["service_scope_gated_policy_benefit_established"])
        self.assertFalse(result["service_scope_net_ndu_benefit_established"])
        self.assertEqual(report, before)
        report, spec = cohort_fixture(native_calls=0)
        result = evaluate(report, spec)
        self.assertTrue(result["service_scope_gated_policy_benefit_established"])
        self.assertFalse(result["service_scope_net_ndu_benefit_established"])
        self.assertFalse(result["whole_lifecycle_net_ndu_benefit_established"])
        self.assertFalse(result["complete_lifecycle_cost_known"])

    def test_finalization_rechecks_original_observations_and_cannot_keep_stale_acceptance(self):
        report, spec = cohort_fixture()
        report.update(protocol=spec, status="completed", source_unchanged=True,
                      runtime_inputs_unchanged=True, acceptance=evaluate(report, spec))
        report["policy_runs"][3]["status"] = "failed"
        finalize_acceptance(report)
        self.assertFalse(report["acceptance_observation_valid"])
        self.assertNotIn("acceptance", report)

    def test_finalization_rejects_a_stale_positive_after_a_complete_cost_change(self):
        report, spec = cohort_fixture()
        report.update(protocol=spec, status="completed", source_unchanged=True,
                      runtime_inputs_unchanged=True, acceptance=evaluate(report, spec))
        native = report["policy_runs"][3]
        native["service_total_ns"] = 400
        native["actual_total_ns"] = 400 + native["independent_audit_ns"]
        self.assertFalse(evaluate(report, spec)["service_scope_net_ndu_benefit_established"])
        finalize_acceptance(report)
        self.assertFalse(report["acceptance_observation_valid"])
        self.assertNotIn("acceptance", report)

    def test_complete_cohort_order_does_not_change_admitted_arithmetic(self):
        report, spec = cohort_fixture()
        expected = evaluate(report, spec)
        report["policy_runs"].reverse()
        self.assertEqual(evaluate(report, spec), expected)


if __name__ == "__main__":
    unittest.main()
