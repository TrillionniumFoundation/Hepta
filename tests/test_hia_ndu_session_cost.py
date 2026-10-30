"""Cost and paired-outcome admission controls; no timing is fabricated as data."""
from copy import deepcopy
import unittest

from tools.qualify_hia_ndu_session_cost import ARMS, requests, summarize


def observations():
    return [{"group": group, "arm": arm, "status": "completed", "requests_completed": 2,
             "response_sha256": ["a" * 64, "b" * 64],
             "snapshot": {"requests": 2, "closed": True},
             "outer_wall_ns": 100 if arm == ARMS[0] else 80}
            for group in range(2) for arm in ARMS]


class SessionCostAdmissionTests(unittest.TestCase):
    def report(self, rows=None, build=None):
        return summarize(observations() if rows is None else rows, groups=2, request_count=2,
                         shared_cost_ns=30, build_cost=build)

    def test_every_actual_session_and_one_full_build_are_charged_per_arm(self):
        result = self.report(build={"wall_ns": 1000, "target_cache": "empty"})
        self.assertEqual(result["standalone_total_cost_ns"], {ARMS[0]: 1230, ARMS[1]: 1190})
        self.assertTrue(result["sealed_transport_observed_total_lower"])
        self.assertFalse(result["compiler_vs_fixed_or_light_acceptance_changed"])
        self.assertFalse(result["native_ndu_advantage_established"])
        self.assertFalse(result["safety_certificate"])

    def test_unknown_warm_or_boolean_build_cost_cannot_pass_complete_cost_gate(self):
        for cost in (None, {}, {"wall_ns": 3, "target_cache": "existing"},
                     {"wall_ns": True, "target_cache": "empty"}):
            with self.subTest(cost=cost):
                result = self.report(build=cost)
                self.assertEqual(result["standalone_total_cost_ns"], dict.fromkeys(ARMS))
                self.assertFalse(result["complete_within_declared_scope"])
                self.assertFalse(result["sealed_transport_observed_total_lower"])

    def test_failed_incomplete_duplicate_or_unclosed_sessions_never_win(self):
        changes = (lambda rows: rows[1].update(status="failed"),
                   lambda rows: rows[1].update(requests_completed=1),
                   lambda rows: rows.pop(),
                   lambda rows: rows.append(deepcopy(rows[0])),
                   lambda rows: rows[1]["snapshot"].update(closed=False))
        for change in changes:
            rows = observations()
            change(rows)
            result = self.report(rows, {"wall_ns": 1000, "target_cache": "empty"})
            self.assertFalse(result["sealed_transport_observed_total_lower"])

    def test_response_mismatch_prevents_cost_qualification(self):
        rows = observations()
        rows[1]["response_sha256"][0] = "c" * 64
        result = self.report(rows, {"wall_ns": 1000, "target_cache": "empty"})
        self.assertTrue(result["all_sessions_completed"])
        self.assertFalse(result["all_actual_native_responses_match"])
        self.assertFalse(result["sealed_transport_observed_total_lower"])

    def test_registered_requests_bind_distinct_generations_and_refused_paths(self):
        corpus = requests(3)
        self.assertEqual([row["generation"] for row in corpus], [1, 2, 3])
        self.assertEqual(len({row["snapshot_digest"] for row in corpus}), 3)
        for request in corpus:
            self.assertTrue(any(not candidate["verified"] for candidate in request["candidates"]))
            self.assertEqual(request["candidates"][-1]["id"], "abstain")
            self.assertTrue(any(len(candidate["events"]) == 6 for candidate in request["candidates"]))


if __name__ == "__main__":
    unittest.main()
