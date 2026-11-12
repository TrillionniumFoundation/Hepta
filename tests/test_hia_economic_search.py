"""Finite measured continuation plans and the actual original NDU engine."""
import copy
import os
import unittest

from hepta.hia_economic_search import EconomicSearchRejected, choose_measurement, measurement_request
from hepta.hia_ndu import NduBridge


def snapshot():
    return {"baseline_sha256": "a" * 64, "objective_sha256": "b" * 64,
        "baseline_lower_ps": 10000, "expected_calls": 100_000_000,
        "spent_search_ns": 100_000, "remaining_budget_ns": 500_000_000,
        "remaining_measurements": 6, "sample_quorum": 2,
        "publication_estimate_ns": 10_000_000, "generation": 1,
        "candidates": [dict(id=cid, program_sha256=digest*64, support_sha256="e"*64,
            runtime_upper_ps=runtime, prepare_estimate_ns=prepare, sample_estimate_ns=2_000_000,
            successful_samples=0, prepared=False, blocked=False)
            for cid, digest, runtime, prepare in (("fast", "c", 6000, 20_000_000),
                                                   ("slow", "d", 8000, 5_000_000))]}


class EconomicSearchModelTests(unittest.TestCase):
    def test_multistage_cost_can_choose_slower_kernel_and_replan_after_feedback(self):
        state = snapshot()
        state["candidates"][0]["prepare_estimate_ns"] = 300_000_000
        first = choose_measurement(state, backend="arithmetic")
        self.assertEqual(first["action"], {"kind": "measure", "candidate_id": "slow"})
        self.assertEqual(first["actions"]["measure_slow"]["future_stage_costs_ns"],
                         [5_000_000, 2_000_000, 2_000_000, 10_000_000])
        # One actual observation is not a quorum and cannot become an incumbent.
        row = state["candidates"][1]
        row.update(prepared=True, successful_samples=1, runtime_upper_ps=12000)
        state["candidates"][0]["blocked"] = True
        later = choose_measurement(state, backend="arithmetic")
        self.assertEqual(later["action"], {"kind": "stop", "candidate_id": "abstain"})
        self.assertNotEqual(first["request"]["snapshot_digest"], later["request"]["snapshot_digest"])

    def test_ready_incumbent_stops_when_new_measurement_is_not_worth_cost(self):
        state = snapshot()
        state["candidates"][0].update(prepared=True, successful_samples=2)
        choice = choose_measurement(state, backend="arithmetic")
        self.assertEqual(choice["action"], {"kind": "stop", "candidate_id": "fast"})
        self.assertNotIn("measure_fast", choice["actions"])
        self.assertFalse(choice["claims"]["HIA_safety_proved"])

    def test_measurement_quorum_wall_budget_blocked_actions_and_horizon_are_hard_limits(self):
        for mutation in (lambda s: s.update(remaining_measurements=1),
                         lambda s: s.update(remaining_budget_ns=1),
                         lambda s: s.update(expected_calls=0),
                         lambda s: [r.update(blocked=True) for r in s["candidates"]]):
            state = snapshot()
            mutation(state)
            decision = choose_measurement(state, backend="arithmetic")
            self.assertEqual(decision["action"], {"kind": "stop", "candidate_id": "abstain"})

    def test_paid_cost_is_bound_but_not_double_charged_to_future_continuations(self):
        first = choose_measurement(snapshot(), backend="arithmetic")
        changed = snapshot()
        changed["spent_search_ns"] += 100_000_000
        later = choose_measurement(changed, backend="arithmetic")
        self.assertEqual(first["action"], later["action"])
        self.assertEqual(first["actions"], later["actions"])
        self.assertNotEqual(first["request"]["snapshot_digest"], later["request"]["snapshot_digest"])

    def test_snapshots_are_detached_and_malformed_observations_fail_closed(self):
        state = snapshot()
        saved = copy.deepcopy(state)
        request = measurement_request(state)
        self.assertEqual(saved, state)
        state["candidates"][0]["runtime_upper_ps"] = 99999
        self.assertEqual(request["snapshot"], saved)
        changes = [lambda s: s.update(remaining_measurements=True),
                   lambda s: s.update(untrusted_permission=True),
                   lambda s: s["candidates"][0].update(program_sha256="0"*64),
                   lambda s: s["candidates"][0].update(successful_samples=1),
                   lambda s: s["candidates"][0].update(blocked=1),
                   lambda s: s["candidates"][1].update(id="fast"),
                   lambda s: s["candidates"][0].update(runtime_upper_ps=0.1)]
        for change in changes:
            broken = snapshot()
            change(broken)
            with self.assertRaises(EconomicSearchRejected):
                measurement_request(broken)
        with self.assertRaises(EconomicSearchRejected):
            choose_measurement(snapshot(), backend="ndu")


@unittest.skipUnless(os.environ.get("HEPTA_RECURSIVE_NDU_IDENTITY")
                     and os.environ.get("HEPTA_RECURSIVE_NDU_BRIDGE"),
                     "actual pinned recursive NDU bridge is required")
class NativeEconomicSearchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bridge = NduBridge.from_environment()

    def test_real_native_recursion_matches_strong_control_over_finite_feedback_states(self):
        states = []
        for calls in (0, 5_000_000, 100_000_000):
            for count in (0, 1, 2):
                state = snapshot()
                state["expected_calls"] = calls
                state["candidates"][0].update(successful_samples=count, prepared=count > 0)
                states.append(state)
        for mutation in (lambda s: s.update(remaining_measurements=0),
                         lambda s: s.update(remaining_budget_ns=1),
                         lambda s: s["candidates"][0].update(blocked=True)):
            state = snapshot()
            mutation(state)
            states.append(state)
        for state in states:
            with self.subTest(calls=state["expected_calls"], candidates=state["candidates"]):
                native = choose_measurement(state, backend="ndu", bridge=self.bridge)
                simple = choose_measurement(state, backend="arithmetic")
                self.assertEqual(native["action"], simple["action"])
                self.assertEqual(native["request"], simple["request"])
                self.assertTrue(native["claims"]["native_recursive_utility_invoked"])
                self.assertEqual(native["native_response"]["identity"]["source_commit"],
                                 "2590c0c94c5bf9a9004caeeb7b75edd6faf3eb8b")
                for path in native["native_response"]["paths"]:
                    row = next(r for r in native["request"]["candidates"] if r["id"] == path["id"])
                    expected = [row["terminal_q32"]]
                    for step in reversed(row["events"]):
                        expected.insert(0, step["instant_q32"] + expected[0])
                    self.assertEqual(path["values_q32"], expected)

    def test_tie_and_foreign_pin_do_not_silently_become_arbitrary_native_choices(self):
        state = snapshot()
        state["candidates"][1].update(runtime_upper_ps=6000, prepare_estimate_ns=20_000_000)
        native = choose_measurement(state, backend="ndu", bridge=self.bridge)
        self.assertIsNone(native["native_response"]["advisory_candidate_id"])
        self.assertEqual(native["action"], {"kind": "stop", "candidate_id": "abstain"})
        self.assertEqual(native["action"], choose_measurement(state, backend="arithmetic")["action"])
        old = self.bridge.manifest["identity"]["source_commit"]
        try:
            self.bridge.manifest["identity"]["source_commit"] = "d3c2d760eca5065fc966820379c35c6e8d56e855"
            with self.assertRaisesRegex(EconomicSearchRejected, "pin mismatch"):
                choose_measurement(snapshot(), backend="ndu", bridge=self.bridge)
        finally:
            self.bridge.manifest["identity"]["source_commit"] = old


if __name__ == "__main__":
    unittest.main()
