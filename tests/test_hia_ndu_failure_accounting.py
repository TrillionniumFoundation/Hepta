"""Synthetic clock/failure controls, not process or performance observations."""
from copy import deepcopy
import unittest
from unittest.mock import patch

from hepta import hia_ndu_cost as cost
from tests.test_hia_ndu_cost import fixture
from tools.qualify_hia_ndu_cost import episodes_without_native_start


def episode(*decisions):
    return {"policy": "native_ndu",
            "native_invocations": sum(int(row["native_invoked"]) for row in decisions),
            "steps": [{"decision": row} for row in decisions]}


class FailureAccountingTests(unittest.TestCase):
    def test_failed_factory_keeps_cost_without_claiming_process_state(self):
        for elapsed in (0, 250_000):
            for simulated_process_created in (False, True):
                with self.subTest(elapsed=elapsed, process_created=simulated_process_created):
                    clock, events = [0], []
                    def factory():
                        # Both pre-spawn refusal and post-spawn handshake failure
                        # can escape the factory. This is only an injected marker.
                        events.append(simulated_process_created)
                        clock[0] += elapsed
                        raise cost.NduBridgeError("controlled startup refusal")
                    controller = cost.AdvisoryController(factory)
                    with patch.object(cost.time, "monotonic_ns", side_effect=lambda: clock[0]):
                        action, row = controller.decide(fixture(1))
                    self.assertEqual(events, [simulated_process_created])
                    self.assertEqual(row["startup_ns"], elapsed)
                    self.assertIs(row.get("startup_attempted"), True)
                    self.assertIs(row.get("session_ready_before"), False)
                    self.assertFalse(row["native_invoked"])
                    self.assertEqual(row["request_ns"], 0)
                    self.assertEqual(row["wall_ns"], elapsed)
                    self.assertEqual(row["native_error"], "controlled startup refusal")
                    self.assertEqual(row["reason"], "native refusal; retain admitted incumbent")
                    self.assertEqual(action["mode"], "skip")
                    self.assertEqual(action["acquired"], [])
                    self.assertIsNone(controller.session)
                    self.assertNotIn("response", row)
                    self.assertNotIn("process_started", row)
                    self.assertEqual(episodes_without_native_start([episode(row)]), 0)

    def test_failed_request_keeps_cost_and_cleanup_for_new_or_existing_session(self):
        for existing in (False, True):
            for elapsed in (0, 23, 1_000_001):
                with self.subTest(existing=existing, elapsed=elapsed):
                    clock, closed, started = [0], [], []
                    class Session:
                        def evaluate(self, request):
                            clock[0] += elapsed
                            raise cost.NduBridgeError("controlled request refusal")
                        def close(self):
                            closed.append(True)
                            clock[0] += 7
                    def factory():
                        started.append(True)
                        clock[0] += 17
                        return Session()
                    controller = cost.AdvisoryController(factory)
                    if existing:
                        controller.session = Session()
                    model = fixture(1)
                    model["session_ready"] = existing
                    with patch.object(cost.time, "monotonic_ns", side_effect=lambda: clock[0]):
                        action, row = controller.decide(model)
                    self.assertEqual(row["startup_ns"], 0 if existing else 17)
                    self.assertIs(row.get("startup_attempted"), not existing)
                    self.assertIs(row.get("session_ready_before"), existing)
                    self.assertEqual(row["request_ns"], elapsed)
                    self.assertEqual(row["wall_ns"], elapsed + 7 + (0 if existing else 17))
                    self.assertEqual(started, [] if existing else [True])
                    self.assertEqual(closed, [True])
                    self.assertIsNone(controller.session)
                    self.assertTrue(row["native_invoked"])
                    self.assertEqual(row["native_error"], "controlled request refusal")
                    self.assertNotIn("response", row)
                    self.assertNotIn("optional_action_withheld", row)
                    self.assertEqual(action["mode"], "skip")
                    self.assertEqual(action["acquired"], [])
                    self.assertEqual(episodes_without_native_start([episode(row)]), 0)

    def test_failed_startup_without_feasible_incumbent_remains_refusal(self):
        model = fixture(1)
        model["baseline"]["latency_ns"] = [2_000_000]
        controller = cost.AdvisoryController(
            lambda: (_ for _ in ()).throw(cost.NduBridgeError("controlled refusal")))
        with patch.object(cost.time, "monotonic_ns", return_value=0):
            action, row = controller.decide(model)
        self.assertIsNone(action)
        self.assertIs(row.get("startup_attempted"), True)
        self.assertEqual(row["reason"], "native refusal; retain admitted incumbent")

    def test_failure_then_retry_keeps_separate_attempt_costs(self):
        clock, attempts = [0], []
        model = fixture(1)
        bundle = cost.build_request(model)
        best = min(bundle["plans"], key=lambda key: bundle["plans"][key]["total_ns"])
        response = {"authority": "DENY_ALL", "safety_certificate": False,
                    "pareto_candidate_ids": [best]}
        class Session:
            def evaluate(self, request):
                clock[0] += 20
                return response
        def factory():
            attempts.append(True)
            clock[0] += 10
            if len(attempts) == 1:
                raise cost.NduBridgeError("first attempt")
            return Session()
        controller = cost.AdvisoryController(factory)
        with patch.object(cost.time, "monotonic_ns", side_effect=lambda: clock[0]):
            _, first = controller.decide(model)
            saved = deepcopy(first)
            action, second = controller.decide(model)
        self.assertEqual(first, saved)
        self.assertEqual(controller.ledger, [first, second])
        self.assertEqual((first["startup_ns"], second["startup_ns"]), (10, 10))
        self.assertEqual((first["request_ns"], second["request_ns"]), (0, 20))
        self.assertEqual((first["wall_ns"], second["wall_ns"]), (10, 30))
        self.assertTrue(all(row.get("startup_attempted") is True for row in controller.ledger))
        self.assertIs(second["response"], response)
        self.assertNotIn("native_error", second)
        self.assertEqual(action["mode"], "invoke")
        self.assertEqual(episodes_without_native_start([episode(first, second)]), 0)

    def test_late_successful_startup_is_not_a_no_start_episode(self):
        clock, evaluated = [0], []
        class Session:
            def evaluate(self, request):
                evaluated.append(True)
                raise AssertionError("startup consumed budget")
        def factory():
            clock[0] = 1_000_001
            return Session()
        controller = cost.AdvisoryController(factory)
        with patch.object(cost.time, "monotonic_ns", side_effect=lambda: clock[0]):
            action, row = controller.decide(fixture(1))
        self.assertIs(row.get("startup_attempted"), True)
        self.assertEqual(row["startup_ns"], 1_000_001)
        self.assertFalse(row["native_invoked"])
        self.assertEqual(evaluated, [])
        self.assertIsNotNone(controller.session)
        self.assertEqual(action["mode"], "skip")
        self.assertEqual(row["reason"], "actual session startup exhausted optional budget")
        self.assertEqual(episodes_without_native_start([episode(row)]), 0)

    def test_skip_with_existing_session_does_not_claim_no_session(self):
        model = fixture(1)
        model["session_ready"] = True
        model["baseline"]["latency_ns"] = [0]
        controller = cost.AdvisoryController(lambda: self.fail("unexpected startup"))
        controller.session = object()
        with patch.object(cost.time, "monotonic_ns", return_value=0):
            action, row = controller.decide(model)
        self.assertIs(row.get("startup_attempted"), False)
        self.assertIs(row.get("session_ready_before"), True)
        self.assertEqual(row["startup_ns"], 0)
        self.assertFalse(row["native_invoked"])
        self.assertEqual(action["mode"], "skip")
        self.assertEqual(episodes_without_native_start([episode(row)]), 0)

    def test_non_bridge_exception_is_not_converted_to_a_native_refusal(self):
        error = RuntimeError("unrelated failure")
        def factory():
            raise error
        controller = cost.AdvisoryController(factory)
        with patch.object(cost.time, "monotonic_ns", return_value=0):
            with self.assertRaises(RuntimeError) as caught:
                controller.decide(fixture(1))
        self.assertIs(caught.exception, error)
        self.assertEqual(controller.ledger, [])


class NoStartEvidenceTests(unittest.TestCase):
    def skipped(self):
        model = fixture(1)
        model["decision"]["startup_ns"] = 100_000
        controller = cost.AdvisoryController(lambda: self.fail("unexpected startup"))
        with patch.object(cost.time, "monotonic_ns", return_value=0):
            _, decision = controller.decide(model)
        return episode(decision)

    def test_explicit_skips_count_once_without_mutating_receipts(self):
        row = self.skipped()
        saved = deepcopy(row)
        self.assertIs(row["steps"][0]["decision"].get("startup_attempted"), False)
        self.assertIs(row["steps"][0]["decision"].get("session_ready_before"), False)
        self.assertEqual(episodes_without_native_start([row]), 1)
        self.assertEqual(row, saved)

    def test_legacy_receipts_without_attempt_evidence_are_unknown(self):
        row = self.skipped()
        for field in ("startup_attempted", "session_ready_before"):
            changed = deepcopy(row)
            changed["steps"][0]["decision"].pop(field, None)
            with self.subTest(field=field):
                self.assertEqual(episodes_without_native_start([changed]), 0)

    def test_unknown_or_conflicting_decision_evidence_cannot_count(self):
        row = self.skipped()
        mutations = [(field, value) for field in
                     ("startup_attempted", "session_ready_before", "native_invoked")
                     for value in (True, None, 0, 1, "false", [], {})]
        mutations += [("startup_ns", value) for value in (None, False, 0.0, -1, 1, "0")]
        mutations += [("native_error", "refusal"), ("native_error", None), ("response", {})]
        for field, value in mutations:
            changed = deepcopy(row)
            changed["steps"][0]["decision"][field] = value
            with self.subTest(field=field, value=value):
                self.assertEqual(episodes_without_native_start([changed]), 0)

    def test_episode_receipts_require_zero_calls_no_session_and_nonempty_steps(self):
        row = self.skipped()
        changes = [{"native_invocations": value} for value in (None, False, 0.0, -1, 1, "0")]
        changes += [{"native_session": None}, {"native_session": {}}, {"steps": []}, {"policy": "fixed"}]
        for change in changes:
            with self.subTest(change=change):
                self.assertEqual(episodes_without_native_start([{**row, **change}]), 0)
        mixed = deepcopy(row)
        mixed["steps"].append({"decision": {**mixed["steps"][0]["decision"], "startup_attempted": True}})
        self.assertEqual(episodes_without_native_start([mixed]), 0)


if __name__ == "__main__":
    unittest.main()
