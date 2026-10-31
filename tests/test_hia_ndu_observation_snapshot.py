"""Bounded caller-owned observation intake, with no native/solver execution.

Proof, native advice and the cost clock are explicit test doubles. These tests
exercise the real Core checker and ranker's observation admission/consumption;
they are neither NDU value evidence nor executable-program proof evidence.
"""
from contextlib import contextmanager
import copy
from hashlib import sha256
from itertools import count
import json
import sys
import unittest
from unittest.mock import patch

from hepta import hia_ndu_optimizer as optimizer
from tests.test_hia_ndu_optimizer import baseline_program, observation, proposal


class ObservationSnapshotTests(unittest.TestCase):
    boundary_observations = []

    def setUp(self):
        self.baseline = baseline_program()
        self.candidates = [proposal()]
        self.observations = {
            "abstain": observation(self.baseline, 100_000),
            "cancel": observation(self.candidates[0]["program"], 1_000),
        }
        self.objective = {
            "expected_calls": 1_000, "resource_cap_ns": 5_000_000_000,
            "target": "x86_64-unknown-linux-gnu",
            "measurement_profile": "controlled-observation-intake-not-performance",
        }
        self.calls = None

    def rank(self, recommendation="cancel"):
        clock = count(0, 100_000)
        with patch.object(optimizer, "_fresh_proof", return_value=(True, {"test_double": True})) as proof, \
                patch.object(optimizer, "_native_rank", return_value=(
                    {"advisory_recommendation": recommendation}, {"test_double": True})) as native, \
                patch.object(optimizer.time, "perf_counter_ns", side_effect=lambda: next(clock)):
            try:
                return optimizer.rank_candidates(
                    self.baseline, self.candidates, self.observations,
                    function="calculate", bridge={}, objective=self.objective)
            finally:
                self.calls = {"controlled_proof": proof.call_count,
                              "controlled_native": native.call_count}

    @contextmanager
    def after_capture(self, cid, action):
        """Deterministically schedule a caller mutation after its row is copied."""
        fired = []
        previous = sys.gettrace()
        def schedule(frame, event, unused):
            if (event == "line" and not fired
                    and frame.f_globals.get("__name__") == optimizer.__name__):
                captured = frame.f_locals.get("observed")
                if type(captured) is dict and cid in captured:
                    fired.append(True)
                    action()
            return schedule
        try:
            sys.settrace(schedule)
            yield fired
        finally:
            sys.settrace(previous)

    def assert_no_external_work(self):
        self.assertEqual(self.calls, {"controlled_proof": 0, "controlled_native": 0})

    def test_negative_captured_runtime_cannot_be_laundered_by_later_valid_caller_value(self):
        self.observations["cancel"]["runtime_ns"] = -1
        with self.after_capture("cancel", lambda: self.observations["cancel"].update(runtime_ns=1)) as fired:
            with self.assertRaises(optimizer.OptimizationRejected):
                self.rank()
        self.assertEqual(fired, [True])
        self.assert_no_external_work()

    def test_boolean_captured_runtime_cannot_be_laundered_by_later_integer(self):
        self.observations["cancel"]["runtime_ns"] = True
        with self.after_capture("cancel", lambda: self.observations["cancel"].update(runtime_ns=1)) as fired:
            with self.assertRaises(optimizer.OptimizationRejected):
                self.rank()
        self.assertEqual(fired, [True])
        self.assert_no_external_work()

    def test_later_caller_changes_do_not_replace_validated_costs_or_their_digest(self):
        expected = copy.deepcopy(self.observations)
        def mutate():
            self.observations["cancel"].update(runtime_ns="now-invalid", program_sha256=[])
        with self.after_capture("cancel", mutate) as fired:
            try:
                result = self.rank()
            except Exception as error:
                self.fail("caller changes escaped the captured observation: " + type(error).__name__)
        self.assertEqual(fired, [True])
        self.assertTrue(result["admitted"])
        self.assertEqual(result["candidate_reports"][0]["observation"], expected["cancel"])
        raw = json.dumps(expected, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode()
        self.assertEqual(result["observations_sha256"], sha256(raw).hexdigest())
        row = result["native_request"]["candidates"][1]
        charged = (expected["cancel"]["runtime_ns"] * self.objective["expected_calls"]
                   + result["costs"]["search_at_native_rank_ns"])
        self.assertEqual(row["cost_q32"], optimizer.ns_to_ms_q32(charged))

    def test_outer_mapping_change_has_the_public_refusal_type_and_no_external_work(self):
        def mutate():
            self.observations["unexpected"] = copy.deepcopy(self.observations["cancel"])
        caught = None
        with self.after_capture("abstain", mutate) as fired:
            try:
                self.rank()
            except Exception as error:
                caught = error
        self.assertEqual(fired, [True])
        self.assertIsInstance(caught, optimizer.OptimizationRejected)
        self.assert_no_external_work()

    def test_subclasses_and_mutable_values_are_rejected_before_external_work(self):
        class HostileDict(dict):
            def items(self):
                raise AssertionError("subclass hook must not run")
        class HostileInt(int):
            def __repr__(self):
                raise AssertionError("integer conversion hook must not run")
        class HostileString(str):
            def __str__(self):
                raise AssertionError("string conversion hook must not run")
        valid = copy.deepcopy(self.observations)
        cases = [
            lambda: HostileDict(valid),
            lambda: {**valid, "cancel": HostileDict(valid["cancel"])},
            lambda: {**valid, "cancel": {**valid["cancel"], "runtime_ns": HostileInt(1)}},
            lambda: {**valid, "cancel": {**valid["cancel"], "program_sha256": HostileString("1" * 64)}},
            lambda: {**valid, "cancel": {**valid["cancel"], "runtime_ns": []}},
            lambda: {**valid, "cancel": {**valid["cancel"], "uncertainty_ns": {}}},
            lambda: {**valid, "cancel": {**valid["cancel"], "search_ns": (0,)}},
            lambda: {**valid, "cancel": {**valid["cancel"], "program_sha256": []}},
        ]
        for number, make in enumerate(cases):
            with self.subTest(number=number):
                self.observations = make()
                with self.assertRaises(optimizer.OptimizationRejected):
                    self.rank()
                self.assert_no_external_work()

    def test_unknown_or_missing_rows_and_fields_are_rejected(self):
        valid = copy.deepcopy(self.observations)
        cases = [
            {"abstain": valid["abstain"]},
            {**valid, "unknown": valid["cancel"]},
            {"abstain": valid["abstain"], "unknown": valid["cancel"]},
            {**valid, "cancel": {**valid["cancel"], "unknown": 0}},
            {**valid, "cancel": {k: v for k, v in valid["cancel"].items() if k != "runtime_ns"}},
            {**valid, "cancel": {"program_sha256": valid["cancel"]["program_sha256"],
                                "runtime_ns": 1, "uncertainty_ns": 0, "unknown": 0}},
        ]
        for number, value in enumerate(cases):
            with self.subTest(number=number):
                self.observations = value
                with self.assertRaises(optimizer.OptimizationRejected):
                    self.rank()
                self.assert_no_external_work()

    def test_all_33_legal_observations_are_bound_and_charged_once(self):
        self.candidates = [proposal(cid="candidate" + str(index)) for index in range(32)]
        self.observations = {"abstain": observation(self.baseline, 100_000, search_ns=1)}
        for index, row in enumerate(self.candidates):
            self.observations[row["id"]] = observation(row["program"], 1_000, search_ns=index + 2)
        result = self.rank(recommendation=None)
        self.assertEqual(len(result["candidate_reports"]), 32)
        self.assertEqual(result["costs"]["supplied_search_ns"], sum(range(1, 34)))
        self.assertEqual(len(result["native_request"]["candidates"]), 33)
        self.assertEqual(result["selected_id"], "abstain")
        expected = json.dumps(self.observations, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=False, allow_nan=False).encode()
        self.assertEqual(result["observations_sha256"], sha256(expected).hexdigest())

    def test_excessive_mapping_width_is_refused_before_row_value_conversion(self):
        self.observations["cancel"].update({"extra" + str(index): object() for index in range(100)})
        with self.assertRaises(optimizer.OptimizationRejected):
            self.rank()
        self.assert_no_external_work()

    def test_candidate_list_growth_is_refused_before_overflow_verification_or_external_work(self):
        self.candidates = [proposal(cid="candidate" + str(index)) for index in range(32)]
        self.observations = {"abstain": observation(self.baseline, 100_000)}
        for row in self.candidates:
            self.observations[row["id"]] = observation(row["program"], 1_000)
        overflow = proposal(cid="overflow")
        overflow_observation = observation(overflow["program"], 1_000)
        first = self.candidates[0]["program"]
        original_verify = optimizer.verify_program
        verified, appended = [], []

        def append_during_verification(program):
            if program is not self.baseline:
                verified.append(program)
            if program is first and not appended:
                # The ordinary caller-owned list already passed len <= 32.
                # This callback schedules one finite mutation; the Core
                # verifier still executes normally for each supplied input.
                self.candidates.append(overflow)
                self.observations["overflow"] = overflow_observation
                appended.append(True)
            return original_verify(program)

        caught, result = None, None
        with patch.object(optimizer, "verify_program", side_effect=append_during_verification):
            try:
                result = self.rank(recommendation=None)
            except Exception as error:
                caught = error
        type(self).boundary_observations.append({
            "case": "caller_appends_candidate_after_initial_length_check",
            "initial_candidates": 32, "caller_candidates_after": len(self.candidates),
            "caller_observations_after": len(self.observations),
            "append_events": len(appended), "candidate_verifications": len(verified),
            "overflow_verified": any(program is overflow["program"] for program in verified),
            "refusal_type": type(caught).__name__ if caught is not None else None,
            "refusal": str(caught) if caught is not None else None,
            "returned_candidate_reports": len(result["candidate_reports"]) if result else None,
            "returned_native_rows": len(result["native_request"]["candidates"]) if result else None,
            "controlled_calls": dict(self.calls),
        })
        self.assertEqual(appended, [True])
        self.assertIsInstance(caught, optimizer.OptimizationRejected)
        self.assertIn("thirty-two", str(caught))
        self.assertEqual(len(verified), 32)
        self.assertFalse(any(program is overflow["program"] for program in verified))
        self.assert_no_external_work()

    def test_snapshot_helper_independently_refuses_more_than_33_expected_rows(self):
        expected = {"abstain", *("candidate" + str(index) for index in range(33))}
        observations = {cid: dict(self.observations["cancel"]) for cid in expected}
        caught, captured = None, None
        with patch.object(optimizer, "_integer", wraps=optimizer._integer) as validate:
            try:
                captured = optimizer._observation_snapshot(observations, expected)
            except Exception as error:
                caught = error
        type(self).boundary_observations.append({
            "case": "helper_34_expected_rows_without_public_entry",
            "expected_ids": len(expected), "input_rows": len(observations),
            "captured_rows": len(captured) if captured is not None else None,
            "cost_validations": validate.call_count,
            "refusal_type": type(caught).__name__ if caught is not None else None,
            "refusal": str(caught) if caught is not None else None,
        })
        self.assertIsInstance(caught, optimizer.OptimizationRejected)
        self.assertEqual(validate.call_count, 0)


if __name__ == "__main__":
    unittest.main()
