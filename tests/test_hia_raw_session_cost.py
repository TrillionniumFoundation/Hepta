"""Protocol/accounting controls only: no native planner or benchmark runs."""
from collections import Counter
from contextlib import redirect_stdout
from copy import deepcopy
import gzip
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from tools import measure_hia_raw_session_cost as study


def protocol():
    case_rows = study.cases()
    return {"schema": study.SCHEMA, "fixed": study.definition(), "cases": case_rows,
            "schedule": study.schedule(case_rows), "binary": "/fixture/binary",
            "build_receipt": "/fixture/build", "binary_sha256": "f" * 64,
            "build_cost": {"wall_ns": None, "status": "unmeasured", "scope": None}}


class ClockFixture:
    """All times are synthetic; no subprocess or native operation occurs."""
    def __init__(self, fail_call=None, fail_close=False, fail_startup=False):
        self.now = 0
        self.calls = 0
        self.sessions = []
        self.fail_call = fail_call
        self.fail_close = fail_close
        self.fail_startup = fail_startup

    def response(self, mode):
        return {"bundle": {"plans": {"p": {"actions": [{"n": 1, "ready": False}]}}},
                "pareto_candidate_ids": ["p"], "selected_first_action": {"n": 1},
                "mode": mode, "measured": {"fixture_only": True}}

    def call(self, mode, session=None):
        self.calls += 1
        self.now += 30 if session else 50
        if self.calls == self.fail_call:
            raise RuntimeError("original fixture request failure")
        response = self.response(mode)
        receipt = {"binary_sha256": "f" * 64, "mode": mode,
                   "outer_wall_ns": 30 if session else 50, "stdout": json.dumps(response)}
        # This happens after the runtime's internal receipt clock. The outer
        # timer must retain it, for both public API return paths.
        self.now += 7 if session else 3
        if session:
            session.requests += 1
            receipt["sequence"] = session.requests
            session._last_received_frame = receipt["stdout"].encode()
        return response, receipt

    def invoke(self, binary, build, model, *, mode, timeout):
        return self.call(mode)

    def session(self, binary, build, *, timeout, image_check):
        self.now += 20
        if self.fail_startup:
            raise RuntimeError("fixture startup failure")
        owner = self

        class Session:
            def __init__(self):
                self.requests = 0
                self.closed = False
                self.close_count = 0
                self._fd = 123
                self._last_received_frame = b'{"fixture_hello":true}'
                self._process = SimpleNamespace(returncode=None,
                    stdin=SimpleNamespace(closed=False), stdout=SimpleNamespace(closed=False),
                    stderr=SimpleNamespace(closed=False))

            def evaluate(self, model, *, mode):
                if self.requests >= study.SESSION_LIMIT:
                    raise AssertionError("fixture received more than 256 requests")
                return owner.call(mode, self)

            def snapshot(self):
                return {"binary_sha256": "f" * 64, "closed": self.closed, "requests": self.requests,
                        "cleanup_errors": [], "stderr": "", "pid": 111}

            def close(self):
                owner.now += 5
                self.close_count += 1
                self.closed = True
                self._fd = None
                self._process.returncode = 0
                for pipe in (self._process.stdin, self._process.stdout, self._process.stderr):
                    pipe.closed = True
                if owner.fail_close and self is owner.sessions[0]:
                    raise RuntimeError("additional fixture close failure")

        session = Session()
        self.sessions.append(session)
        return session

    def run(self, registered):
        rows = []
        with patch.object(study.time, "monotonic_ns", lambda: self.now), \
                patch.object(study, "invoke", self.invoke), patch.object(study, "RawModelSession", self.session):
            observations = study._run_schedule(registered, rows.append)
        return observations, rows


class RawSessionCostTests(unittest.TestCase):
    def test_schedule_fixes_counts_alternation_and_actual_segment_boundaries(self):
        registered = protocol()
        rows = registered["schedule"]
        study.validate_definition(registered)
        self.assertEqual(len(rows), 2976)
        self.assertEqual(Counter(row["arm"] for row in rows), dict.fromkeys(study.ARMS, 744))
        self.assertEqual([row["slot"] for row in rows], list(range(2976)))
        for offset in range(0, len(rows), 4):
            group = rows[offset:offset + 4]
            case_index = offset // 4 % 24
            order = study.ARMS if (group[0]["round"] + case_index) % 2 == 0 else study.ARMS[::-1]
            self.assertEqual(tuple(row["arm"] for row in group), order)
        for arm in study.SESSION_ARMS:
            selected = [row for row in rows if row["arm"] == arm]
            self.assertEqual(Counter(row["segment"] for row in selected), {0: 256, 1: 256, 2: 232})
            self.assertEqual([row["sequence"] for row in selected], list(range(1, 257)) * 2 + list(range(1, 233)))

    def test_registration_rejects_definition_model_and_typed_slot_changes(self):
        original = protocol()
        for mutate in (
            lambda value: value["fixed"].__setitem__("rounds", 30),
            lambda value: value["fixed"].__setitem__("warmup_calls", False),
            lambda value: value["schedule"][0].__setitem__("slot", False),
            lambda value: value["schedule"].pop(),
            lambda value: value["cases"][0]["model"].__setitem__("generation", True),
        ):
            changed = deepcopy(original)
            mutate(changed)
            with self.assertRaisesRegex(ValueError, "fixed four-arm protocol"):
                study.validate_definition(changed)

    def test_every_decision_field_and_json_type_is_compared_for_all_six_pairs(self):
        fixture = ClockFixture()
        responses = {arm: fixture.response(study.MODES[arm]) for arm in study.ARMS}
        equal = study.compare_decisions(responses)
        self.assertTrue(equal["all_equal"])
        self.assertEqual(len(equal["pairs"]), 6)
        for field, replacement in (("bundle", {"plans": {}}), ("pareto_candidate_ids", []),
                                   ("selected_first_action", {"n": True}),
                                   ("selected_first_action", {"n": 1.0})):
            changed = deepcopy(responses)
            changed["session_ndu"][field] = replacement
            with self.subTest(field=field, replacement=replacement):
                result = study.compare_decisions(changed)
                self.assertFalse(result["all_equal"])
                self.assertEqual(sum(not row["fields_equal"][field] for row in result["pairs"]), 3)

    def test_synthetic_complete_run_counts_receipt_return_startup_and_close_once(self):
        registered = protocol()
        fixture = ClockFixture()
        observed, rows = fixture.run(registered)
        report = study.analyze(registered, observed, True)
        self.assertTrue(report["measurement_complete"])
        self.assertEqual(fixture.calls, 2976)
        self.assertEqual(len(fixture.sessions), 6)
        self.assertEqual(sorted(session.requests for session in fixture.sessions), [232, 232, 256, 256, 256, 256])
        self.assertTrue(all(session.close_count == 1 for session in fixture.sessions))
        self.assertEqual(len([row for row in rows if row["event"] == "decision-quartet"]), 744)
        for arm in study.ARMS:
            totals = report["arms"][arm]
            expected_call = 37 if arm in study.SESSION_ARMS else 53
            expected_overhead = 75 if arm in study.SESSION_ARMS else 0
            self.assertEqual(totals["call"]["sum_ns"], expected_call * 744)
            self.assertEqual(totals["standalone_service_ns"], expected_call * 744 + expected_overhead)
            self.assertIsNone(report["amortization"]["standalone_build_plus_service_ns"][arm])
        self.assertTrue(all(row["outer_observed_ns"] > row["api_reported_ns"] for row in observed["calls"]))
        self.assertFalse(report["full_application_lifecycle_advantage_established"])
        registered["build_cost"]["wall_ns"] = 23
        charged = study.analyze(registered, observed, True)
        for arm in study.ARMS:
            total = report["arms"][arm]["standalone_service_ns"]
            self.assertEqual(charged["amortization"]["standalone_build_plus_service_ns"][arm], total + 23)
            self.assertEqual(charged["amortization"]["amortized_build_plus_service_per_call_ns"][arm], (total + 23) / 744)

    def test_request_failure_stops_without_retry_and_preserves_original_and_cleanup_errors(self):
        registered = protocol()
        fixture = ClockFixture(fail_call=7, fail_close=True)
        observed, rows = fixture.run(registered)
        self.assertEqual(fixture.calls, 7)
        self.assertEqual(len(observed["calls"]), 7)
        self.assertEqual(observed["calls"][-1]["status"], "failure")
        self.assertTrue(all(session.close_count == 1 for session in fixture.sessions))
        messages = [row["error"]["message"] for row in observed["errors"]]
        self.assertIn("original fixture request failure", messages)
        self.assertIn("additional fixture close failure", messages)
        report = study.analyze(registered, observed, True)
        self.assertFalse(report["measurement_complete"])
        self.assertEqual(report["unattempted_calls"], 2969)
        self.assertTrue(all(row["standalone_service_ns"] is None for row in report["arms"].values()))
        self.assertTrue(all(row["service_cost_ratio"] is None for row in report["descriptive_comparisons"]))
        self.assertGreater(sum(row["observed_partial_service_ns"] for row in report["arms"].values()), 0)

    def test_startup_failure_keeps_elapsed_work_without_inventing_a_request(self):
        registered = protocol()
        fixture = ClockFixture(fail_startup=True)
        observed, rows = fixture.run(registered)
        self.assertEqual(fixture.calls, 2)
        self.assertEqual(observed["operations"][0]["status"], "failure")
        self.assertEqual(observed["operations"][0]["outer_observed_ns"], 20)
        self.assertEqual(observed["errors"][0]["phase"], "startup")
        self.assertFalse(study.analyze(registered, observed, True)["measurement_complete"])

    def test_original_record_failure_stops_requests_but_still_closes_acquired_sessions(self):
        registered = protocol()
        fixture = ClockFixture()

        def broken_writer(row):
            if row["event"] == "call-finish" and row["slot"] == 4:
                raise OSError("fixture evidence volume full")

        with patch.object(study.time, "monotonic_ns", lambda: fixture.now), \
                patch.object(study, "invoke", fixture.invoke), patch.object(study, "RawModelSession", fixture.session):
            observed = study._run_schedule(registered, broken_writer)
        self.assertEqual(fixture.calls, 5)
        self.assertEqual(len(fixture.sessions), 2)
        self.assertTrue(all(session.closed and session.close_count == 1 for session in fixture.sessions))
        self.assertEqual(observed["errors"][0]["phase"], "original-record-write")
        self.assertFalse(study.analyze(registered, observed, True)["measurement_complete"])

    def test_tampered_registration_is_logged_before_any_native_api_and_cannot_replay(self):
        registered = protocol()
        registered["fixed"]["rounds"] = 1
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "REGISTRATION.json").write_text(json.dumps(registered))
            with patch.object(study, "invoke") as invoke, patch.object(study, "RawModelSession") as session:
                with redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
                    study.execute(SimpleNamespace(output=output))
                invoke.assert_not_called()
                session.assert_not_called()
            report = json.loads((output / "RESULT.json").read_bytes())
            self.assertFalse(report["measurement_complete"])
            self.assertEqual(report["attempted_calls"], 0)
            errors = json.loads((output / "ERRORS.json").read_bytes())
            self.assertIn("fixed four-arm protocol", errors[0]["error"]["message"])
            original = (output / "ORIGINAL.jsonl").read_bytes()
            self.assertEqual(gzip.decompress((output / "ORIGINAL.jsonl.gz").read_bytes()), original)
            with self.assertRaisesRegex(ValueError, "cannot be replayed"):
                study.execute(SimpleNamespace(output=output))

    def test_existing_build_cost_admission_keeps_unknown_and_refuses_malformed_measurement(self):
        self.assertIsNone(study.build_cost_observation({})["wall_ns"])
        self.assertIsNone(study.build_cost_observation({"build_cost": None})["wall_ns"])
        with self.assertRaises(ValueError):
            study.build_cost_observation({"build_cost": {"wall_ns": False}})


if __name__ == "__main__":
    unittest.main()
