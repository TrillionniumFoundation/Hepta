"""No-model admission, quality and failure-retention controls for the new study.

Real native execution is the separate mandatory development command. These
unit tests do not turn mocked processes into native study evidence.
"""
from copy import deepcopy
import lzma
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from experiments.hia_ndu_identical_inputs_continuation_20261030 import planning, study


class InputAndOracleTests(unittest.TestCase):
    def test_formal_seed_cannot_be_relabelled_development_or_run_without_registration(self):
        with self.assertRaises(ValueError):
            planning.fields(0, seed=planning.SEEDS["formal"], phase="development")
        with self.assertRaises(ValueError):
            planning.fields(0, seed=planning.SEEDS["formal"], phase="formal")
        with self.assertRaises(ValueError):
            planning.fields(0, seed=planning.SEEDS["development"], phase="formal", permit_formal=True)

    def test_indices_and_seed_require_exact_bounded_integer_types(self):
        for index in (True, -1, 4096):
            with self.subTest(index=index), self.assertRaises(ValueError):
                planning.fields(index, seed=planning.SEEDS["development"], phase="development")
        with self.assertRaises(ValueError):
            planning.fields(0, seed=True, phase="development")

    def test_shared_graph_enumeration_is_complete_for_all_development_regimes(self):
        counts = []
        for index, states in enumerate((2, 4, 8)):
            packet = planning.packet(index, seed=planning.SEEDS["development"], phase="development")
            self.assertEqual(len(packet["fields"]["states"]), states)
            self.assertTrue(packet["bundle"]["enumeration_complete"])
            raw = planning.canonical(packet["bundle"]["request"])
            self.assertEqual(raw.decode(), packet["canonical_request"])
            counts.append(len(packet["bundle"]["request"]["candidates"]))
        self.assertEqual(counts, [24, 95, 95])

    def test_exact_q32_fraction_ties_and_one_unit_resource_boundary(self):
        requests = dict(study.tiny_requests())
        one = planning.python_oracle(requests["q32-fraction-and-inclusive-budget"])
        self.assertEqual(one["values_q32"]["tiny-a"][0], 3*planning.Q32-1)
        self.assertEqual(one["frontier"], ["tiny-a"])
        tied = planning.python_oracle(requests["complete-value-tie"])
        self.assertEqual(tied["frontier"], ["tiny-a", "tiny-b"])
        self.assertIsNone(tied["selected"])
        over = planning.python_oracle(requests["one-q32-unit-over-budget"])
        self.assertEqual(over["frontier"], ["abstain"])
        self.assertEqual(set(over["rejected"]), {"tiny-a", "tiny-b"})

    def test_infeasible_candidates_keep_full_value_tables_and_explicit_abstention(self):
        request = dict(study.tiny_requests())["only-explicit-abstain-feasible"]
        result = planning.python_oracle(request)
        self.assertEqual(set(result["values_q32"]), {"tiny-a", "tiny-b", "abstain"})
        self.assertEqual(result["evaluated"], ["abstain"])
        self.assertEqual(result["selected"], "abstain")

    def test_myopic_ties_are_not_turned_into_arbitrary_execution_choices(self):
        request = dict(study.tiny_requests())["complete-value-tie"]
        tail = deepcopy(request["candidates"][1]["events"][-1])
        tail["event_digest"] = planning.digest(["different-third-event"])
        request["candidates"][1]["events"].append(tail)
        exact = planning.python_oracle(request)
        myopic = planning.python_oracle(request, myopic=True)
        self.assertEqual(exact["frontier"], ["tiny-a"])
        self.assertEqual(myopic["frontier"], ["tiny-a", "tiny-b"])
        self.assertIsNone(myopic["selected"])
        self.assertEqual(exact["full_optimum_q32"]-myopic["values_q32"]["tiny-b"][0], planning.Q32)


class RuntimeAccountingBoundaryTests(unittest.TestCase):
    def test_byte_identity_is_checked_before_native_invocation(self):
        class Endpoint:
            calls = 0
            def __init__(self): pass
            def _invoke(self, arguments, payload):
                self.calls += 1
                return {}
        class Timed(study.TransportTiming, Endpoint): pass
        session = Timed()
        session.expect(b'{"same":1}')
        with self.assertRaises(ValueError):
            session._invoke([], b'{"same":2}')
        self.assertEqual(session.calls, 0)

    def test_journal_losslessly_retains_exact_wire_frame(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/"wire.xz"
            frame = '{"response":"λ","sequence":1}\n'
            journal = study.Journal(path)
            journal.put({"raw_response_frame": frame})
            journal.close()
            with lzma.open(path, "rt") as stream:
                saved = json.loads(stream.read())
            self.assertEqual(saved["raw_response_frame"].encode(), frame.encode())
            self.assertEqual(journal.snapshot()["rows"], 1)

    def test_formal_denominator_and_registration_guard_precede_any_generation(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(planning, "packet") as generate:
            with self.assertRaises(ValueError):
                study.execute({}, Path(temp)/"formal", phase="formal", count=2048)
            generate.assert_not_called()
            self.assertFalse((Path(temp)/"formal").exists())

    def test_quality_failure_preserves_started_request_and_actual_response_frame(self):
        frame = b'{"actual":"mismatched-native-response"}\n'
        class FailedAdvice:
            transport_parse_ns = [7]
            _request_costs_ns = [9]
            _last_received_frame = frame
            def expect(self, payload):
                self.sent_request_digests = [study.sha256(payload).hexdigest()]
            def evaluate(self, request): return {"bad": True}
            def close(self): pass
            def snapshot(self): return {"mock_unit_process": True}
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)/"run"
            manifests = {}
            for arm in planning.ARMS:
                path = Path(temp)/(arm+".json")
                path.write_text("{}")
                manifests[arm] = path
            with patch.object(study, "open_session", side_effect=lambda *args: FailedAdvice()), \
                 patch.object(planning, "compare_receipt", side_effect=ValueError("quality mismatch")):
                with self.assertRaisesRegex(ValueError, "quality mismatch"):
                    study.execute(manifests, out, phase="development", count=1)
            report = json.loads((out/"RESULT.json").read_bytes())
            self.assertFalse(report["ok"])
            self.assertEqual(report["started_decisions"], 1)
            self.assertEqual(report["completed_decisions"], 0)
            with lzma.open(out/"wire.jsonl.xz", "rt") as stream:
                rows = [json.loads(line) for line in stream]
            rows = [r for r in rows if r["channel"] == "native-ndu"]
            self.assertEqual([r["state"] for r in rows], ["started", "quality_failed"])
            self.assertEqual(rows[-1]["raw_response_frame"].encode(), frame)

    def test_retention_failure_cannot_leave_successful_result(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)/"run"
            manifests = {}
            for arm in planning.ARMS:
                path = Path(temp)/(arm+".json")
                path.write_text("{}")
                manifests[arm] = path
            cfg = study.protocol()
            cfg["max_retained_bytes"] = 1
            with patch.object(study, "protocol", return_value=cfg), self.assertRaises(ValueError):
                study.execute(manifests, out, phase="development", count=1)
            self.assertFalse(json.loads((out/"RESULT.json").read_bytes())["ok"])

    def test_old_development_receipt_cannot_register_changed_source(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            controls = {"ok": True, "phase": "development", "case_count": 12,
                        "source_identity": {}, "source_unchanged": True,
                        "session_cap_controls": [{"arm": arm, "accepted_requests": 256, "request257_rejected": True, "closed": True} for arm in planning.ARMS]}
            matrix = {"ok": True, "phase": "development", "completed_decisions": 32,
                      "source_identity": {}, "source_unchanged": True}
            (temp/"controls.json").write_text(json.dumps(controls))
            (temp/"matrix.json").write_text(json.dumps(matrix))
            with self.assertRaisesRegex(ValueError, "current exact study sources"):
                study.freeze(temp/"freeze.json", temp/"controls.json", temp/"matrix.json")
            self.assertFalse((temp/"freeze.json").exists())


if __name__ == "__main__":
    unittest.main()
