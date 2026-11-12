"""Native stream controls, separate from timing or decision advantage."""
from copy import deepcopy
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_ndu import NduBridgeError
from hepta.hia_ndu_cost import CostModelError
from hepta.hia_ndu_raw_model import invoke, request_bytes
from hepta.hia_ndu_raw_session import RawModelSession
from tests.test_hia_ndu_cost import fixture

BINARY = os.environ.get("HEPTA_RAW_MODEL_BRIDGE")
BUILD = os.environ.get("HEPTA_RAW_MODEL_BUILD")


@unittest.skipUnless(BINARY and BUILD, "actual source-bound native build required")
class RawModelSessionTests(unittest.TestCase):
    def test_modes_match_one_shot_without_python_search(self):
        with RawModelSession(BINARY, BUILD) as session:
            pid = session.snapshot()["pid"]
            with patch("hepta.hia_ndu_cost._Planner", side_effect=AssertionError("Python search")):
                for generation in (1, 2, 7):
                    model = fixture(generation % 4 + 1)
                    model["generation"] = generation
                    answers = []
                    for mode in ("exact_dp", "ndu"):
                        one, _ = invoke(BINARY, BUILD, model, mode=mode)
                        actual, receipt = session.evaluate(model, mode=mode)
                        for key in ("bundle", "selected_first_action", "pareto_candidate_ids", "request_sha256"):
                            self.assertEqual(actual[key], one[key])
                        self.assertEqual(actual["generation"], generation)
                        self.assertEqual(receipt["sequence"], len(session.snapshot()["request_costs_ns"]))
                        answers.append(actual)
                    self.assertEqual(answers[0]["selected_first_action"], answers[1]["selected_first_action"])
            self.assertEqual(session.snapshot()["pid"], pid)
            self.assertEqual(session.snapshot()["requests"], 6)
        self.assertIsNotNone(session._process.returncode)
        self.assertIsNone(session._fd)

    def test_default_exact_dp_and_new_input_not_cached(self):
        with RawModelSession(BINARY, BUILD) as session:
            before, _ = session.evaluate(fixture())
            model = fixture()
            model["completion_value_ns"] = 0
            after, _ = session.evaluate(model)
            self.assertEqual(before["mode"], "exact_dp")
            self.assertFalse(before["native_evaluation"])
            self.assertNotEqual(before["request_sha256"], after["request_sha256"])
            self.assertIn("abstain", after["pareto_candidate_ids"])
            self.assertIsNone(after["selected_first_action"])

    def test_request_budget_closes_without_extra_native_request(self):
        session = RawModelSession(BINARY, BUILD)
        try:
            for sequence in range(1, 257):
                _, row = session.evaluate(fixture(1))
                self.assertEqual(row["sequence"], sequence)
            with self.assertRaisesRegex(NduBridgeError, "exhausted"):
                session.evaluate(fixture(1))
            self.assertEqual(session._sequence, 256)
            self.assertTrue(session._closed)
            self.assertIsNotNone(session._process.returncode)
        finally:
            session.close()

    def test_native_rejects_incomplete_oversized_or_extra_frames(self):
        _, payload = request_bytes(fixture(1), "exact_dp")
        for raw in (payload, b" " * 1_048_577 + b"\n", payload + b"{}\n", b"\n"):
            with self.subTest(size=len(raw)):
                result = subprocess.run([BINARY, "--stream"], input=raw, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(len(result.stdout.splitlines()), 1)
                self.assertEqual(json.loads(result.stderr)["authority"], "DENY_ALL")

    def test_native_budget_is_independent_of_python(self):
        _, payload = request_bytes(fixture(1), "exact_dp")
        result = subprocess.run([BINARY, "--stream"], input=(payload+b"\n")*257,
                                capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 2)
        replies = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(len(replies), 257)
        self.assertEqual([r["sequence"] for r in replies[1:]], list(range(1, 257)))

    def test_protocol_mismatch_closes_owned_child(self):
        for mutation in (lambda r: r.update(sequence=True),
                         lambda r: r["response"].update(generation=42)):
            with self.subTest(mutation=mutation):
                session = RawModelSession(BINARY, BUILD)
                exchange = session._exchange
                def changed(payload):
                    row = deepcopy(exchange(payload))
                    mutation(row)
                    return row
                with patch.object(session, "_exchange", side_effect=changed):
                    with self.assertRaises((NduBridgeError, CostModelError)):
                        session.evaluate(fixture(1))
                self.assertTrue(session._closed)
                self.assertIsNotNone(session._process.returncode)
                self.assertIsNone(session._fd)

    def test_manifest_drift_rejects_before_next_request(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory)/"build.json"
            manifest.write_bytes(Path(BUILD).read_bytes())
            session = RawModelSession(BINARY, manifest)
            session.evaluate(fixture(1))
            manifest.write_bytes(manifest.read_bytes()+b" ")
            with self.assertRaisesRegex(NduBridgeError, "identity drift"):
                session.evaluate(fixture(1))
            self.assertEqual(session._sequence, 1)
            self.assertTrue(session._closed)

    def test_adapter_drift_closes_before_request(self):
        session = RawModelSession(BINARY, BUILD)
        with patch("hepta.hia_ndu_raw_session._adapter_files", return_value={}):
            with self.assertRaisesRegex(NduBridgeError, "adapter source changed"):
                session.evaluate(fixture(1))
        self.assertEqual(session._sequence, 0)
        self.assertTrue(session._closed)

    def test_dead_child_refuses_and_releases_image(self):
        session = RawModelSession(BINARY, BUILD)
        session._process.terminate()
        session._process.wait(timeout=3)
        with self.assertRaisesRegex(NduBridgeError, "closed"):
            session.evaluate(fixture(1))
        self.assertIsNone(session._fd)

    def test_fork_cannot_use_or_close_parent_session(self):
        with RawModelSession(BINARY, BUILD) as session:
            child = os.fork()
            if child == 0:
                try:
                    for action in (lambda: session.evaluate(fixture(1)), session.snapshot, session.close):
                        try: action()
                        except NduBridgeError: pass
                        else: os._exit(90)
                    os._exit(0)
                except BaseException:
                    os._exit(91)
            _, status = os.waitpid(child, 0)
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)
            response, row = session.evaluate(fixture(1))
            self.assertEqual(row["sequence"], 1)
            self.assertEqual(response["mode"], "exact_dp")

    def test_stopped_child_times_out_without_replay(self):
        session = RawModelSession(BINARY, BUILD, timeout=0.1)
        os.kill(session._process.pid, signal.SIGSTOP)
        with self.assertRaisesRegex(NduBridgeError, "timed out"):
            session.evaluate(fixture(1))
        self.assertTrue(session._closed)
        self.assertEqual(session._sequence, 0)
        self.assertIsNotNone(session._process.returncode)
        self.assertIsNone(session._fd)


if __name__ == "__main__":
    unittest.main()
