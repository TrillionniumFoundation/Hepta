"""Real native session reuse plus transport identity and terminal fault paths."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import signal
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_ndu import NduBridge, NduBridgeError
from hepta.hia_ndu_session import MAX_SESSION_REQUESTS, NduSession
from tests.test_hia_ndu import plan, request


@unittest.skipUnless(os.environ.get("HEPTA_NDU_STREAM_IDENTITY"),
                     "set HEPTA_NDU_STREAM_IDENTITY for actual native stream tests")
class NativeNduSessionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = Path(os.environ["HEPTA_NDU_STREAM_IDENTITY"])
        cls.manifest = json.loads(cls.path.read_text())

    def session(self, **options):
        session = NduSession(self.manifest["binary"], self.path, **options)
        self.addCleanup(session.close)
        return session

    def test_native_stream_reuses_one_actual_pid_and_matches_one_shot_results(self):
        stream = self.session()
        one = NduBridge(self.manifest["binary"], self.path)
        pid = stream.snapshot()["pid"]
        for generation in range(1, 9):
            value = request(plan("continue", [-2, generation]), plan("stop", [1]))
            value["generation"] = generation
            self.assertEqual(stream.evaluate(value), one.evaluate(value))
            self.assertEqual(stream.snapshot()["pid"], pid)
        self.assertEqual(stream.snapshot()["requests"], 8)
        self.assertEqual(len(stream.snapshot()["request_costs_ns"]), 8)
        self.assertEqual(stream.snapshot()["authority"], "DENY_ALL")

    def test_input_mutation_after_send_cannot_rebind_the_actual_reply(self):
        stream = self.session()
        value = request(plan("candidate", [3]))
        original = stream._invoke
        def mutate_after_native_reply(arguments, payload):
            result = original(arguments, payload)
            value["generation"] = 999
            return result
        with patch.object(stream, "_invoke", side_effect=mutate_after_native_reply):
            self.assertEqual(stream.evaluate(value)["generation"], 1)
        self.assertEqual(value["generation"], 999)

    def test_mutable_publication_path_cannot_replace_the_pinned_process_image(self):
        with tempfile.TemporaryDirectory(prefix="hia-ndu-image-") as directory:
            binary = Path(directory) / "bridge"
            shutil.copyfile(self.manifest["binary"], binary)
            binary.chmod(0o700)
            with NduSession(binary, self.path) as stream:
                binary.write_bytes(b"replaced after sealed process started")
                self.assertEqual(stream.evaluate(request(plan("live", [2])))["advisory_candidate_id"], "live")
                self.assertEqual(stream.snapshot()["binary_sha256"], self.manifest["binary_sha256"])

    def test_native_malformed_request_poisoning_is_terminal_and_no_later_reply_can_be_used(self):
        stream = self.session()
        bad = request(plan("candidate", [3]))
        bad["activate"] = True
        with self.assertRaises(NduBridgeError):
            stream.evaluate(bad)
        self.assertTrue(stream.snapshot()["closed"])
        self.assertIsNotNone(stream._process.returncode)
        with self.assertRaisesRegex(NduBridgeError, "closed"):
            stream.evaluate(request(plan("later", [10])))

    def test_exact_session_request_budget_refuses_the_257th_evaluation(self):
        stream = self.session()
        value = request(plan("candidate", [1]))
        for _ in range(MAX_SESSION_REQUESTS):
            self.assertEqual(stream.evaluate(value)["advisory_candidate_id"], "candidate")
        self.assertEqual(stream.snapshot()["requests"], MAX_SESSION_REQUESTS)
        with self.assertRaisesRegex(NduBridgeError, "budget"):
            stream.evaluate(value)
        self.assertTrue(stream.snapshot()["closed"])

    def test_real_native_stall_times_out_closes_and_cannot_resume(self):
        stream = self.session(timeout=2.0)
        stream.timeout = 0.02
        os.kill(stream._process.pid, signal.SIGSTOP)
        with self.assertRaisesRegex(NduBridgeError, "timed out"):
            stream.evaluate(request(plan("candidate", [1])))
        self.assertTrue(stream.snapshot()["closed"])
        self.assertIsNotNone(stream._process.returncode)

    def test_stale_sequence_and_authority_fail_before_returning_advice(self):
        for change in ({"sequence": 2}, {"authority": "ALLOW_ALL"}):
            stream = self.session()
            exchange = stream._exchange
            def alter(payload, change=change):
                return {**exchange(payload), **change}
            with patch.object(stream, "_exchange", side_effect=alter):
                with self.assertRaisesRegex(NduBridgeError, "sequence or authority"):
                    stream.evaluate(request(plan("candidate", [1])))
            self.assertTrue(stream.snapshot()["closed"])

    def test_oversized_identity_is_rejected_by_a_bounded_read_before_native_launch(self):
        with tempfile.TemporaryDirectory(prefix="hia-ndu-manifest-") as directory:
            manifest = Path(directory) / "oversized.json"
            with manifest.open("wb") as stream:
                stream.truncate(128 * 1024 * 1024)
            with patch("hepta.hia_ndu_session.subprocess.Popen", side_effect=AssertionError("launched")):
                with self.assertRaisesRegex(NduBridgeError, "exceeds 1 MiB"):
                    NduSession(self.manifest["binary"], manifest)


if __name__ == "__main__":
    unittest.main()
