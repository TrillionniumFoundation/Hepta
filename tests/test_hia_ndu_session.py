"""Real native session reuse plus transport identity and terminal fault paths."""
from __future__ import annotations

import json
from copy import deepcopy
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

    def test_sealed_profile_reuses_kernel_byte_immutability_without_rereading_the_image(self):
        stream = self.session(image_check="sealed")
        # Admission already performed a complete digest and sealed readback.
        # A valid subsequent native request must not need another image read.
        with patch("hepta.hia_ndu_session.os.pread", side_effect=AssertionError("image reread")):
            self.assertEqual(stream.evaluate(request(plan("live", [2])))["advisory_candidate_id"], "live")
        self.assertEqual(stream.snapshot()["image_check_profile"], "sealed")
        self.assertTrue(stream.snapshot()["initial_full_digest_verified"])

    def test_rehash_comparison_profile_keeps_real_full_image_checks(self):
        stream = self.session(image_check="rehash")
        actual_read = os.pread
        with patch("hepta.hia_ndu_session.os.pread", wraps=actual_read) as read:
            self.assertEqual(stream.evaluate(request(plan("live", [2])))["advisory_candidate_id"], "live")
        self.assertEqual(read.call_count, 2)
        self.assertTrue(all(call.args[1] == stream._pinned_stat.st_size for call in read.call_args_list))

    def test_manifest_memory_and_file_changes_poison_both_profiles(self):
        for profile in ("sealed", "rehash"):
            for location in ("memory", "file"):
                with self.subTest(profile=profile, location=location), tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "identity.json"
                    path.write_bytes(self.path.read_bytes())
                    stream = NduSession(self.manifest["binary"], path, image_check=profile)
                    self.addCleanup(stream.close)
                    if location == "memory":
                        stream.manifest["binary_sha256"] = "0" * 64
                    else:
                        path.write_bytes(path.read_bytes() + b" ")
                    with self.assertRaisesRegex(NduBridgeError, "identity drift"):
                        stream.evaluate(request(plan("live", [2])))
                    self.assertTrue(stream.snapshot()["closed"])

    def test_descriptor_replacement_is_terminal_even_with_same_sized_bytes(self):
        stream = self.session(image_check="sealed")
        original = stream._fd
        replacement = os.memfd_create("wrong-ndu-image", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        os.ftruncate(replacement, stream._pinned_stat.st_size)
        stream._fd = replacement
        try:
            with self.assertRaisesRegex(NduBridgeError, "descriptor changed"):
                stream.evaluate(request(plan("live", [2])))
            self.assertTrue(stream.snapshot()["closed"])
        finally:
            os.close(original)

    def test_missing_required_seal_is_refused_before_native_request(self):
        import fcntl
        stream = self.session(image_check="sealed")
        actual = fcntl.fcntl
        def missing_write_seal(descriptor, operation, *args):
            value = actual(descriptor, operation, *args)
            return value & ~0x0008 if operation == getattr(fcntl, "F_GET_SEALS", 1034) else value
        with patch("hepta.hia_ndu_session.fcntl.fcntl", side_effect=missing_write_seal):
            with self.assertRaisesRegex(NduBridgeError, "seals changed"):
                stream.evaluate(request(plan("live", [2])))
        self.assertTrue(stream.snapshot()["closed"])
        self.assertEqual(stream.snapshot()["requests"], 0)

    def test_stream_source_profile_cannot_alias_an_existing_finite_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identity.json"
            wrong = deepcopy(self.manifest)
            wrong["identity"]["source_commit"] = "4b6391e116949af0c7e59776baead67271856bdb"
            path.write_text(json.dumps(wrong))
            with patch("hepta.hia_ndu_session.subprocess.Popen", side_effect=AssertionError("launched")):
                with self.assertRaisesRegex(NduBridgeError, "distinct c4 source"):
                    NduSession.for_stream_profile(self.manifest["binary"], path)


if __name__ == "__main__":
    unittest.main()

