"""Reject inconsistent inference evidence and count language/interface costs fairly."""
import copy
import os
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock

from tools.provider_adapter.llama_cpp_engine import LlamaCppEngine, validate_completion
from tools.qualify_hia_agent_gguf import summarize
from tools.qualify_hia_agent_pilot import native_control_passed


def response():
    return {"content": "ok", "tokens": [11, 12], "tokens_evaluated": 3,
            "truncated": False, "stop_type": "eos",
            "generation_settings": {"temperature": 0, "seed": 0},
            "timings": {"predicted_n": 3}}


class GGUFProtocolTests(unittest.TestCase):
    def test_exact_prompt_and_eos_cost_are_preserved(self):
        self.assertEqual(validate_completion(response(), [4, 5, 6], 4),
                         {"input_tokens": 3, "output_tokens": 3,
                          "returned_token_ids": 2, "total_tokens": 6})

    def test_changed_sampling_truncation_and_forged_usage_reject(self):
        cases = [{"tokens_evaluated": 2}, {"truncated": True}, {"tokens": [True, 12]},
                 {"stop_type": "word"}, {"timings": {"predicted_n": 9}},
                 {"timings": {"predicted_n": 1}},
                 {"generation_settings": {"temperature": 0.1, "seed": 0}},
                 {"generation_settings": {"temperature": 0, "seed": 1}}]
        for fields in cases:
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                validate_completion({**response(), **fields}, [4, 5, 6], 4)

    def test_retries_and_rejections_still_count_toward_cost(self):
        a = {"ok": False, "accepted": False, "usage": {"input_tokens": 10, "output_tokens": 5},
             "wall_nanoseconds": 20, "evaluation_nanoseconds": 3}
        b = copy.deepcopy(a)
        b.update(ok=True, accepted=True)
        actual = summarize([{"arm": "hia_semantic_patch", "success": True, "attempts": [a, b]}])
        value = actual["hia_semantic_patch"]
        self.assertEqual((value["tasks"], value["successes"], value["first_attempt_successes"]), (1, 1, 0))
        self.assertEqual((value["attempts"], value["rejected_candidates"]), (2, 1))
        self.assertEqual((value["input_tokens"], value["output_tokens"], value["inference_nanoseconds"]), (20, 10, 40))

    def test_failed_compile_is_not_a_successful_negative_native_control(self):
        self.assertFalse(native_control_passed({"ok": False, "native_executed": False}, False))
        self.assertTrue(native_control_passed({"ok": False, "native_executed": True}, False))

    def test_incomplete_inference_remains_in_attempt_cost_and_unknown_usage(self):
        item = {"ok": False, "accepted": False, "usage": None,
                "wall_nanoseconds": 180_000_000_000, "evaluation_nanoseconds": 0}
        row = {"arm": "rust_full_function", "success": False, "completed": False, "attempts": [item]}
        value = summarize([row])["rust_full_function"]
        self.assertEqual((value["attempts"], value["completed_tasks"], value["unknown_usage_attempts"]), (1, 0, 1))
        self.assertFalse(value["token_cost_complete"])
        self.assertEqual(value["inference_nanoseconds"], 180_000_000_000)
        self.assertEqual(value["rejected_candidates"], 0)

    def test_unrelated_socket_peer_cannot_impersonate_owned_inference(self):
        engine = object.__new__(LlamaCppEngine)
        engine.socket_path = "/tmp/not-connected-test.sock"
        engine.process = SimpleNamespace(pid=123, poll=lambda: None)
        fake_socket = Mock()
        fake_socket.getsockopt.return_value = struct.pack("3i", 456, os.geteuid(), os.getegid())
        with patch("tools.provider_adapter.llama_cpp_engine.socket.socket", return_value=fake_socket), \
             self.assertRaisesRegex(RuntimeError, "response peer"):
            engine.request("/props")


if __name__ == "__main__":
    unittest.main()
