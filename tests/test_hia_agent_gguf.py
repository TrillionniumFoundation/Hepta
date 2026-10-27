"""Reject inconsistent inference evidence and count language/interface costs fairly."""
import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
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


def json_response():
    raw = response()
    raw["content"] = "{}"
    raw["generation_settings"].update(grammar='root ::= "{}"', grammar_lazy=False)
    return raw


def offline_engine(directory, *, json_object, raw):
    """Protocol fixture only: no model, process or native inference is run."""
    engine = object.__new__(LlamaCppEngine)
    engine.output, engine.context = directory, 8192
    engine.json_object = json_object
    engine.generation_count = engine.response_count = 0

    def request(endpoint, payload=None, **kwargs):
        if endpoint == "/apply-template":
            return {"prompt": "template-rendered input"}
        if endpoint == "/tokenize":
            return {"tokens": [4, 5, 6]}
        if endpoint == "/completion":
            return copy.deepcopy(raw)
        raise AssertionError("Unexpected fixture endpoint: " + endpoint)

    engine.request = Mock(side_effect=request)
    return engine


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

    def test_json_mode_requires_an_explicit_bool_before_any_process_starts(self):
        for value in (None, 0, 1, "false", "true", [], {}):
            with self.subTest(value=value), \
                 patch("tools.provider_adapter.llama_cpp_engine.subprocess.Popen") as process, \
                 self.assertRaisesRegex(ValueError, "E_GGUF_CONFIG"):
                LlamaCppEngine(binary="not-read", model="not-read", model_sha256="not-read",
                               output_dir="not-created", json_object=value)
            process.assert_not_called()

    def test_json_mode_checks_actual_grammar_in_flat_and_nested_settings(self):
        for nested in (False, True):
            raw = json_response()
            if nested:
                raw["generation_settings"] = {"params": raw["generation_settings"]}
            with self.subTest(nested=nested):
                self.assertEqual(validate_completion(raw, [4, 5, 6], 4, json_object=True)["output_tokens"], 3)
        for grammar, lazy in ((None, False), ("", False), (" \n", False), ([], False),
                              ('root ::= "{}"', True), ('root ::= "{}"', 0),
                              ('root ::= "{}"', None)):
            raw = json_response()
            raw["generation_settings"].update(grammar=grammar, grammar_lazy=lazy)
            with self.subTest(grammar=grammar, lazy=lazy), self.assertRaisesRegex(ValueError, "grammar"):
                validate_completion(raw, [4, 5, 6], 4, json_object=True)
        with self.assertRaises(ValueError):
            validate_completion(response(), [4, 5, 6], 4, json_object=True)

    def test_only_generic_object_schema_is_added_to_every_json_mode_request(self):
        expected = {"prompt": [4, 5, 6], "n_predict": 4, "temperature": 0, "seed": 0,
                    "top_k": 0, "top_p": 1, "min_p": 0, "repeat_penalty": 1,
                    "cache_prompt": False, "return_tokens": True, "stream": False,
                    "stop": [], "ignore_eos": False}
        for mode in (False, True):
            with self.subTest(json_object=mode), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                engine = offline_engine(directory, json_object=mode,
                                        raw=json_response() if mode else response())
                wire = {**expected, **({"json_schema": {"type": "object"}} if mode else {})}
                for index in (1, 2):
                    generated = engine.generate([{"role": "user", "content": "Change an arbitrary field."}], limit=4)
                    self.assertEqual(generated["request"], wire)
                    request = json.loads((directory / f"transport-{index:03d}.request.json").read_text())
                    self.assertEqual(request["payload"], wire)
                self.assertEqual((engine.generation_count, engine.response_count), (2, 2))

    def test_token_budget_partial_json_is_completed_inference_for_downstream_rejection(self):
        raw = json_response()
        raw.update(content='{"replacement":', stop_type="limit", timings={"predicted_n": 2})
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            engine = offline_engine(directory, json_object=True, raw=raw)
            generated = engine.generate([{"role": "user", "content": "Return a JSON object."}], limit=2)
            self.assertEqual(generated["status"], "completed")
            self.assertEqual(generated["usage"]["output_tokens"], 2)
            self.assertEqual(generated["text"], raw["content"])
            with self.assertRaises(json.JSONDecodeError):
                json.loads(generated["text"])
            self.assertEqual(json.loads((directory / "transport-001.response.json").read_text()), raw)

    def test_missing_json_grammar_retains_response_but_does_not_accept_generation(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            engine = offline_engine(directory, json_object=True, raw=response())
            with self.assertRaisesRegex(ValueError, "grammar"):
                engine.generate([{"role": "user", "content": "Return an object."}], limit=4)
            self.assertEqual((engine.generation_count, engine.response_count), (1, 1))
            self.assertEqual(json.loads((directory / "transport-001.response.json").read_text()), response())

    def test_identity_records_default_and_json_decoders_without_running_a_model(self):
        for mode in (False, True):
            with self.subTest(json_object=mode), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                binary, model = directory / "fixture-runtime", directory / "fixture-model"
                binary.write_bytes(b"unit-test runtime identity, not executable")
                model.write_bytes(b"unit-test model identity, not a GGUF")
                process = Mock(pid=123)
                process.poll.return_value = None
                version = SimpleNamespace(stdout="unit-test fixture", stderr="")
                with patch("tools.provider_adapter.llama_cpp_engine.subprocess.run", return_value=version), \
                     patch("tools.provider_adapter.llama_cpp_engine.subprocess.Popen", return_value=process), \
                     patch.object(LlamaCppEngine, "request", side_effect=[{"status": "ok"}, {}]):
                    # Omit the argument in the first case to exercise the old default.
                    arguments = {"json_object": True} if mode else {}
                    with LlamaCppEngine(binary=binary, model=model,
                                        model_sha256=hashlib.sha256(model.read_bytes()).hexdigest(),
                                        output_dir=directory / "run", **arguments) as engine:
                        expected = ({"mode": "json_object", "json_schema": {"type": "object"},
                                     "scope": "syntax_only_no_task_fields_or_answers"}
                                    if mode else {"mode": "unconstrained"})
                        self.assertEqual(engine.identity["decoder"], expected)
                        retained = json.loads((engine.output / "identity.json").read_text())
                        self.assertEqual(retained["decoder"], expected)

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
