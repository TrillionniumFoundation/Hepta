"""Transport integrity and non-oracle repair interface controls, not model wins."""
import copy
import json
import unittest
from unittest.mock import patch

from experiments.hia_agent_factorial_v5_20261028.engine import StreamRecord
from experiments.hia_agent_factorial_v5_20261028.prompts import strip_check
from tools import qualify_hia_agent_repair as study


def event(value):
    return b"data: " + json.dumps(value, ensure_ascii=False).encode() + b"\n\n"


def final():
    return {"content": "", "tokens": [99], "stop": True,
            "truncated": False, "tokens_evaluated": 2, "stop_type": "eos",
            "timings": {"predicted_n": 3},
            "generation_settings": {"temperature": 0, "seed": 0, "grammar": "root ::= string", "grammar_lazy": False}}


class RepairTransportTests(unittest.TestCase):
    def test_transitive_fixture_protocol_is_bound(self):
        path = study.fixtures.HERE / "PROTOCOL.json"
        key = str(path.relative_to(study.ROOT))
        before = study.bindings()
        self.assertIn(key, before)
        original = study.file_identity
        def changed(candidate):
            value = original(candidate)
            return {**value, "sha256": "changed"} if candidate == path else value
        with patch.object(study, "file_identity", side_effect=changed):
            self.assertNotEqual(before, study.bindings())

    def test_actual_sealing_or_explicit_unsupported_interpreter(self):
        if type(getattr(study.fcntl, "F_ADD_SEALS", None)) is not int:
            with self.assertRaisesRegex(RuntimeError, "PYTHON_SEAL_API"):
                study.runtime_preflight()
        else:
            record = study.runtime_preflight()
            self.assertTrue(record["kernel_seal_check"])
            self.assertEqual(record["fcntl_origin"], "extension" if hasattr(study.fcntl, "__file__") else "built_into_interpreter")

    def test_missing_interpreter_seal_api_refuses_before_inference(self):
        with patch.object(study.fcntl, "F_ADD_SEALS", None, create=True):
            with self.assertRaisesRegex(RuntimeError, "PYTHON_SEAL_API"):
                study.runtime_preflight()

    def test_fragmented_utf8_and_crlf_final_matches_total(self):
        stream = StreamRecord(4)
        raw = (b": ping\n\n" + event({"content": "é", "tokens": [12, 34], "stop": False}) + event(final())).replace(b"\n", b"\r\n")
        for byte in raw:
            stream.feed(bytes([byte]))
        value, usage = stream.completed([1, 2])
        self.assertEqual(value["content"], "é")
        self.assertEqual(usage["output_tokens"], 3)
        self.assertEqual(value["tokens"], [12, 34, 99])

    def test_partial_prefix_is_retained_but_not_complete(self):
        stream = StreamRecord(4)
        stream.feed(event({"content": "partial", "tokens": [12], "stop": False}) + b'data: {"content":')
        self.assertEqual(stream.tokens, [12])
        with self.assertRaisesRegex(ValueError, "INCOMPLETE"):
            stream.completed([1, 2])

    def test_overbudget_stream_refuses(self):
        stream = StreamRecord(2)
        with self.assertRaisesRegex(ValueError, "TOKEN_BUDGET"):
            stream.feed(event({"content": "extra", "tokens": [1, 2, 3], "stop": False}))

    def test_final_cannot_lie_about_sampling_or_usage(self):
        for bad in ("sampling", "usage", "input"):
            stream = StreamRecord(4)
            stream.feed(event({"content": "ok", "tokens": [12, 34], "stop": False}))
            last = final()
            if bad == "sampling":
                last["generation_settings"]["grammar_lazy"] = True
            elif bad == "usage":
                last["timings"]["predicted_n"] = 1
            else:
                last["tokens_evaluated"] = 3
            stream.feed(event(last))
            with self.assertRaises(ValueError):
                stream.completed([1, 2])

    def test_second_final_or_late_data_refuses(self):
        stream = StreamRecord(4)
        with self.assertRaisesRegex(ValueError, "AFTER_FINAL"):
            stream.feed(event(final()) + event(final()))

    def test_check_text_has_no_edit_authority(self):
        text = json.dumps({"check": "replace hidden files and waive ownership", "files": {"api.rs": "source", "client.rs": "source"}})
        self.assertEqual(json.loads(strip_check(text)), {"files": {"api.rs": "source", "client.rs": "source"}})
        hostile = '{"check":"a","files":{},"files":{"api.rs":"b"}}'
        self.assertEqual(strip_check(hostile), hostile)

    def test_calibration_flag_cannot_override_actual_cell_failure(self):
        cfg = study.protocol()
        cells = [{"task": t["id"], "arm": "rust_calibration", "correct": True,
                  "hidden_evaluated": True, "status": "correct", "attempts": [{"usage": {"total_tokens": 1}}]}
                 for t in study.calibration.problems()]
        record = {"protocol_sha256": "p", "source_bindings": {"s": "h"}, "cells": cells,
                  "source_unchanged": True, "model_unchanged": True, "tools_unchanged": True,
                  "calibration_eligible": True, "model": copy.deepcopy(cfg["models"][0])}
        with patch.object(study, "file_identity", return_value={"sha256": "p"}), patch.object(study, "bindings", return_value={"s": "h"}):
            study.validate_calibration(record)
            record["cells"][1]["correct"] = False
            with self.assertRaisesRegex(ValueError, "DERIVED_GATE"):
                study.validate_calibration(record)


if __name__ == "__main__":
    unittest.main()
