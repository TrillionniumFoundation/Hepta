"""Focused mock controls; these are not model-generated task results."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from experiments.hia_optimizer_eval.primary_continuation_20261028 import run_remaining as driver


class PrimaryContinuationControls(unittest.TestCase):
    def test_shutdown_and_identity_failures_keep_request_counts(self):
        class Engine:
            generation_count = 6
            response_count = 5
            def __init__(self, failure): self.failure = failure
            def close(self):
                if self.failure == "close": raise OSError("controlled shutdown failure")
            def verify_final_identity(self):
                if self.failure == "verify": raise OSError("controlled identity read failure")
                return {"model_unchanged": False, "runtime_unchanged": True}
        for failure in ("close", "verify", "false_identity"):
            with self.subTest(failure=failure):
                record = {}
                with self.assertRaises((OSError, RuntimeError)):
                    driver.finish_engine(Engine(failure), record)
                self.assertEqual(record["requests_started"], 6)
                self.assertEqual(record["responses_received"], 5)
                self.assertIn("shutdown_or_identity_error", record)
                self.assertGreaterEqual(record["shutdown_and_identity_wall_ns"], 0)

    def test_transport_timeout_prefix_is_not_retried(self):
        order = [{"id": f"cell{i}"} for i in range(16)]
        rows = [{"id": f"cell{i}", "attempt_started": True, "state": "inference_failed" if i == 3 else "response_rejected"} for i in range(4)]
        with tempfile.TemporaryDirectory() as raw:
            previous = Path(raw); model = previous / "model"; engine = model / "engine"; engine.mkdir(parents=True)
            for i in range(2):
                (engine / f"transport-{i+1:03d}.request.json").write_text(json.dumps({"messages": [f"probe{i}"]}))
            for i in range(4):
                request = {"messages": [f"task{i}"]}
                (model / f"cell{i}.request.json").write_text(json.dumps(request))
                (engine / f"transport-{i+3:03d}.request.json").write_text(json.dumps(request))
            report = {"model": {"id": "model"}, "rows": rows, "requests_started": 6}
            self.assertEqual([item["id"] for item in driver.pending_cells({"scheduled_cells": order}, report, previous)], [f"cell{i}" for i in range(4, 16)])
            (engine / "transport-006.request.json").unlink()
            with self.assertRaises(ValueError):
                driver.pending_cells({"scheduled_cells": order}, report, previous)

    def test_canonical_destination_cannot_be_repeated_or_renamed(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); previous = root / "primary"; previous.mkdir(); target = root / "primary-continuation"
            self.assertEqual(driver.canonical_output(previous, target), target)
            with self.assertRaises(ValueError):
                driver.canonical_output(previous, root / "second-try")
            target.mkdir()
            with self.assertRaises(ValueError):
                driver.canonical_output(previous, target)

    def test_timeout_then_positive_cell_has_one_request_and_no_feedback(self):
        class Engine:
            def __init__(self, output): self.output = output; self.generation_count = 0; self.calls = []
            def generate(self, messages, *, limit, wall_seconds):
                self.generation_count += 1; self.calls.append((messages, limit, wall_seconds))
                (self.output / f"transport-{self.generation_count:03d}.request.json").write_text(json.dumps({"payload": {"prompt": [1, 2, 3]}}))
                if self.generation_count == 1: raise TimeoutError("controlled timeout")
                return {"text": "{}", "usage": {"input_tokens": 3, "output_tokens": 2}, "wall_nanoseconds": 10}
        with tempfile.TemporaryDirectory() as raw, mock.patch.object(driver, "current_sources", return_value={}), mock.patch.object(driver.frozen, "prompt", return_value="registered prompt"), mock.patch.object(driver.frozen, "parse_response", return_value={}) as parse, mock.patch.object(driver.frozen, "native", return_value={"status": "correct", "ok": True}) as native:
            root = Path(raw); engine = Engine(root)
            first, usable = driver.run_cell({"id": "first", "arm": "hia_edit_query"}, {}, root / "first", engine, "clang", "rustc", {})
            self.assertFalse(usable); self.assertFalse(first["ok"]); self.assertIsNone(first["output_tokens"])
            self.assertIsNone(first["inference_ns"]); self.assertIsNone(first["evaluation_ns"])
            self.assertEqual(first["known_input_tokens"], 3); parse.assert_not_called(); native.assert_not_called()
            second, usable = driver.run_cell({"id": "next", "arm": "rust_edit_query"}, {}, root / "next", engine, "clang", "rustc", {})
            self.assertTrue(usable); self.assertTrue(second["ok"]); self.assertEqual(len(engine.calls), 2)
            self.assertEqual(engine.calls[0][0], engine.calls[1][0])
            self.assertTrue(all((limit, wall) == (512, 180) for _, limit, wall in engine.calls))
            native.assert_called_once()


if __name__ == "__main__":
    unittest.main()
