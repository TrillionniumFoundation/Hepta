"""Focused positive/timeout controls for the supplemental outer-loop repair."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from experiments.hia_optimizer_eval.upgrade_continuation_20261028 import run_remaining as driver


class ContinuationControls(unittest.TestCase):
    def test_single_canonical_continuation_destination(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); previous = root / "upgrade"; previous.mkdir()
            output = root / "upgrade-continuation"
            self.assertEqual(driver.require_canonical_output(previous, output), output)
            with self.assertRaises(ValueError):
                driver.require_canonical_output(previous, root / "another-attempt")
            output.mkdir()
            with self.assertRaises(ValueError):
                driver.require_canonical_output(previous, output)

    def test_attempted_prefix_is_never_retried(self):
        order = [{"id": str(i)} for i in range(4)]
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); (root / "0").mkdir(); (root / "0/attempt-0.request.json").write_text("{}")
            remaining = driver.pending_cells({"scheduled_cells": order}, {"cells": [{"id": "0", "attempts": [{}]}]}, root)
            self.assertEqual([row["id"] for row in remaining], ["1", "2", "3"])
            (root / "1").mkdir(); (root / "1/attempt-0.request.json").write_text("{}")
            with self.assertRaises(ValueError):
                driver.pending_cells({"scheduled_cells": order}, {"cells": [{"id": "0", "attempts": [{}]}]}, root)

    def test_timeout_then_positive_cell_preserves_limits_and_hidden_boundary(self):
        class Engine:
            def __init__(self, output):
                self.output = output; self.generation_count = 0; self.calls = []
            def generate(self, messages, *, limit, wall_seconds):
                self.calls.append((messages, limit, wall_seconds)); self.generation_count += 1
                (self.output / f"transport-{self.generation_count:03d}.request.json").write_text(json.dumps({"payload": {"prompt": [1, 2, 3]}}))
                if self.generation_count == 1:
                    raise TimeoutError("controlled deadline")
                return {"text": "{}", "usage": {"input_tokens": 3, "output_tokens": 2}, "wall_nanoseconds": 10}
        task = {"public_cases": [[1]], "public_expected": [2], "hidden_cases": [[3]], "hidden_expected": [4]}
        with tempfile.TemporaryDirectory() as raw, mock.patch.object(driver.frozen, "bindings", return_value={}), mock.patch.object(driver.frozen, "prompt", return_value="same fixed prompt"), mock.patch.object(driver.frozen, "build", return_value={"native_built": True, "status": "built"}) as build, mock.patch.object(driver.frozen, "execute", return_value={"status": "correct", "artifact_unchanged": True}) as execute:
            root = Path(raw); engine = Engine(root)
            failed, reusable = driver.run_cell({"id": "first", "language": "hia"}, task, root / "first", engine, "clang", "rustc", {})
            self.assertFalse(reusable); self.assertEqual(failed["status"], "budget_timeout")
            self.assertEqual(len(failed["attempts"]), 1); self.assertIsNone(failed["output_tokens"])
            self.assertEqual(failed["known_input_tokens"], 3); build.assert_not_called(); execute.assert_not_called()
            passed, reusable = driver.run_cell({"id": "next", "language": "rust"}, task, root / "next", engine, "clang", "rustc", {})
            self.assertTrue(reusable); self.assertTrue(passed["correct"])
            self.assertEqual(len(engine.calls), 2)
            self.assertTrue(all((limit, wall) == (1536, 180) for _, limit, wall in engine.calls))
            self.assertEqual(execute.call_args_list[0].args[1:], (task["public_cases"], task["public_expected"]))
            self.assertEqual(execute.call_args_list[1].args[1:], (task["hidden_cases"], task["hidden_expected"]))
            self.assertEqual(engine.calls[0][0], engine.calls[1][0])


if __name__ == "__main__":
    unittest.main()
