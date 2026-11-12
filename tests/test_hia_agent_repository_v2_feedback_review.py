"""Independent state-machine review; synthetic providers are not model scores."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools import qualify_hia_agent_repository_maintenance_v2 as study


class TerminalFeedbackReviewTests(unittest.TestCase):
    def run_synthetic(self, directory, evaluate, hidden):
        configuration = study.protocol()
        model = next(row for row in configuration["models"] if row["provider"] == "codex_cli")
        prompts = {task["id"] + "/" + arm: sha256(study.base.prompt(task, arm).encode()).hexdigest()
                   for task in study.base.cfg()["tasks"] for arm in study.base.cfg()["arms"]}
        requests = []

        def generate(messages, *_):
            requests.append(deepcopy(messages))
            return {"status": "completed", "generation_requested": True, "text": "candidate",
                    "usage": {"input_tokens": 15, "cached_input_tokens": 3,
                              "cache_write_input_tokens": 0, "output_tokens": 4,
                              "reasoning_output_tokens": 1},
                    "process": {"status": "exited", "cleanup_confirmed": True}}

        with patch.object(study, "bindings", return_value={}), \
                patch.object(study, "codex_generate", side_effect=generate), \
                patch.object(study, "evaluate", side_effect=evaluate) as public, \
                patch.object(study, "evaluate_hidden", return_value=hidden) as terminal:
            result = study.run_model(SimpleNamespace(clang="unused-synthetic-tool"), model,
                configuration, {"wall_ns": 0, "prompt_bindings": prompts}, {}, {},
                Path(directory) / "synthetic", {"cli_identity": {}})
        return result, requests, public.call_count, terminal.call_count

    def test_hidden_failure_is_terminal_for_all_four_cells(self):
        with TemporaryDirectory() as directory:
            result, requests, public_calls, hidden_calls = self.run_synthetic(directory,
                [{"accepted": True, "status": "public_accepted", "wall_ns": 1}] * 4,
                {"passed": False, "wall_ns": 1, "secret": "HIDDEN_SENTINEL"})
        self.assertEqual(result["status"], "completed")
        self.assertEqual((len(requests), public_calls, hidden_calls), (4, 4, 4))
        self.assertTrue(all(len(request) == 1 for request in requests))
        self.assertTrue(all(cell["status"] == "hidden_failed" and not cell["correct"]
                            and len(cell["attempts"]) == 1 for cell in result["cells"]))
        self.assertNotIn("HIDDEN_SENTINEL", repr(requests))
        self.assertTrue(all(arm["planned_tasks"] == arm["attempted_tasks"] == 2
                            and arm["successes"] == 0 and arm["tokens_per_success"] is None
                            for arm in result["summary"]["arms"].values()))

    def test_only_public_error_enters_repair_and_next_cell_starts_fresh(self):
        public_error = {"type": "ValueError", "message": "PUBLIC_SENTINEL"}
        outcomes = [{"accepted": False, "status": "candidate_rejected", "wall_ns": 1,
                     "error": public_error},
                    {"accepted": True, "status": "public_accepted", "wall_ns": 1}] * 4
        with TemporaryDirectory() as directory:
            result, requests, public_calls, hidden_calls = self.run_synthetic(directory, outcomes,
                {"passed": False, "wall_ns": 1, "secret": "HIDDEN_SENTINEL"})
        self.assertEqual((len(requests), public_calls, hidden_calls), (8, 8, 4))
        for index in range(4):
            self.assertEqual(len(requests[2 * index]), 1)
            repair = requests[2 * index + 1]
            self.assertEqual([message["role"] for message in repair], ["user", "assistant", "user"])
            self.assertEqual(repair[1]["content"], "candidate")
            self.assertIn("PUBLIC_SENTINEL", repair[2]["content"])
        self.assertNotIn("HIDDEN_SENTINEL", repr(requests))
        self.assertTrue(all(len(cell["attempts"]) == 2 and cell["status"] == "hidden_failed"
                            for cell in result["cells"]))


if __name__ == "__main__":
    unittest.main()
