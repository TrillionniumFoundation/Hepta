"""Adversarial event-map parser regression: real CI no-job failure on 2026-10-31.

Three workflows had the invalid inline header "on:  push:", which GitHub
could not parse, producing completed/failure runs with zero jobs.
Test exact repaired files with a real YAML parser, not a text-only grep.
"""
from __future__ import annotations

from pathlib import Path
import unittest
import yaml


ROOT = Path(__file__).resolve().parents[1]
SOURCE_BRANCH = "work/hia-seven-track-reconcile-p7-driver-digest-20261031-gpt6"
TARGETS = (
    ".github/workflows/hepta-c-posttest-hosts.yml",
    ".github/workflows/hepta-crc-context.yml",
    ".github/workflows/hepta-intelligent-assembly-closure.yml",
)


class ReconciledWorkflowYamlTests(unittest.TestCase):
    def test_actual_files_have_valid_nested_push_and_job_declarations(self):
        for relative in TARGETS:
            with self.subTest(workflow=relative):
                raw = (ROOT / relative).read_text(encoding="utf-8")
                document = yaml.load(raw, Loader=yaml.BaseLoader)
                self.assertIsInstance(document, dict)
                event_map = document.get("on")
                self.assertIsInstance(event_map, dict)
                self.assertIsInstance(event_map.get("push"), dict)
                self.assertIn(SOURCE_BRANCH, event_map["push"].get("branches", []))
                self.assertIsInstance(event_map.get("pull_request"), dict)
                self.assertIn("workflow_dispatch", event_map)
                self.assertIsInstance(document.get("jobs"), dict)
                self.assertTrue(document["jobs"])

    def test_real_previous_inline_on_push_form_is_parser_rejected(self):
        for relative in TARGETS:
            with self.subTest(workflow=relative):
                original = (ROOT / relative).read_text(encoding="utf-8")
                self.assertIn("on:\n  push:\n", original)
                malformed = original.replace("on:\n  push:\n", "on:  push:\n", 1)
                with self.assertRaises(yaml.YAMLError):
                    yaml.load(malformed, Loader=yaml.BaseLoader)

    def test_scalar_or_missing_event_map_never_qualifies(self):
        for invalid in ("on: false\njobs: {}\n", "name: no-event\njobs: {}\n"):
            with self.subTest(invalid=invalid):
                document = yaml.load(invalid, Loader=yaml.BaseLoader)
                self.assertNotIsInstance(document.get("on"), dict)


if __name__ == "__main__":
    unittest.main()
