"""Producer refusal and failure-retention controls, not native execution credit."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import qualify_hia_native_loans as producer


class NativeLoanQualificationProtocolTests(unittest.TestCase):
    def test_a_pending_attempt_is_not_a_spawn_or_entry_observation(self):
        counts = producer._execution_counts([{"name": "admission-or-start-failed"}])
        self.assertEqual(counts["attempted_calls"], 1)
        self.assertEqual(counts["child_processes_started"], 0)
        self.assertFalse(counts["child_process_start_count_complete"])
        self.assertEqual(counts["unavailable_child_start_outcomes"], 1)
        self.assertEqual(counts["completed_observations"], 0)
        self.assertIsNone(counts["native_entry_invocations"])

    def test_existing_evidence_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "existing"
            output.mkdir()
            prior = output / "report.json"
            prior.write_bytes(b"previous evidence\n")
            with self.assertRaisesRegex(ValueError, "must be new"):
                producer.qualify(output, clang="must-not-run")
            self.assertEqual(prior.read_bytes(), b"previous evidence\n")

    def test_output_inside_source_checkout_is_refused(self):
        output = producer.ROOT / "must-not-create-native-loan-evidence"
        with self.assertRaisesRegex(ValueError, "outside the source checkout"):
            producer.qualify(output, clang="must-not-run")
        self.assertFalse(output.exists())

    def test_compiler_failure_and_interruption_retain_partial_report(self):
        # Source and compiler failure are controlled here. No observation in
        # these protocol tests is credited as actual native execution.
        for error in (RuntimeError("compiler could not run"), KeyboardInterrupt("interrupted")):
            with self.subTest(error=type(error).__name__), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "new"
                git = lambda *args: "c" * 40 if args[0] == "rev-parse" else ""
                with mock.patch.object(producer, "snapshot", return_value={"sha256": "a" * 64, "files": {}}), \
                        mock.patch.object(producer, "_git", side_effect=git), \
                        mock.patch.object(producer, "NativeVersionDispatcher", side_effect=error):
                    result = producer.qualify(output, clang="must-not-run")
                self.assertFalse(result["ok"])
                self.assertFalse(result["execution_passed"])
                self.assertEqual(result["error"]["type"], type(error).__name__)
                self.assertEqual(result["attempts"], [])
                self.assertEqual(json.loads((output / "report.json").read_text()), result)
                self.assertTrue((output / "baseline.json").is_file())
                self.assertTrue((output / "candidate.json").is_file())

    def test_snapshot_failure_still_retains_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "new"
            with mock.patch.object(producer, "snapshot", side_effect=OSError("source unavailable")):
                result = producer.qualify(output, clang="must-not-run")
            self.assertFalse(result["ok"])
            self.assertIn("post_snapshot_error", result)
            self.assertEqual(result["error"]["type"], "OSError")
            self.assertEqual(json.loads((output / "report.json").read_text()), result)
