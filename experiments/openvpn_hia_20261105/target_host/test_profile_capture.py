#!/usr/bin/env python3
"""Regression for the real target's truncated perf-record finalization.

Artifact #13484017940 recorded 2,178 real samples and 672 samples from the
C-user OpenVPN client, but the recorder was SIGTERM'd after a 3-second
post-traffic wait (exit -15, timed_out=true). The raw profile therefore
failed despite containing partial samples. These tests exercise the bounded
recorder wait only; they do not qualify a target profile or tunnel.
"""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("run_matrix", HERE / "run_matrix.py")
matrix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(matrix)


class ProfileRecorderWaitTests(unittest.TestCase):
    def test_grace_includes_recording_shutdown_margin_after_traffic(self):
        self.assertEqual(matrix.profile_record_grace_seconds(10, 15), 15)
        self.assertEqual(matrix.profile_record_grace_seconds(10, 5), 15)
        self.assertEqual(matrix.profile_record_grace_seconds(10, 20), 20)

    def test_grace_rejects_invalid_workload_or_plan_values(self):
        for workload, configured in ((0, 15), (True, 15), (10, True), (10, 4), (10, 121)):
            with self.subTest(workload=workload, configured=configured):
                with self.assertRaises(ValueError):
                    matrix.profile_record_grace_seconds(workload, configured)

    def test_real_recorder_child_finishes_without_three_second_truncation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / "private"
            private.mkdir(mode=0o700)
            ledger = matrix.Ledger(root, private, 20)
            try:
                child = matrix.Job(
                    ledger,
                    "delayed-perf-finalizer",
                    [sys.executable, "-c", "import time; time.sleep(3.5)"],
                    root / "commands",
                )
                row = matrix.wait_for_profile_recorder(child, 10, 15)
                self.assertEqual(row["exit_code"], 0)
                self.assertFalse(row.get("timed_out", False))
                self.assertEqual(row["signals"], [])
            finally:
                ledger.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
