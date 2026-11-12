"""Pure regression controls for Darwin ps signed system UIDs.

The unrelated ``97472 1 97472 -2 Ss`` row was observed by the explicitly
read-only native diagnostic. Its original complete snapshot and provenance
are retained outside the repository. These controls spawn no target process.
"""
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "hia_agent_owned_uid_subject", ROOT / "tools/hia_agent_codex_transport.py"
)
SUBJECT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUBJECT)


class OwnedProcessSignedUIDTests(unittest.TestCase):
    def snapshot(self, raw, pgid=101, returncode=0):
        result = subprocess.CompletedProcess([], returncode, raw, b"")
        with patch.object(SUBJECT.subprocess, "run", return_value=result) as call:
            rows = SUBJECT._group_snapshot(pgid)
        self.assertEqual(call.call_args.args[0], ["/bin/ps", "-ax", "-o", "pid=,ppid=,pgid=,uid=,stat="])
        self.assertEqual(call.call_args.kwargs["timeout"], 3)
        return rows

    def test_actual_unrelated_negative_uid_does_not_hide_owned_group(self):
        raw = b"97472 1 97472 -2 Ss\n101 11 101 501 Z\n"
        self.assertEqual(self.snapshot(raw), [[101, 11, 101, 501, "Z"]])

    def test_unsigned_uid_rows_keep_their_values_and_group_filter(self):
        raw = b"101 11 101 501 Z\n102 11 101 0 S\n202 1 202 0 Ss\n"
        self.assertEqual(self.snapshot(raw), [[101, 11, 101, 501, "Z"], [102, 11, 101, 0, "S"]])

    def test_same_group_signed_uid_is_not_normalized_or_owned(self):
        rows = self.snapshot(b"101 11 101 -2 Z\n")
        self.assertEqual(rows, [[101, 11, 101, -2, "Z"]])
        self.assertNotEqual(rows[0][3], SUBJECT.os.getuid())

    def test_malformed_uid_still_fails_closed(self):
        for value in (b"--2", b"-", b"+2", b"-x", b"12x", b"UID"):
            with self.subTest(value=value), self.assertRaisesRegex(RuntimeError, "E_PILOT_GROUP_OBSERVATION_SHAPE"):
                self.snapshot(b"101 11 101 " + value + b" Z\n")

    def test_pid_ppid_pgid_remain_unsigned(self):
        for index in range(3):
            row = ["101", "11", "101", "501", "Z"]
            row[index] = "-" + row[index]
            with self.subTest(index=index), self.assertRaisesRegex(RuntimeError, "E_PILOT_GROUP_OBSERVATION_SHAPE"):
                self.snapshot((" ".join(row) + "\n").encode())

    def test_wrong_field_counts_or_header_still_fail_closed(self):
        for raw in (b"101 11 101 501\n", b"101 11 101 501 Z extra\n", b"PID PPID PGID UID STAT\n"):
            with self.subTest(raw=raw), self.assertRaisesRegex(RuntimeError, "E_PILOT_GROUP_OBSERVATION_SHAPE"):
                self.snapshot(raw)

    def test_failed_ps_is_not_an_empty_group_proof(self):
        with self.assertRaisesRegex(RuntimeError, "E_PILOT_GROUP_OBSERVATION_FAILED"):
            self.snapshot(b"", returncode=1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
