#!/usr/bin/env python3
"""Offline privacy gate counterexamples; no TUN or DCO claims."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("publication_guard", HERE / "publication_guard.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class PrivacyGateTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        self.public = self.root / "public"
        self.public.mkdir()
        (self.public / "build.json").write_text('{"ok": false, "failure": "real runtime failure"}\n')
        self.marker = self.root / "publication-ok.json"

    def tearDown(self):
        self.dir.cleanup()

    def run_gate(self):
        return guard.main(["--public", str(self.public), "--marker", str(self.marker)])

    def test_failed_experiment_nonsecret_logs_remain_uploadable(self):
        self.assertEqual(self.run_gate(), 0)
        self.assertTrue(json.loads(self.marker.read_text())["safe_to_upload"])
        self.assertEqual(json.loads(self.marker.read_text())["files_scanned"], 1)

    def test_private_key_file_is_rejected(self):
        (self.public / "ca.key").write_text("not a real key")
        self.assertEqual(self.run_gate(), 1)
        self.assertFalse(self.marker.exists())

    def test_embedded_private_key_is_rejected(self):
        (self.public / "build.json").write_bytes(b"-----BEGIN PRIVATE KEY-----\nFAKE\n")
        self.assertEqual(self.run_gate(), 1)
        self.assertFalse(self.marker.exists())

    def test_github_token_in_json_is_rejected(self):
        (self.public / "build.json").write_bytes(b'"token":"github_pat_' + b'a' * 21 + b'"')
        self.assertEqual(self.run_gate(), 1)
        self.assertFalse(self.marker.exists())

    def test_raw_perf_stack_is_rejected(self):
        (self.public / "trace.perf.data").write_bytes(b"raw private stack bytes")
        self.assertEqual(self.run_gate(), 1)
        self.assertFalse(self.marker.exists())

    def test_symlink_to_secret_outside_public_is_rejected(self):
        (self.root / "outside").write_text("private data")
        (self.public / "alias.txt").symlink_to(self.root / "outside")
        self.assertEqual(self.run_gate(), 1)
        self.assertFalse(self.marker.exists())

    def test_symlinked_public_root_is_rejected(self):
        alias = self.root / "alias"
        alias.symlink_to(self.public)
        self.assertEqual(guard.main(["--public", str(alias), "--marker", str(self.marker)]), 1)

    def test_oversized_file_is_rejected_without_allocation(self):
        with (self.public / "large.log").open("wb") as stream:
            stream.truncate(guard.MAX_FILE_BYTES + 1)
        self.assertEqual(self.run_gate(), 1)
        self.assertFalse(self.marker.exists())

    def test_empty_public_evidence_fails_closed(self):
        (self.public / "build.json").unlink()
        self.assertEqual(self.run_gate(), 1)
        self.assertFalse(self.marker.exists())

    def test_stale_marker_fails(self):
        self.assertEqual(self.run_gate(), 0)
        self.assertNotEqual(self.run_gate(), 0)

    def test_marker_inside_artifact_is_rejected(self):
        marker = self.public / "publication-ok.json"
        self.assertEqual(guard.main(["--public", str(self.public), "--marker", str(marker)]), 1)
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
