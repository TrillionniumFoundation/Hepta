"""Actual isolated Git snapshots must remain the collector's exact source."""
from __future__ import annotations

import contextlib
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import qualify_hia_verified_increment as gate


class _Observation(unittest.TestCase):
    callback = staticmethod(lambda: None)
    executed = 0

    def runTest(self):
        type(self).executed += 1
        type(self).callback()


class IncrementSourceAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.parent = Path(self.temporary.name)
        self.repo = self.parent / "source"
        self.repo.mkdir()
        self.git("init", "--quiet")
        self.git("config", "user.name", "Gate fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        (self.repo / "fixture.py").write_text("value = 1\n")
        self.git("add", "fixture.py")
        self.git("commit", "--quiet", "-m", "base")
        _Observation.executed = 0

    def git(self, *arguments):
        return subprocess.check_output(["git", *arguments], cwd=self.repo, text=True).strip()

    def collect(self, output=None, callback=lambda: None):
        with patch.object(gate, "ROOT", self.repo), \
                patch.object(gate, "MODULES", (__name__ + "._Observation",)), \
                patch.object(gate, "inventory", return_value={"fixture.py": "unchanged"}), \
                patch.object(_Observation, "callback", staticmethod(callback)), \
                contextlib.redirect_stdout(io.StringIO()):
            return gate.run(output or self.parent / "evidence")

    def test_dirty_source_refuses_before_discovery_or_output(self):
        (self.repo / "fixture.py").write_text("value = 2\n")
        with self.assertRaisesRegex(ValueError, "dirty"):
            self.collect()
        self.assertEqual(_Observation.executed, 0)
        self.assertFalse((self.parent / "evidence").exists())

    def test_output_inside_source_refuses_before_test_side_effects(self):
        with self.assertRaisesRegex(ValueError, "outside"):
            self.collect(self.repo / "evidence")
        self.assertEqual(_Observation.executed, 0)
        self.assertFalse((self.repo / "evidence").exists())

    def test_same_tree_new_commit_during_execution_invalidates_receipt(self):
        before_tree = self.git("rev-parse", "HEAD^{tree}")
        receipt = self.collect(callback=lambda: self.git("commit", "--quiet", "--allow-empty", "-m", "drift"))
        self.assertEqual(self.git("rev-parse", "HEAD^{tree}"), before_tree)
        self.assertFalse(receipt["passed"])
        self.assertFalse(receipt["worktree_unchanged"])
        self.assertTrue(receipt["source_identity_drift"])

    def test_unchanged_clean_source_keeps_the_positive_control(self):
        receipt = self.collect()
        self.assertTrue(receipt["passed"])
        self.assertEqual(receipt["git_base"], self.git("rev-parse", "HEAD"))
        self.assertEqual(_Observation.executed, 1)


if __name__ == "__main__":
    unittest.main()
