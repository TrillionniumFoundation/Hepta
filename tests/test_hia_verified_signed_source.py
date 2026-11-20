"""A clean index cannot authorize measured bytes different from HEAD."""
from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import benchmark_hia_verified_signed as signed

GIT = shutil.which("git")


@unittest.skipUnless(GIT, "Git is required for committed-source controls")
class SignedCommittedSourceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hia-signed-commit-")
        self.addCleanup(self.temporary.cleanup)
        self.environment = patch.dict(os.environ, {key: value for key, value in os.environ.items()
                                                  if key not in signed.GIT_ROUTING_ENV}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.base = Path(self.temporary.name)
        self.root = self.base / "checkout"
        self.root.mkdir()
        self.source = self.root / "measure.py"
        self.original = "value = 1\n# exact UTF-8 π\n".encode()
        self.source.write_bytes(self.original)
        self.git("init", "-q")
        self.git("config", "user.name", "Source identity test")
        self.git("config", "user.email", "source-test@example.invalid")
        self.git("add", "measure.py")
        self.git("commit", "-qm", "Committed source")
        self.commit = self.git("rev-parse", "HEAD").decode().strip()

    def git(self, *args):
        result = subprocess.run([GIT, "--no-optional-locks", "-C", str(self.root), *args],
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        return result.stdout

    def bind(self, root=None, names=("measure.py",), commit=None):
        root = root or self.root
        sources = {name: sha256((root / name).read_bytes()).hexdigest() for name in names}
        return signed.committed_source_identity(root, sources, commit or self.commit, git=GIT)

    def test_clean_blob_binding_is_exact_and_repeatable(self):
        first = self.bind()
        self.assertEqual(first, self.bind())
        self.assertEqual(first["commit"], self.commit)
        self.assertEqual(first["sources"]["measure.py"]["sha256"], sha256(self.original).hexdigest())
        self.assertEqual(first["sources"]["measure.py"]["bytes"], len(self.original))
        self.assertEqual(first["git_context"]["index"]["path"], str(self.root / ".git/index"))

    def test_assume_unchanged_cannot_hide_modified_executed_bytes(self):
        self.git("update-index", "--assume-unchanged", "measure.py")
        self.source.write_bytes(self.original.replace(b"1", b"2"))
        self.assertEqual(self.git("status", "--porcelain=v1", "--untracked-files=no"), b"")
        self.assertEqual(self.git("ls-files", "-z", "--", "measure.py"), b"measure.py\0")
        with self.assertRaisesRegex(ValueError, "differs from declared commit"):
            self.bind()

    def test_skip_worktree_cannot_hide_modified_executed_bytes(self):
        self.git("update-index", "--skip-worktree", "measure.py")
        self.source.write_bytes(self.original.replace(b"1", b"2"))
        self.assertEqual(self.git("status", "--porcelain=v1", "--untracked-files=no"), b"")
        self.assertEqual(self.git("ls-files", "-z", "--", "measure.py"), b"measure.py\0")
        with self.assertRaisesRegex(ValueError, "differs from declared commit"):
            self.bind()

    def test_unchanged_bytes_with_index_flags_remain_valid(self):
        for flag in ("--assume-unchanged", "--skip-worktree"):
            with self.subTest(flag=flag):
                self.git("update-index", flag, "measure.py")
                self.assertEqual(self.bind()["sources"]["measure.py"]["sha256"], sha256(self.original).hexdigest())

    def test_index_change_is_visible_to_campaign_before_after_comparison(self):
        before = self.bind()
        self.git("update-index", "--assume-unchanged", "measure.py")
        after = self.bind()
        self.assertEqual(before["sources"], after["sources"])
        self.assertNotEqual(before["git_context"]["index"], after["git_context"]["index"])

    def test_untracked_executed_source_is_not_in_the_commit(self):
        (self.root / "extra.py").write_bytes(self.original)
        with self.assertRaisesRegex(ValueError, "inventory differs"):
            self.bind(names=("measure.py", "extra.py"))

    def test_git_routing_overrides_are_rejected(self):
        for variable in signed.GIT_ROUTING_ENV:
            with self.subTest(variable=variable), patch.dict(os.environ, {variable: str(self.base / "alternate")}):
                with self.assertRaisesRegex(ValueError, "ordinary Git routing"):
                    self.bind()

    def test_parent_checkout_cannot_stand_in_for_declared_source_root(self):
        nested = self.root / "nested"
        nested.mkdir()
        (nested / "measure.py").write_bytes(self.original)
        with self.assertRaisesRegex(ValueError, "declared Git checkout root"):
            self.bind(root=nested)

    def test_replacement_commit_cannot_relabel_source(self):
        self.source.write_bytes(self.original.replace(b"1", b"2"))
        self.git("commit", "-qam", "Other tree")
        alternate = self.git("rev-parse", "HEAD").decode().strip()
        self.git("reset", "--hard", self.commit)
        self.git("replace", self.commit, alternate)
        # Ordinary Git now shows another tree under the unchanged HEAD name.
        self.assertNotEqual(self.git("show", "HEAD:measure.py"), self.original)
        self.assertEqual(self.bind()["sources"]["measure.py"]["sha256"], sha256(self.original).hexdigest())
        self.source.write_bytes(self.original.replace(b"1", b"2"))
        with self.assertRaisesRegex(ValueError, "differs from declared commit"):
            self.bind()

    def test_real_linked_worktree_is_supported(self):
        worktree = self.base / "detached"
        self.git("worktree", "add", "--detach", str(worktree), self.commit)
        first = self.bind(root=worktree)
        self.assertEqual(first, self.bind(root=worktree))
        self.assertEqual(first["git_context"]["checkout"]["kind"], "worktree-file")
        self.assertEqual(first["sources"]["measure.py"]["sha256"], sha256(self.original).hexdigest())

    def test_wrong_head_and_relative_git_path_refuse(self):
        with self.assertRaisesRegex(ValueError, "HEAD changed"):
            self.bind(commit="0" * len(self.commit))
        with self.assertRaisesRegex(ValueError, "absolute Git executable"):
            signed.committed_source_identity(self.root, {"measure.py": sha256(self.original).hexdigest()},
                                             self.commit, git="git")


if __name__ == "__main__":
    unittest.main()
