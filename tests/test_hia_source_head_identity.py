"""Real Git source snapshots must bind HEAD bytes, not index/status hints.

These are identity-boundary regressions. They execute no integrated native gate
and grant no language, compiler, runtime or hostile-host qualification.
"""
from contextlib import contextmanager
from hashlib import sha256
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import qualify_hia_integrated as integrated


class SourceHeadIdentityTests(unittest.TestCase):
    def git(self, root, *arguments, payload=None):
        return subprocess.run(["git", "--no-replace-objects", "-C", str(root), *arguments],
                              input=payload, capture_output=True, check=True, timeout=10).stdout

    @contextmanager
    def repository(self):
        with tempfile.TemporaryDirectory(prefix="hepta-head-identity-") as directory:
            root = Path(directory)
            self.git(root, "init", "--quiet", "--object-format=sha1")
            for name, value in (("user.name", "Source identity fixture"),
                                ("user.email", "fixture@example.invalid"),
                                ("commit.gpgsign", "false"), ("core.hooksPath", "/dev/null"),
                                ("core.fileMode", "true"), ("core.autocrlf", "false")):
                self.git(root, "config", name, value)
            (root / "sample.py").write_bytes(b"VALUE = 'committed'\n")
            (root / "nested").mkdir()
            (root / "nested/child.txt").write_bytes(b"nested raw bytes\x00\xff\n")
            (root / "executable.sh").write_bytes(b"#!/bin/sh\nexit 0\n")
            (root / "executable.sh").chmod(0o755)
            self.git(root, "add", ".")
            self.git(root, "commit", "--quiet", "-m", "frozen source")
            # Preserve the actual git implementation and its no-replace policy.
            # Only redirect its repository, like the original independent repro.
            raw_git = integrated._git
            with patch.object(integrated, "ROOT", root), \
                    patch.object(integrated, "_git", side_effect=lambda *args: raw_git(*args, root=root)):
                yield root

    def set_hint(self, root, flag):
        self.git(root, "update-index", "--no-assume-unchanged", "--", "sample.py")
        self.git(root, "update-index", "--no-skip-worktree", "--", "sample.py")
        self.git(root, "update-index", "--refresh")
        self.git(root, "update-index", flag, "--", "sample.py")

    def assert_hidden_change(self, root):
        original = self.git(root, "rev-parse", "HEAD:sample.py").strip()
        actual = self.git(root, "hash-object", "--no-filters", "--", "sample.py").strip()
        self.assertNotEqual(original, actual)
        self.assertEqual(self.git(root, "status", "--porcelain", "--untracked-files=all"), b"")

    def test_clean_before_after_and_unchanged_hints_keep_exact_source_identity(self):
        with self.repository() as root:
            before = integrated._source_state()
            self.assertEqual(before["head"], self.git(root, "rev-parse", "HEAD").decode().strip())
            self.assertEqual(before["tree"], self.git(root, "rev-parse", "HEAD^{tree}").decode().strip())
            self.assertEqual(before["status"], "")
            self.assertEqual(before["files"], {name: sha256((root / name).read_bytes()).hexdigest()
                for name in ("sample.py", "nested/child.txt", "executable.sh")})
            for flag in ("--assume-unchanged", "--skip-worktree"):
                with self.subTest(flag=flag):
                    self.set_hint(root, flag)
                    self.assertEqual(integrated._source_state(), before)
                    self.assertEqual(integrated._source_state(), before)

    def test_index_hints_cannot_hide_modified_bytes_before_first_snapshot(self):
        for flag in ("--assume-unchanged", "--skip-worktree"):
            with self.subTest(flag=flag), self.repository() as root:
                self.set_hint(root, flag)
                (root / "sample.py").write_bytes(b"VALUE = 'changed-uncommitted'\n")
                self.assert_hidden_change(root)
                # Two equal snapshots used to pass under the original HEAD.
                for _ in range(2):
                    with self.assertRaisesRegex(ValueError, "source bytes differ from raw HEAD blob"):
                        integrated._source_state()

    def test_index_hints_cannot_hide_modified_bytes_after_clean_snapshot(self):
        for flag in ("--assume-unchanged", "--skip-worktree"):
            with self.subTest(flag=flag), self.repository() as root:
                before = integrated._source_state()
                self.set_hint(root, flag)
                (root / "sample.py").write_bytes(b"VALUE = 'changed-uncommitted'\n")
                self.assert_hidden_change(root)
                self.assertEqual(before["head"], self.git(root, "rev-parse", "HEAD").decode().strip())
                with self.assertRaisesRegex(ValueError, "source bytes differ from raw HEAD blob"):
                    integrated._source_state()

    def test_complete_paths_come_from_raw_tree_even_when_index_removes_a_file(self):
        with self.repository() as root:
            before = integrated._source_state()
            self.git(root, "update-index", "--force-remove", "--", "nested/child.txt")
            self.assertNotIn(b"nested/child.txt", self.git(root, "ls-files", "-z").split(b"\0"))
            after = integrated._source_state()
            self.assertEqual(before["files"], after["files"])
            self.assertEqual(before["head"], after["head"])
            self.assertTrue(after["status"])  # The existing clean-status gate still refuses it.

    def test_missing_and_nonregular_working_files_never_satisfy_head_identity(self):
        for replacement in ("missing", "directory", "symlink", "fifo"):
            with self.subTest(replacement=replacement), self.repository() as root:
                self.set_hint(root, "--skip-worktree")
                target = root / "sample.py"
                target.unlink()
                if replacement == "directory":
                    target.mkdir()
                elif replacement == "symlink":
                    target.symlink_to("nested/child.txt")
                elif replacement == "fifo":
                    os.mkfifo(target)
                with self.assertRaises((ValueError, FileNotFoundError)):
                    integrated._source_state()

    def test_mode_changes_cannot_hide_behind_core_filemode_false(self):
        for name, changed_mode in (("sample.py", 0o755), ("executable.sh", 0o644)):
            with self.subTest(name=name), self.repository() as root:
                before = integrated._source_state()
                self.git(root, "config", "core.fileMode", "false")
                (root / name).chmod(changed_mode)
                self.assertEqual(self.git(root, "status", "--porcelain"), b"")
                with self.assertRaisesRegex(ValueError, "source mode differs from raw HEAD tree"):
                    integrated._source_state()
                (root / name).chmod(0o755 if name == "executable.sh" else 0o644)
                self.assertEqual(integrated._source_state(), before)

    def test_non_git_permission_bits_do_not_change_blob_or_executable_identity(self):
        with self.repository() as root:
            before = integrated._source_state()
            (root / "sample.py").chmod(0o600)
            (root / "executable.sh").chmod(0o700)
            self.assertEqual(integrated._source_state(), before)

    def set_raw_tree(self, root, members):
        payload = b"".join(mode + b" " + name + b"\0" + bytes.fromhex(oid)
                           for mode, name, oid in members)
        tree = self.git(root, "hash-object", "--literally", "-w", "-t", "tree", "--stdin",
                        payload=payload).decode().strip()
        head = self.git(root, "commit-tree", tree, "-m", "synthetic raw tree").decode().strip()
        self.git(root, "update-ref", "HEAD", head)

    def test_raw_tree_nonregular_members_and_unsafe_paths_are_refused(self):
        for mode, name, object_kind in ((b"120000", b"sample.py", "blob"),
                                       (b"160000", b"submodule", "commit"),
                                       (b"100644", b"../outside", "blob"),
                                       (b"100644", b"/absolute", "blob"),
                                       (b"100644", b".git/config", "blob")):
            with self.subTest(mode=mode, name=name), self.repository() as root:
                object_name = "HEAD:sample.py" if object_kind == "blob" else "HEAD"
                oid = self.git(root, "rev-parse", object_name).decode().strip()
                self.set_raw_tree(root, [(mode, name, oid)])
                with self.assertRaisesRegex(ValueError, "raw HEAD tree (member|path)"):
                    integrated._source_state()

    def test_duplicate_raw_tree_paths_are_refused(self):
        with self.repository() as root:
            oid = self.git(root, "rev-parse", "HEAD:sample.py").decode().strip()
            self.set_raw_tree(root, [(b"100644", b"sample.py", oid)] * 2)
            with self.assertRaisesRegex(ValueError, "duplicate raw HEAD tree path"):
                integrated._source_state()

    def test_unsafe_empty_subtrees_and_duplicate_directory_paths_are_refused(self):
        for name in (b"..", b".git", b"/absolute", b"./empty", b"nested//empty", b"duplicate"):
            with self.subTest(name=name), self.repository() as root:
                empty_tree = self.git(root, "mktree", payload=b"").decode().strip()
                blob = self.git(root, "rev-parse", "HEAD:sample.py").decode().strip()
                directories = [(b"40000", name, empty_tree)] * (2 if name == b"duplicate" else 1)
                self.set_raw_tree(root, directories + [(b"100644", b"sample.py", blob)])
                # Without -t the tree listing omits every empty directory,
                # including those carrying unsafe or duplicate paths.
                with self.assertRaisesRegex(ValueError, "unsafe or duplicate raw HEAD tree path"):
                    integrated._source_state()

    def test_safe_empty_subtree_is_checked_without_becoming_a_file(self):
        with self.repository() as root:
            before = integrated._source_state()
            empty_tree = self.git(root, "mktree", payload=b"").decode().strip()
            members = [(b"40000", b"empty", empty_tree)]
            for record in self.git(root, "ls-tree", "-z", "HEAD").split(b"\0")[:-1]:
                metadata, name = record.split(b"\t", 1)
                mode, _, oid = metadata.split(b" ")
                members.append((mode, name, oid.decode()))
            self.set_raw_tree(root, members)
            after = integrated._source_state()
            self.assertEqual(after["files"], before["files"])
            self.assertEqual(after["status"], "")
            self.assertNotEqual(after["tree"], before["tree"])

    def test_replacement_refs_cannot_rebind_main_source_head_or_blob(self):
        for replace_kind in ("commit", "blob"):
            with self.subTest(replace_kind=replace_kind), self.repository() as root:
                before = integrated._source_state()
                original_blob = self.git(root, "rev-parse", "HEAD:sample.py").decode().strip()
                (root / "sample.py").write_bytes(b"VALUE = 'replacement-object'\n")
                self.git(root, "add", "sample.py")
                self.git(root, "commit", "--quiet", "-m", "replacement bytes")
                changed_head = self.git(root, "rev-parse", "HEAD").decode().strip()
                changed_blob = self.git(root, "rev-parse", "HEAD:sample.py").decode().strip()
                self.git(root, "reset", "--hard", before["head"])
                old, new = ((before["head"], changed_head) if replace_kind == "commit"
                            else (original_blob, changed_blob))
                self.git(root, "replace", old, new)
                self.assertEqual(integrated._source_state(), before)
                self.set_hint(root, "--skip-worktree")
                (root / "sample.py").write_bytes(b"VALUE = 'replacement-object'\n")
                with self.assertRaisesRegex(ValueError, "source bytes differ from raw HEAD blob"):
                    integrated._source_state()

    def test_actual_file_mutation_during_streaming_read_is_refused(self):
        with self.repository() as root:
            path = root / "sample.py"
            actual_fstat = integrated.os.fstat
            reads = 0

            def mutate_after_open(fd):
                nonlocal reads
                value = actual_fstat(fd)
                reads += 1
                if reads == 1:
                    path.write_bytes(b"changed during the descriptor read\n")
                return value

            with patch.object(integrated.os, "fstat", side_effect=mutate_after_open):
                with self.assertRaisesRegex(ValueError, "file changed during identity read"):
                    integrated._digest_file(path)


if __name__ == "__main__":
    unittest.main()
