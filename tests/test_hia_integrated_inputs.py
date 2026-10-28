"""Qualification must bind raw source blobs and every native dependency."""
from hashlib import sha256
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

from tools import qualify_hia_integrated as integrated


class IntegratedInputIdentityTests(unittest.TestCase):
    def git(self, root, *arguments):
        return subprocess.check_output(["git", "-C", str(root), *arguments], stderr=subprocess.PIPE)

    def repository(self, root):
        self.git(root, "init", "--quiet")
        self.git(root, "config", "user.name", "Qualification fixture")
        self.git(root, "config", "user.email", "fixture@example.invalid")
        (root / "source.rs").write_bytes(b'// $Format:%H$\nfn main() {}\n')
        (root / ".gitattributes").write_text("source.rs export-subst\n")
        self.git(root, "add", ".")
        self.git(root, "commit", "--quiet", "-m", "frozen source")
        return self.git(root, "rev-parse", "HEAD").decode().strip()

    def test_source_identity_uses_raw_commit_blobs_not_archive_transformation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commit = self.repository(root)
            expected = {"source.rs": sha256((root / "source.rs").read_bytes()).hexdigest()}
            # export-subst affects archive bytes but cannot change source identity.
            self.assertEqual(integrated._git_inventory(root, commit, expected), commit)
            # A dirty working file cannot replace the pinned commit's source.
            (root / "source.rs").write_text("uncommitted replacement\n")
            self.assertEqual(integrated._git_inventory(root, commit, expected), commit)
            changed = {"source.rs": sha256((root / "source.rs").read_bytes()).hexdigest()}
            with self.assertRaisesRegex(ValueError, "exact upstream Git object"):
                integrated._git_inventory(root, commit, changed)

    def test_missing_commit_paths_do_not_satisfy_source_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commit = self.repository(root)
            with self.assertRaisesRegex(ValueError, "source tree paths differ"):
                integrated._git_inventory(root, commit, {"missing.rs": "0" * 64})

    def test_commit_and_blob_replacements_cannot_relabel_different_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original_commit = self.repository(root)
            original_blob = self.git(root, "rev-parse", original_commit + ":source.rs").decode().strip()
            original = {"source.rs": sha256((root / "source.rs").read_bytes()).hexdigest()}
            (root / "source.rs").write_text("fn replacement() {}\n")
            self.git(root, "add", "source.rs")
            self.git(root, "commit", "--quiet", "-m", "different source")
            changed_commit = self.git(root, "rev-parse", "HEAD").decode().strip()
            changed_blob = self.git(root, "rev-parse", "HEAD:source.rs").decode().strip()
            changed = {"source.rs": sha256((root / "source.rs").read_bytes()).hexdigest()}
            for old, new in ((original_commit, changed_commit), (original_blob, changed_blob)):
                with self.subTest(replaced_object=old):
                    self.git(root, "replace", old, new)
                    try:
                        self.assertEqual(integrated._git_inventory(root, original_commit, original), original_commit)
                        with self.assertRaisesRegex(ValueError, "exact upstream Git object"):
                            integrated._git_inventory(root, original_commit, changed)
                    finally:
                        self.git(root, "replace", "-d", old)

    def test_stream_binary_receipt_and_sources_all_remain_in_external_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            values = {}
            for label in ("ranking_bridge", "ranking_build_receipt", "recursive_bridge",
                          "recursive_identity", "finite_bridge", "finite_identity",
                          "stream_bridge", "stream_identity"):
                path = root / label
                path.write_bytes(label.encode())
                values[label] = path
            for profile in ("recursive", "finite", "stream"):
                values[profile + "_upstream"] = root
            source = root / "stream-source.rs"
            source.write_bytes(b"frozen native source\n")
            options = SimpleNamespace(**values)
            row = {"name": "stream_bridge_identity", "passed": True,
                   "manifest_binary_invocation": str(options.stream_bridge),
                   "binary": str(options.stream_bridge),
                   "binary_sha256": sha256(options.stream_bridge.read_bytes()).hexdigest(),
                   "receipt_sha256": sha256(options.stream_identity.read_bytes()).hexdigest(),
                   "native_sources": {source.name: sha256(source.read_bytes()).hexdigest()},
                   "bridge_sources": {}, "build_tools": {}}
            inventory = integrated._external_inventory(options, [row])
            for path in (options.stream_bridge, options.stream_identity, source):
                with self.subTest(path=path.name):
                    self.assertEqual(inventory[str(path)], sha256(path.read_bytes()).hexdigest())
                    original = path.read_bytes()
                    path.write_bytes(original + b"modified")
                    try:
                        with self.assertRaisesRegex(ValueError, "external inputs changed"):
                            integrated._external_inventory(options, [row])
                    finally:
                        path.write_bytes(original)
            self.assertIn("stream_bridge_identity", integrated.EXPECTED_GATE_NAMES)


if __name__ == "__main__":
    unittest.main()
