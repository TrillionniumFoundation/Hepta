"""Real temporary-Git custody controls; no synthetic cold record qualifies HIA."""
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import zlib

from tools.hia_component_input_custody import capture_component_custody, verify_component_custody


class ComponentInputCustodyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hia-input-custody-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.git("init", "-q")
        self.git("config", "user.name", "Custody control")
        self.git("config", "user.email", "custody-control@example.invalid")
        self.captured = {"native/owner.hepta": b"synthetic HIA source control\n",
                         "tools/author.py": b"# separate authoring control\n"}
        for name, raw in self.captured.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        self.commit()
        self.compiler = b"synthetic compiler for custody controls only"
        self.sources = {"native/owner.hepta": sha256(self.captured["native/owner.hepta"]).hexdigest()}
        # This deliberately incomplete record is only input to a custody gate.
        # It is never passed off as an admitted actual native cold qualification.
        self.report = {"schema": "hepta.hia.selfhost-cold-replay.v2",
                       "source_manifest": self.sources,
                       "generation_sha256": [sha256(self.compiler).hexdigest()] * 3}

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root,
                                       stderr=subprocess.PIPE)

    def commit(self):
        self.git("add", "--all")
        self.git("commit", "-qm", "custody control source")

    def raw(self):
        return json.dumps(self.report).encode()

    def capture(self):
        return capture_component_custody(self.compiler, self.raw(), self.sources,
                                         self.captured, root=self.root)

    def verify(self, custody):
        verify_component_custody(custody, self.compiler, self.raw(), self.sources,
                                 self.captured, root=self.root)

    def corrupt_loose_object(self, identity, kind, raw):
        path = self.root / ".git/objects" / identity[:2] / identity[2:]
        self.assertTrue(path.is_file())
        path.chmod(0o600)
        path.write_bytes(zlib.compress(kind.encode("ascii") + b" "
                                       + str(len(raw)).encode("ascii") + b"\0" + raw))

    def test_exact_real_git_blobs_separate_native_and_authoring_domains(self):
        receipt = self.capture()
        self.verify(receipt)
        self.assertEqual(set(receipt["native_inputs"]), {"native/owner.hepta"})
        self.assertEqual(set(receipt["host_authoring_inputs"]), {"tools/author.py"})
        self.assertIs(receipt["host_authoring_is_native_qualified"], False)
        self.assertIs(receipt["whole_native_delivery_qualified"], False)
        self.assertEqual(receipt["source_head"], self.git("rev-parse", "HEAD").decode().strip())
        for name, data in self.captured.items():
            row = (receipt["native_inputs"] | receipt["host_authoring_inputs"])[name]
            self.assertEqual(self.git("cat-file", "blob", row["git_blob"]), data)
            self.assertEqual(row["sha256"], sha256(data).hexdigest())

    def test_dirty_or_staged_authoring_cannot_borrow_native_qualification(self):
        name = "tools/author.py"
        self.captured[name] += b"# changed\n"
        (self.root / name).write_bytes(self.captured[name])
        with self.assertRaises(ValueError):
            self.capture()
        self.git("add", name)
        with self.assertRaises(ValueError):
            self.capture()

    def test_assume_unchanged_cannot_hide_different_physical_bytes(self):
        name = "tools/author.py"
        self.git("update-index", "--assume-unchanged", name)
        self.captured[name] += b"# hidden from index stat checks\n"
        (self.root / name).write_bytes(self.captured[name])
        self.assertEqual(self.git("status", "--porcelain", "--untracked-files=no"), b"")
        with self.assertRaises(ValueError):
            self.capture()

    def test_corrupt_loose_blob_cannot_borrow_its_original_object_name(self):
        name = "tools/author.py"
        identity = self.git("rev-parse", "HEAD:" + name).decode().strip()
        self.git("update-index", "--assume-unchanged", name)
        self.captured[name] = b"# altered authoring control\n"
        (self.root / name).write_bytes(self.captured[name])
        self.corrupt_loose_object(identity, "blob", self.captured[name])
        self.assertEqual(self.git("status", "--porcelain", "--untracked-files=no"), b"")
        # Git cat-file returns the requested name even when its object body
        # hashes differently; the custody gate must verify that binding itself.
        self.assertEqual(self.git("cat-file", "blob", identity), self.captured[name])
        with self.assertRaisesRegex(ValueError, "Git blob identity"):
            self.capture()

    def test_corrupt_head_commit_body_is_rejected_even_with_unchanged_tree(self):
        identity = self.git("rev-parse", "HEAD").decode().strip()
        raw = self.git("cat-file", "commit", identity)
        self.corrupt_loose_object(identity, "commit", raw + b"changed message\n")
        self.assertEqual(self.git("status", "--porcelain", "--untracked-files=no"), b"")
        with self.assertRaises(ValueError):
            self.capture()

    def test_corrupt_root_tree_body_is_rejected_with_identical_logical_entries(self):
        identity = self.git("rev-parse", "HEAD^{tree}").decode().strip()
        raw = self.git("cat-file", "tree", identity)
        # Leading zeroes leave Git's interpreted mode and logical entries
        # unchanged, while changing the actual tree object bytes and hash.
        self.corrupt_loose_object(identity, "tree", b"0" + raw)
        with self.assertRaises(ValueError):
            self.capture()

    def test_corrupt_intermediate_tree_cannot_borrow_a_valid_parent_link(self):
        identity = self.git("rev-parse", "HEAD:tools").decode().strip()
        raw = self.git("cat-file", "tree", identity)
        self.corrupt_loose_object(identity, "tree", b"0" + raw)
        self.assertEqual(self.git("status", "--porcelain", "--untracked-files=no"), b"")
        with self.assertRaisesRegex(ValueError, "Git tree identity"):
            self.capture()

    def test_changed_physical_mode_is_rejected_even_when_git_ignores_modes(self):
        self.git("config", "core.filemode", "false")
        os.chmod(self.root / "tools/author.py", 0o755)
        self.assertEqual(self.git("status", "--porcelain", "--untracked-files=no"), b"")
        with self.assertRaises(ValueError):
            self.capture()

    def test_untracked_input_and_committed_symlink_are_rejected(self):
        name = "tools/untracked.py"
        self.captured[name] = b"# untracked\n"
        (self.root / name).write_bytes(self.captured[name])
        with self.assertRaises(ValueError):
            self.capture()
        del self.captured[name]
        (self.root / name).unlink()
        path = self.root / "tools/author.py"
        raw = path.read_bytes()
        path.rename(path.with_suffix(".retained"))
        path.symlink_to("author.retained")
        self.commit()
        self.assertEqual(path.read_bytes(), raw)
        with self.assertRaises(ValueError):
            self.capture()

    def test_native_source_cannot_be_relabelled_as_host_authoring(self):
        self.sources.clear()
        with self.assertRaises(ValueError):
            self.capture()

    def test_native_bytes_and_compiler_must_match_the_already_admitted_report(self):
        self.sources["native/owner.hepta"] = "0" * 64
        with self.assertRaises(ValueError):
            self.capture()
        self.sources["native/owner.hepta"] = sha256(self.captured["native/owner.hepta"]).hexdigest()
        self.report["generation_sha256"][1] = "0" * 64
        with self.assertRaises(ValueError):
            self.capture()

    def test_post_compile_commit_drift_is_rejected_even_with_identical_input_bytes(self):
        receipt = self.capture()
        (self.root / "another-file.txt").write_text("new authoring tree\n")
        self.commit()
        with self.assertRaises(ValueError):
            self.verify(receipt)

    def test_receipt_fields_blobs_and_false_authority_claims_are_independently_rederived(self):
        original = self.capture()
        changes = [("source_head", "0" * 40), ("source_tree", "0" * 40),
                   ("compiler_sha256", "0" * 64), ("cold_report_sha256", "0" * 64),
                   ("native_source_manifest_sha256", "0" * 64),
                   ("host_authoring_is_native_qualified", True),
                   ("host_authoring_is_native_qualified", 0),
                   ("whole_native_delivery_qualified", True), ("extra", False)]
        for field, value in changes:
            with self.subTest(field=field, value=value):
                altered = deepcopy(original)
                altered[field] = value
                with self.assertRaises(ValueError):
                    self.verify(altered)
        for field, value in (("git_blob", "0" * 40), ("git_mode", "100755"),
                             ("bytes", True), ("sha256", "0" * 64)):
            with self.subTest(input_field=field):
                altered = deepcopy(original)
                altered["host_authoring_inputs"]["tools/author.py"][field] = value
                with self.assertRaises(ValueError):
                    self.verify(altered)

    def test_legacy_source_domain_keeps_the_original_all_inputs_requirement(self):
        self.report["schema"] = "hepta.hia.selfhost-cold-replay.v1"
        with self.assertRaises(ValueError):
            self.capture()
        self.sources["tools/author.py"] = sha256(self.captured["tools/author.py"]).hexdigest()
        self.assertIsNone(self.capture())
        self.verify(None)

    def test_unsafe_paths_and_duplicate_report_fields_are_rejected(self):
        for name in ("../tools/author.py", "/absolute", "tools//author.py",
                     "tools/./author.py", "tools\\author.py", ".git/config", "a\nb"):
            with self.subTest(path=name), self.assertRaises(ValueError):
                capture_component_custody(self.compiler, self.raw(), self.sources,
                                           {name: b"control"}, root=self.root)
        with self.assertRaises(ValueError):
            capture_component_custody(self.compiler, b'{"schema":1,"schema":2}',
                                       self.sources, self.captured, root=self.root)


if __name__ == "__main__":
    unittest.main()
