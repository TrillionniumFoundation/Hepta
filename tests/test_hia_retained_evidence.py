"""Historical byte integrity survives relocation without weakening its oracle."""
from copy import deepcopy
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest

from tools import verify_hia_retained_evidence as evidence


def identity(name, data):
    return {"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


class RetainedEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.owner = tempfile.TemporaryDirectory()
        self.addCleanup(self.owner.cleanup)
        self.root = Path(self.owner.name)
        self.program, self.receipt = b"original program\n", b"original receipt\n"
        self.rows = [identity("archive/BASE.json", self.program), identity("archive/base.json", self.receipt)]
        self.migration = {"schema": "hepta.archive-path-migrations.v1", "original_source_commit": "a" * 40,
            "reason": "fixture case collision", "historical_snapshots_edited": False,
            "new_native_execution_claimed": False, "migrations": [{
                "original_path": self.rows[0]["path"], "current_path": "archive/BASE_PROGRAM.json",
                "bytes": self.rows[0]["bytes"], "sha256": self.rows[0]["sha256"],
                "unchanged_receipt": self.rows[1].copy()}]}
        (self.root / "archive").mkdir()
        (self.root / "archive/BASE_PROGRAM.json").write_bytes(self.program)
        (self.root / "archive/base.json").write_bytes(self.receipt)

    def verify(self):
        aliases = evidence.migration_aliases(self.rows, self.migration)
        return evidence.verify_rows(self.root, self.rows, aliases)

    def test_relocation_preserves_both_original_byte_oracles(self):
        result = self.verify()
        self.assertTrue(result["passed"])
        self.assertEqual(result["files_checked"], 2)
        self.assertEqual(result["bytes_checked"], len(self.program) + len(self.receipt))
        self.assertEqual(result["path_migrations"], {"archive/BASE.json": "archive/BASE_PROGRAM.json"})

    def test_modified_moved_program_and_unmoved_receipt_are_both_refused(self):
        for name, original in (("BASE_PROGRAM.json", self.program), ("base.json", self.receipt)):
            path = self.root / "archive" / name
            for changed in (b"X" + original[1:], original + b"extra"):
                path.write_bytes(changed)
                result = self.verify()
                self.assertFalse(result["passed"])
                self.assertEqual(len(result["failures"]), 1)
            path.write_bytes(original)

    def test_missing_unmigrated_row_is_not_excluded_from_the_denominator(self):
        self.rows.append(identity("missing.json", b"required"))
        result = self.verify()
        self.assertFalse(result["passed"])
        self.assertEqual(result["files_checked"], 3)
        self.assertEqual(result["failures"][0]["path"], "missing.json")

    def test_duplicate_unknown_or_changed_migration_oracle_refuses(self):
        duplicate = deepcopy(self.migration)
        duplicate["migrations"].append(deepcopy(duplicate["migrations"][0]))
        variants = [duplicate]
        for key, value in (("original_path", "unknown.json"), ("bytes", True),
                           ("sha256", "0" * 64), ("current_path", "archive/base.json")):
            changed = deepcopy(self.migration)
            changed["migrations"][0][key] = value
            variants.append(changed)
        changed = deepcopy(self.migration)
        changed["migrations"][0]["unchanged_receipt"]["sha256"] = "0" * 64
        variants.append(changed)
        for variant in variants:
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                evidence.migration_aliases(self.rows, variant)

    def test_absolute_traversal_and_platform_alias_paths_refuse(self):
        for name in ("../escape", "/absolute", "archive//file", "archive/./file", "C:stream", "archive\\file"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                evidence.verify_rows(self.root, self.rows, {self.rows[0]["path"]: name})
        with self.assertRaises(ValueError):
            evidence.verify_rows(self.root, self.rows, {self.rows[0]["path"]: "archive/BASE.JSON"})


class RetainedGitEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.owner = tempfile.TemporaryDirectory()
        self.addCleanup(self.owner.cleanup)
        self.root = Path(self.owner.name)
        self.git("init", "-q")
        self.payloads = {"original.bin": b"original\0bytes\n",
                         "literal[1].json": b'{"original": true}\n'}
        for name, data in self.payloads.items():
            (self.root / name).write_bytes(data)
        self.rows = [identity(name, data) for name, data in self.payloads.items()]
        self.first = self.commit()

    def git(self, *args):
        return subprocess.check_output(
            ["git", "-C", str(self.root), "-c", "user.name=Evidence Fixture",
             "-c", "user.email=evidence-fixture@example.invalid", "-c", "commit.gpgsign=false", *args],
            stderr=subprocess.DEVNULL,
        ).decode().strip()

    def commit(self):
        self.git("add", "-A")
        self.git("commit", "-qm", "Independent historical evidence fixture")
        return self.git("rev-parse", "HEAD")

    def test_explicit_git_mode_preserves_original_bytes_without_restoring_current_paths(self):
        (self.root / "original.bin").unlink()
        (self.root / "literal[1].json").write_bytes(b"uncommitted different bytes")
        result = evidence.verify_git_rows(self.root, self.rows, self.first[:12])
        self.assertTrue(result["passed"])
        self.assertEqual(result["resolved_commit"], self.first)
        self.assertEqual(result["files_checked"], 2)
        self.assertEqual(result["bytes_checked"], sum(map(len, self.payloads.values())))
        self.assertFalse((self.root / "original.bin").exists())
        current = evidence.verify_rows(self.root, self.rows, {})
        self.assertFalse(current["passed"])
        self.assertEqual(len(current["failures"]), 2)

    def test_changed_same_size_blob_fails_original_hash_at_resolved_new_revision(self):
        data = self.payloads["original.bin"]
        (self.root / "original.bin").write_bytes(b"X" + data[1:])
        changed = self.commit()
        result = evidence.verify_git_rows(self.root, self.rows, "HEAD")
        self.assertFalse(result["passed"])
        self.assertEqual(result["resolved_commit"], changed)
        self.assertEqual(result["failures"], [{"path": "original.bin",
                         "reason": "Original hash mismatch in selected Git commit"}])
        self.assertTrue(evidence.verify_git_rows(self.root, self.rows, self.first)["passed"])

    def test_missing_path_retains_complete_denominator_and_never_uses_worktree_substitution(self):
        (self.root / "original.bin").unlink()
        removed = self.commit()
        (self.root / "original.bin").write_bytes(self.payloads["original.bin"])
        result = evidence.verify_git_rows(self.root, self.rows, removed)
        self.assertFalse(result["passed"])
        self.assertEqual(result["files_checked"], 2)
        self.assertEqual(result["failures"], [{"path": "original.bin",
                         "reason": "Original path is absent from selected Git commit"}])

    def test_wrong_unavailable_or_option_shaped_revision_is_refused(self):
        for revision in ("missing-evidence-revision", "--help", "HEAD\nother", "", "a" * 513):
            with self.subTest(revision=revision), self.assertRaises(ValueError):
                evidence.verify_git_rows(self.root, self.rows, revision)

    def test_symlink_blob_is_refused_even_when_its_target_bytes_match_the_manifest(self):
        target = b"outside.dat"
        (self.root / "outside.dat").write_bytes(b"must not be read through the link")
        (self.root / "original.bin").unlink()
        (self.root / "original.bin").symlink_to(target.decode())
        linked = self.commit()
        result = evidence.verify_git_rows(self.root, [identity("original.bin", target)], linked)
        self.assertFalse(result["passed"])
        self.assertEqual(result["bytes_checked"], 0)
        self.assertEqual(result["failures"], [{"path": "original.bin",
                         "reason": "Original path is not an ordinary Git file blob"}])

    def test_blob_size_mismatch_and_oversized_manifest_are_refused_before_payload_read(self):
        (self.root / "original.bin").write_bytes(self.payloads["original.bin"] + b"extra")
        changed = self.commit()
        result = evidence.verify_git_rows(self.root, self.rows, changed)
        self.assertFalse(result["passed"])
        self.assertEqual(result["bytes_checked"], len(self.payloads["literal[1].json"]))
        self.assertEqual(result["failures"], [{"path": "original.bin",
                         "reason": "Original size mismatch in selected Git commit"}])
        oversized = deepcopy(self.rows)
        oversized[0]["bytes"] = evidence.MAX_GIT_MEMBER_BYTES + 1
        with self.assertRaisesRegex(ValueError, "member or total byte bounds"):
            evidence.verify_git_rows(self.root, oversized, self.first)

    def test_replacement_refs_cannot_substitute_the_selected_commit(self):
        (self.root / "original.bin").write_bytes(b"replacement commit")
        changed = self.commit()
        self.git("replace", self.first, changed)
        result = evidence.verify_git_rows(self.root, self.rows, self.first)
        self.assertTrue(result["passed"])
        self.assertEqual(result["resolved_commit"], self.first)
        self.assertFalse(result["replacement_objects_allowed"])

    def test_partial_clone_missing_blobs_never_trigger_implicit_fetch(self):
        self.git("config", "uploadpack.allowFilter", "true")
        owner = tempfile.TemporaryDirectory()
        self.addCleanup(owner.cleanup)
        partial = Path(owner.name) / "partial"
        subprocess.run(
            ["git", "-c", "protocol.file.allow=always", "clone", "-q",
             "--filter=blob:none", "--no-checkout", self.root.as_uri(), str(partial)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

        def objects():
            return {str(path.relative_to(partial)): hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in (partial / ".git/objects").rglob("*") if path.is_file()}

        before = objects()
        result = evidence.verify_git_rows(partial, self.rows, self.first)
        self.assertFalse(result["passed"])
        self.assertEqual(result["files_checked"], 2)
        self.assertEqual(len(result["failures"]), 2)
        self.assertEqual(result["bytes_checked"], 0)
        self.assertEqual(objects(), before)




if __name__ == "__main__":
    unittest.main()
