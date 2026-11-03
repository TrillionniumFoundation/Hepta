"""Historical byte integrity survives relocation without weakening its oracle."""
from copy import deepcopy
import hashlib
from pathlib import Path
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

    def test_frozen_contract_has_exact_original_inventory_and_two_moves(self):
        rows, aliases = evidence.load_contract()
        self.assertEqual(len(rows), 611)
        self.assertEqual(len(aliases), 2)
        original_verifier = next(row for row in rows if row["path"].endswith("/VERIFY.py"))
        self.assertEqual(original_verifier["sha256"], "55ba4daaae15855b7905dd37614959b7e4b7f9c8c85272a1b96ce9671f21a1e6")

    def test_modified_contract_cannot_reseal_or_drop_old_rows(self):
        for name in (evidence.INDEX, evidence.MIGRATIONS):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((evidence.ROOT / name).read_bytes())
        for name in (evidence.INDEX, evidence.MIGRATIONS):
            path = self.root / name
            original = path.read_bytes()
            path.write_bytes(original + b" ")
            with self.assertRaisesRegex(ValueError, "contract bytes changed"):
                evidence.load_contract(self.root)
            path.write_bytes(original)


if __name__ == "__main__":
    unittest.main()
