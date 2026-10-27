"""Focused positive/negative source-drift evidence tests.

These do not qualify the full native release workflow.
"""
import unittest

from tools.release_check import source_snapshot_delta


class ReleaseSnapshotDeltaTests(unittest.TestCase):
    def test_unchanged_source_produces_no_diagnostic_changes(self):
        snapshot = {"sha256": "same", "files": {"hepta/a.py": "aaa"}}
        self.assertEqual(source_snapshot_delta(snapshot, snapshot), [])

    def test_mutation_retains_both_exact_source_digests(self):
        before = {"sha256": "old", "files": {"hepta/a.py": "aaa"}}
        after = {"sha256": "new", "files": {"hepta/a.py": "bbb"}}
        self.assertEqual(
            source_snapshot_delta(before, after),
            [{"path": "hepta/a.py", "before_sha256": "aaa", "after_sha256": "bbb"}],
        )
        self.assertNotEqual(before, after)

    def test_addition_and_removal_have_deterministic_path_order(self):
        before = {"files": {"z.py": "old"}}
        after = {"files": {"a.py": "new"}}
        self.assertEqual(
            source_snapshot_delta(before, after),
            [
                {"path": "a.py", "before_sha256": None, "after_sha256": "new"},
                {"path": "z.py", "before_sha256": "old", "after_sha256": None},
            ],
        )

    def test_file_order_does_not_generate_false_changes(self):
        before = {"files": {"z.py": "z", "a.py": "a"}}
        after = {"files": {"a.py": "a", "z.py": "z"}}
        self.assertEqual(source_snapshot_delta(before, after), [])

    def test_missing_source_inventory_refuses_instead_of_claiming_no_change(self):
        with self.assertRaises(KeyError):
            source_snapshot_delta({}, {"files": {}})


if __name__ == "__main__":
    unittest.main()
