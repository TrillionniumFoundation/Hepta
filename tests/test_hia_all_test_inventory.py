"""The broad inventory includes all live modules and safely resolves its report."""
from pathlib import Path
import tempfile
import unittest
from tools.qualify_hia_all_tests import ROOT, inventory, normalize_report_path


class FullHIAInventoryTests(unittest.TestCase):
    def test_repository_mode_includes_non_hia_tests_without_replacing_hia_inventory(self):
        rows = inventory(repository_wide=True)
        expected = {p.relative_to(ROOT).as_posix() for p in (ROOT / "tests").rglob("test*.py")}
        self.assertEqual({row["path"] for row in rows}, expected)
        self.assertEqual(len(rows), len(expected))
        self.assertLess({row["path"] for row in inventory()}, expected)
        self.assertTrue(any(not row["module"].startswith("tests.test_hia")
                            for row in rows))

    def test_every_live_hia_and_shared_acceptance_module_is_included_once(self):
        rows = inventory()
        expected = {p.relative_to(ROOT).as_posix() for p in (ROOT / "tests").rglob("test_hia*.py")}
        expected |= {p.relative_to(ROOT).as_posix() for p in (ROOT / "tests").rglob("test_core_seven_shared*.py")}
        self.assertEqual({row["path"] for row in rows}, expected)
        self.assertEqual(len(rows), len(expected))
        self.assertTrue(all(len(row["sha256"]) == 64 for row in rows))
        self.assertIn("tests.test_hia_all_test_inventory", {row["module"] for row in rows})

    def test_parent_relative_outputs_resolve_outside_but_links_and_overwrites_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "checkout"; root.mkdir()
            self.assertEqual(normalize_report_path(root / ".." / "report.json", root),
                             Path(directory) / "report.json")
            existing = Path(directory) / "existing.json"; existing.write_text("retained")
            linked = Path(directory) / "linked"; linked.symlink_to(root, target_is_directory=True)
            dangling = Path(directory) / "dangling.json"; dangling.symlink_to(Path(directory) / "absent.json")
            for value in (root / "inside.json", existing, linked / ".." / "other.json", dangling):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    normalize_report_path(value, root)
            self.assertEqual(existing.read_text(), "retained")
            self.assertFalse((Path(directory) / "absent.json").exists())


if __name__ == "__main__":
    unittest.main()
