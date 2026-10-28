"""Direct migration API must not clobber an aliased C input or output."""
from pathlib import Path
import tempfile
import unittest

from tools.c2hepta import UnsupportedC, migrate


class MigrationPublicAPIPathIsolation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-c2hepta-paths-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "module.c"
        self.output = self.root / "module.hepta"
        self.report = self.root / "migration.json"
        self.original = b"int identity(int x) { return x; }\n"
        self.source.write_bytes(self.original)

    def assert_alias_rejected(self, output, report):
        with self.assertRaisesRegex(UnsupportedC, "must be distinct"):
            migrate(self.source, output, report, clang="/no/such/clang")
        self.assertEqual(self.source.read_bytes(), self.original)

    def test_output_alias_source_is_rejected_before_processing(self):
        self.assert_alias_rejected(self.source, self.report)
        self.assertFalse(self.report.exists())

    def test_report_alias_source_is_rejected_even_on_failed_conversion(self):
        # Prior direct API behavior overwrote the original C file with a
        # JSON rejection report when clang was unavailable.
        self.assert_alias_rejected(self.output, self.source)
        self.assertFalse(self.output.exists())

    def test_output_alias_report_preserves_existing_artifact(self):
        self.output.write_text("previous-artifact", encoding="utf-8")
        self.assert_alias_rejected(self.output, self.output)
        self.assertEqual(self.output.read_text(), "previous-artifact")

    def test_parent_symlink_alias_cannot_bypass_isolation(self):
        alias = self.root / "alternate"
        alias.symlink_to(self.root, target_is_directory=True)
        self.assert_alias_rejected(self.output, alias / "module.c")

    def test_distinct_paths_still_produce_rejection_report(self):
        result = migrate(self.source, self.output, self.report,
                         clang="/no/such/clang")
        self.assertEqual(result["status"], "rejected")
        self.assertIn("clang executable unavailable", result["reason"])
        self.assertEqual(self.source.read_bytes(), self.original)
        self.assertFalse(self.output.exists())
        self.assertTrue(self.report.exists())


if __name__ == "__main__":
    unittest.main()
