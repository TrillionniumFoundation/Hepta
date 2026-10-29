"""Reject output/report parent-symlink rebinding without clobbering C input.

A path-distinctness check made before Clang runs does not make an alias stable:
an attacker can retarget a parent symlink while the compiler is running.
Both artifact writes must use the initially admitted, canonical destinations.
"""
from __future__ import annotations

from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from tools import c2hepta


class ClangArtifactParentRebind(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(shutil.which("clang"), "real Clang required for path-isolation acceptance")
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-artifact-path-rebind-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "input.c"
        self.original = b"int identity(int x) { return x; }\n"
        self.source.write_bytes(self.original)
        self.safe = self.root / "safe"
        self.safe.mkdir()
        self.alias = self.root / "alias"
        self.alias.symlink_to(self.safe, target_is_directory=True)

    def convert_with_parent_rebind(self, output: Path, report: Path):
        real_probe = c2hepta._probe_clang
        changed = False

        def rebound(args, *, label, max_stdout_bytes=16_384):
            nonlocal changed
            if not changed and label == "version":
                self.alias.unlink()
                self.alias.symlink_to(self.root, target_is_directory=True)
                changed = True
            return real_probe(args, label=label, max_stdout_bytes=max_stdout_bytes)

        with patch.object(c2hepta, "_probe_clang", side_effect=rebound):
            result = c2hepta.migrate(self.source, output, report, clang="clang")
        self.assertTrue(changed, "test never exercised the rebinding window")
        return result

    def test_report_parent_rebind_must_not_overwrite_original_c(self):
        report = self.alias / "input.c"
        stable_report = self.safe / "input.c"
        output = self.root / "converted.hepta"
        result = self.convert_with_parent_rebind(output, report)
        self.assertEqual(self.source.read_bytes(), self.original,
                         "report publication clobbered the admitted source")
        self.assertEqual(result["status"], "rejected", result)
        self.assertIn("path binding changed", result["reason"])
        self.assertFalse(output.exists(), "changed destinations must not publish Hepta")
        self.assertTrue(stable_report.is_file(), "rejection report must use the pinned safe path")

    def test_output_parent_rebind_must_not_overwrite_original_c(self):
        output = self.alias / "input.c"
        report = self.root / "audit.json"
        result = self.convert_with_parent_rebind(output, report)
        self.assertEqual(self.source.read_bytes(), self.original,
                         "Hepta output publication clobbered the admitted C source")
        self.assertEqual(result["status"], "rejected", result)
        self.assertIn("path binding changed", result["reason"])
        self.assertFalse((self.safe / "input.c").exists())
        self.assertTrue(report.is_file())

    def test_unmodified_parent_symlink_preserves_regular_conversion(self):
        output = self.alias / "converted.hepta"
        report = self.alias / "audit.json"
        result = c2hepta.migrate(self.source, output, report, clang="clang")
        self.assertEqual(result["status"], "converted", result)
        self.assertEqual(result["frontend_validation"], "passed")
        self.assertEqual(self.source.read_bytes(), self.original)
        self.assertTrue((self.safe / "converted.hepta").is_file())
        self.assertTrue((self.safe / "audit.json").is_file())


if __name__ == "__main__":
    unittest.main()
