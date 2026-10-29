"""Canonical directory replacement must never redirect Clang migration artifacts.

A resolved absolute pathname is not an immutable directory capability:
rename(parent) followed by symlink(parent, source_dir) redirects _atomic_write
even when the caller correctly rejected mutable *alias* rebindings earlier.
The POSIX publisher must keep a directory descriptor opened before the Clang
window and use descriptor-relative staging and replacement for BOTH artifacts.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from tools import c2hepta


class CanonicalDirectorySwap(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.name, "posix", "this gate qualifies POSIX dir-fd publication")
        self.assertIsNotNone(shutil.which("clang"), "real Clang required")
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-dirfd-swap-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "input.c"
        self.original = b"int identity(int x) { return x; }\n"
        self.source.write_bytes(self.original)
        self.safe = self.root / "safe"
        self.safe.mkdir()
        self.parked = self.root / "original-safe"

    def convert_swapping_canonical_parent(self, output: Path, report: Path, clang: str):
        original_atomic = c2hepta._atomic_write
        swapped = False

        def sabotage(path, content, **kwargs):
            nonlocal swapped
            if not swapped and path == self.safe / "input.c":
                self.safe.rename(self.parked)
                self.safe.symlink_to(self.root, target_is_directory=True)
                swapped = True
            return original_atomic(path, content, **kwargs)

        with patch.object(c2hepta, "_atomic_write", side_effect=sabotage):
            result = c2hepta.migrate(self.source, output, report, clang=clang)
        self.assertTrue(swapped, "test never swapped the canonical artifact directory")
        return result

    def test_rejection_report_cannot_overwrite_source_after_canonical_directory_swap(self):
        result = self.convert_swapping_canonical_parent(
            self.root / "translated.hepta", self.safe / "input.c", "/no/such/clang")
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(self.source.read_bytes(), self.original,
                         "rejection report redirected through replaced canonical directory")
        report = json.loads((self.parked / "input.c").read_text())
        self.assertEqual(report["status"], "rejected")
        self.assertFalse((self.root / "translated.hepta").exists())

    def test_converted_output_cannot_overwrite_source_after_canonical_directory_swap(self):
        result = self.convert_swapping_canonical_parent(
            self.safe / "input.c", self.root / "audit.json", "clang")
        self.assertEqual(self.source.read_bytes(), self.original,
                         "converted output redirected through replaced canonical directory")
        self.assertTrue((self.parked / "input.c").read_text().startswith(
            "module c2hepta_generated;"))
        self.assertTrue((self.root / "audit.json").is_file())
        self.assertIn(result["status"], {"converted", "rejected"})

    def test_stable_canonical_parent_still_publishes_real_clang_output_and_report(self):
        result = c2hepta.migrate(
            self.source, self.safe / "converted.hepta", self.safe / "audit.json",
            clang="clang")
        self.assertEqual(result["status"], "converted", result)
        self.assertEqual(result["frontend_validation"], "passed")
        self.assertEqual(self.source.read_bytes(), self.original)
        self.assertTrue((self.safe / "converted.hepta").read_text().startswith(
            "module c2hepta_generated;"))
        self.assertEqual(json.loads((self.safe / "audit.json").read_text())["status"],
                         "converted")


if __name__ == "__main__":
    unittest.main()
