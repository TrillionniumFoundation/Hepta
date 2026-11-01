"""Actual frontend and native evidence for the direct release/reset profile."""
from __future__ import annotations

import gzip
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from tools.qualify_cpp_unique_reset import qualify, qualify_source_refusals, SOURCE_REFUSALS

CLANGXX = os.environ.get("CLANGXX", "clang++")
CLANG = os.environ.get("CLANG", "clang")


@unittest.skipUnless(shutil.which(CLANGXX), "Actual Clang20+ and system C++ headers required")
class UniqueResetTests(unittest.TestCase):
    def test_real_source_refusals(self):
        with tempfile.TemporaryDirectory(prefix="hepta-unique-reset-refusal-") as temporary:
            report = qualify_source_refusals(Path(temporary) / "evidence", clangxx=CLANGXX)
            self.assertTrue(report["ok"], report.get("error"))
            self.assertEqual(len(report["controls"]), len(SOURCE_REFUSALS))
            self.assertTrue(all(control["rejected"] and control["fresh_clang_capture"]
                                and control["code"] == control["expected_code"]
                                for control in report["controls"]))

    def test_native_values_lifetime_c_abi_and_project_api_change(self):
        if not all(shutil.which(tool) for tool in (CLANG, "gcc", "g++")):
            self.skipTest("Native C/C++ tools required")
        with tempfile.TemporaryDirectory(prefix="hepta-unique-reset-native-") as temporary:
            report = qualify(Path(temporary) / "evidence", clangxx=CLANGXX, clang=CLANG)
            self.assertTrue(report["ok"], report.get("error"))
            self.assertEqual(len(report["variants"]), 2)
            self.assertTrue(report["claims"]["independent_c_abi_caller_for_both_implementations"])
            self.assertFalse(report["claims"]["real_upstream_library_upgrade_tested"])
            for row in report["variants"]:
                self.assertEqual(row["case_count"], 1245)
                self.assertEqual(row["expected"]["allocations"], row["expected"]["frees"])
                self.assertEqual(row["expected"]["refusals"], 642)
                self.assertEqual(row["expected"]["live"], 0)
                self.assertEqual(row["standalone_hia"]["original_cpp_link_inputs"], [])
                migration = row["migration"]
                self.assertEqual(migration["unconverted_declarations"], [])
                self.assertEqual(migration["translation_statistics"]["distinct_release_reset"], 1)
                self.assertEqual(migration["translation_statistics"]["self_release_reset"], 1)
                self.assertEqual(migration["translation_statistics"]["explicit_reset_null"], 2)
                self.assertIsNone(migration["costs"]["human_engineering_seconds"])
                census = migration["standard_library_census"]
                raw = gzip.decompress(Path(census["path"]).read_bytes())
                self.assertEqual(sha256(raw).hexdigest(), census["uncompressed_sha256"])
                self.assertEqual(len(json.loads(raw)), census["declarations"])
                self.assertTrue(all(item["status"] == "standard_library_dependency_not_migrated"
                                    for item in json.loads(raw)))
            for name, control in report["negative_controls"].items():
                if name.endswith("missing_drop"):
                    self.assertTrue(control["rejected"])
                    self.assertFalse(control["artifact_exists"])
                else:
                    self.assertTrue(control["resource_check_passed"])
                    self.assertTrue(control["detected"])


if __name__ == "__main__":
    unittest.main()
