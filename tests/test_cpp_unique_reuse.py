"""Actual Clang source boundaries and independent native lifecycle controls."""
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.cpp_unique_reset import lower_unique_reset_project, REUSABLE_PROFILE
from tools.qualify_cpp_unique_reset import qualify
from tools.qualify_cpp_unique_reuse import qualify_refusals, REFUSALS


class UniqueReuseProfileTests(unittest.TestCase):
    def test_profile_flag_is_exact_boolean(self):
        for invalid in (1, "yes", None, [], {}):
            with self.assertRaisesRegex(ValueError, "explicit Boolean"):
                lower_unique_reset_project("unopened.json", reusable_released_owners=invalid)

    def test_actual_cpp_and_core_preserve_values_and_ordered_lifetimes(self):
        clangxx, clang = os.environ.get("CLANGXX", "clang++"), os.environ.get("CLANG", "clang")
        if not all(shutil.which(tool) for tool in (clangxx, clang, "gcc", "g++")):
            self.skipTest("Actual Clang 20 and native C/C++ tools required")
        with tempfile.TemporaryDirectory(prefix="hia-unique-reuse-") as temporary:
            result = qualify(Path(temporary) / "native", clangxx=clangxx, clang=clang,
                             reusable_released_owners=True)
            self.assertTrue(result["ok"], result.get("error"))
            self.assertEqual(len(result["variants"]), 2)
            for row in result["variants"]:
                self.assertEqual(row["case_count"], 2211)
                self.assertEqual(row["expected"]["live"], 0)
                self.assertEqual(row["expected"]["allocations"], row["expected"]["frees"])
                migration = row["migration"]
                self.assertEqual(migration["profile"], REUSABLE_PROFILE)
                self.assertEqual(migration["unconverted_declarations"], [])
                self.assertTrue(migration["claims"]["released_source_reuse_supported"])
                self.assertFalse(migration["claims"]["pointer_escape_supported"])
                self.assertEqual(migration["translation_statistics"]["distinct_release_reset"], 4)
                self.assertEqual(migration["translation_statistics"]["self_release_reset"], 2)
                self.assertIsNone(migration["costs"]["human_engineering_seconds"])
                self.assertEqual(row["standalone_hia"]["original_cpp_link_inputs"], [])
            self.assertFalse(result["claims"]["real_upstream_library_upgrade_tested"])
            self.assertTrue(all(v.get("rejected", v.get("detected")) for v in result["negative_controls"].values()))

    def test_fresh_source_refusals_and_original_profile_boundary(self):
        if not shutil.which(os.environ.get("CLANGXX", "clang++")):
            self.skipTest("Actual Clang 20 and system C++ headers required")
        with tempfile.TemporaryDirectory(prefix="hia-unique-reuse-refusal-") as temporary:
            result = qualify_refusals(Path(temporary) / "refusals",
                                      clangxx=os.environ.get("CLANGXX", "clang++"))
            self.assertTrue(result["ok"], result.get("error"))
            self.assertEqual(len(result["controls"]), len(REFUSALS) + 1)
            self.assertTrue(all(c["rejected"] and c["code"] == c["expected_code"]
                                for c in result["controls"]))


if __name__ == "__main__":
    unittest.main()
