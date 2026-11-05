"""Fresh Clang admission and native allocation identities for member swap."""
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.cpp_unique_reset import lower_unique_reset_project, SWAP_PROFILE
from tools.qualify_cpp_unique_reset import qualify
from tools.qualify_cpp_unique_swap import cases, qualify_refusals, REFUSALS


class UniqueSwapTests(unittest.TestCase):
    def test_explicit_profile_and_reusable_slots_required(self):
        for invalid in (1, "yes", None, [], {}):
            with self.assertRaisesRegex(ValueError, "explicit Boolean"):
                lower_unique_reset_project("unopened.json", owner_swaps=invalid)
        with self.assertRaisesRegex(ValueError, "requires reusable_released_owners=True"):
            lower_unique_reset_project("unopened.json", owner_swaps=True)

    def test_native_lifetimes_and_current_length_after_swap(self):
        clangxx, clang = os.environ.get("CLANGXX", "clang++"), os.environ.get("CLANG", "clang")
        if not all(shutil.which(p) for p in (clangxx, clang, "gcc", "g++")):
            self.skipTest("Actual Clang20+ and native C/C++ tools required")
        with tempfile.TemporaryDirectory(prefix="hia-swap-native-") as directory:
            report = qualify(Path(directory) / "native", clangxx=clangxx, clang=clang,
                             reusable_released_owners=True, owner_swaps=True)
            self.assertTrue(report["ok"], report.get("error"))
            self.assertEqual(len(report["variants"]), 2)
            for variant in report["variants"]:
                self.assertEqual(variant["case_count"], len(cases(3)))
                self.assertEqual(variant["expected"]["allocations"], variant["expected"]["frees"])
                self.assertEqual(variant["expected"]["live"], 0)
                migration = variant["migration"]
                self.assertEqual(migration["profile"], SWAP_PROFILE)
                self.assertEqual(migration["unconverted_declarations"], [])
                self.assertEqual(migration["translation_statistics"]["distinct_owner_swaps"], 3)
                self.assertEqual(migration["translation_statistics"]["self_owner_swaps"], 2)
                self.assertTrue(migration["claims"]["bound_member_swap_supported"])
                self.assertFalse(migration["claims"]["std_swap_supported"])
                self.assertFalse(migration["claims"]["source_equivalence_formally_proved"])
                self.assertEqual(variant["standalone_hia"]["original_cpp_link_inputs"], [])
            self.assertTrue(all(c.get("rejected", c.get("detected"))
                                for c in report["negative_controls"].values()))

    def test_legacy_boundary_stale_lengths_empty_reads_and_aliases_reject(self):
        clangxx = os.environ.get("CLANGXX", "clang++")
        if not shutil.which(clangxx):
            self.skipTest("Actual Clang20+ required")
        with tempfile.TemporaryDirectory(prefix="hia-swap-refusals-") as directory:
            report = qualify_refusals(Path(directory) / "refusals", clangxx=clangxx)
            self.assertTrue(report["ok"], report.get("error"))
            self.assertEqual(len(report["controls"]), len(REFUSALS) + 2)
            self.assertTrue(all(c["rejected"] and c["code"] == c["expected_code"]
                                for c in report["controls"]))


if __name__ == "__main__":
    unittest.main()
