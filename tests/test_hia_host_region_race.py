"""A real native recovery race; scheduling control does not fake native work."""
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

from tests.hia_host_region_race_fixture import run


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "memfd_create"), "Linux memfd required")
class HostRegionRaceTests(unittest.TestCase):
    def test_competing_recovery_and_late_caller_preserve_new_epoch(self):
        clang = shutil.which(os.environ.get("HEPTA_TEST_CLANG", "clang"))
        if clang is None:
            self.skipTest("Actual native Clang required")
        with tempfile.TemporaryDirectory(prefix="hia-native-race-") as directory:
            result = run(Path(directory) / "evidence", clang)
            self.assertTrue(result["qualification_valid"], result.get("error"))
            execution = result["execution"]
            self.assertEqual(execution["native_reader_entries"], 2)
            self.assertEqual(sorted(r["status"] for r in execution["recoveries"]), ["committed", "denied"])
            self.assertTrue(execution["old_caller_cannot_commit_or_revoke_recovered_epoch"])
            self.assertTrue(execution["all_native_workers_joined"])
            self.assertEqual(len(execution["denials"]), 5)
            self.assertFalse(execution["retained_after"]["regions"])
            self.assertFalse(execution["retained_after"]["libraries"])


if __name__ == "__main__":
    unittest.main()
