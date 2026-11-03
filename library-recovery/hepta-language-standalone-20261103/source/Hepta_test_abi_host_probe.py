"""Separate host GCC/Clang ABI runtime checks; not a Hepta backend proof."""
from __future__ import annotations

from pathlib import Path
import shutil
import tempfile
import unittest

from tools.abi_host_probe import run_matrix


@unittest.skipUnless(shutil.which("gcc") and shutil.which("clang"),
                     "GCC and Clang are needed for cross-compiler C ABI testing")
class HostABITests(unittest.TestCase):
    def test_bidirectional_actual_c_caller_and_callee(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = run_matrix(Path(tmp), shutil.which("gcc"), shutil.which("clang"))
        self.assertEqual(report["status"], "passed_host_only")
        self.assertEqual(len(report["executions"]), 16)
        self.assertTrue(all(r["passed"] for r in report["executions"]))
        self.assertEqual(report["negative_control"]["exit_code"], 11)
        self.assertFalse(report["claims"]["hepta_abi_validated"])
        self.assertFalse(report["claims"]["cross_target_abi_validated"])
        self.assertEqual({r["producer"] for r in report["executions"]}, {"gcc", "clang"})
        self.assertEqual({r["consumer"] for r in report["executions"]}, {"gcc", "clang"})


if __name__ == "__main__":
    unittest.main()
