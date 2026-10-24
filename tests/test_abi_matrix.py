"""Finite native ABI generation, complementary to the small handpicked fixture."""
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

from tools.abi_fuzz import audit_boundaries, run_matrix
from tools.validate import Runner, rustc_path


@unittest.skipUnless(sys.platform.startswith("linux") and rustc_path() and shutil.which("gcc"),
                     "native ABI matrix requires Linux, pinned rustc, and GCC")
class AbiMatrixTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hepta-test-abi-matrix-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.runner = Runner(rustc_path())

    def test_seeded_bidirectional_aggregate_pointer_and_register_spill_matrix(self):
        report = run_matrix(self.runner, self.directory)
        self.assertEqual(report["status"], "passed")
        self.assertEqual(len(report["executions"]), 3)

    def test_unsupported_layouts_and_c_identifier_collisions_fail_closed(self):
        self.assertEqual(audit_boundaries(self.runner, self.directory)["status"], "passed")


if __name__ == "__main__":
    unittest.main()
