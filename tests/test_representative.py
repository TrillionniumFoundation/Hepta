from pathlib import Path
import shutil
import tempfile
import unittest

from tools.benchmark_suite import build_suite, correctness
from tools.validate import Runner, rustc_path


@unittest.skipUnless(shutil.which("gcc") and rustc_path(), "GCC and pinned rustc required")
class RepresentativeKernelTests(unittest.TestCase):
    def test_all_four_kernels_match_independent_references_on_tails_and_empty_inputs(self):
        with tempfile.TemporaryDirectory(prefix="hepta-representative-test-") as td:
            runner = Runner(rustc_path())
            binaries, _ = build_suite(runner, Path(td))
            result = correctness(runner, binaries)
            self.assertEqual(result["status"], "passed")


if __name__ == "__main__":
    unittest.main()
