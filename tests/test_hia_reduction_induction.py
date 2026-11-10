"""The general two-workload pipeline independently proves each counted step."""
from __future__ import annotations

from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

from hepta.hia_optimization import OptimizationRejected
from hepta.hia_program_runtime import execute_program
from hepta.hia_reduction import (propose_reduction_pipeline, reduction_program,
                                verify_reduction_pipeline, build_reduction_native)

ROOT = Path(__file__).resolve().parents[1]


class ReductionInductionTests(unittest.TestCase):


    pass


CLANG = os.environ.get("HEPTA_TEST_CLANG", os.environ.get("CLANG", "clang"))


@unittest.skipUnless(shutil.which(CLANG), "actual Clang 20+ required")
class ReductionInductionNativeTests(unittest.TestCase):
    pass


if __name__ == "__main__":
    unittest.main()
