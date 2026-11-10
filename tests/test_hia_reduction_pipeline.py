"""Independent semantics, counterexamples, fallback, and publication checks."""
from __future__ import annotations

import copy
import ctypes
from hashlib import sha256
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program, HIAProgramTrap
from hepta.hia_optimization import DEFAULT_POLICY, OptimizationRejected, verify_optimization
from hepta.hia_guarded_optimization import BYTE_SUM_LIMIT, propose_guarded_reduction
from hepta.hia_reduction import (propose_byte_narrowing, propose_reduction_pipeline,
    verify_reduction_pipeline, reduction_program, build_reduction_native,
    reduction_checker_identity)

try:
    import z3
except ImportError:
    z3 = None

ROOT = Path(__file__).resolve().parents[1]


def expected(n, seed):
    # Direct mathematical oracle, independent of HIA lowering and both solvers.
    return sum((i + seed) % 256 for i in range(n))




@unittest.skipUnless(z3 is not None and shutil.which(os.environ.get("HEPTA_TEST_CLANG","clang")),"native Clang and Z3 required")
class ReductionNativeTests(unittest.TestCase):
    pass


if __name__ == "__main__":
    unittest.main()
