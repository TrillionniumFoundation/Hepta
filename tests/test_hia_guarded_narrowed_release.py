"""Bind induction and modular proofs to the actual release object and controls."""
from __future__ import annotations

from copy import deepcopy
import ctypes
from hashlib import sha256
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_guarded_optimization import propose_guarded_reduction
from hepta.hia_narrowing import (
    propose_guarded_narrowing, verify_guarded_narrowing,
    build_guarded_narrowed_native,
)
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_optimization import OptimizationRejected

ROOT = Path(__file__).resolve().parents[1]
PROFILE = "verified-reduction-narrowed-release-v1"
CLANG = os.environ.get("CLANG", "clang")
RUSTC = os.environ.get("RUSTC", "rustc")




@unittest.skipUnless(shutil.which(CLANG) and shutil.which(RUSTC), "actual Clang and Rust toolchains required")
class GuardedNarrowedReleaseNativeTests(unittest.TestCase):
    pass


if __name__ == "__main__":
    unittest.main()
