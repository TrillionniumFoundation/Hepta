"""Guard discharge, inductive counterexamples, original fallback and native bytes."""
from __future__ import annotations

import copy
import contextlib
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_program_runtime import execute_program
from hepta.hia_optimization import DEFAULT_POLICY, OptimizationRejected, _digest, verify_optimization
from hepta.hia_guarded_optimization import (propose_guarded_reduction, guarded_program,
    verify_guarded_optimization, build_guarded_native, BYTE_SUM_LIMIT)

try:
    import z3
except ImportError:
    z3 = None





@unittest.skipUnless(z3 is not None and shutil.which(os.environ.get("CLANG", "clang")),
                     "pinned Z3 and native Clang required")
class GuardedNativeTests(unittest.TestCase):

    pass


if __name__ == "__main__":
    unittest.main()
