"""Independent proof, original fallback, and real checked-reduction execution."""
from __future__ import annotations

from copy import deepcopy
import ctypes
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

from hepta.hia_guarded_optimization import (
    build_guarded_native, guarded_program, propose_guarded_reduction,
    verify_guarded_optimization,
)
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program

ROOT = Path(__file__).resolve().parents[1]




if __name__ == "__main__":
    unittest.main()
