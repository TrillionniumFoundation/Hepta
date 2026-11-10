"""Original upstream bodies reach Core; cursor extrema and lifetimes stay checked."""
from __future__ import annotations

from collections import deque
import ctypes
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_program import execute_program, verify_program
from hepta.hia_program_runtime import HIAProgramTrap
from hepta.hia_program_llvm import build_program_native

CLANG = os.environ.get("CLANG") or shutil.which("clang")




if __name__=="__main__":unittest.main()
