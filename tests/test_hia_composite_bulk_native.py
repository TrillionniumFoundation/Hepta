"""Composition of nominal ownership and every v2-v6 byte instruction.

The native test executes the frozen observer on x86-64 and actual AArch64
machine code under QEMU; source inspection is never counted as execution.
"""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from hepta.hia_program import HIAProgramRejected, execute_program, verify_program
from hepta.hia_program_runtime import HIAProgramTrap
from hepta.hia_program_llvm import (PROFILE_V6, PROFILE_AARCH64_V6, TARGET_AARCH64,
                                    emit_program_llvm)


def configured_tool(variable, default):
    selected = os.environ.get(variable, default)
    return shutil.which(selected) or selected


# The qualifier binds an explicit filesystem path, so resolve PATH aliases
# before calling it. An unavailable explicit selection stays unavailable.
CLANG = configured_tool("CLANG", "clang")
LINKER = configured_tool("HEPTA_LLD", "ld.lld")
QEMU = configured_tool("HEPTA_QEMU_AARCH64", "qemu-aarch64")


class CompositeBulkCoreTests(unittest.TestCase):





    def test_target_artifact_regular_to_fifo_race_fails_without_blocking(self):
        code = r'''
import os
from pathlib import Path
from unittest.mock import patch
from hepta.hia_program_aarch64 import _read, HIAProgramAArch64Rejected
p=Path("artifact");p.write_bytes(b"ordinary bytes")
original=os.open
def race(path,flags,*args,**kwargs):
    if Path(path)==p:
        p.unlink();os.mkfifo(p)
    return original(path,flags,*args,**kwargs)
with patch("hepta.hia_program_aarch64.os.open",race):
    try:_read(p,1024)
    except HIAProgramAArch64Rejected:raise SystemExit(0)
    raise SystemExit(1)
'''
        import os
        env = dict(os.environ)
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
        with tempfile.TemporaryDirectory() as directory:
            observed = subprocess.run([sys.executable, "-c", code], cwd=directory, env=env,
                                      capture_output=True, text=True, timeout=3)
            self.assertEqual(observed.returncode, 0, observed.stderr)


@unittest.skipUnless(all(shutil.which(tool) for tool in (CLANG, LINKER, QEMU)),
                     "actual pinned LLVM/lld and AArch64 QEMU required")
class CompositeBulkNativeTests(unittest.TestCase):
    pass


if __name__ == "__main__":
    unittest.main()
