"""Actual v8 AArch64/RV64 execution and retained-evidence refusal controls."""
from copy import deepcopy
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.hia_program import HIAProgramRejected, verify_program


def configured_tool(variable, fallback):
    selected = os.environ.get(variable, fallback)
    return shutil.which(selected) or selected


TOOLS = {"clang": configured_tool("CLANG", "clang"),
         "linker": configured_tool("HEPTA_LLD", "ld.lld"),
         "readobj": configured_tool("HEPTA_LLVM_READOBJ", "llvm-readobj"),
         "qemu_aarch64": configured_tool("HEPTA_QEMU_AARCH64", "qemu-aarch64"),
         "qemu_riscv64": configured_tool("HEPTA_QEMU_RISCV64", "qemu-riscv64")}


class ReturnedLoanCrossContract(unittest.TestCase):


    pass


@unittest.skipUnless(all(shutil.which(path) for path in TOOLS.values()),
                     "actual Clang, LLD, LLVM reader and both QEMU targets required")
class ReturnedLoanCrossNative(unittest.TestCase):
    pass


if __name__ == "__main__":
    unittest.main()
