"""Actual RV64GC/LP64D ABI, execution and fail-closed target controls."""
from copy import deepcopy
from dataclasses import replace
import os
from pathlib import Path
import re
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta.clang_capture import run_bounded
from hepta.hia_program import verify_program
from hepta.hia_program_llvm import (HIAProgramLLVMRejected, TARGET_RISCV64,
                                    compile_program_llvm, emit_program_llvm)
from tools.qualify_hia_program import block, function, ret

def configured_tool(variable, default):
    selected = os.environ.get(variable, default)
    return shutil.which(selected) or selected


# Bind the configured executable or its exact PATH resolution. An explicit
# missing path must remain missing, even if a different PATH tool is present.
CLANG = configured_tool("CLANG", "clang")
LINKER = configured_tool("HEPTA_LLD", "ld.lld")
READOBJ = configured_tool("HEPTA_LLVM_READOBJ", "llvm-readobj")
QEMU = configured_tool("HEPTA_QEMU_RISCV64", "qemu-riscv64")




class Riscv64EmissionTests(unittest.TestCase):



    pass


@unittest.skipUnless(all(shutil.which(x) for x in (CLANG, LINKER, READOBJ, QEMU)),
                     "actual Clang 20, LLD, LLVM reader and RV64 QEMU required")
class Riscv64NativeTests(unittest.TestCase):


    pass


if __name__ == "__main__":
    unittest.main()
