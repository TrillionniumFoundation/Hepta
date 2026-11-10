"""Real kernel-profile boundaries; native tests inspect the actual HIA object.

These local tests are development validation, not a Linux boot qualification.
"""
from __future__ import annotations

import copy
import gzip
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import struct
import tempfile
import unittest

from hepta.hia_program_llvm import emit_program_llvm
from hepta.clang_capture import run_bounded
from hepta.hia_linux_kernel import (KernelProfileRejected, build_kernel_object,
                                   config_profile, inspect_kernel_object, kernel_ir, qualify_leaf,
                                   reinspect_kernel_object, _sections)

CONFIG = b"""CONFIG_X86_64=y
CONFIG_64BIT=y
CONFIG_CC_IS_CLANG=y
CONFIG_MITIGATION_RETHUNK=y
CONFIG_X86_KERNEL_IBT=y
CONFIG_CALL_PADDING=y
CONFIG_FUNCTION_ALIGNMENT=16
CONFIG_FUNCTION_PADDING_BYTES=16
"""
CLANG = os.environ.get("HIA_KERNEL_CLANG", os.environ.get("CLANG", "/usr/lib/llvm-20/bin/clang"))
OBJDUMP = os.environ.get("HIA_KERNEL_OBJDUMP", "llvm-objdump")


def source(expression):
    return 'module t; export "C" fn f(w:u32)->u32 effects {panic} {return ' + expression + ';}'


class KernelLeafAdmissionTests(unittest.TestCase):



    def test_exact_configuration_rejects_unimplemented_instrumentation(self):
        for extra in (b"CONFIG_CFI=y\n", b"CONFIG_LTO_CLANG=y\n", b"CONFIG_KMSAN=y\n", b"CONFIG_X86_64=y\n"):
            with self.subTest(extra=extra), self.assertRaises(KernelProfileRejected):
                config_profile(CONFIG + extra)








if __name__ == "__main__":
    unittest.main()
