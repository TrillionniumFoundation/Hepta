"""Native host binding and actual captured C -> HIA LLVM application behavior.

The application tests execute only the current host. An x86 run never counts as
an AArch64 execution, even though the existing backend can emit an ARM object.
"""
from __future__ import annotations

import ctypes
from dataclasses import replace
import json
import os
from pathlib import Path
import platform
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hepta.clang_capture import run_bounded
from hepta.hia_program import execute_program, verify_program
from hepta.hia_program_llvm import (HIAProgramLLVMRejected, TARGET, TARGET_AARCH64,
                                    compile_program_llvm, emit_program_llvm,
                                    native_driver_matches_host, native_host_profile)
from tools.qualify_hia_program import block, function, ret


CLANG = os.environ.get("CLANG", "/usr/lib/llvm-20/bin/clang")
HOSTED = platform.system() == "Linux" and platform.machine().lower() in {
    "x86_64", "amd64", "aarch64", "arm64"}


def tiny_program():
    return verify_program({"schema": "hepta.hia.program.v1", "module": "native_host_test",
        "functions": [function("identity", [("x", "u64")], ["u64"], [],
                               [block("entry", [("x", "u64")], [], ret("x"))])]})


class HIAProgramNativeHostContractTests(unittest.TestCase):

    def test_driver_target_rejects_foreign_machine_ilp32_and_non_linux(self):
        for target, arch in ((TARGET, "x86_64"), (TARGET_AARCH64, "aarch64")):
            host = {"target": target}
            for triple in (arch + "-linux-gnu", arch + "-unknown-linux-gnu", arch + "-pc-linux-gnu"):
                self.assertTrue(native_driver_matches_host(triple, host))
            other = "aarch64" if arch == "x86_64" else "x86_64"
            for triple in (other + "-unknown-linux-gnu", arch + "-unknown-linux-gnuilp32",
                           arch + "-apple-darwin", arch + "-linux-musl", target + "\nextra"):
                self.assertFalse(native_driver_matches_host(triple, host), triple)

    def test_host_rejects_wrong_os_unknown_machine_and_big_endian(self):
        for system, machine, byteorder in (("Darwin", "arm64", "little"),
                                            ("Linux", "riscv64", "little"),
                                            ("Linux", "aarch64", "big")):
            with self.subTest(system=system, machine=machine, byteorder=byteorder), \
                 patch("hepta.hia_program_llvm.platform.system", return_value=system), \
                 patch("hepta.hia_program_llvm.platform.machine", return_value=machine), \
                 patch("hepta.hia_program_llvm.sys.byteorder", byteorder):
                with self.assertRaisesRegex(HIAProgramLLVMRejected, "little-endian.*LP64"):
                    native_host_profile()

    def test_host_rejects_llp64_and_ilp32_processes(self):
        real_sizeof = ctypes.sizeof
        for changed_type in (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_long):
            with self.subTest(changed_type=changed_type), \
                 patch("hepta.hia_program_llvm.platform.system", return_value="Linux"), \
                 patch("hepta.hia_program_llvm.platform.machine", return_value="aarch64"), \
                 patch("hepta.hia_program_llvm.ctypes.sizeof", side_effect=lambda value:
                       4 if value is changed_type else real_sizeof(value)):
                with self.assertRaisesRegex(HIAProgramLLVMRejected, "LP64"):
                    native_host_profile()



    @unittest.skipUnless(HOSTED and shutil.which(CLANG), "actual selected Clang required")
    def test_a_host_label_alone_cannot_admit_an_unmatched_compiler(self):
        program = tiny_program()
        other = "aarch64" if native_host_profile()["normalized_machine"] == "x86_64" else "x86_64"
        ir = emit_program_llvm(program, target=TARGET_AARCH64 if other == "aarch64" else TARGET)
        actual_target = TARGET if other == "aarch64" else TARGET_AARCH64
        with tempfile.TemporaryDirectory() as directory, \
             patch("hepta.hia_program_llvm.platform.machine", return_value=other), \
             patch("hepta.hia_program_llvm.run_bounded", side_effect=[
                 SimpleNamespace(returncode=0, stdout="clang version 20.1.8\n"),
                 SimpleNamespace(returncode=0, stdout=actual_target + "\n")]) as invoked:
            output = Path(directory) / "not-native.o"
            with self.assertRaisesRegex(HIAProgramLLVMRejected, "matching the measured native host"):
                compile_program_llvm(ir, program=program, output=output, clang=CLANG, kind="object")
            self.assertEqual(invoked.call_count, 2)
            self.assertFalse(output.exists())

    def test_aarch64_shared_and_forged_target_still_reject_before_tools(self):
        program = tiny_program()
        ir = emit_program_llvm(program, target=TARGET_AARCH64)
        with tempfile.TemporaryDirectory() as directory, \
             patch("hepta.hia_program_llvm.run_bounded", side_effect=AssertionError("compiler must not run")):
            with self.assertRaisesRegex(HIAProgramLLVMRejected, "relocatable"):
                compile_program_llvm(ir, program=program, output=Path(directory) / "arm.so", clang=CLANG)
            with self.assertRaisesRegex(HIAProgramLLVMRejected, "ORIGIN"):
                compile_program_llvm(replace(ir, target=TARGET), program=program,
                                     output=Path(directory) / "forged.o", clang=CLANG, kind="object")




if __name__ == "__main__":
    unittest.main()
