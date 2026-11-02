"""Explicit native AArch64 admission cannot inherit a QEMU observation."""
from __future__ import annotations

from pathlib import Path
import contextlib
import io
import os
import platform
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hepta import hia_program_aarch64 as target
from hepta.hia_program_llvm import TARGET, TARGET_AARCH64
from tools.qualify_hia_program_aarch64 import aarch64_program, qualify
from tools import qualify_hia_program_aarch64 as qualification


def arm_host():
    return {"system": "Linux", "normalized_machine": "aarch64", "target": TARGET_AARCH64}


class AArch64ExecutionAdmissionTests(unittest.TestCase):
    def test_unknown_modes_cannot_fall_back_before_program_or_tools(self):
        for mode in (None, True, 0, "auto", "QEMU", ""):
            with self.subTest(mode=mode), \
                    patch.object(target, "verify_program", side_effect=AssertionError("must not verify")), \
                    patch.object(target, "_tool", side_effect=AssertionError("must not start tool")):
                with self.assertRaisesRegex(target.HIAProgramAArch64Rejected, "explicit qemu or native"):
                    target.run_finite_program_aarch64({}, clang="unused", linker="unused", execution=mode)

    def test_x86_profile_refuses_native_before_program_or_tools(self):
        host = {"system": "Linux", "normalized_machine": "x86_64", "target": TARGET}
        with patch.object(target, "native_host_profile", return_value=host), \
                patch.object(target, "verify_program", side_effect=AssertionError("must not verify")), \
                patch.object(target, "_tool", side_effect=AssertionError("must not start tool")):
            with self.assertRaisesRegex(target.HIAProgramAArch64Rejected, "actual Linux AArch64"):
                target.run_finite_program_aarch64({}, clang="unused", linker="unused", execution="native")

    def test_nonlinux_or_nonlp64_profile_refuses_native(self):
        for system in ("Darwin", "Windows"):
            with self.subTest(system=system), \
                    patch("hepta.hia_program_llvm.platform.system", return_value=system), \
                    patch("hepta.hia_program_llvm.platform.machine", return_value="aarch64"), \
                    patch.object(target, "verify_program", side_effect=AssertionError("must not verify")):
                with self.assertRaisesRegex(target.HIAProgramAArch64Rejected, "actual Linux AArch64"):
                    target.run_finite_program_aarch64({}, clang="unused", linker="unused", execution="native")
        with patch("hepta.hia_program_llvm.platform.system", return_value="Linux"), \
                patch("hepta.hia_program_llvm.platform.machine", return_value="aarch64"), \
                patch("hepta.hia_program_llvm.ctypes.sizeof", return_value=4), \
                patch.object(target, "verify_program", side_effect=AssertionError("must not verify")):
            with self.assertRaisesRegex(target.HIAProgramAArch64Rejected, "actual Linux AArch64"):
                target.run_finite_program_aarch64({}, clang="unused", linker="unused", execution="native")

    def test_native_rejects_every_explicit_qemu_path_without_host_or_core_probe(self):
        for runner in ("qemu-aarch64", Path("/usr/bin/qemu-aarch64-static"), "", True):
            with self.subTest(runner=runner), \
                    patch.object(target, "native_host_profile", side_effect=AssertionError("must refuse first")), \
                    patch.object(target, "verify_program", side_effect=AssertionError("must not verify")):
                with self.assertRaisesRegex(target.HIAProgramAArch64Rejected, "cannot accept a QEMU"):
                    target.run_finite_program_aarch64({}, clang="unused", linker="unused",
                                                       execution="native", qemu_aarch64=runner)

    def test_an_arm_profile_label_without_matching_kernel_is_not_native(self):
        with patch.object(target, "native_host_profile", return_value=arm_host()), \
                patch.object(target.os, "uname", return_value=SimpleNamespace(sysname="Linux", machine="x86_64", release="test")):
            with self.assertRaisesRegex(target.HIAProgramAArch64Rejected, "kernel architecture disagree"):
                target._execution_host("native", None)

    def test_real_current_host_admission_has_no_emulator_fallback(self):
        if platform.system() == "Linux" and platform.machine().lower() in {"aarch64", "arm64"}:
            observed = target._execution_host("native", None)
            self.assertEqual(observed["target"], TARGET_AARCH64)
        else:
            with self.assertRaises(target.HIAProgramAArch64Rejected):
                target._execution_host("native", None)

    def test_qemu_executable_cannot_be_relabelled_as_native_target_tool(self):
        with patch.object(target, "_execution_host", return_value=arm_host()), \
                patch.object(target, "_tool", side_effect=[(Path("/qemu-aarch64"), target.QEMU_SHA256),
                                                           (Path("/ld.lld"), "0" * 64)]), \
                patch.object(target, "_run_logged", side_effect=AssertionError("must not execute QEMU")):
            with self.assertRaisesRegex(target.HIAProgramAArch64Rejected, "tools cannot be a QEMU"):
                target.run_finite_program_aarch64(aarch64_program(), clang="fixture", linker="fixture", execution="native")

    def test_native_log_contract_is_plain_list_and_does_not_change_qemu_v1(self):
        class ListSubclass(list):
            pass
        for log in ({}, (), ListSubclass()):
            with self.subTest(log=type(log).__name__), \
                    patch.object(target, "_execution_host", return_value=arm_host()), \
                    patch.object(target, "verify_program", side_effect=AssertionError("must refuse first")):
                with self.assertRaisesRegex(target.HIAProgramAArch64Rejected, "plain list"):
                    target.run_finite_program_aarch64({}, clang="unused", linker="unused", execution="native", command_log=log)
        with patch.object(target, "verify_program", side_effect=AssertionError("must refuse first")):
            with self.assertRaisesRegex(target.HIAProgramAArch64Rejected, "QEMU retains its original report"):
                target.run_finite_program_aarch64({}, clang="unused", linker="unused", qemu_aarch64="unused", command_log=[])

    def test_native_qualifier_cannot_pass_on_x86_or_accept_qemu_runner(self):
        with patch.object(target, "native_host_profile", return_value={"target": TARGET, "normalized_machine": "x86_64"}):
            result = qualify(clang="unused", linker="unused", execution="native")
        self.assertFalse(result["ok"])
        self.assertEqual(result["schema"], "hepta.hia.program.aarch64-native-host-qualification.v1")
        self.assertEqual(result["reference_cases"], [])
        self.assertEqual(result["commands"], [])
        self.assertFalse(result["claims"]["finite_corpus_native_host_execution_passed"])
        self.assertFalse(result["claims"]["finite_corpus_qemu_execution_passed"])
        self.assertFalse(result["claims"]["physical_board_executed"])
        result = qualify(clang="unused", linker="unused", execution="native", qemu_aarch64="qemu-aarch64")
        self.assertFalse(result["ok"])
        self.assertIn("cannot accept a QEMU", result["error"]["message"])

    def test_native_cli_refuses_source_output_or_an_explicit_qemu_before_work(self):
        inside = Path(__file__).resolve().parents[1] / "forbidden-native-receipt.json"
        for output in (str(inside), "relative-native-receipt.json"):
            argv = ["qualify", "--execution", "native", "--output", output]
            with self.subTest(output=output), patch.object(sys, "argv", argv), \
                    patch.object(qualification, "qualify", side_effect=AssertionError("must not begin qualification")), \
                    contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as denied:
                    qualification.main()
            self.assertEqual(denied.exception.code, 2)
        with tempfile.TemporaryDirectory(prefix="hia-native-cli-") as folder:
            argv = ["qualify", "--execution", "native", "--qemu-aarch64", "qemu-aarch64",
                    "--output", str(Path(folder) / "refused.json")]
            with patch.object(sys, "argv", argv), \
                    patch.object(qualification, "qualify", side_effect=AssertionError("must not begin qualification")), \
                    contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as denied:
                    qualification.main()
            self.assertEqual(denied.exception.code, 2)


CLANG = os.environ.get("CLANG") or shutil.which("clang")
LINKER = os.environ.get("HEPTA_LLD") or shutil.which("ld.lld")
QEMU = os.environ.get("HEPTA_QEMU_AARCH64") or os.environ.get("QEMU_AARCH64") or shutil.which("qemu-aarch64")


@unittest.skipUnless(CLANG and LINKER and QEMU, "reviewed Clang/lld/QEMU required for the real unchanged v1 corpus")
class AArch64DefaultQEMURegressionTests(unittest.TestCase):
    def test_actual_default_qemu_keeps_original_profile_cases_controls_and_claims(self):
        result = qualify(clang=CLANG, linker=LINKER, qemu_aarch64=QEMU)
        self.assertTrue(result["ok"], result.get("error"))
        self.assertEqual(result["schema"], "hepta.hia.program.aarch64-qualification.v1")
        self.assertEqual(result["status"], "finite_standalone_aarch64_qemu_corpus_passed")
        self.assertEqual(result["counts"]["reference_and_native_return_cases"], 17)
        self.assertEqual(result["counts"]["actual_wrong_core_controls"], 2)
        self.assertEqual(result["counts"]["actual_bounds_abort_exit"], 1)
        self.assertNotIn("commands", result)
        self.assertNotIn("execution_mode", result)
        positive = result["positive"]
        self.assertEqual(positive["schema"], target.PROFILE)
        self.assertEqual(positive["status"], "finite_qemu_execution_observed")
        self.assertEqual(positive["runner"]["sha256"], target.QEMU_SHA256)
        self.assertTrue(positive["claims"]["qemu_userspace_executed"])
        self.assertFalse(positive["claims"]["physical_target_executed"])
        self.assertNotIn("native_linux_aarch64_executed", positive["claims"])


if __name__ == "__main__":
    unittest.main()
