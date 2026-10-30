"""Whole-interface admission and abnormal cooperative-cancellation semantics.

These controls cover real mismatches at the Core/native boundary and interrupted
cleanup. They do not turn finite observations into a compiler refinement proof.
"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_program import verify_program
from hepta.hia_program_runtime import (
    HIAProgramBudgetExceeded, HIAProgramTrap, execute_program,
)
from hepta.hia_program_llvm import (
    HIAProgramLLVMRejected, TARGET, TARGET_AARCH64, TARGET_RISCV64,
    build_program_native, emit_program_llvm,
)
from tests.test_hia_program import b, c, f, i, jump, m, ret
from tests.test_hia_program_composite import task_program


CLANG = os.environ.get("CLANG", "/usr/lib/llvm-20/bin/clang")


def mixed_scalar_interfaces():
    scalar = f("scalar", [("n", "u64")], ["u64"], [], [
        b("entry", [("n", "u64")], [], ret("n")),
    ])
    pair = f("pair", [("n", "u64")], ["u64", "u64"], [], [
        b("entry", [("n", "u64")], [], ret("n", "n")),
    ])
    unit_arg = f("unit_arg", [("token", "unit")], [], [], [
        b("entry", [("token", "unit")], [], ret()),
    ])
    return m(scalar, pair, unit_arg)


def interrupted_cancel(*, loop=False):
    document = task_program()
    cancel = next(fn for fn in document["functions"] if fn["name"] == "cancel_owned")
    entry = cancel["blocks"][0]
    # The actual state unpack stays in place. Interrupt before consuming the
    # real owner, so a false cleanup claim cannot pass merely on a scalar task.
    entry["ops"] = entry["ops"][:1]
    if loop:
        entry["term"] = jump("wait", "owned")
        cancel["blocks"].append(b("wait", [("waiting_owner", "buffer")], [],
                                  jump("wait", "waiting_owner")))
    else:
        cancel["effects"].append("trap")
        entry["ops"].append(i("borrow.read", ["owned"], [("view", "readbuf")]))
        entry["term"] = {"op": "trap", "code": "user"}
    return document


class NativeInterfaceContractTests(unittest.TestCase):
    def test_declared_multiple_results_cannot_disappear_on_any_native_target(self):
        document = mixed_scalar_interfaces()
        document["exports"] = ["scalar", "pair"]
        checked = verify_program(document)
        self.assertEqual(execute_program(checked, "pair", [7])["result"], [7, 7])
        for target in (TARGET, TARGET_AARCH64, TARGET_RISCV64):
            with self.subTest(target=target), self.assertRaisesRegex(
                    HIAProgramLLVMRejected, "E_HIA_PROGRAM_ABI:.*pair"):
                emit_program_llvm(checked, target=target)

    def test_declared_unit_parameter_cannot_disappear(self):
        document = mixed_scalar_interfaces()
        document["exports"] = ["scalar", "unit_arg"]
        checked = verify_program(document)
        self.assertEqual(execute_program(checked, "unit_arg", [None])["values"], [])
        with self.assertRaisesRegex(HIAProgramLLVMRejected, "E_HIA_PROGRAM_ABI:.*unit_arg"):
            emit_program_llvm(checked)

    def test_unsupported_internal_signatures_do_not_expand_explicit_exports(self):
        document = mixed_scalar_interfaces()
        document["exports"] = ["scalar"]
        checked = verify_program(document)
        for target in (TARGET, TARGET_AARCH64, TARGET_RISCV64):
            with self.subTest(target=target):
                self.assertEqual(emit_program_llvm(checked, target=target).exports, ("scalar",))

    def test_implicit_native_profile_retains_its_existing_subset(self):
        checked = verify_program(mixed_scalar_interfaces())
        self.assertEqual(checked.scalar_entrypoints, frozenset({"scalar", "pair", "unit_arg"}))
        self.assertEqual(emit_program_llvm(checked).exports, ("scalar",))

    def test_unsupported_explicit_interface_rejects_before_compile_or_publication(self):
        document = mixed_scalar_interfaces()
        document["exports"] = ["pair", "scalar", "unit_arg"]
        with tempfile.TemporaryDirectory(prefix="hia-contract-refusal-") as directory:
            output = Path(directory) / "candidate.so"
            with patch("hepta.hia_program_llvm.run_bounded",
                       side_effect=AssertionError("unsupported ABI reached the compiler")):
                with self.assertRaisesRegex(HIAProgramLLVMRejected,
                                            "E_HIA_PROGRAM_ABI:.*pair, unit_arg"):
                    build_program_native(document, output, clang=CLANG)
            self.assertFalse(output.exists())


class CancellationOutcomeContractTests(unittest.TestCase):
    def test_trap_during_cancel_preserves_stopped_owner_and_loan_ledger(self):
        checked = verify_program(interrupted_cancel())
        with self.assertRaises(HIAProgramTrap) as caught:
            execute_program(checked, "task_case", [0])
        report = caught.exception.report
        self.assertEqual(report["status"], "trapped")
        self.assertEqual(report["error"]["code"], "user")
        self.assertNotIn("values", report)
        self.assertEqual(report["resources"]["live_bytes"], 7)
        self.assertGreater(report["resources"]["live_owners"], 0)
        self.assertEqual(report["resources"]["frees"], 0)
        self.assertEqual(report["resources"]["live_local_loans"], 1)

    def test_cancellation_handler_budget_stop_is_not_success_or_program_trap(self):
        checked = verify_program(interrupted_cancel(loop=True))
        with self.assertRaises(HIAProgramBudgetExceeded) as caught:
            execute_program(checked, "task_case", [0], max_steps=100)
        report = caught.exception.report
        self.assertEqual(report["status"], "budget_exceeded")
        self.assertEqual(report["error"]["code"], "steps")
        self.assertNotIn("values", report)
        self.assertEqual(report["resources"]["live_bytes"], 7)
        self.assertEqual(report["resources"]["frees"], 0)

    def test_cancel_after_completion_does_not_execute_the_trapping_handler(self):
        report = execute_program(interrupted_cancel(), "task_case", [2])
        self.assertEqual(report["status"], "returned")
        self.assertEqual(report["result"], 28)
        self.assertEqual(report["resources"]["allocations"], 1)
        self.assertEqual(report["resources"]["frees"], 1)
        self.assertEqual(report["resources"]["live_owners"], 0)
        self.assertEqual(report["resources"]["live_local_loans"], 0)


@unittest.skipUnless(shutil.which(CLANG), "actual Clang 20+ native toolchain required")
class NativeSemanticsContractTests(unittest.TestCase):
    def test_actual_library_preserves_the_entire_supported_explicit_interface(self):
        document = mixed_scalar_interfaces()
        flag = f("flag", [("value", "bool")], ["bool"], [], [
            b("entry", [("value", "bool")], [], ret("value")),
        ])
        unit_result = f("unit_result", [], ["unit"], [], [
            b("entry", [], [c("token", "unit", None)], ret("token")),
        ])
        document["functions"].extend([flag, unit_result])
        document["exports"] = ["unit_result", "scalar", "flag"]
        with tempfile.TemporaryDirectory(prefix="hia-contract-native-") as directory:
            output = Path(directory) / "program.so"
            receipt = build_program_native(document, output, clang=CLANG)
            self.assertEqual(set(receipt["exports"]), set(document["exports"]))
            library = ctypes.CDLL(str(output))
            library.scalar.argtypes = [ctypes.c_uint64]
            library.scalar.restype = ctypes.c_uint64
            library.flag.argtypes = [ctypes.c_bool]
            library.flag.restype = ctypes.c_bool
            library.unit_result.argtypes = []
            library.unit_result.restype = None
            for value in (0, 7, (1 << 64) - 1):
                self.assertEqual(library.scalar(value), value)
            for value in (False, True):
                self.assertEqual(library.flag(value), value)
            self.assertIsNone(library.unit_result())
            self.assertFalse(hasattr(library, "pair"))
            self.assertFalse(hasattr(library, "unit_arg"))

    def test_actual_cancel_trap_aborts_and_late_cancel_still_returns(self):
        with tempfile.TemporaryDirectory(prefix="hia-cancel-native-") as directory:
            output = Path(directory) / "program.so"
            build_program_native(interrupted_cancel(), output, clang=CLANG)
            script = (
                "import ctypes,resource,sys; "
                "resource.setrlimit(resource.RLIMIT_CORE,(0,0)); "
                "lib=ctypes.CDLL(sys.argv[1]); "
                "lib.task_case.argtypes=[ctypes.c_uint8]; "
                "lib.task_case.restype=ctypes.c_uint64; "
                "print(lib.task_case(int(sys.argv[2])),flush=True)"
            )
            completed = subprocess.run([sys.executable, "-c", script, str(output), "2"],
                                       capture_output=True, timeout=10, check=False)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout.strip(), b"28")
            trapped = subprocess.run([sys.executable, "-c", script, str(output), "0"],
                                     capture_output=True, timeout=10, check=False)
            self.assertEqual(trapped.returncode, -signal.SIGABRT, trapped.stderr)
            self.assertEqual(trapped.stdout, b"")


if __name__ == "__main__":
    unittest.main()
