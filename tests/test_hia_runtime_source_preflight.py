"""P0/P7: invalid Core and ABI must fail before native build-directory creation.

These are source-admission tests, not native/LLVM semantic qualification. Native
execution remains mandatory in the companion pinned-toolchain workflow.
"""
from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_adaptive import AdaptiveRejected, AdaptiveRuntime
from hepta.hia_optimization import DEFAULT_POLICY
from hepta.hia_stateful import OwnedAdaptiveRuntime
from tests.test_hia_program import resource_program
from tools.qualify_hia_adaptive import programs as scalar_programs
from tools.qualify_hia_stateful import programs as owner_programs


class EarlySourceAndAbiAdmissionTests(unittest.TestCase):
    def reject_without_private_directory(self, runtime_class, program, *,
                                         policy=None, values=None):
        with tempfile.TemporaryDirectory(prefix="hia-early-source-") as directory:
            destination = Path(directory) / "native-must-not-exist"
            kwargs = {"policy": policy, "clang": "compiler-must-not-be-launched"}
            with self.assertRaises(ValueError):
                if values is None:
                    runtime_class(program, destination, **kwargs)
                else:
                    runtime_class(program, destination, values, **kwargs)
            self.assertFalse(destination.exists(), "invalid source/ABI created native files")
            self.assertFalse(destination.is_symlink(), "invalid source/ABI published a path")

    def test_invalid_closed_core_does_not_create_adaptive_directory(self):
        self.reject_without_private_directory(AdaptiveRuntime, None)

    def test_invalid_closed_core_does_not_create_owned_directory(self):
        self.reject_without_private_directory(OwnedAdaptiveRuntime, None, values=[11, 17])

    def test_valid_core_with_forbidden_effect_does_not_create_directory(self):
        base, _ = scalar_programs()
        unsupported = copy.deepcopy(base)
        unsupported["functions"][0]["effects"] = ["trap"]
        self.reject_without_private_directory(AdaptiveRuntime, unsupported)

    def test_resource_program_rejected_before_owned_native_setup(self):
        self.reject_without_private_directory(OwnedAdaptiveRuntime, resource_program(), values=[11, 17])

    def test_unsupported_runtime_target_rejected_before_directory(self):
        policy = {**DEFAULT_POLICY, "target": "aarch64-unknown-linux-gnu"}
        base, _ = scalar_programs()
        self.reject_without_private_directory(AdaptiveRuntime, base, policy=policy)

    def test_owned_target_abi_mismatch_rejected_before_directory(self):
        policy = {**DEFAULT_POLICY, "target": "riscv64-unknown-linux-gnu"}
        base, _ = owner_programs()
        self.reject_without_private_directory(OwnedAdaptiveRuntime, base, policy=policy, values=[11, 17])

    def test_invalid_source_rejected_before_toolchain_identity(self):
        with tempfile.TemporaryDirectory(prefix="hia-before-identity-") as directory:
            target = Path(directory) / "native-must-not-exist"
            with patch("hepta.hia_adaptive._identity", side_effect=AssertionError("toolchain identity too early")):
                with self.assertRaises(ValueError):
                    AdaptiveRuntime(None, target, policy=DEFAULT_POLICY)
            self.assertFalse(target.exists())

    def test_valid_core_can_reach_native_build_after_profile_admission(self):
        class ReachedNativeBuild(Exception):
            pass

        base, _ = scalar_programs()
        with tempfile.TemporaryDirectory(prefix="hia-valid-source-") as directory:
            target = Path(directory) / "native-build-requested"
            with patch("hepta.hia_adaptive._identity", return_value="test-identity"), \
                 patch("hepta.hia_adaptive.build_optimized_native",
                       side_effect=ReachedNativeBuild) as native:
                with self.assertRaises(ReachedNativeBuild):
                    AdaptiveRuntime(base, target, policy=DEFAULT_POLICY)
            native.assert_called_once()
            self.assertTrue(target.is_dir(), "valid native build should reach private directory creation")


if __name__ == "__main__":
    unittest.main()
