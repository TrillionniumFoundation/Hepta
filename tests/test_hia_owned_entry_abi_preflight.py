"""P0/P7 negative control: a checked scalar function is not an owned transition ABI.

The native owned runtime invokes a u64(state), u64(delta) -> u64 transition.
The generic finite-scalar helper profile also accepts 1..8 arguments, which
must not make a 1- or 3-argument *entry* an admitted owned native callable.
These tests do not weaken or mock the semantic Core checker.
"""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_adaptive import AdaptiveRejected
from hepta.hia_stateful import OwnedAdaptiveRuntime
from tests.test_hia_program import b, f, i, m, ret


def scalar_transition(arity: int) -> dict:
    names = ("x", "y", "z")[:arity]
    params = [(name, "u64") for name in names]
    rhs = "y" if arity >= 2 else "x"
    return m(f("transition", params, ["u64"], [], [
        b("entry", params, [i("int.add.wrap", ["x", rhs], [("r", "u64")])], ret("r"))
    ]))


class OwnedEntryArityBeforeNativeTests(unittest.TestCase):
    def test_valid_two_argument_core_remains_supported(self):
        runtime = object.__new__(OwnedAdaptiveRuntime)
        checked, abi = runtime._admit_profile(scalar_transition(2))
        self.assertEqual(len(checked.as_dict()["functions"][0]["params"]), 2)
        self.assertEqual([p["type"] for p in abi["params"]], ["u64", "u64"])
        self.assertEqual(abi["target"], "x86_64-unknown-linux-gnu")

    def test_wrong_entry_arity_denied_by_source_profile(self):
        runtime = object.__new__(OwnedAdaptiveRuntime)
        for arity in (1, 3):
            with self.subTest(arity=arity):
                with self.assertRaisesRegex(AdaptiveRejected, "E_STATE_ABI"):
                    runtime._admit_profile(scalar_transition(arity))

    def test_wrong_entry_arity_rejected_before_compiler_identity(self):
        for arity in (1, 3):
            with self.subTest(arity=arity), tempfile.TemporaryDirectory(
                prefix="hia-owned-entry-abi-"
            ) as root:
                destination = Path(root) / "must-not-exist"
                caught = None
                with patch("hepta.hia_adaptive._identity",
                           side_effect=AssertionError("compiler identity reached before entry ABI")):
                    try:
                        OwnedAdaptiveRuntime(scalar_transition(arity), destination,
                                             [11, 17], clang="compiler-must-not-run")
                    except BaseException as error:
                        caught = error
                self.assertIsInstance(caught, AdaptiveRejected, repr(caught))
                self.assertIn("E_STATE_ABI", str(caught))
                self.assertFalse(destination.exists(), "wrong ABI created private native state")

    def test_wrong_entry_arity_cannot_create_directory_or_start_native_builder(self):
        class UnexpectedNativeBuild(Exception):
            pass

        for arity in (1, 3):
            with self.subTest(arity=arity), tempfile.TemporaryDirectory(
                prefix="hia-owned-entry-native-"
            ) as root:
                destination = Path(root) / "no-build"
                caught = None
                with patch("hepta.hia_adaptive._identity",
                           return_value="stable-synthetic-identity"), patch(
                           "hepta.hia_adaptive.build_optimized_native",
                           side_effect=UnexpectedNativeBuild) as native:
                    try:
                        OwnedAdaptiveRuntime(scalar_transition(arity), destination,
                                             [11, 17], clang="compiler-must-not-run")
                    except BaseException as error:
                        caught = error
                self.assertIsInstance(caught, AdaptiveRejected, repr(caught))
                self.assertIn("E_STATE_ABI", str(caught))
                native.assert_not_called()
                self.assertFalse(destination.exists(), "wrong ABI created private build directory")

    def test_valid_entry_reaches_existing_native_build_boundary(self):
        class ReachedNativeBuilder(Exception):
            pass

        with tempfile.TemporaryDirectory(prefix="hia-owned-valid-entry-") as root:
            destination = Path(root) / "native"
            with patch("hepta.hia_adaptive._identity",
                       return_value="stable-synthetic-identity"), patch(
                       "hepta.hia_adaptive.build_optimized_native",
                       side_effect=ReachedNativeBuilder) as native:
                with self.assertRaises(ReachedNativeBuilder):
                    OwnedAdaptiveRuntime(scalar_transition(2), destination,
                                         [11, 17], clang="compiler-must-not-run")
            native.assert_called_once()
            self.assertTrue(destination.is_dir())


if __name__ == "__main__":
    unittest.main()
