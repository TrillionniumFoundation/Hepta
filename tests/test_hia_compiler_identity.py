"""P0/P2: source-qualified HIA LLVM must pin current compiler implementation.

No remote CI or LLVM success is inferred. This unit tests the pre-native
fail-closed identity boundary for both existing scalar and owned profiles.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch


_COMPILER = "a" * 64
_PROJECT = "e" * 64


class SourceCompilerIdentityTests(unittest.TestCase):

    def test_compiler_drift_before_lowering_refuses_scalar_and_owned(self):
        for profile in ("scalar", "owned"):
            with self.subTest(profile=profile):
                result = self.execute_case(_COMPILER, "b" * 64, profile=profile)
                self.assertIn("compiler implementation differs",
                              result["diagnostics"][0]["message"])

    def test_missing_nonsha_and_boolean_compiler_identity_reject(self):
        for value in (None, True, 0, "bad", "A" * 64, "a" * 63):
            with self.subTest(identity=repr(value)):
                result = self.execute_case(value, _COMPILER)
                self.assertEqual(result["diagnostics"][0]["code"],
                                 "E_HIA_HEPTA_BRIDGE")

    def test_compiler_drift_during_source_to_core_never_reaches_native(self):
        for profile in ("scalar", "owned"):
            with self.subTest(profile=profile):
                result = self.execute_case(
                    _COMPILER, _COMPILER, second="b" * 64, profile=profile)
                self.assertIn("compiler changed during source-to-Core",
                              result["diagnostics"][0]["message"])


if __name__ == "__main__":
    unittest.main()
