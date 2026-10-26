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

from hepta.hia_source_bridge import build_checked_hepta_hia_native

_COMPILER = "a" * 64
_PROJECT = "e" * 64


class SourceCompilerIdentityTests(unittest.TestCase):
    def execute_case(self, identity, current, *, profile="scalar", second=None):
        with tempfile.TemporaryDirectory(prefix="hia-identity-") as temporary:
            source = Path(temporary) / "program.hepta"
            target = Path(temporary) / "not-published.so"
            source.write_text("module identity;\n", encoding="utf-8")
            project = SimpleNamespace(identity=_PROJECT,
                                      sources={str(source): "fixed"},
                                      unchanged=lambda: True)
            report = {"ok": True,
                      "checks": {"rust_borrows_types": "rustc_checked"},
                      "compiler_sha256": identity}
            analyzed = SimpleNamespace(
                report=report, checked=object(), program=object(), project=project)
            selected = ("lower_checked_owned_hia" if profile == "owned"
                        else "lower_checked_scalar_hia")
            with (patch("hepta.pipeline.analyze_project", return_value=analyzed),
                  patch("hepta.pipeline.compiler_hash",
                        side_effect=[current, second] if second is not None else None,
                        return_value=current) as hash_source,
                  patch("hepta.hia_source_bridge." + selected,
                        return_value=SimpleNamespace()) as source_lower,
                  patch("hepta.hia_program_llvm.emit_program_llvm") as native):
                result = build_checked_hepta_hia_native(
                    source, target, profile=profile)
            self.assertFalse(result["ok"], result)
            self.assertFalse(target.exists())
            self.assertFalse(result["claims"]["native_codegen_consumed_verified_hia_core"])
            native.assert_not_called()
            if second is None or current != identity:
                source_lower.assert_not_called()
            else:
                source_lower.assert_called_once()
            return result

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
