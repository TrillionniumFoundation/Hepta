"""P0 convergence: one canonical scalar import plus checked owned source on v6.

These tests use actual Hepta parser/checker and the existing Core/verifier.
No LLVM-native or cross-target qualification is inferred from successful
source/interpreter tests, and no second SSA converter is introduced.
"""
from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta.checker import check
from hepta.core import from_scalar_core
from hepta.hia_program import SCHEMA, SCHEMA_V6, verify_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_program_llvm import emit_program_llvm
from hepta.hia_source_bridge import (
    HIAHeptaBridgeRejected, lower_checked_scalar_hia, lower_checked_owned_hia,
)
from hepta.parser import parse
from tests.test_hia_source_bridge import SIMPLE
from tests.test_hia_owned_source_bridge import SOURCE as OWNED_SOURCE
from tests.test_hia_range_fill_v6 import fill_program
from tools.build_checked_hia_source import main as build_cli

_PROJECT = "e" * 64


def checked(text):
    program = parse(text, "hia-convergence.hepta")
    report = check(program)
    if not report.ok:
        raise AssertionError([d.to_dict() for d in report.diagnostics])
    return program, report


class HIAAuthoritativeSourceConvergence(unittest.TestCase):
    def test_scalar_uses_existing_single_core_converter_not_second_translator(self):
        p, c = checked(SIMPLE)
        # Patch only the canonical converter boundary; the real converter
        # and all existing source/IR verification still execute.
        with patch("hepta.hia_source_bridge.from_scalar_core",
                   wraps=from_scalar_core) as converter:
            derived = lower_checked_scalar_hia(p, c, project_sha256=_PROJECT)
        self.assertEqual(converter.call_count, 2)  # verified source replay
        self.assertEqual(derived.program.as_dict()["schema"], SCHEMA)
        self.assertEqual(execute_program(derived.program, "increment", [11])["result"], 12)
        self.assertFalse(derived.claims["source_to_core_semantic_refinement_proved"])
        emitted = emit_program_llvm(derived.program)
        self.assertEqual(emitted.core_sha256, derived.program.sha256)

    def test_owned_resource_program_and_v6_reuse_the_same_verifier(self):
        p, c = checked(OWNED_SOURCE)
        owned = lower_checked_owned_hia(p, c, project_sha256=_PROJECT)
        self.assertEqual(owned.program, verify_program(owned.program))
        self.assertEqual(execute_program(owned.program, "drop_case", [])["result"], 7)
        self.assertTrue(owned.claims["independent_resource_cfg_verified"])
        self.assertFalse(owned.claims["general_memory_provenance_proved"])
        self.assertFalse(owned.claims["source_to_core_semantic_refinement_proved"])
        self.assertEqual(owned.program.as_dict()["schema"], SCHEMA)
        v6 = verify_program(fill_program(read=False))
        self.assertEqual(v6.as_dict()["schema"], SCHEMA_V6)
        self.assertEqual(execute_program(v6, "fill_range",
                         [0, 0, 0, 99, 0])["result"], 9)

    def test_owned_proof_flags_must_preserve_boolean_type(self):
        from hepta.resource_ir import verify_resource_ir as real
        p, c = checked(OWNED_SOURCE)

        def tampered_report(graph):
            result = real(graph)
            result["claims"]["whole_language_soundness_proved"] = 0
            return result

        with patch("hepta.resource_ir.verify_resource_ir",
                   side_effect=tampered_report):
            with self.assertRaisesRegex(HIAHeptaBridgeRejected,
                                        "E_HIA_HEPTA_BRIDGE"):
                lower_checked_owned_hia(p, c, project_sha256=_PROJECT)

    def test_one_cli_exposes_both_profiles_without_silent_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.hepta"
            artifact = root / "artifact.so"
            source.write_text(SIMPLE, encoding="utf-8")
            # Unit-isolate CLI argument routing; neither fake receipt nor
            # stdout is treated as a compiler qualification.
            for profile in ("scalar", "owned"):
                with self.subTest(profile=profile), patch(
                    "tools.build_checked_hia_source.build_checked_hepta_hia_native",
                    return_value={"ok": False, "status": "rejected"}) as build:
                    output = io.StringIO()
                    with redirect_stdout(output):
                        status = build_cli([str(source), "-o", str(artifact),
                                            "--profile", profile])
                    self.assertEqual(status, 2)
                    self.assertFalse(json.loads(output.getvalue())["ok"])
                    self.assertEqual(build.call_args.kwargs["profile"], profile)
            self.assertFalse(artifact.exists())

    def test_owned_no_rustc_cannot_publish_native_artifact(self):
        from hepta.hia_source_bridge import build_checked_owned_hia_native
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "owned.hepta"
            artifact = Path(folder) / "owned.so"
            source.write_text(OWNED_SOURCE, encoding="utf-8")
            report = build_checked_owned_hia_native(
                source, artifact, rustc="/missing/hepta-rustc")
            self.assertFalse(report["ok"])
            self.assertFalse(artifact.exists())
            self.assertFalse(report["claims"]["native_codegen_consumed_verified_hia_core"])


if __name__ == "__main__":
    unittest.main()
