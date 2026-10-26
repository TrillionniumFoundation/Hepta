"""Rust-gated owned source -> verified Resource IR/Core -> sole native LLVM path."""
from __future__ import annotations
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta.checker import check
from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_program_llvm import emit_program_llvm
from hepta.hia_source_bridge import (HIAHeptaBridgeRejected,
    lower_checked_owned_hia, build_checked_owned_hia_native,
    build_checked_hepta_hia_native)
from hepta.parser import parse


SOURCE = '''module owned_hia;
export "C" fn drop_case() -> u64 effects {alloc,block,panic} {
    let bytes = buffer(4);
    drop(move bytes);
    return 7;
}'''
PROJECT = "f" * 64


def lower():
    program = parse(SOURCE, "owned_hia.hepta")
    checked = check(program)
    if not checked.ok:
        raise AssertionError([x.to_dict() for x in checked.diagnostics])
    return lower_checked_owned_hia(program, checked, project_sha256=PROJECT)


class SourceBoundOwnedHIATests(unittest.TestCase):
    def test_owned_allocation_drop_uses_one_checked_executable_core(self):
        a = lower()
        b = lower()
        self.assertEqual(a.program.sha256, b.program.sha256)
        self.assertEqual(a.program, verify_program(a.program))
        self.assertTrue(a.claims["independent_resource_cfg_verified"])
        self.assertTrue(a.claims["independent_executable_owned_core_verified"])
        self.assertFalse(a.claims["source_to_core_semantic_refinement_proved"])
        report = execute_program(a.program, "drop_case", [])
        self.assertEqual(report["result"], 7)
        self.assertEqual(report["resources"]["allocations"], 1)
        self.assertEqual(report["resources"]["frees"], 1)
        self.assertEqual(report["resources"]["live_owners"], 0)
        native_ir = emit_program_llvm(a.program)
        self.assertEqual(native_ir.core_sha256, a.program.sha256)
        self.assertIn("call void @free(", native_ir.text)

    def test_incomplete_abstract_resource_gate_rejects_without_native(self):
        from hepta.resource_ir import verify_resource_ir as actual
        def forge(document):
            record = actual(document)
            return {**record, "status": "passed_but_not_really"}
        with patch("hepta.resource_ir.verify_resource_ir", side_effect=forge):
            with self.assertRaises(HIAHeptaBridgeRejected):
                lower()

    def test_mutated_or_unchecked_source_cannot_claim_owner_core(self):
        program = parse(SOURCE, "owned_hia.hepta")
        checked = check(program)
        for digest in ("bad", "f" * 63, "f" * 65):
            with self.subTest(digest=digest[:8]):
                with self.assertRaisesRegex(HIAHeptaBridgeRejected, "E_HIA_HEPTA_BRIDGE"):
                    lower_checked_owned_hia(program, checked, project_sha256=digest)
        with self.assertRaises(HIAHeptaBridgeRejected):
            lower_checked_owned_hia(program, object(), project_sha256=PROJECT)

    def test_native_build_rejects_missing_pinned_rustc_without_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "owned.hepta"
            output = root / "owned.so"
            source.write_text(SOURCE, encoding="utf-8")
            report = build_checked_owned_hia_native(
                source, output, rustc="/missing/hepta-rustc")
            self.assertFalse(report["ok"], report)
            self.assertEqual(report["schema"], "hepta.build-checked-hia-owned-source.v1")
            self.assertFalse(output.exists())
            self.assertFalse(report["claims"]["native_codegen_consumed_verified_hia_core"])

    def test_unknown_profile_has_no_native_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            src, output = root / "source.hepta", root / "artifact.so"
            src.write_text(SOURCE, encoding="utf-8")
            result = build_checked_hepta_hia_native(src, output, profile="unsafe_auto_fallback")
            self.assertFalse(result["ok"])
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
