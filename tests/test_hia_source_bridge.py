"""Checked Hepta scalar SSA -> HIA executable v1, with native guarded build.

These in-repository tests require full Hepta checkout. No test here claims
source/back-end semantic refinement, arbitrary owner translation or Rust parity.
"""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta.checker import check
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_program_llvm import emit_program_llvm
from hepta.hia_source_bridge import (
    HIAHeptaBridgeRejected, build_checked_hepta_hia_native,
    lower_checked_scalar_hia,
)
from hepta.parser import parse

PROJECT = "e" * 64

SIMPLE = '''module hepta_hia_bridge;
export "C" fn increment(n: i32) -> i32 effects {panic} {
    return n + 1;
}
'''
BRANCH = '''module hepta_hia_bridge;
export "C" fn choose(a: i32, b: i32) -> i32 effects {panic} {
    if a < b { return a + 1; }
    else { return b; }
}
'''
LOOP = '''module hepta_hia_bridge;
export "C" fn accumulate(n: i32) -> i32 effects {panic} {
    let mut x: i32 = 0;
    while x < n { x = x + 1; }
    return x;
}
'''
UNSIGNED = '''module hepta_hia_bridge;
export "C" fn compare_unsigned(a: u32, b: u32) -> u32 effects {panic} {
    if a < b { return a + 1; }
    else { return b; }
}
'''
SHORT_CIRCUIT = '''module hepta_hia_bridge;
export "C" fn choose(a: i32, b: i32) -> i32 effects {panic} {
    if a != 0 && b / a > 0 { return 1; }
    else { return 0; }
}
'''


def lower(text):
    parsed = parse(text, "hia_source_bridge.hepta")
    checked = check(parsed)
    if not checked.ok:
        raise AssertionError([item.to_dict() for item in checked.diagnostics])
    return lower_checked_scalar_hia(parsed, checked, project_sha256=PROJECT)


class HIAHeptaSourceBridgeTests(unittest.TestCase):
    def test_checked_source_direct_integer_llvm_and_execution(self):
        hia = lower(SIMPLE)
        self.assertEqual(hia.program, lower(SIMPLE).program)
        self.assertEqual(hia.project_sha256, PROJECT)
        self.assertTrue(hia.claims["source_bound_resource_ir_checked"])
        self.assertFalse(hia.claims["source_to_core_semantic_refinement_proved"])
        self.assertEqual(verify_program(hia.program).canonical_bytes,
                         hia.program.canonical_bytes)
        ir = emit_program_llvm(hia.program)
        self.assertEqual(ir.core_sha256, hia.program.sha256)
        self.assertIn("define internal i32 @__hia_fn_0", ir.text)
        for n in (-100, -1, 0, 1, 20, 100):
            self.assertEqual(execute_program(hia.program, "increment", [n])["result"], n + 1)

    def test_diamond_branch_has_checked_block_arguments(self):
        hia = lower(BRANCH)
        program = hia.program.as_dict()["functions"][0]
        self.assertEqual(len(program["blocks"]), 3)
        self.assertEqual(program["blocks"][0]["term"]["op"], "branch")
        for a in (-3, 0, 1, 4, 12):
            for b in (-1, 0, 2, 8):
                result = execute_program(hia.program, "choose", [a, b])["result"]
                self.assertEqual(result, a + 1 if a < b else b)

    def test_loop_phi_and_dominating_parameter_forwarding(self):
        hia = lower(LOOP)
        blocks = hia.program.as_dict()["functions"][0]["blocks"]
        self.assertGreaterEqual(len(blocks), 4)
        self.assertTrue(any(b["term"]["op"] == "jump" for b in blocks))
        for n in (-9, -1, 0, 1, 2, 4, 10, 23, 99):
            self.assertEqual(execute_program(hia.program, "accumulate", [n])["result"], max(0, n))

    def test_unsigned_comparison_has_unsigned_vm_semantics(self):
        hia = lower(UNSIGNED)
        for a, b in ((0, 0), (0, 2**32 - 1), (2**32 - 1, 0), (99, 100), (1, 17)):
            self.assertEqual(execute_program(hia.program, "compare_unsigned", [a, b])["result"],
                             a + 1 if a < b else b)
        emitted = emit_program_llvm(hia.program)
        self.assertIn("icmp ult i32", emitted.text)

    def test_short_circuit_with_possible_rhs_trap_fails_closed(self):
        with self.assertRaisesRegex(HIAHeptaBridgeRejected, "E_HIA_HEPTA_BRIDGE"):
            lower(SHORT_CIRCUIT)

    def test_corrupted_resource_gate_never_generates_hia(self):
        with patch("hepta.hia_source_bridge.qualify_native_resource_source",
                   side_effect=ValueError("E_NATIVE_RESOURCE_GATE: rejected")):
            with self.assertRaisesRegex(HIAHeptaBridgeRejected, "E_HIA_HEPTA_BRIDGE"):
                lower(SIMPLE)

    def test_stale_project_and_bad_source_profile_rejected(self):
        program = parse(SIMPLE, "hia_source_bridge.hepta")
        checked = check(program)
        for digest in ("x" * 64, "e" * 63, "e" * 65, "-invalid"):
            with self.subTest(digest=digest[:8]):
                with self.assertRaisesRegex(HIAHeptaBridgeRejected, "E_HIA_HEPTA_BRIDGE"):
                    lower_checked_scalar_hia(program, checked, project_sha256=digest)
        with self.assertRaisesRegex(HIAHeptaBridgeRejected, "E_HIA_HEPTA_BRIDGE"):
            lower_checked_scalar_hia(program, object(), project_sha256=PROJECT)

    def test_source_native_rejects_stale_graph_before_codegen(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "input.hepta", root / "unpublished.so"
            source.write_text(SIMPLE, encoding="utf-8")
            project = SimpleNamespace(identity=PROJECT, sources={str(source): "locked"},
                                      unchanged=lambda: False)
            checked = check(parse(SIMPLE, str(source)))
            fake = SimpleNamespace(
                program=parse(SIMPLE, str(source)), checked=checked, project=project,
                report={"ok": True, "checks": {"rust_borrows_types": "rustc_checked"}})
            with (patch("hepta.pipeline.analyze_project", return_value=fake),
                  patch("hepta.hia_source_bridge.lower_checked_scalar_hia") as lowerer):
                result = build_checked_hepta_hia_native(source, output)
            self.assertFalse(result["ok"])
            self.assertFalse(output.exists())
            lowerer.assert_not_called()

    def test_standalone_source_qualified_cli_rejects_missing_native(self):
        from tools.build_checked_hia_source import main
        from contextlib import redirect_stdout
        import io
        import json
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "source.hepta", root / "not-published.so"
            source.write_text(SIMPLE, encoding="utf-8")
            stream = io.StringIO()
            with redirect_stdout(stream):
                exit_code = main([str(source), "-o", str(output),
                                  "--rustc", "/missing/hepta-rustc"])
            self.assertEqual(exit_code, 2)
            self.assertFalse(json.loads(stream.getvalue())["ok"])
            self.assertFalse(output.exists())

    def test_source_facing_native_never_publishes_without_rustc(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            src, output = root / "input.hepta", root / "artifact.so"
            src.write_text(SIMPLE, encoding="utf-8")
            report = build_checked_hepta_hia_native(src, output, rustc="/missing/hepta-rustc")
            self.assertFalse(report["ok"], report)
            self.assertFalse(output.exists())
            self.assertFalse(report["claims"]["native_codegen_consumed_verified_hia_core"])


if __name__ == "__main__":
    unittest.main()
