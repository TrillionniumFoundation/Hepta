"""Real frontend/CLI qualification for versioned HSIR v1 project export.

These tests require the Hepta source tree and exercise parse/check/pipeline;
they are distinct from the isolated envelope conformance fixtures.
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from hepta.checker import check
from hepta.hsir_v1 import integrate_v0, verify_v1
from hepta.parser import parse
from hepta.pipeline import analyze, hsir_analysis, hsir_v1_analysis


class HSIRV1FrontendTests(unittest.TestCase):
    SOURCE = "fn add(a: i64, b: i64) -> i64 effects {panic} { return a + b; }"

    def test_real_checker_producer_and_integrity(self):
        program = parse(self.SOURCE, "same.hepta")
        checked = check(program)
        self.assertTrue(checked.ok)
        from hepta.semantic_ir import lower_checked_program
        v0 = lower_checked_program(program, checked)
        new = integrate_v0(v0)
        self.assertEqual(new["producer"]["wire_profile"], "source_bound_v0")
        self.assertEqual(new["opaque_producer_payload"], v0)
        self.assertFalse(verify_v1(new)["codegen_qualified"])
        self.assertTrue(new["interface_projection"]["functions"])

    def test_frontend_only_never_promoted(self):
        result = analyze(self.SOURCE, "same.hepta", native=False)
        self.assertTrue(result.report["ok"])
        output = hsir_v1_analysis(result)
        self.assertTrue(output["ok"])
        self.assertEqual(output["status"], "frontend_only")
        self.assertTrue(output["native_validity_not_established_by_hsir_v1"])
        self.assertFalse(output["hsir"]["claims"]["native_validation_by_this_envelope"])
        self.assertEqual(output["hsir"]["opaque_producer_payload"], hsir_analysis(result)["hsir"])

    def test_rejected_source_never_exports_v1(self):
        result = analyze("fn bad() -> i64 effects {} { return false; }", "bad.hepta", native=False)
        self.assertFalse(result.report["ok"])
        output = hsir_v1_analysis(result)
        self.assertFalse(output["ok"])
        self.assertIsNone(output["hsir"])

    def test_cli_legacy_unchanged_new_command_separate(self):
        with tempfile.TemporaryDirectory() as d:
            source = Path(d) / "source.hepta"
            source.write_text(self.SOURCE, encoding="utf-8")
            def run(cmd):
                proc = subprocess.run([sys.executable, "-m", "hepta", cmd,
                                       str(source), "--frontend-only"],
                                      capture_output=True, text=True, timeout=30)
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                return json.loads(proc.stdout)
            legacy = run("hsir")
            new = run("hsir-v1")
            self.assertEqual(legacy["schema"], "hepta.hsir.export.v0")
            self.assertEqual(new["schema"], "hepta.hsir.integration.export.v1")
            self.assertEqual(new["hsir"]["opaque_producer_payload"], legacy["hsir"])
            self.assertEqual(new["status"], "frontend_only")


if __name__ == "__main__":
    unittest.main()
