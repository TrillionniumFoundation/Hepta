"""Run real Hepta CLI importer on PR14-shaped identity-bound scalar snapshots.

The input is not an executable binary or a native validation receipt. These
tests exercise the actual PR37 CFG/SSA/verifier imports and do not request LLVM
emission, cross-target compilation, or trust caller-provided validation status.
"""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from hepta.hsir_v1 import integrate_v0
from test_hsir_v1_scalar_integration import sign, source


class ImportedV1CLITests(unittest.TestCase):
    def run_import(self, document):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "payload.json"
            path.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
            proc = subprocess.run([sys.executable, "-m", "hepta", "ssa-v1-import", str(path)],
                                  text=True, capture_output=True, timeout=30)
            self.assertTrue(proc.stdout, proc.stderr)
            return proc.returncode, json.loads(proc.stdout)

    def test_pr14_export_runs_real_cfg_phi_ssa(self):
        v1 = integrate_v0(source())
        exported = {"schema": "hepta.hsir.integration.export.v1", "ok": True,
                    "status": "frontend_only", "hsir": v1,
                    "validation": {"status": "frontend_only"},
                    "native_validity_not_established_by_hsir_v1": True}
        code, output = self.run_import(exported)
        self.assertEqual(code, 0, output)
        self.assertEqual(output["schema"], "hepta.ssa.integration.v1")
        self.assertEqual(output["source_hsir_v1_sha256"], v1["sha256"])
        self.assertTrue(output["scalar_mapping"])
        self.assertGreater(sum(x["phi_count"] for x in output["ssa_verification"]["functions"]), 0)
        self.assertFalse(output["claims"]["native_codegen_qualified_by_adapter"])

    def test_v1_import_does_not_trust_forged_native_wrapper(self):
        exported = {"schema": "hepta.hsir.integration.export.v1", "ok": True,
                    "status": "checked", "hsir": integrate_v0(source()),
                    "validation": {"status": "checked", "native_safety_proven": True},
                    "native_validity_not_established_by_hsir_v1": True}
        code, output = self.run_import(exported)
        self.assertEqual(code, 0, output)
        self.assertFalse(output["claims"]["memory_safety_proved"])
        self.assertFalse(output["claims"]["native_codegen_qualified_by_adapter"])

    def test_foreign_contract_rejected(self):
        d = source()
        d["foreign_assumptions"] = [{"function": "foreign_fn", "status": "unproved"}]
        code, output = self.run_import(integrate_v0(sign(d)))
        self.assertNotEqual(code, 0)
        self.assertEqual(output["status"], "rejected")

    def test_unknown_export_wrapper_rejected(self):
        wrapper = {"schema": "hepta.hsir.integration.export.v1", "ok": True,
                   "status": "checked", "hsir": integrate_v0(source()),
                   "validation": {}, "native_validity_not_established_by_hsir_v1": False}
        code, output = self.run_import(wrapper)
        self.assertNotEqual(code, 0)
        self.assertEqual(output["status"], "rejected")


if __name__ == "__main__":
    unittest.main()
