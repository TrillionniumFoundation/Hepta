"""End-to-end analysis-only CLI import of PR14/PR36 HSIR v1 snapshots."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from hepta.hsir_v1 import integrate_v0
from test_hsir_scalar_bridge import sample


def envelope():
    doc = sample()
    doc.pop("sha256", None)
    doc["sha256"] = hashlib.sha256(json.dumps(
        doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False).encode()).hexdigest()
    return integrate_v0(doc)


class ImportCLI(unittest.TestCase):
    def invoke(self, value):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "input.json"
            path.write_text(json.dumps(value, sort_keys=True))
            return subprocess.run([sys.executable, "-m", "hepta", "ssa-v1-import",
                                   str(path)], capture_output=True, text=True, timeout=30)

    def test_raw_sourcebound_v1_accepts_only_structural_verification(self):
        proc = self.invoke(envelope())
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        out = json.loads(proc.stdout)
        self.assertEqual(out["status"], "analysis_only_no_native_check")
        self.assertEqual(out["native_validation"], "not_run")
        self.assertEqual(out["analysis"]["scalar_mapping_profile"], "source_bound_scalar_structure_v1")
        self.assertFalse(out["analysis"]["claims"]["native_codegen_qualified_by_adapter"])

    def test_hepta_hsir_v1_export_wrapper_never_grants_native_status(self):
        inp = {"schema": "hepta.hsir.integration.export.v1", "ok": True,
               "status": "checked", "hsir": envelope(),
               "validation": {"backend": {"ok": True}, "status": "checked"}}
        proc = self.invoke(inp)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["native_validation"], "not_run")

    def test_tampered_source_rejected_without_partial_result(self):
        inp = envelope()
        inp["opaque_producer_payload"]["source_sha256"] = "f" * 64
        proc = self.invoke(inp)
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn('"analysis":', proc.stdout)

    def test_export_wrapper_rejects_ok_false(self):
        inp = {"schema": "hepta.hsir.integration.export.v1", "ok": False,
               "status": "rejected", "hsir": envelope()}
        self.assertNotEqual(self.invoke(inp).returncode, 0)


if __name__ == "__main__":
    unittest.main()
