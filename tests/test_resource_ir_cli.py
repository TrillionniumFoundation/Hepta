"""Source export and data-only verification retain distinct qualification scopes."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from hepta.checker import check
from hepta.parser import parse
from hepta.resource_lowering import lower_resource_ir


ROOT = Path(__file__).resolve().parents[1]
SOURCE = "fn main()->Unit effects {alloc,block,panic} {let b=buffer(4);drop(move b);}"


class ResourceIRCommandTests(unittest.TestCase):
    def source_command(self, source=SOURCE, *options):
        with tempfile.TemporaryDirectory(prefix="hepta-rir-cli-") as temp:
            path = Path(temp) / "main.hepta"
            path.write_text(source, encoding="utf-8")
            process = subprocess.run([sys.executable, "-m", "hepta", "resource-ir", str(path), *options],
                                     cwd=ROOT, capture_output=True, text=True, timeout=30)
            return process.returncode, json.loads(process.stdout)

    def test_native_source_export_has_both_native_and_resource_checks(self):
        code, report = self.source_command()
        self.assertEqual(code, 0, report)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["validation"]["checks"]["rust_borrows_types"], "rustc_checked")
        self.assertTrue(report["verifier"]["ok"])
        self.assertFalse(report["verifier"]["claims"]["source_to_ir_refinement_proved"])

    def test_frontend_only_export_does_not_claim_native_qualification(self):
        code, report = self.source_command(SOURCE, "--frontend-only")
        self.assertEqual(code, 0, report)
        self.assertEqual(report["status"], "frontend_only")
        self.assertEqual(report["validation"]["checks"]["rust_borrows_types"], "not_run")

    def test_unsupported_pointer_source_is_machine_readable_rejection(self):
        code, report = self.source_command('extern "C" fn value(p:raw const u8)->u8 effects {ffi,unsafe};', "--frontend-only")
        self.assertEqual(code, 1, report)
        self.assertFalse(report["ok"])
        self.assertEqual(report["diagnostics"][0]["code"], "E_RIR_LOWER_UNSUPPORTED")

    def test_data_only_cli_accepts_graph_and_rejects_removed_release(self):
        program = parse(SOURCE)
        graph = lower_resource_ir(program, check(program))
        with tempfile.TemporaryDirectory(prefix="hepta-rir-cli-") as temp:
            path = Path(temp) / "graph.json"
            for tampered in (False, True):
                if tampered:
                    for block in graph["functions"][0]["blocks"]:
                        block["ops"] = [op for op in block["ops"] if op["op"] != "drop"]
                path.write_text(json.dumps(graph), encoding="utf-8")
                process = subprocess.run([sys.executable, "-m", "hepta.resource_ir", str(path)],
                                         cwd=ROOT, capture_output=True, text=True, timeout=10)
                report = json.loads(process.stdout)
                self.assertEqual(process.returncode, int(tampered), report)
                self.assertFalse(report["source_binding_verified"])
                if tampered:
                    self.assertEqual(report["diagnostics"][0]["code"], "E_RIR_LEAK")

    def test_ambiguous_json_is_rejected_before_graph_validation(self):
        with tempfile.TemporaryDirectory(prefix="hepta-rir-cli-") as temp:
            path = Path(temp) / "graph.json"
            path.write_text('{"schema":"bad","schema":"hepta.resource-ir.v1"}', encoding="utf-8")
            process = subprocess.run([sys.executable, "-m", "hepta.resource_ir", str(path)],
                                     cwd=ROOT, capture_output=True, text=True, timeout=10)
            self.assertEqual(process.returncode, 1)
            self.assertEqual(json.loads(process.stdout)["diagnostics"][0]["code"], "E_RIR_JSON")


if __name__ == "__main__":
    unittest.main()
