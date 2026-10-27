"""Integrated normalization, explicit legacy import and compact-edit CLI."""
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta.cli import main
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_program_tools import apply_program_patch
from hepta.hia_patch_impact import analyze_patch_impact, HIAImpactRejected
from tests.test_hia_edit_query import fixture
from tests.test_hia_program_composite import stored_loan_program


class SevenStageCLIIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hepta-cli-seven-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(["hia", *map(str, args)])
        return code, out.getvalue(), err.getvalue()

    def test_compact_query_roundtrip_preserves_interface_and_publishes_no_replace(self):
        source, query, response, target = (self.root / name for name in ("source.hia", "query.json", "response.json", "target.hia"))
        source.write_text(json.dumps(fixture()))
        response.write_text('{"op":"int.sub.wrap"}')
        code, out, err = self.run_cli("edit-query", source, "--function", "calculate", "--block", "entry",
                                      "--value", "y", "--fields", "op", "--output", query)
        self.assertEqual(code, 0, (out, err))
        self.assertEqual(json.loads(query.read_text())["schema"], "hepta.hia.edit-query.v1")
        code, out, err = self.run_cli("edit-apply", source, "--query", query, "--response", response, "--output", target)
        self.assertEqual(code, 0, (out, err))
        receipt = json.loads(out)
        self.assertTrue(receipt["edit_query"]["entire_module_reverified"])
        self.assertEqual(execute_program(verify_program(target.read_bytes()), "caller", [9])["result"], 8)
        original = target.read_bytes()
        code, _, _ = self.run_cli("edit-apply", source, "--query", query, "--response", response, "--output", target)
        self.assertNotEqual(code, 0)
        self.assertEqual(target.read_bytes(), original)
        source.write_text(json.dumps(fixture()).replace('"value": 1', '"value": 2'))
        code, _, _ = self.run_cli("edit-apply", source, "--query", query, "--response", response)
        self.assertNotEqual(code, 0)

    def test_legacy_nominal_v2_needs_explicit_adapter_then_normalize_runs_v6(self):
        document = stored_loan_program()
        document["schema"] = "hepta.hia.program.v2"
        legacy, target, report = (self.root / name for name in ("old.hia", "new.hia", "import.json"))
        legacy.write_text(json.dumps(document))
        self.assertNotEqual(self.run_cli("verify", legacy)[0], 0)
        code, out, err = self.run_cli("import-composite-v2", legacy, "--output", target, "--report", report)
        self.assertEqual(code, 0, (out, err))
        normalized = verify_program(target.read_bytes())
        self.assertEqual(normalized.as_dict()["schema"], "hepta.hia.program.v6")
        self.assertEqual(execute_program(normalized, "stored", [True])["result"], 91)
        self.assertTrue(json.loads(report.read_text())["ok"])
        self.assertEqual(self.run_cli("normalize", target)[0], 0)

    def test_composite_patch_impact_retains_checked_input_domain_identity(self):
        program = verify_program(stored_loan_program())
        function = next(fn for fn in program.as_dict()["functions"] if fn["name"] == "stored")
        block = next(block for block in function["blocks"] if any(op["attrs"].get("value") == 91 for op in block["ops"]))
        index = next(i for i, op in enumerate(block["ops"]) if op["attrs"].get("value") == 91)
        operation = deepcopy(block["ops"][index])
        operation["attrs"]["value"] = 90
        request = {"schema": "hepta.hia.patch.v1", "expected_sha256": program.sha256,
                   "edits": [{"action": "replace_operation", "function": "stored", "block": block["id"],
                              "index": index, "operation": operation}]}
        candidate, receipt, impact = analyze_patch_impact(program, request)
        self.assertEqual(execute_program(candidate, "stored", [True])["result"], 90)
        self.assertEqual(receipt["original_input_sha256"], program.input_sha256)
        self.assertNotEqual(program.input_sha256, program.sha256)
        for field, replacement in (("original_input_sha256", "0" * 64), ("edit_domain", "trusted_without_verification")):
            forged = deepcopy(receipt)
            forged[field] = replacement
            with patch("hepta.hia_patch_impact.apply_program_patch", return_value=(candidate, forged)):
                with self.assertRaises(HIAImpactRejected):
                    analyze_patch_impact(program, request)


if __name__ == "__main__":
    unittest.main()
