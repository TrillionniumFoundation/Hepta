"""Cross-branch v5 owned-copy verifier with v3 Agent callgraph impact."""
from __future__ import annotations

from copy import deepcopy
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

from hepta.hia_patch_impact import analyze_patch_impact
from hepta.hia_program import HIAProgramRejected, SCHEMA_V5, verify_program
from hepta.hia_program_runtime import execute_program
from tests.test_hia_offset_copy_v5 import copy_program, ins


def patch_request(document, *, invalid=False):
    old = verify_program(document)
    ops = document["functions"][0]["blocks"][0]["ops"]
    if invalid:
        index = next(i for i, operation in enumerate(ops)
                     if operation["op"] == "buffer.copy_range")
        replacement = ins("buffer.copy_range", ["writer", "writer", "dst", "src", "count"])
    else:
        index = next(i for i, operation in enumerate(ops)
                     if operation["op"] == "const" and
                     operation["out"] == [{"name": "byte0", "type": "u8"}])
        replacement = deepcopy(ops[index])
        replacement["attrs"]["value"] = 91
    return {
        "schema": "hepta.hia.patch.v2",
        "expected_sha256": old.sha256,
        "interface_policy": "preserve",
        "edits": [{
            "action": "replace_operation", "function": "copy_offset",
            "block": "entry", "index": index, "operation": replacement,
        }],
    }


class V5AgentConvergenceTests(unittest.TestCase):
    def test_v5_copy_patch_rechecks_ownership_and_callgraph(self):
        source = copy_program()
        request = patch_request(source)
        candidate, receipt, impact = analyze_patch_impact(source, request)
        self.assertEqual(candidate.as_dict()["schema"], SCHEMA_V5)
        self.assertEqual(impact["direct_changed_functions"], ["copy_offset"])
        self.assertEqual(impact["potentially_affected_functions"], ["copy_offset"])
        self.assertEqual(impact["interface_changed_functions"], [])
        self.assertTrue(receipt["claims"]["whole_module_rechecked"])
        self.assertTrue(receipt["claims"]["interface_preserved"])
        self.assertFalse(receipt["claims"]["external_callers_revalidated"])
        self.assertFalse(impact["claims"]["native_execution_qualified"])
        args = [5, 0, 0, 1, 0]
        self.assertEqual(execute_program(source, "copy_offset", args)["result"], 11)
        self.assertEqual(execute_program(candidate, "copy_offset", args)["result"], 91)

    def test_alias_forgery_has_no_agent_impact_receipt(self):
        source = copy_program()
        with self.assertRaises(HIAProgramRejected):
            analyze_patch_impact(source, patch_request(source, invalid=True))

    def test_read_only_cli_does_not_publish_v5_candidate(self):
        from hepta.cli import main
        source = copy_program()
        request = patch_request(source)
        with tempfile.TemporaryDirectory(prefix="hia-v5-impact-") as folder:
            root = Path(folder)
            program = root / "program.hia"
            packet = root / "patch.json"
            program.write_text(json.dumps(source), encoding="utf-8")
            packet.write_text(json.dumps(request), encoding="utf-8")
            with io.StringIO() as output, redirect_stdout(output):
                rc = main(["hia", "impact", str(program), "--request", str(packet)])
                response = json.loads(output.getvalue())
            self.assertEqual(rc, 0, response)
            self.assertEqual(response["schema"], "hepta.hia.impact-query.v1")
            self.assertEqual(response["status"], "verified_unpublished")
            self.assertEqual(response["impact"]["direct_changed_functions"], ["copy_offset"])
            self.assertFalse(response["impact"]["claims"]["native_execution_qualified"])
            self.assertNotIn("publication", response)
            self.assertEqual(sorted(p.name for p in root.iterdir()), ["patch.json", "program.hia"])


if __name__ == "__main__":
    unittest.main()
