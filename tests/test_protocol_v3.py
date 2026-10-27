"""Multi-file v3 Agent validation is graph-bound, read-only and fail-closed."""
import copy
from pathlib import Path
import tempfile
import unittest

from hepta.backend import sha256
from hepta.modules import load_project
from hepta.pipeline import interface_hash
from hepta.protocol_v3 import preview_project_patch


class MultiFilePreviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.entry = self.root / "main.hepta"
        self.dep = self.root / "dep.hepta"
        self.entry.write_text('import dep; fn main() -> i32 effects {} { return dep::answer() as i32; }')
        self.dep.write_text('pub fn answer() -> u64 effects {} { return 7; }')
        project = load_project(self.entry)
        self.request = {
            "schema": "hepta.patch.v3.preview",
            "expected_project_sha256": project.identity,
            "expected_interface_sha256": interface_hash(project.program),
            "edits": [
                {"target": "main.hepta", "symbol": "main",
                 "expected_source_sha256": sha256(self.entry.read_bytes()),
                 "replacement_body": "{ return dep::answer() as i32; }"},
                {"target": "dep.hepta", "symbol": "answer",
                 "expected_source_sha256": sha256(self.dep.read_bytes()),
                 "replacement_body": "{ return 9; }"},
            ],
        }

    def test_validates_all_edits_as_one_graph_without_any_write(self):
        before = (self.entry.read_bytes(), self.dep.read_bytes())
        report = preview_project_patch(self.entry, self.request)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["status"], "validated")
        self.assertEqual(len(report["changes"]), 2)
        self.assertFalse(report["applied"])
        self.assertFalse(report["functional_equivalence_proved"])
        self.assertEqual(report["writeback"], "not_implemented_for_multi_file_atomicity")
        self.assertEqual((self.entry.read_bytes(), self.dep.read_bytes()), before)

    def test_apply_is_explicitly_rejected_before_writes(self):
        before = (self.entry.read_bytes(), self.dep.read_bytes())
        report = preview_project_patch(self.entry, self.request, apply=True)
        self.assertFalse(report["ok"])
        self.assertEqual(report["diagnostics"][0]["code"], "E_MULTI_FILE_ATOMICITY")
        self.assertEqual((self.entry.read_bytes(), self.dep.read_bytes()), before)

    def test_stale_project_rejected(self):
        self.entry.write_text(self.entry.read_text() + "\n// changed")
        report = preview_project_patch(self.entry, self.request)
        self.assertEqual(report["diagnostics"][0]["code"], "E_STALE_PROJECT")
        self.assertEqual(self.dep.read_text(), 'pub fn answer() -> u64 effects {} { return 7; }')

    def test_duplicate_path_or_file_outside_graph_rejected(self):
        request = copy.deepcopy(self.request)
        request["edits"][1] = copy.deepcopy(request["edits"][0])
        report = preview_project_patch(self.entry, request)
        self.assertEqual(report["diagnostics"][0]["code"], "E_PATCH_DUPLICATE")
        request = copy.deepcopy(self.request)
        request["edits"][1]["target"] = "../outside.hepta"
        report = preview_project_patch(self.entry, request)
        self.assertEqual(report["diagnostics"][0]["code"], "E_PATCH_FILE")

    def test_declaration_injection_does_not_escape_body(self):
        request = copy.deepcopy(self.request)
        request["edits"][1]["replacement_body"] = "{ return 9; } fn escape() -> i32 effects {} { return 1; }"
        report = preview_project_patch(self.entry, request)
        self.assertFalse(report["ok"])
        self.assertEqual(report["diagnostics"][0]["code"], "E_PATCH_SCOPE")
        self.assertIn("return 7", self.dep.read_text())

    def test_candidate_type_error_rejected_without_mutation(self):
        request = copy.deepcopy(self.request)
        request["edits"][1]["replacement_body"] = "{ return false; }"
        report = preview_project_patch(self.entry, request)
        self.assertFalse(report["ok"])
        self.assertEqual(report["diagnostics"][0]["code"], "E_PATCH_VALIDATION")
        self.assertIn("return 7", self.dep.read_text())

    def test_unknown_edit_fields_and_wrong_types_rejected(self):
        request = copy.deepcopy(self.request)
        request["edits"][0]["bypass"] = True
        self.assertEqual(preview_project_patch(self.entry, request)["diagnostics"][0]["code"], "E_PATCH_SCHEMA")
        request = copy.deepcopy(self.request)
        request["edits"][0]["target"] = 5
        self.assertEqual(preview_project_patch(self.entry, request)["diagnostics"][0]["code"], "E_PATCH_SCHEMA")


if __name__ == "__main__":
    unittest.main()
