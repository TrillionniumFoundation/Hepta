from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta.backend import sha256
from hepta.modules import load_project
from hepta.pipeline import interface_hash
from hepta.protocol import apply_project_patch


class ProjectPatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-project-patch-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.entry = self.root / "main.hepta"
        self.dep = self.root / "dep.hepta"
        self.entry.write_text("import dep; fn main() -> i32 effects {} { return dep::answer() as i32; }")
        self.dep.write_text("pub fn answer() -> u64 effects {} { return 7; }")
        project = load_project(self.entry)
        self.request = {"schema": "hepta.patch.v2", "expected_project_sha256": project.identity,
                        "target": "dep.hepta", "expected_source_sha256": sha256(self.dep.read_bytes()),
                        "expected_interface_sha256": interface_hash(project.program), "symbol": "answer",
                        "replacement_body": "{ return 0; }"}

    def reject(self, code, **updates):
        result = apply_project_patch(self.entry, {**self.request, **updates}, apply=True)
        self.assertFalse(result["ok"], result)
        self.assertEqual(result["diagnostics"][0]["code"], code, result)
        return result

    def test_candidate_validates_entire_graph_then_applies_one_file(self):
        entry_before = self.entry.read_bytes()
        result = apply_project_patch(self.entry, self.request, apply=True)
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["applied"])
        self.assertIn("return 0", self.dep.read_text())
        self.assertEqual(self.entry.read_bytes(), entry_before)
        self.assertFalse(result["functional_equivalence_proved"])
        self.assertEqual(len(result["validation"]["project"]["sources"]), 2)

    def test_dry_run_preserves_bytes(self):
        before = self.dep.read_bytes()
        result = apply_project_patch(self.entry, self.request)
        self.assertTrue(result["ok"], result)
        self.assertFalse(result["applied"])
        self.assertEqual(self.dep.read_bytes(), before)

    def test_modified_other_module_rejects_stale_project(self):
        self.entry.write_text(self.entry.read_text() + "\n// new context")
        self.reject("E_STALE_PROJECT")

    def test_wrong_target_source_identity_rejected(self):
        self.reject("E_STALE_SOURCE", expected_source_sha256="0" * 64)

    def test_wrong_interface_identity_rejected(self):
        self.reject("E_STALE_INTERFACE", expected_interface_sha256="0" * 64)

    def test_target_outside_imported_graph_rejected(self):
        (self.root / "unrelated.hepta").write_text(self.dep.read_text())
        self.reject("E_PATCH_FILE", target="unrelated.hepta")

    def test_absolute_target_rejected(self):
        self.reject("E_PATCH_FILE", target=str(self.dep))

    def test_body_injection_rejected(self):
        self.reject("E_PATCH_SCOPE", replacement_body="{ return 0; } fn extra() -> u64 effects {} { return 1; }")

    def test_bad_return_type_rejected(self):
        result = apply_project_patch(self.entry, {**self.request, "replacement_body": "{ return true; }"}, apply=True)
        self.assertFalse(result["ok"], result)
        self.assertIn("return 7", self.dep.read_text())

    def test_existing_graph_lock_rejects_writer(self):
        self.entry.with_name("main.hepta.hepta-lock").write_text("busy")
        self.reject("E_PATCH_BUSY")

    def test_graph_change_during_validation_rejected(self):
        from hepta.pipeline import analyze_project as real_analyze
        def raced(*args, **kwargs):
            result = real_analyze(*args, **kwargs)
            self.entry.write_text(self.entry.read_text() + "\n// concurrent edit")
            return result
        with patch("hepta.pipeline.analyze_project", side_effect=raced):
            self.reject("E_STALE_PROJECT")
        self.assertIn("return 7", self.dep.read_text())

    def test_unknown_request_fields_rejected(self):
        self.reject("E_PATCH_SCHEMA", bypass=True)


if __name__ == "__main__":
    unittest.main()
