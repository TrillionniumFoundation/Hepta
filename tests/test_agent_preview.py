"""P7 multi-source preview: combined validation without write capability."""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import tempfile
import unittest

from hepta.agent_preview import SCHEMA, preview_multi_body_patch
from hepta.modules import load_project
from hepta.pipeline import interface_hash


class AgentPreviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "main.hepta").write_text(
            "module main;\nimport math;\nfn main() -> i32 effects {} { return math::first(1); }\n")
        (self.root / "math.hepta").write_text(
            "module math;\npub fn first(x: i32) -> i32 effects {} { return x; }\n"
            "pub fn second(x: i32) -> i32 effects {} { return x; }\n")
        self.entry = self.root / "main.hepta"
        self.project = load_project(self.entry)
        self.initial = {p: Path(p).read_bytes() for p in self.project.sources if p.endswith(".hepta")}

    def request(self, edits=None):
        def edit(path, symbol, body):
            p = self.root / path
            return {"target": path, "symbol": symbol,
                    "expected_source_sha256": sha256(p.read_bytes()).hexdigest(),
                    "replacement_body": body}
        return {"schema": SCHEMA, "expected_project_sha256": self.project.identity,
                "expected_interface_sha256": interface_hash(self.project.program),
                "edits": edits if edits is not None else [edit("main.hepta", "main", "{ return math::first(2); }"),
                                                          edit("math.hepta", "first", "{ return 42; }")]}

    def unchanged(self):
        self.assertEqual(self.initial, {p: Path(p).read_bytes() for p in self.initial})

    def test_schema_and_apply_must_fail_closed_without_writes(self):
        req = self.request()
        for altered in [{**req, "schema": "hepta.patch.v3"}, {**req, "extra": True}]:
            self.assertEqual(preview_multi_body_patch(self.entry, altered)["diagnostics"][0]["code"],
                             "E_PREVIEW_SCHEMA")
        result = preview_multi_body_patch(self.entry, req, apply=True)
        self.assertEqual(result["diagnostics"][0]["code"], "E_PREVIEW_APPLY_UNSUPPORTED")
        self.assertFalse(result["write_capability"])
        self.unchanged()

    def test_snapshot_collision_duplicate_and_path_escape(self):
        req = self.request()
        changed = {**req, "expected_project_sha256": "0" * 64}
        self.assertEqual(preview_multi_body_patch(self.entry, changed)["diagnostics"][0]["code"],
                         "E_STALE_PROJECT")
        duplicate = {**req, "edits": [req["edits"][0], req["edits"][0]]}
        self.assertEqual(preview_multi_body_patch(self.entry, duplicate)["diagnostics"][0]["code"],
                         "E_PREVIEW_DUPLICATE")
        attack = dict(req["edits"][0], target="../outside.hepta")
        result = preview_multi_body_patch(self.entry, {**req, "edits": [attack]})
        self.assertFalse(result["ok"])
        self.unchanged()

    def test_reject_outside_body_injection_and_stale_source(self):
        req = self.request()
        injection = dict(req["edits"][0], replacement_body="{ return 2; }\nfn extra() -> i32 effects {} { return 2; }")
        result = preview_multi_body_patch(self.entry, {**req, "edits": [injection]})
        self.assertEqual(result["status"], "rejected")
        stale = dict(req["edits"][0], expected_source_sha256="f" * 64)
        self.assertEqual(preview_multi_body_patch(self.entry, {**req, "edits": [stale]})["diagnostics"][0]["code"],
                         "E_STALE_SOURCE")
        self.unchanged()

    def test_combined_multi_source_preview_never_writes(self):
        result = preview_multi_body_patch(self.entry, self.request())
        self.assertFalse(result["applied"])
        self.assertFalse(result["write_capability"])
        self.assertEqual(result["transaction_atomicity"], "not_implemented")
        if result["ok"]:
            self.assertEqual(result["status"], "validated")
            self.assertEqual(len(result["edits"]), 2)
            self.assertEqual(result["scope"], "multi_body_complete_import_graph_preview_only")
            self.assertNotEqual(result["project_before_sha256"], result["project_candidate_sha256"])
            self.assertFalse(result["functional_equivalence_proved"])
        else:
            # Missing pinned rustc is rejection, never frontend-only success.
            self.assertEqual(result["diagnostics"][0]["code"], "E_PREVIEW_NATIVE")
            self.assertFalse(result["validation"]["ok"])
        self.unchanged()

    def test_two_edits_to_distinct_functions_of_same_file(self):
        file = self.root / "math.hepta"
        digest = sha256(file.read_bytes()).hexdigest()
        req = self.request([
            {"target": "math.hepta", "symbol": "first", "expected_source_sha256": digest,
             "replacement_body": "{ return 11; }"},
            {"target": "math.hepta", "symbol": "second", "expected_source_sha256": digest,
             "replacement_body": "{ return 12; }"},
        ])
        result = preview_multi_body_patch(self.entry, req)
        if result["ok"]:
            self.assertEqual(len(result["edits"]), 2)
            self.assertNotEqual(result["edits"][0]["source_before_sha256"],
                                result["edits"][0]["source_after_sha256"])
        else:
            self.assertEqual(result["diagnostics"][0]["code"], "E_PREVIEW_NATIVE")
        self.unchanged()


if __name__ == "__main__":
    unittest.main()
