"""Native validation and actual process-death tests for version publication."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.backend import find_rustc
from hepta.workspace import (PATCH_SCHEMA, WorkspaceError, apply_workspace_patch,
                             initialize, inspect_workspace, pin, recover)


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-workspace-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "source"
        self.root.mkdir()
        self.store = Path(self.temp.name) / "store"
        self.rustc = find_rustc()
        (self.root / "main.hepta").write_text("import api;\nfn main() -> i32 effects {} { let n: i32 = 2; return api::value(n); }\n")
        (self.root / "api.hepta").write_text("pub fn value(n: i32) -> i32 effects {} { return n; }\n")
        report = initialize(self.store, self.root, "main.hepta", rustc=self.rustc)
        self.assertTrue(report["ok"], report)

    def request(self, modifications, policy="preserve"):
        view = inspect_workspace(self.store)
        edits = []
        for target, kind, symbol, replacement in modifications:
            candidates = [n for n in view["nodes"][target] if n["kind"] == kind and n["symbol"] == symbol]
            self.assertEqual(len(candidates), 1)
            edits.append({"op": "replace_" + kind, "target": target,
                          "node": candidates[0]["id"], "replacement": replacement})
        return {"schema": PATCH_SCHEMA, "expected_version": view["snapshot"]["version"],
                "expected_interface_sha256": view["snapshot"]["manifest"]["interface_sha256"],
                "interface_policy": policy, "edits": edits}

    def migration(self):
        return self.request([
            ("api.hepta", "function", "value", "pub fn value(n: i64) -> i32 effects {} { return n as i32; }"),
            ("main.hepta", "body", "main", "{ return api::value(7 as i64); }")], "migrate")

    def test_native_cross_file_interface_migration_and_pinned_reader(self):
        old = pin(self.store)
        request = self.migration()
        result = apply_workspace_patch(self.store, request, apply=True, rustc=self.rustc)
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["interface_changed"])
        self.assertEqual(pin(self.store)["version"], result["after"])
        self.assertIn("value(n: i32)", (Path(old["root"]) / "api.hepta").read_text())
        self.assertIn("value(n: i64)", (Path(pin(self.store)["root"]) / "api.hepta").read_text())
        self.assertEqual(pin(self.store, old["version"])["version"], old["version"])
        self.assertIn("value(n: i32)", (self.root / "api.hepta").read_text())
        stale = apply_workspace_patch(self.store, request, apply=True, rustc=self.rustc)
        self.assertFalse(stale["ok"])
        self.assertEqual(stale["diagnostics"][0]["code"], "E_STALE_PROJECT")

    def test_unmigrated_call_site_rejected_without_publication(self):
        before = pin(self.store)["version"]
        request = self.migration()
        request["edits"].pop()
        result = apply_workspace_patch(self.store, request, apply=True, rustc=self.rustc)
        self.assertFalse(result["ok"], result)
        self.assertEqual(pin(self.store)["version"], before)

    def test_preserve_policy_rejects_contract_change(self):
        request = self.migration()
        request["interface_policy"] = "preserve"
        result = apply_workspace_patch(self.store, request, apply=True, rustc=self.rustc)
        self.assertFalse(result["ok"])
        self.assertEqual(result["diagnostics"][0]["code"], "E_CONTRACT_CHANGE")

    def test_preview_does_not_publish(self):
        before = pin(self.store)["version"]
        result = apply_workspace_patch(self.store, self.migration(), rustc=self.rustc)
        self.assertTrue(result["ok"], result)
        self.assertFalse(result["applied"])
        self.assertEqual(pin(self.store)["version"], before)

    def test_semantic_node_scope_rejects_body_injection(self):
        request = self.request([("main.hepta", "body", "main",
                                 "{ return 0; } fn injected() -> Unit effects {} {}")])
        result = apply_workspace_patch(self.store, request, apply=True, rustc=self.rustc)
        self.assertFalse(result["ok"])
        self.assertEqual(result["diagnostics"][0]["code"], "E_PATCH_SCOPE")

    def test_overlapping_and_stale_nodes_rejected(self):
        request = self.request([("main.hepta", "body", "main", "{ return 1; }")])
        request["edits"].append(dict(request["edits"][0]))
        result = apply_workspace_patch(self.store, request, rustc=self.rustc)
        self.assertFalse(result["ok"])
        self.assertEqual(result["diagnostics"][0]["code"], "E_PATCH_OVERLAP")
        request["edits"].pop()
        request["edits"][0]["node"] = "0" * 64
        self.assertEqual(apply_workspace_patch(self.store, request, rustc=self.rustc)["diagnostics"][0]["code"], "E_PATCH_NODE")

    def test_snapshot_tampering_detected(self):
        p = Path(pin(self.store)["root"]) / "api.hepta"
        p.write_text(p.read_text() + "\n// changed\n")
        with self.assertRaisesRegex(WorkspaceError, "bytes changed"):
            pin(self.store)

    def test_symlink_input_rejected(self):
        (self.root / "alias.hepta").symlink_to(self.root / "api.hepta")
        with self.assertRaisesRegex(WorkspaceError, "regular files"):
            initialize(Path(self.temp.name) / "other", self.root, "main.hepta", rustc=self.rustc)

    def crash_at(self, point):
        request = self.migration()
        req = Path(self.temp.name) / "request.json"
        req.write_text(json.dumps(request))
        code = """import json,os,sys
from hepta.workspace import apply_workspace_patch
def crash(at):
    if at == sys.argv[4]: os._exit(71)
r=apply_workspace_patch(sys.argv[1],json.load(open(sys.argv[2])),apply=True,rustc=sys.argv[3],_checkpoint=crash)
print(json.dumps(r));sys.exit(2)
"""
        process = subprocess.run([sys.executable, "-c", code, str(self.store), str(req), self.rustc, point],
                                 capture_output=True, text=True, timeout=40)
        self.assertEqual(process.returncode, 71, process.stdout + process.stderr)
        return request

    def test_process_death_before_publication_recovers_old_complete_tree(self):
        before = pin(self.store)["version"]
        self.crash_at("prepared")
        result = recover(self.store)
        self.assertEqual(result["recovery"], "aborted")
        self.assertEqual(result["snapshot"]["version"], before)
        self.assertEqual(recover(self.store)["recovery"], "aborted")

    def test_process_death_after_publication_recovers_new_complete_tree(self):
        before = pin(self.store)["version"]
        self.crash_at("published")
        result = recover(self.store)
        self.assertEqual(result["recovery"], "committed")
        self.assertNotEqual(result["snapshot"]["version"], before)
        tree = Path(result["snapshot"]["root"])
        self.assertIn("value(n: i64)", (tree / "api.hepta").read_text())
        self.assertIn("value(7 as i64)", (tree / "main.hepta").read_text())

    def test_error_after_commit_never_reports_not_applied(self):
        def fail_journal(point):
            if point == "published":
                raise OSError("injected storage failure after head publication")
        report = apply_workspace_patch(self.store, self.migration(), apply=True,
                                       rustc=self.rustc, _checkpoint=fail_journal)
        self.assertFalse(report["ok"])
        self.assertTrue(report["applied"])
        self.assertEqual(report["status"], "recovery_required")
        self.assertEqual(recover(self.store)["recovery"], "committed")

    def test_concurrent_writers_compare_and_swap_one_complete_version(self):
        requests = [self.request([("main.hepta", "body", "main", "{ return " + str(n) + "; }")]) for n in (11, 12)]
        paths = []
        for i, request in enumerate(requests):
            path = Path(self.temp.name) / ("request" + str(i) + ".json")
            path.write_text(json.dumps(request))
            paths.append(path)
        code = """import json,sys
from hepta.workspace import apply_workspace_patch
print(json.dumps(apply_workspace_patch(sys.argv[1],json.load(open(sys.argv[2])),apply=True,rustc=sys.argv[3])))
"""
        processes = [subprocess.Popen([sys.executable, "-c", code, str(self.store), str(p), self.rustc],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for p in paths]
        results = []
        for process in processes:
            out, err = process.communicate(timeout=40)
            self.assertEqual(process.returncode, 0, err)
            results.append(json.loads(out))
        self.assertEqual(sum(r["applied"] is True for r in results), 1)
        rejected = next(r for r in results if not r["ok"])
        self.assertEqual(rejected["diagnostics"][0]["code"], "E_STALE_PROJECT")
        committed = next(r for r in results if r["ok"])
        self.assertEqual(pin(self.store)["version"], committed["after"])

    def test_c_header_identity_survives_snapshot_relocation(self):
        from hepta.c_import import import_header
        from hepta.pipeline import analyze_project
        header = self.root / "native.h"
        header.write_text("#include <stdint.h>\nuint64_t native_value(uint64_t value);\n")
        imported = import_header(header, module="native")
        (self.root / "native.hepta").write_text(imported.source)
        (self.root / "native.hepta.imports.json").write_text(json.dumps(imported.manifest))
        (self.root / "main.hepta").write_text("import native; fn main() -> Unit effects {alloc, block, ffi, io, panic, spawn, unsafe, write} { unsafe { let n = native::native_value(1); } }")
        other = Path(self.temp.name) / "portable"
        report = initialize(other, self.root, "main.hepta", rustc=self.rustc)
        self.assertTrue(report["ok"], report)
        snap = pin(other)
        copied = Path(snap["root"])
        metadata = json.loads((copied / "native.hepta.imports.json").read_bytes())
        self.assertEqual(metadata["header_path_kind"], "relative_to_manifest")
        self.assertEqual(metadata["header"], "native.h")
        header.unlink()
        checked = analyze_project(snap["entry"], rustc=self.rustc)
        self.assertTrue(checked.report["ok"], checked.report)
        self.assertTrue(Path(snap["manifest"]["validation"]["path"]).is_file())

    def test_initialize_fsync_failure_reports_observed_publication(self):
        from hepta import workspace
        dest = Path(self.temp.name) / "init-failure"
        original = workspace._fsync_dir
        def fail_after_head(directory):
            if Path(directory) == dest and (dest / "CURRENT").exists():
                raise OSError("injected directory fsync failure")
            original(directory)
        with patch.object(workspace, "_fsync_dir", side_effect=fail_after_head):
            result = initialize(dest, self.root, "main.hepta", rustc=self.rustc)
        self.assertFalse(result["ok"])
        self.assertTrue(result["applied"])
        self.assertEqual(result["status"], "recovery_required")
        self.assertEqual(pin(dest)["version"], result["candidate_version"])
        self.assertTrue(recover(dest)["ok"])

    def test_versions_parent_cannot_redirect_publication(self):
        dest = Path(self.temp.name) / "redirected"
        outside = Path(self.temp.name) / "outside"
        dest.mkdir()
        outside.mkdir()
        (dest / "versions").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(WorkspaceError, "Version storage directory"):
            initialize(dest, self.root, "main.hepta", rustc=self.rustc)
        self.assertEqual(list(outside.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
