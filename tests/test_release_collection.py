"""Failure retention and fresh source/native evidence at the release boundary.

Source-row fixtures deliberately combine current frontend output with historical
native metadata for structural tests; they do not assert fresh native execution.
The separate C++ class executes the real complete 100000-iteration qualifier.
"""
from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.pipeline import analyze_project, compiler_hash
from hepta.resource_ir import verify_resource_ir
from hepta.resource_lowering import lower_resource_ir
from hepta.resource_source import _seal, verify_resource_source
from tools import qualify_resource_source as source
from tools import release_check as release


ROOT = Path(__file__).resolve().parents[1]


class ReleaseCollectionTests(unittest.TestCase):
    def driver(self, root, *, special=None, directory=True, keep_going=True, snapshots=None):
        output = root / "evidence/candidate" if directory else root / "artifacts"
        calls = []

        def run(argv, **kwargs):
            if argv[:2] == ["git", "rev-parse"]:
                return subprocess.CompletedProcess(argv, 0, stdout="test-commit\n", stderr="")
            calls.append(argv)
            if special is not None:
                result = special(len(calls), argv, root)
                if result is not None:
                    return result
            if "--output" in argv:
                path = root / argv[argv.index("--output") + 1]
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps({"ok": False, "status": "failed", "projects": [
                    {"name": "first", "status": "passed"},
                    {"name": "second", "status": "failed", "error": "specific observed cause"}]}))
            return subprocess.CompletedProcess(argv, 1, stdout="Ran 1 tests in 0.001s\nfailed gate\n", stderr="diagnostic\n")

        args = (["--output-directory", str(output)] if directory else [])
        if keep_going:
            args += ["--continue-on-failure"]
        snapshot_patch = (patch.object(release, "snapshot", side_effect=snapshots) if snapshots is not None
                          else patch.object(release, "snapshot", return_value={"sha256": "a" * 64, "files": {}}))
        with patch.object(release, "ROOT", root), snapshot_patch, \
                patch.object(release, "compiler_hash", return_value="b" * 64), \
                patch.object(release.subprocess, "run", side_effect=run), contextlib.redirect_stdout(io.StringIO()):
            code = release.main(args)
        return code, json.loads((output / "release-validation.json").read_text()), output, calls

    def test_nonobject_evidence_fails_one_gate_and_collects_the_rest(self):
        for invalid in (None, []):
            with self.subTest(value=invalid), tempfile.TemporaryDirectory(prefix="hepta-release-null-") as td:
                root = Path(td)

                def malformed(index, argv, cwd):
                    if index == 2:
                        (cwd / argv[argv.index("--output") + 1]).write_text(json.dumps(invalid))
                        return subprocess.CompletedProcess(argv, 0, stdout="producer exited zero\n", stderr="")

                code, report, output, calls = self.driver(root, special=malformed)
                self.assertEqual(code, 1)
                self.assertEqual(len(report["gates"]), len(report["planned_gates"]))
                self.assertGreater(len(calls), 2)
                gate = report["gates"][1]
                self.assertEqual(gate["status"], "failed")
                self.assertIn("JSON object", gate["validation_error"])
                receipt = report["evidence"][gate["evidence"]]
                self.assertEqual(receipt["sha256"], hashlib.sha256((root / gate["evidence"]).read_bytes()).hexdigest())
                self.assertEqual(receipt["validation_status"], "failed")

    def test_failed_json_keeps_detailed_rows_hashes_and_relative_paths(self):
        with tempfile.TemporaryDirectory(prefix="hepta-release-failed-") as td:
            root = Path(td)
            code, report, output, _ = self.driver(root)
            self.assertEqual(code, 1)
            self.assertEqual(report["status"], "failed")
            self.assertEqual(len(report["gates"]), len(report["planned_gates"]))
            self.assertTrue(report["evidence"])
            for name, item in report["evidence"].items():
                self.assertFalse(Path(name).is_absolute())
                self.assertTrue(item["fresh"])
                self.assertEqual(item["validation_status"], "failed")
                self.assertIn("validation_error", item)
                self.assertEqual(item["sha256"], hashlib.sha256((root / name).read_bytes()).hexdigest())
                self.assertEqual(json.loads((root / name).read_text())["projects"][1]["error"], "specific observed cause")

    def test_timeout_keeps_exact_partial_streams_then_continues(self):
        with tempfile.TemporaryDirectory(prefix="hepta-release-timeout-") as td:
            root = Path(td)

            def timeout(index, argv, cwd):
                if index == 1:
                    raise subprocess.TimeoutExpired(argv, 1, output=b"partial stdout\xff", stderr=b"partial stderr\x00")

            code, report, output, _ = self.driver(root, special=timeout)
            self.assertEqual(code, 1)
            self.assertEqual(len(report["gates"]), len(report["planned_gates"]))
            captured = report["gates"][0]["partial_output"]
            for stream, data in (("stdout", b"partial stdout\xff"), ("stderr", b"partial stderr\x00")):
                self.assertEqual((root / captured[stream]["path"]).read_bytes(), data)
                self.assertEqual(captured[stream]["sha256"], hashlib.sha256(data).hexdigest())
            self.assertIn("partial stdout", (output / "unit_and_integration.log").read_text())

    def test_old_untouched_report_cannot_be_credited_to_zero_exit(self):
        with tempfile.TemporaryDirectory(prefix="hepta-release-stale-") as td:
            root = Path(td)
            (root / "artifacts").mkdir()
            (root / "artifacts/formal-validation.json").write_text('{"status":"passed"}\n')

            def leave_old_report(index, argv, cwd):
                if "tools/verify_formal.py" in argv:
                    return subprocess.CompletedProcess(argv, 0, stdout="no new output\n", stderr="")

            code, report, _, _ = self.driver(root, special=leave_old_report, directory=False)
            gate = next(row for row in report["gates"] if row["name"] == "formal_core")
            self.assertEqual(code, 1)
            self.assertEqual(gate["status"], "failed")
            self.assertIn("not refreshed", gate["validation_error"])
            self.assertFalse(report["evidence"][gate["evidence"]]["fresh"])

    def test_fail_fast_still_records_the_failed_gate(self):
        with tempfile.TemporaryDirectory(prefix="hepta-release-stop-") as td:
            code, report, _, calls = self.driver(Path(td), keep_going=False)
            self.assertEqual(code, 1)
            self.assertEqual(len(calls), 1)
            self.assertEqual(len(report["gates"]), 1)
            self.assertEqual(report["status"], "failed")

    def test_source_drift_keeps_both_exact_inventories_and_changed_paths(self):
        before = {"sha256": "1" * 64, "files": {
            "source.py": "a" * 64, "removed.py": "b" * 64, "stable.py": "c" * 64}}
        after = {"sha256": "2" * 64, "files": {
            "source.py": "d" * 64, "rust/hia-core-shadow/target/new": "e" * 64,
            "stable.py": "c" * 64}}
        with tempfile.TemporaryDirectory(prefix="hepta-release-drift-") as td:
            code, report, _, _ = self.driver(Path(td), snapshots=[before, after])
        self.assertEqual(code, 1)
        self.assertFalse(report["snapshot_unchanged"])
        self.assertEqual(report["source_snapshot"], before)
        self.assertEqual(report["source_snapshot_after"], after)
        self.assertEqual(report["source_snapshot_changes"], {
            "added": ["rust/hia-core-shadow/target/new"],
            "removed": ["removed.py"], "modified": ["source.py"]})


class SourceQualificationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hepta-source-gate-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for directory in ("owned", "resource_ir", "owned_generics"):
            shutil.copytree(ROOT / "examples" / directory, self.root / "examples" / directory)
        examples = {name: self.root / path.relative_to(ROOT) for name, path in source.EXAMPLES.items()}
        for module, name, value in ((source, "ROOT", self.root), (release, "ROOT", self.root), (source, "EXAMPLES", examples)):
            context = patch.object(module, name, value)
            context.start()
            self.addCleanup(context.stop)
        self.original = json.loads((ROOT / "tests/fixtures/release_evidence/resources.json").read_text())
        self.receipts = []
        for row in self.original["projects"]:
            path = examples[row["name"]]
            analysis = analyze_project(path, native=False)
            self.assertTrue(analysis.report["ok"])
            graph = lower_resource_ir(analysis.program, analysis.checked, project_sha256=analysis.project.identity)
            data = json.dumps(graph, sort_keys=True).encode()
            graph_path = self.root / (row["name"] + ".json")
            graph_path.write_bytes(data)
            verified = verify_resource_ir(graph)
            self.assertTrue(verified["ok"])
            row["resource_verifier"] = {**verified, "frontend_modules_imported": []}
            row["resource_ir"] = {"path": graph_path.name, "sha256": hashlib.sha256(data).hexdigest(),
                                  "bytes": len(data), "canonical_sha256": verified["ir_sha256"]}
            row["native_gate"].update(compiler_sha256=compiler_hash(), path=str(path), project=analysis.project.report(),
                                      source_sha256=analysis.report["source_sha256"])
            row["inputs"] = {str(Path(p).relative_to(self.root)): value for p, value in analysis.project.sources.items()}
            receipt = verify_resource_source(path, graph, native=False)
            self.assertTrue(receipt["ok"])
            # Historical native observations are shape fixtures only. This
            # stub lets validator tests run without falsely claiming execution.
            validation = receipt["source_validation"]
            validation["backend"] = copy.deepcopy(row["native_gate"]["backend"])
            validation["backend"].update(crate_type="rlib", rust_sha256=validation["rust_sha256"])
            validation["checks"]["rust_borrows_types"] = "rustc_checked"
            validation["status"] = "checked"
            receipt["status"] = "source_replayed"
            receipt["source_binding"]["native_reference"] = "rustc_checked"
            receipt.pop("sha256")
            self.receipts.append(_seal(receipt))
        self.input = self.root / "original.json"
        self.input.write_text(json.dumps(self.original))
        with patch.object(source, "verify_resource_source", side_effect=copy.deepcopy(self.receipts)):
            self.report = source.qualify(Path("original.json"))
        self.assertEqual(self.report["status"], "passed", self.report)

    def reject(self, mutate, *, reseal=False):
        report = copy.deepcopy(self.report)
        mutate(report)
        if reseal:
            for row in report["projects"]:
                row["source_replay"].pop("sha256", None)
                _seal(row["source_replay"])
        with self.assertRaises(ValueError):
            release.require_qualification("source_bound_resource_ir", report)

    def test_valid_report_reuses_relative_retained_graphs_without_native_reexecution(self):
        with patch.object(source, "verify_resource_source", side_effect=AssertionError("validator must not execute native tools")):
            source.validate_report(self.report)

    def test_missing_binding_native_failure_and_open_claims_reject_after_rehash(self):
        mutations = [lambda r: r["projects"][0]["source_replay"].update(source_binding=None),
                     lambda r: r["projects"][0]["source_replay"]["source_validation"].update(ok=False, status="frontend_only"),
                     lambda r: r["projects"][0]["source_replay"]["source_validation"]["backend"].update(ok=False, status="not_run"),
                     lambda r: r["projects"][0]["source_replay"].update(claims={"unrelated_false_flag": False}),
                     lambda r: r["projects"][0]["source_replay"]["source_binding"].update(compiler_sha256="0" * 64),
                     lambda r: r["projects"][0]["source_replay"]["source_binding"].update(source_inventory={}),
                     lambda r: r["projects"][0]["source_replay"]["source_validation"]["claims"].update(whole_language_soundness_proved=True)]
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                self.reject(mutation, reseal=True)

    def test_input_path_hash_and_original_project_rows_are_required(self):
        for mutation in (lambda r: r.update(input="absent.json"), lambda r: r.update(input_sha256="0" * 64),
                         lambda r: r["projects"][0]["resource_ir"].update(canonical_sha256="0" * 64),
                         lambda r: r["projects"].__setitem__(1, copy.deepcopy(r["projects"][0]))):
            self.reject(mutation)

    def test_older_compiler_native_run_is_not_promoted_by_fresh_source_replay(self):
        self.original["projects"][0]["native_gate"]["compiler_sha256"] = "0" * 64
        self.input.write_text(json.dumps(self.original))
        self.reject(lambda r: r.update(input_sha256=hashlib.sha256(self.input.read_bytes()).hexdigest()))

    def test_current_source_change_invalidates_retained_replay(self):
        path = source.EXAMPLES["owned_library"]
        path.write_bytes(path.read_bytes() + b"\n// source changed after the receipt\n")
        self.reject(lambda r: None)

    def test_native_boolean_exit_in_input_does_not_count_as_execution(self):
        self.original["projects"][0]["execution"]["exit_code"] = False
        self.input.write_text(json.dumps(self.original))
        self.reject(lambda r: r.update(input_sha256=hashlib.sha256(self.input.read_bytes()).hexdigest()))

    def test_second_project_error_preserves_first_and_attempts_third(self):
        responses = [copy.deepcopy(self.receipts[0]), OSError("second source could not be opened"), copy.deepcopy(self.receipts[2])]
        with patch.object(source, "verify_resource_source", side_effect=responses) as replay:
            report = source.qualify(Path("original.json"))
        self.assertEqual(replay.call_count, 3)
        self.assertEqual(report["status"], "failed")
        self.assertEqual([row["status"] for row in report["projects"]], ["passed", "failed", "passed"])
        self.assertEqual(report["projects"][0]["source_replay"], self.receipts[0])
        self.assertIn("second source", report["projects"][1]["validation_error"])

    def test_rejected_native_receipt_diagnostics_are_retained(self):
        responses = copy.deepcopy(self.receipts)
        responses[1].update(ok=False, status="rejected", diagnostics=[{"code": "E_NATIVE_CONTROL", "message": "specific failure"}])
        with patch.object(source, "verify_resource_source", side_effect=responses):
            report = source.qualify(Path("original.json"))
        self.assertEqual([row["status"] for row in report["projects"]], ["passed", "failed", "passed"])
        self.assertEqual(report["projects"][1]["source_replay"]["diagnostics"][0]["code"], "E_NATIVE_CONTROL")


@unittest.skipUnless(shutil.which("g++") and shutil.which(os.environ.get("RUSTC", "rustc")), "native C++ and pinned Rust are required")
class ScopedReleaseNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from hepta.cpp_scoped import qualify_scoped_cpp
        temporary = tempfile.TemporaryDirectory(prefix="hepta-scoped-release-")
        cls.addClassCleanup(temporary.cleanup)
        cls.report = qualify_scoped_cpp(temporary.name, iterations=100000)
        release.require_qualification("cpp_scoped_raii", cls.report)

    def test_real_native_complete_lifecycle_gate_passes(self):
        self.assertTrue(self.report["ok"])
        self.assertEqual(len(self.report["performance"]["measurements"]), 4)
        self.assertEqual(self.report["execution"]["scoped_wrapper_allocation_delta"], 0)

    def test_failed_or_missing_processes_and_boolean_exit_reject(self):
        mutations = [lambda r: r["execution_process"].update(returncode=False),
                     lambda r: r["performance"]["process"].update(returncode=17),
                     lambda r: r["performance"].pop("process"),
                     lambda r: r["performance"].pop("benchmark_sha256"),
                     lambda r: r["hepta_consumer"]["backend"].update(ok=False, status="not_run")]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                report = copy.deepcopy(self.report)
                mutate(report)
                with self.assertRaises(ValueError):
                    release.require_qualification("cpp_scoped_raii", report)

    def test_current_inputs_generated_bridge_tools_and_library_are_bound(self):
        mutations = [lambda r: r.update(inputs={}),
                     lambda r: r["hepta_consumer"].update(compiler_sha256="0" * 64),
                     lambda r: r["bridge_generation"]["outputs"]["bridge.hepta"].update(sha256="0" * 64),
                     lambda r: r["bridge_generation"]["compiler"].update(executable_sha256="0" * 64),
                     lambda r: r.update(hepta_library_sha256="0" * 64),
                     lambda r: r["performance"]["observed_median_ratios_to_native"].update(native_cpp_lifecycle=0.1),
                     lambda r: r["performance"]["measurements"][0].update(iterations=100000.0)]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                report = copy.deepcopy(self.report)
                mutate(report)
                with self.assertRaises(ValueError):
                    release.require_qualification("cpp_scoped_raii", report)


if __name__ == "__main__":
    unittest.main()
