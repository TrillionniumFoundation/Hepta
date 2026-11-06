"""Adversarial acceptance checks; synthetic xfail data never enters real suites."""
from contextlib import redirect_stderr
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import py_compile
import subprocess
import sys
import tempfile
import unittest

from tools import qualify_hia_delivery as gate


def test_summary():
    return {"inventory": 1, "tests_run": 1, "failures": 0, "errors": 0, "skips": 0,
            "expected_failures": 0, "unexpected_successes": 0,
            "suite_inventory": {"required": 1}, "test_ids": ["required.test_ok"],
            "executed_test_ids": ["required.test_ok"]}


def identities():
    names = gate.CANDIDATE_EXTRA | gate.QUOTA_SOURCES | gate.AUDIT_SOURCES | {"hepta/example.py"}
    files = [{"path": name, "sha256": gate.sha256(name.encode()).hexdigest(), "size_bytes": len(name)}
             for name in sorted(names)]
    snapshot = {"source_commit": "a" * 40, "source_tree": "b" * 40, "files": files}
    source_files = [row for row in files if row["path"].startswith("hepta/") or row["path"] in gate.CANDIDATE_EXTRA]
    manifest = {"source_commit": snapshot["source_commit"], "source_tree": snapshot["source_tree"],
        "worktree_dirty": False, "source_files": source_files,
        "source_manifest_sha256": gate.sha256(gate.encoded(source_files)).hexdigest(),
        "compatibility": {"abi": {"targets": ["host", "other"]}}}
    return snapshot, manifest


class HIADeliveryGateTests(unittest.TestCase):
    def test_empty_partial_skipped_expected_and_unexpected_outcomes_reject(self):
        good = test_summary()
        gate.check_test_summary(good, expected_suites=["required"])
        mutations = [lambda d: d.update(inventory=0, tests_run=0),
                     lambda d: d.update(tests_run=0),
                     lambda d: d.update(suite_inventory={"required": 0}),
                     lambda d: d.update(test_ids=["other.test_ok"]),
                     lambda d: d.update(inventory=True)]
        for key in ("failures", "errors", "skips", "expected_failures", "unexpected_successes"):
            mutations.append(lambda d, key=key: d.update({key: 1}))
        for mutation in mutations:
            value = deepcopy(good)
            mutation(value)
            with self.assertRaises(ValueError):
                gate.check_test_summary(value, expected_suites=["required"])
        duplicated = deepcopy(good)
        duplicated.update(inventory=2, tests_run=2, suite_inventory={"required": 2},
                          test_ids=["required.test_ok"] * 2, executed_test_ids=["required.test_ok"] * 2)
        with self.assertRaises(ValueError):
            gate.check_test_summary(duplicated, expected_suites=["required"])

    def test_actual_empty_runner_retains_failure_and_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as directory, redirect_stderr(io.StringIO()):
            output = Path(directory) / "empty.json"
            self.assertEqual(gate.run_regressions([], output), 1)
            result = json.loads(output.read_bytes())
            self.assertFalse(result["qualified"])
            self.assertEqual(result["inventory"], 0)
            self.assertIn("empty", result["failure"])

    def test_all_tracked_bytes_are_checked_even_when_git_stat_flags_hide_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "tracked.txt").write_text("first\n")
            (root / "other.txt").write_text("second\n")
            commands = [("init", "-q"), ("add", "."),
                        ("-c", "user.name=HIA test", "-c", "user.email=hia@example.invalid", "commit", "-qm", "fixture")]
            for command in commands:
                subprocess.run(["git", "-C", str(root), *command], check=True, capture_output=True)
            snapshot = gate.source_snapshot(root)
            self.assertEqual({row["path"] for row in snapshot["files"]}, {"other.txt", "tracked.txt"})
            gate.unchanged(snapshot, root)
            subprocess.run(["git", "-C", str(root), "update-index", "--assume-unchanged", "tracked.txt"], check=True)
            (root / "tracked.txt").write_text("changed behind stat cache\n")
            self.assertEqual(gate.git("status", "--porcelain", root=root), "")
            with self.assertRaisesRegex(ValueError, "frozen Git tree"):
                gate.unchanged(snapshot, root)

    def test_candidate_cannot_borrow_other_commit_tree_or_source_bytes(self):
        snapshot, manifest = identities()
        gate.check_candidate(manifest, snapshot)
        mutations = [lambda d: d.update(source_commit="c" * 40),
                     lambda d: d.update(source_tree="d" * 40),
                     lambda d: d.update(worktree_dirty=True),
                     lambda d: d["source_files"].pop(),
                     lambda d: d["source_files"][0].update(sha256="0" * 64),
                     lambda d: d.update(source_manifest_sha256="0" * 64)]
        for mutation in mutations:
            value = deepcopy(manifest)
            mutation(value)
            with self.assertRaises(ValueError):
                gate.check_candidate(value, snapshot)

    def test_quota_requires_success_complete_observations_and_exact_sources(self):
        snapshot, _ = identities()
        program_ids = {"v1": "1" * 64, "v2": "2" * 64}
        report = {**test_summary(), "schema": "hepta.hia.quota-qualification.v1", "qualified": True,
            "source_unchanged": True,
            "source_sha256": {row["path"]: row["sha256"] for row in snapshot["files"] if row["path"] in gate.QUOTA_SOURCES},
            "program_sha256": program_ids, "native_status": "executed", "claims": {"native_execution_tested": True},
            "observations": [{"test": "required.test_ok", "outcome": "passed"}],
            "native_build_receipts": [{"core_sha256": value, "ok": True, "implementation_sha256": "3" * 64,
                "claims": {"rust_codegen_used": False, "c_codegen_used": False, "fallback_used": False}}
                for value in program_ids.values()]}
        gate.check_quota(report, snapshot, program_ids, "3" * 64)
        mutations = [lambda d: d.update(qualified=False),
                     lambda d: d.update(source_unchanged=False),
                     lambda d: d["source_sha256"].update({"hepta/apps/quota.py": "0" * 64}),
                     lambda d: d.update(expected_failures=1),
                     lambda d: d.update(native_status="not_requested"),
                     lambda d: d["observations"].clear(),
                     lambda d: d["native_build_receipts"][1].update(core_sha256="1" * 64),
                     lambda d: d["native_build_receipts"][0].update(implementation_sha256="4" * 64)]
        for mutation in mutations:
            value = deepcopy(report)
            mutation(value)
            with self.assertRaises(ValueError):
                gate.check_quota(value, snapshot, program_ids, "3" * 64)

    def test_installed_receipt_must_match_checked_wheel_and_manifest(self):
        _, manifest = identities()
        names = {"offline_wheel_install", "installed_layout", "installed_package_before", "installed_package_after",
                 "installed_identity", "verify_counter.hia",
                 "verify_parameter_loan_return_v8.hia", "interpret", "installed_console_script",
                 "installed_quota_init", "installed_quota_reserve", "installed_quota_upgrade", "installed_quota_recover",
                 "native_build", "native_execute", "emit_host", "emit_other"}
        report = {"schema": "hepta.hia.candidate-installed-verification.v1", "status": "passed", "worktree_dirty": False,
            "source_commit": manifest["source_commit"], "source_manifest_sha256": manifest["source_manifest_sha256"],
            "manifest_sha256": "1" * 64, "wheel_sha256": "2" * 64,
            "native": {"execution_qualified": True, "status": "counter_executed"},
            "observations": [{"name": name, "returncode": 0} for name in sorted(names)]}
        package_files = [row for row in manifest["source_files"] if row["path"].startswith("hepta/")]
        for row in report["observations"]:
            if row["name"] in {"installed_package_before", "installed_package_after"}:
                row.update(file_count=len(package_files),
                           package_manifest_sha256=gate.sha256(gate.encoded(package_files)).hexdigest())
        gate.check_installed(report, manifest, "1" * 64, "2" * 64)
        for label in ("installed_package_before", "installed_package_after"):
            value = deepcopy(report)
            row = next(row for row in value["observations"] if row["name"] == label)
            row["package_manifest_sha256"] = "0" * 64
            with self.assertRaises(ValueError):
                gate.check_installed(value, manifest, "1" * 64, "2" * 64)
            row["package_manifest_sha256"] = gate.sha256(gate.encoded(package_files)).hexdigest()
            row["file_count"] -= 1
            with self.assertRaises(ValueError):
                gate.check_installed(value, manifest, "1" * 64, "2" * 64)
        for field in ("source_commit", "source_manifest_sha256", "manifest_sha256", "wheel_sha256"):
            value = deepcopy(report)
            value[field] = "0" * 64
            with self.assertRaises(ValueError):
                gate.check_installed(value, manifest, "1" * 64, "2" * 64)
        value = deepcopy(report)
        value["observations"][-1]["returncode"] = 1
        with self.assertRaises(ValueError):
            gate.check_installed(value, manifest, "1" * 64, "2" * 64)

    def test_value_control_audit_cannot_borrow_changed_source(self):
        snapshot, _ = identities()
        report = {"schema": "hepta.hia.deliverable-controls.run.v1", "new_agent_campaign_executed": False,
            "new_ndu_native_campaign_executed": False,
            "native_free_compute_audit": {"status": "passed", "native_ndu_calls": 0, "model_calls": 0,
                "ndu_advantage_established": False,
                "source_sha256": {row["path"]: row["sha256"] for row in snapshot["files"] if row["path"] in gate.AUDIT_SOURCES}}}
        gate.check_value_controls(report, snapshot)
        report["native_free_compute_audit"]["source_sha256"]["hepta/hia_ndu_stateful.py"] = "0" * 64
        with self.assertRaises(ValueError):
            gate.check_value_controls(report, snapshot)

    def test_child_reads_source_instead_of_valid_timestamp_stale_pyc(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            module = root / "stale_fixture.py"
            module.write_text("VALUE = 'old'\n")
            before = module.stat()
            cache = root / "__pycache__" / ("stale_fixture." + sys.implementation.cache_tag + ".pyc")
            py_compile.compile(str(module), cfile=str(cache), doraise=True)
            module.write_text("VALUE = 'new'\n")
            os.utime(module, ns=(before.st_atime_ns, before.st_mtime_ns))
            code = "import stale_fixture,sys; print(stale_fixture.VALUE, sys.flags.optimize)"
            environment = dict(os.environ)
            environment.pop("PYTHONPYCACHEPREFIX", None)
            environment.pop("PYTHONOPTIMIZE", None)
            stale = subprocess.run([sys.executable, "-B", "-c", code], cwd=root, env=environment,
                                   check=True, capture_output=True, text=True, timeout=20)
            self.assertEqual(stale.stdout.strip(), "old 0")
            environment["PYTHONOPTIMIZE"] = "1"
            command, environment = gate.child_command(["-c", code], environment, root / "fresh-cache")
            actual = subprocess.run(command, cwd=root, env=environment, check=True,
                                    capture_output=True, text=True, timeout=20)
            self.assertEqual(actual.stdout.strip(), "new 0")


if __name__ == "__main__":
    unittest.main()
