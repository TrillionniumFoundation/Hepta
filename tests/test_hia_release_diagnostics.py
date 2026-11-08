"""Actionable, transport-redacted failures at the public release entry."""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tools import hia_release as release


SECRET = "https://fixture-user:fixture-password@private.example.invalid/private-repo?token=fixture-secret"
REMOTE = ("init", "remote_add", "configure_promisor", "configure_blob_filter",
          "fetch", "verify_fetch", "sparse_checkout", "checkout")


class SourceCheckoutDiagnostics(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.lock = {"sources": {
            name: {"repository": url, "commit": str(index) * 40}
            for index, (name, url) in enumerate(release.REPOSITORIES.items(), 1)
        }}
        self.counter = 0

    def plan(self, override):
        return [(name, stage) for name in ("hepta", "runtime")
                for stage in (("clone", "sparse_checkout", "checkout") if override else REMOTE)
                if not (name == "runtime" and stage == "sparse_checkout")]

    def identify(self, command):
        if command[1] in ("init", "clone"):
            return Path(command[-1]).name, command[1]
        name = Path(command[command.index("-C") + 1]).name
        if "rev-parse" in command:
            return name, "verify_fetch"
        if "remote" in command:
            return name, "remote_add"
        if "config" in command:
            return name, ("configure_promisor" if "remote.origin.promisor" in command
                          else "configure_blob_filter")
        if "sparse-checkout" in command:
            return name, "sparse_checkout"
        return name, "fetch" if "fetch" in command else "checkout"

    def invoke(self, *, override=False, failure=None, kind=None, mismatch=False):
        self.counter += 1
        destination = self.root / f"materialized-{self.counter}"
        calls = []

        def run(command, **options):
            role, stage = self.identify(command)
            calls.append(((role, stage), command, options))
            if (role, stage) == failure:
                if kind == "timed_out":
                    raise subprocess.TimeoutExpired([*command, SECRET], options["timeout"],
                                                    output=SECRET.encode(), stderr=SECRET.encode())
                if kind == "could_not_start":
                    raise OSError(2, SECRET, SECRET)
                raise subprocess.CalledProcessError(128, [*command, SECRET],
                                                    output=SECRET.encode(), stderr=SECRET.encode())
            output = self.lock["sources"][role]["commit"].encode() + b"\n"
            if mismatch and stage == "verify_fetch":
                output = b"0" * 40 + b"\n"
            return subprocess.CompletedProcess(command, 0, output, b"")

        argv = ["materialize", "--directory", str(destination)]
        if override:
            argv += ["--hepta-repository", SECRET, "--runtime-repository", SECRET]
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(release, "load_lock", return_value=(self.lock, "a" * 64)), \
             mock.patch.object(release.subprocess, "run", side_effect=run), \
             mock.patch.object(release, "check_lock") as check, \
             redirect_stdout(stdout), redirect_stderr(stderr):
            status = release.main(argv)
        return status, stdout.getvalue(), stderr.getvalue(), calls, check, destination

    def exercise_failures(self, kind):
        for override in (False, True):
            plan = self.plan(override)
            for index, (repository, stage) in enumerate(plan):
                with self.subTest(override=override, repository=repository, stage=stage, kind=kind):
                    status, stdout, stderr, calls, check, destination = self.invoke(
                        override=override, failure=(repository, stage), kind=kind)
                    self.assertEqual(status, 2)
                    self.assertEqual(stdout, "")
                    error = json.loads(stderr)
                    self.assertEqual(error["status"], "rejected")
                    self.assertFalse(error["production_deployed"])
                    diagnostic = error["source_checkout"]
                    self.assertEqual(diagnostic["repository"], repository)
                    self.assertEqual(diagnostic["stage"], stage)
                    self.assertEqual(diagnostic["pinned_commit"],
                                     self.lock["sources"][repository]["commit"])
                    self.assertEqual(diagnostic["failure_kind"], kind)
                    timeout = 30 if stage == "verify_fetch" else (
                        (600 if repository == "runtime" else 120) if stage == "checkout" else
                        (120 if stage == "sparse_checkout" else 300))
                    self.assertEqual(diagnostic["timeout_seconds"], timeout)
                    self.assertIn("--directory", diagnostic["next_step"])
                    expected_fields = {"repository", "stage", "pinned_commit", "failure_kind",
                                       "timeout_seconds", "next_step"}
                    if kind == "command_failed":
                        expected_fields.add("exit_code")
                        self.assertEqual(diagnostic["exit_code"], 128)
                    self.assertEqual(set(diagnostic), expected_fields)
                    for marker in (SECRET, "fixture-password", "private.example.invalid",
                                   "private-repo", "fixture-secret", "Traceback"):
                        self.assertNotIn(marker, stderr)
                    self.assertEqual([call[0] for call in calls], plan[:index + 1])
                    self.assertTrue(destination.is_dir())
                    check.assert_not_called()

    def test_each_stage_reports_failure_without_transport_details(self):
        self.exercise_failures("command_failed")

    def test_each_stage_reports_timeout_without_exception_details(self):
        self.exercise_failures("timed_out")

    def test_each_stage_redacts_process_start_errors(self):
        self.exercise_failures("could_not_start")

    def test_success_keeps_exact_commands_and_contract_check(self):
        for override in (False, True):
            with self.subTest(override=override):
                status, stdout, stderr, calls, check, destination = self.invoke(override=override)
                self.assertEqual(status, 0)
                self.assertEqual(stderr, "")
                result = json.loads(stdout)
                self.assertEqual(result["status"], "exact_sources_materialized")
                self.assertFalse(result["production_deployed"])
                self.assertFalse(result["dependencies_installed"])
                self.assertEqual(result["release_lock_sha256"], "a" * 64)
                self.assertEqual([call[0] for call in calls], self.plan(override))
                for (repository, stage), command, options in calls:
                    if stage in ("fetch", "checkout"):
                        self.assertEqual(command[-1], self.lock["sources"][repository]["commit"])
                    if stage == "fetch":
                        self.assertIn("--depth=1", command)
                        self.assertIn("--filter=blob:none", command)
                        self.assertEqual(options["env"]["GIT_TERMINAL_PROMPT"], "0")
                    if stage == "checkout":
                        self.assertIn("--detach", command)
                        self.assertEqual(options["timeout"], 600 if repository == "runtime" else 120)
                check.assert_called_once_with(self.lock, destination / "hepta",
                                              destination / "runtime", Path(sys.executable))

    def test_fetch_identity_mismatch_stops_before_checkout(self):
        status, stdout, stderr, calls, check, _ = self.invoke(mismatch=True)
        self.assertEqual(status, 2)
        self.assertEqual(stdout, "")
        self.assertIn("hepta source verify_fetch", json.loads(stderr)["error"])
        self.assertEqual([call[0] for call in calls], self.plan(False)[:6])
        check.assert_not_called()

    def test_real_cli_clone_failure_is_redacted(self):
        private_source = self.root / "fixture-secret-private-cache"
        # Use a complete fixture contract so release-metadata age cannot mask
        # the real Git failure this process-level regression is testing.
        lock = {
            "schema": release.SCHEMA, "release_id": "diagnostics-fixture",
            "entrypoint": "python3 -B tools/hia_release.py",
            "materialization": dict(release.MATERIALIZATION),
            "sources": {name: {**source, "tree": "3" * 40}
                        for name, source in self.lock["sources"].items()},
            "installation": {name: "4" * 64 for name in release.preflight.PINS},
            "target_abi": dict(release.TARGET_ABI),
            "selfhost": {**release.SELFHOST_STATIC, "profile": "fixture", "abi": {"entry": "f0"},
                        "limits": {"functions": 128}, "support_matrix_sha256": "5" * 64,
                        "source_sha256": "5" * 64, "loader_sha256": "5" * 64},
            "files": {
                "hepta": {name: "5" * 64 for name in
                          (*release.ENTRY_FILES, *release.BOOTSTRAP_FILES, *release.CANDIDATE_FILES)},
                "runtime": {name: "6" * 64 for name in release.RUNTIME_FILES}},
            "mcp": release.MCP_CONTRACT, "qualification": dict(release.QUALIFICATION),
        }
        lock_path = self.root / "fixture-lock.json"
        lock_path.write_text(json.dumps(lock))
        result = subprocess.run(
            [sys.executable, "-B", str(release.ROOT / "tools/hia_release.py"),
             "--lock", str(lock_path),
             "materialize", "--directory", str(self.root / "real-failure"),
             "--hepta-repository", str(private_source)],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        error = json.loads(result.stderr)
        self.assertEqual(error["source_checkout"]["repository"], "hepta")
        self.assertEqual(error["source_checkout"]["stage"], "clone")
        self.assertEqual(error["source_checkout"]["exit_code"], 128)
        self.assertNotIn(str(private_source), result.stderr)
        self.assertNotIn("fixture-secret", result.stderr)
        self.assertNotIn("fatal:", result.stderr)

    def test_real_timeout_retains_type_and_safe_context(self):
        command = [sys.executable, "-c", "import time; time.sleep(5)", SECRET]
        with self.assertRaises(subprocess.TimeoutExpired) as caught:
            release._source_checkout_run(
                command, repository="runtime", revision="2" * 40,
                stage="fetch", timeout=0.05)
        diagnostic = caught.exception.source_checkout_diagnostic
        self.assertEqual(diagnostic["failure_kind"], "timed_out")
        self.assertEqual(diagnostic["timeout_seconds"], 0.05)
        self.assertNotIn(SECRET, json.dumps(diagnostic))

    def test_real_local_materialization_preserves_both_pinned_commits(self):
        repositories = {}
        lock = {"sources": {}}
        for repository in ("hepta", "runtime"):
            source = self.root / ("origin-" + repository)
            source.mkdir()

            def git(*args):
                return subprocess.check_output(
                    ["git", "-C", str(source), *args], stderr=subprocess.DEVNULL).decode().strip()

            git("init", "-q")
            git("config", "user.name", "HIA diagnostics fixture")
            git("config", "user.email", "fixture@example.invalid")
            (source / "tools").mkdir()
            file = source / "tools" / "source.txt"
            file.write_text("pinned\n")
            if repository == "runtime":
                for name in ("src/main.rs", "vendor/runtime/input.rs",
                             "docs/qualification/release-gate.json",
                             "tests/evidence/archive.tar.gz", "tools/x230/evidence/probe.txt"):
                    artifact = source / name
                    artifact.parent.mkdir(parents=True, exist_ok=True)
                    artifact.write_text("pinned complete runtime closure\n")
            git("add", ".")
            git("commit", "-qm", "pinned")
            revision = git("rev-parse", "HEAD")
            file.write_text("later\n")
            git("commit", "-qam", "later")
            repositories[repository] = str(source)
            lock["sources"][repository] = {"repository": release.REPOSITORIES[repository],
                                            "commit": revision}
        destination = self.root / "real-success"
        with mock.patch.object(release, "check_lock") as check:
            result = release.materialize(lock, destination, repositories, Path(sys.executable))
        self.assertEqual(result["status"], "exact_sources_materialized")
        for repository in repositories:
            target = destination / repository
            self.assertEqual((target / "tools/source.txt").read_text(), "pinned\n")
            self.assertEqual(release.preflight.git(target, "rev-parse", "HEAD").strip(),
                             lock["sources"][repository]["commit"])
            if repository == "runtime":
                for name in ("src/main.rs", "vendor/runtime/input.rs",
                             "docs/qualification/release-gate.json",
                             "tests/evidence/archive.tar.gz", "tools/x230/evidence/probe.txt"):
                    self.assertEqual((target / name).read_text(), "pinned complete runtime closure\n")
        check.assert_called_once_with(lock, destination / "hepta", destination / "runtime",
                                      Path(sys.executable))


if __name__ == "__main__":
    unittest.main()
