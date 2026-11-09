"""Rejection boundaries for the public HIA release entry.

Cold materialization and the actual pinned runtime/worker are validated by the
release campaign; these tests exercise malformed locks and masked source drift.
"""
from __future__ import annotations

import copy
from hashlib import sha256
import json
import marshal
from pathlib import Path
import py_compile
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tools import hia_release as release


def lock_fixture():
    return {"schema": release.SCHEMA, "release_id": "release-test",
        "entrypoint": "python3 -B tools/hia_release.py",
        "materialization": dict(release.MATERIALIZATION),
        "sources": {name: {"repository": url, "commit": "1" * 40, "tree": "2" * 40}
                    for name, url in release.REPOSITORIES.items()},
        "installation": {name: "3" * 64 for name in release.preflight.PINS},
        "target_abi": dict(release.TARGET_ABI),
        "selfhost": {**release.SELFHOST_STATIC, "profile": "test-profile", "abi": {"entry": "f0"},
            "limits": {"functions": 128}, "support_matrix_sha256": "4" * 64,
            "source_sha256": "4" * 64, "loader_sha256": "4" * 64},
        "files": {"hepta": {name: "4" * 64 for name in (*release.ENTRY_FILES, *release.BOOTSTRAP_FILES, *release.CANDIDATE_FILES)},
                  "runtime": {name: "5" * 64 for name in release.RUNTIME_FILES}},
        "mcp": copy.deepcopy(release.MCP_CONTRACT), "qualification": dict(release.QUALIFICATION)}


class ReleaseLockBoundaries(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "lock.json"

    def save(self, value):
        self.path.write_text(json.dumps(value))
        return self.path

    def test_explicit_digest_is_checked_before_parsing(self):
        self.path.write_bytes(b"not-json")
        with self.assertRaisesRegex(ValueError, "digest"):
            release.load_lock(self.path, "0" * 64)

    def test_source_contract_cannot_promote_deployment_or_value(self):
        for name in release.QUALIFICATION:
            value = lock_fixture()
            value["qualification"][name] = not value["qualification"][name]
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "cannot grant"):
                release.load_lock(self.save(value))

    def test_boolean_contract_rejects_integer_substitution(self):
        value = lock_fixture()
        value["qualification"]["production_deployed"] = 0
        with self.assertRaisesRegex(ValueError, "cannot grant"):
            release.load_lock(self.save(value))

    def test_repository_cannot_be_substituted(self):
        for name in release.REPOSITORIES:
            value = lock_fixture()
            value["sources"][name]["repository"] = "https://example.invalid/other.git"
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "source identity"):
                release.load_lock(self.save(value))

    def test_symbolic_or_malformed_commits_are_rejected(self):
        for revision in ("main", "HEAD~1", "-c credential.helper=bad", 3, "a" * 39):
            value = lock_fixture()
            value["sources"]["runtime"]["commit"] = revision
            with self.subTest(revision=revision), self.assertRaisesRegex(ValueError, "source identity"):
                release.load_lock(self.save(value))

    def test_duplicate_json_members_are_rejected(self):
        raw = json.dumps(lock_fixture())
        self.path.write_text(raw[:-1] + ', "schema": "' + release.SCHEMA + '"}')
        with self.assertRaisesRegex(ValueError, "duplicate"):
            release.load_lock(self.path)

    def test_complete_eleven_tool_family_is_required(self):
        value = lock_fixture()
        value["mcp"]["hia_tools"].pop()
        with self.assertRaisesRegex(ValueError, "eleven-tool"):
            release.load_lock(self.save(value))

    def test_bootstrap_loader_cannot_disappear_from_inventory(self):
        for name in ("tools/hia_selfhost_child.py", "tools/hia_selfhost_select.py",
                     "tools/hia_selfhost_bulk.py", "tools/hia_selfhost_loans.py",
                     "tools/hia_selfhost_cfg_worklist.py",
                     "tools/hia_selfhost_process_owner.py", "tests/test_hia_selfhost_process_owner.py",
                     "tools/hia_selfhost_owned_elf.py", "tools/hia_selfhost_owned_elf_cases.py",
                     "tools/hia_selfhost_owned_flow_cases.py", "tools/qualify_hia_selfhost_owned_elf.py",
                     "tests/test_hia_selfhost_owned_flow.py",
                     "tools/hia_selfhost_chain_elf.py", "tools/hia_selfhost_chain_cases.py",
                     "tools/hia_selfhost_chain_flow_cases.py", "tools/hia_selfhost_parameter_cases.py",
                     "tools/hia_selfhost_chain_allocator_child.py", "tools/hia_selfhost_chain_allocator_witness.c",
                     "tools/qualify_hia_selfhost_chain_flow.py", "tools/qualify_hia_selfhost_chain_elf.py",
                     "tests/test_hia_selfhost_chain.py"):
            value = lock_fixture()
            del value["files"]["hepta"][name]
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "incomplete"):
                release.load_lock(self.save(value))

    def test_repository_trial_inputs_and_proof_scope_cannot_disappear_from_inventory(self):
        for name in (
            "tools/hia_repository_agent_trial.py", "tests/test_hia_repository_agent_trial.py",
            "docs/HIA_REPOSITORY_AGENT_TRIAL.md",
            "experiments/hia_repository_select_trial_20261108/public/PROMPT.txt",
            "experiments/hia_repository_select_trial_20261108/public/task.json",
            "tests/test_hia_scalar_proof_contract.py", "docs/HIA_AGENT_PROOF_RESULTS.md",
            "tools/qualify_hia_agent_buffer_lifecycle.py", "tests/test_hia_agent_buffer_lifecycle.py",
            "tests/test_hia_agent_external_roots.py",
            "docs/HIA_AGENT_EXTERNAL_ROOT_REPORT_REPAIR_20261108.md",
            "tools/hia_agent_native_qualification.py",
            "review-evidence/hia-agent-buffer-20261108-5e6c/raw-continuation.zip",
            "tools/qualify_hia_agent_original_select_delta.py",
            "docs/HIA_AGENT_ORIGINAL_SELECT_DELTA_20261108.md",
            "docs/HIA_AGENT_EXTENSION_PROOF_PLAN_20261108.md",
            "review-evidence/hia-agent-original-select-delta-20261108-5e6c/raw-evidence.zip",
            "docs/HIA_SELFHOST_CHAIN_FLOW_QUALIFICATION.md",
            "docs/HIA_SELFHOST_CHAIN_V13_QUALIFICATION.md",
            "docs/HIA_SELFHOST_ALLOC_NODE_FIX_20261108.md",
            "docs/HIA_SELFHOST_CFG_WORKLIST_FIX_20261108.md",
            "docs/HIA_SELFHOST_COLD_PROCESS_OWNER_20261108.md",
            "docs/HIA_SELFHOST_COLD_PARALLEL_OWNER_FIX_20261108.md",
            "tools/qualify_hia_selfhost_machine_plans.py", "tests/test_hia_selfhost_machine_plans.py",
            "docs/HIA_SELFHOST_MACHINE_PLAN_HEADER_REPAIR_20261108.md",
            "tools/qualify_hia_safe_core_cmovne.py", "tools/hia_safe_core_cmovne_child.py",
            "tests/test_hia_safe_core_cmovne.py", "docs/HIA_SAFE_CORE_CMOVNE_20261108.md",
            "tools/qualify_hia_ndu_prepared_ranker.py", "tools/replay_hia_ndu_prepared_ranker.py",
            "tests/test_hia_ndu_prepared_ranker.py", "docs/HIA_NDU_PREPARED_RANKING.md",
            "tests/test_hia_ndu_prepared_cost_intervals.py",
            "review-evidence/hia-ndu-prepared-20261108-5e6c/final-originals.tar.xz",
            "tools/qualify_hia_ndu_persistent_ranker.py", "tools/replay_hia_ndu_persistent_ranker.py",
            "tests/test_hia_ndu_persistent_ranker.py", "docs/HIA_NDU_PERSISTENT_RANKING.md",
            "rust/hia-ndu-bridge/src/main.rs",
            "tools/build_hia_ndu_bridge.py", "rust/hia-ndu-bridge/Cargo.toml",
            "rust/hia-ndu-bridge/Cargo.lock", "rust/hia-ndu-bridge/upstream.json",
            ".github/workflows/hia-ndu-scalar-selection.yml",
        ):
            value = lock_fixture()
            del value["files"]["hepta"][name]
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "incomplete"):
                release.load_lock(self.save(value))

    def test_inventory_path_traversal_is_rejected(self):
        for filename in ("../outside", "/etc/passwd", "tools//bad", "tools/./bad"):
            value = lock_fixture()
            value["files"]["hepta"][filename] = "6" * 64
            with self.subTest(filename=filename), self.assertRaisesRegex(ValueError, "file identity"):
                release.load_lock(self.save(value))

    def test_original_reconciliation_and_final_image_entry_are_source_bound(self):
        for name in ("README.md", "tools/hia_original_reconcile.py", "tools/build_hia_safe_core.py",
                     "docs/HIA_PRODUCT_FOLLOWTHROUGH_20261107.md"):
            value = lock_fixture()
            del value["files"]["hepta"][name]
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "incomplete"):
                release.load_lock(self.save(value))

    def test_existing_materialization_destination_never_launches_git(self):
        with mock.patch.object(release.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "already exists"):
                release.materialize(lock_fixture(), Path(self.tmp.name), {}, Path("/usr/bin/python3"))
        run.assert_not_called()

    def test_describe_cannot_advertise_an_unreviewed_fallback(self):
        value = lock_fixture()
        value["target_abi"]["llvm_or_assembler_fallback"] = True
        with self.assertRaisesRegex(ValueError, "cannot grant"):
            release.load_lock(self.save(value))

    def test_describe_rejects_whole_language_or_unbound_loader(self):
        for field, changed in (("whole_language_selfhost", True), ("loader_sha256", "a" * 64)):
            value = lock_fixture()
            value["selfhost"][field] = changed
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "selfhost"):
                release.load_lock(self.save(value))


class CommittedSourceBoundary(unittest.TestCase):
    def test_exact_remote_commit_is_fetched_without_following_later_tip(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source, target = parent / "source", parent / "target"
            source.mkdir()
            def git(*args):
                return subprocess.check_output(["git", "-C", str(source), *args],
                    stderr=subprocess.DEVNULL).decode().strip()
            git("init", "-q")
            git("config", "user.name", "HIA exact-commit fixture")
            git("config", "user.email", "fixture@example.invalid")
            git("config", "uploadpack.allowFilter", "true")
            (source / "source.py").write_text("version = 1\n")
            prompt_name = "experiments/hia_repository_select_trial_20261108/public/PROMPT.txt"
            prompt = source / prompt_name
            prompt.parent.mkdir(parents=True)
            prompt.write_text("pinned public maintenance task\n")
            git("add", ".")
            git("commit", "-qm", "pinned")
            pinned = git("rev-parse", "HEAD")
            (source / "source.py").write_text("version = 2\n")
            prompt.write_text("later public maintenance task\n")
            git("commit", "-qam", "later tip")
            release.checkout_remote_source(source.as_uri(), pinned, target)
            subprocess.run(["git", "-C", str(target), "sparse-checkout", "set", "--cone",
                            *release.SOURCE_DIRECTORIES], check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run(["git", "-C", str(target), "checkout", "--detach", pinned],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual((target / "source.py").read_text(), "version = 1\n")
            self.assertEqual((target / prompt_name).read_text(), "pinned public maintenance task\n")
            self.assertEqual(release.preflight.git(target, "rev-parse", "HEAD").strip(), pinned)
            self.assertEqual(release.preflight.git(target, "rev-list", "--count", "HEAD").strip(), "1")
            with self.assertRaises(subprocess.CalledProcessError):
                release.checkout_remote_source(source.as_uri(), "0" * 40, parent / "missing")
            self.assertTrue((parent / "missing" / ".git").is_dir())

    def test_source_file_entry_ignores_timestamp_valid_preflight_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            helper = root / "hia_candidate_preflight.py"
            helper.write_bytes((release.ROOT / "tools/hia_candidate_preflight.py").read_bytes())
            entry = root / "hia_release.py"
            entry.write_bytes((release.ROOT / "tools/hia_release.py").read_bytes())
            cached = Path(py_compile.compile(str(helper), doraise=True))
            marker = root / "cached-helper-executed"
            forged = compile("from pathlib import Path\nPath(" + repr(str(marker)) + ").write_text('executed')\n", str(helper), "exec")
            cached.write_bytes(cached.read_bytes()[:16] + marshal.dumps(forged))
            result = subprocess.run([sys.executable, "-B", "-E", "-s", str(entry), "--help"],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("materialize", result.stdout)
            self.assertFalse(marker.exists())

    def test_assume_unchanged_does_not_hide_loader_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.DEVNULL).decode().strip()
            git("init", "-q")
            git("config", "user.name", "HIA release boundary fixture")
            git("config", "user.email", "fixture@example.invalid")
            source = root / "loader.py"
            source.write_text("original = True\n")
            git("add", "loader.py")
            git("commit", "-qm", "fixture")
            revision = git("rev-parse", "HEAD")
            expected = release.committed_files(root, revision, ["loader.py"])
            self.assertEqual(expected["loader.py"], sha256(source.read_bytes()).hexdigest())
            git("update-index", "--assume-unchanged", "loader.py")
            source.write_text("original = False\n")
            self.assertEqual(git("status", "--porcelain"), "")
            with self.assertRaisesRegex(ValueError, "committed bytes"):
                release.committed_files(root, revision, ["loader.py"])

    def test_target_abi_is_read_without_importing_backend(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "backend.py"
            path.write_text("raise RuntimeError('must not execute')\nTARGET='x86_64-unknown-linux-gnu'\n")
            self.assertEqual(release.literal_constant(path, "TARGET"), release.TARGET)


if __name__ == "__main__":
    unittest.main()
