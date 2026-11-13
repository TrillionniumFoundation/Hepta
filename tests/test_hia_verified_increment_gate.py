"""Real and adversarial checks of the broad, source-bound HIA qualification gate.

The older gate treated unittest.expectedFailure as an admissible success and
trusted testsRun alone. These tests assert that the actual runner's outcome,
plan/start/stop identities, and source/worktree consistency are all mandatory.
"""
from __future__ import annotations

from io import StringIO
from hashlib import sha256
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools import qualify_hia_verified_increment as gate

from tools.qualify_hia_verified_increment import (
    MODULES, _IdentityRecordingResult, _outcome_admissible,
    _planned_test_ids, _ids_digest,
)


def fake_result(**changes):
    state = {
        "testsRun": 2, "started_ids": ["one", "two"], "finished_ids": ["one", "two"],
        "errors": [], "failures": [], "skipped": [], "expectedFailures": [],
        "unexpectedSuccesses": [],
    }
    state.update(changes)
    return SimpleNamespace(**state, wasSuccessful=lambda: True)


def accepted(result, planned=("one", "two"), source=True, worktree=True):
    return _outcome_admissible(
        result, planned, source_unchanged=source, worktree_unchanged=worktree
    )


class VerifiedIncrementInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hia-inventory-")
        self.addCleanup(self.temporary.cleanup)
        self.parent = Path(self.temporary.name)
        self.root = self.parent / "repo"
        self.root.mkdir()
        self.git("init", "--quiet", "--object-format=sha1")
        for name, value in (("user.name", "Integration inventory fixture"),
                            ("user.email", "fixture@example.invalid"),
                            ("commit.gpgsign", "false"), ("core.hooksPath", "/dev/null"),
                            ("core.fileMode", "true"), ("core.autocrlf", "false")):
            self.git("config", name, value)
        self.inputs = {
            "examples/hia_recursive_chain/core_v7.hepta":
                (gate.ROOT / "examples/hia_recursive_chain/core_v7.hepta").read_bytes(),
            "examples/hia_recursive_chain/composite_v2.hepta":
                (gate.ROOT / "examples/hia_recursive_chain/composite_v2.hepta").read_bytes(),
            "examples/hia_program/offset_copy_v5.hepta":
                (gate.ROOT / "examples/hia_program/offset_copy_v5.hepta").read_bytes(),
            "rust/hia-core-shadow/Cargo.toml": b"[package]\nname = 'test-input'\n",
            "rust/hia-core-shadow/src/lib.rs": b"pub fn actual_input() {}\n",
            "tools/native_syscalls.S": b".text\n",
            "tests/fixtures/oracle.c": b"int oracle(void) { return 17; }\n",
        }
        for name, raw in self.inputs.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "committed integration inputs")

    def git(self, *arguments):
        return subprocess.check_output(["git", "--no-replace-objects", *arguments],
                                       cwd=self.root, timeout=10)

    def inventory(self):
        with patch.object(gate, "ROOT", self.root):
            return gate.inventory()

    def identity(self):
        with patch.object(gate, "ROOT", self.root):
            return gate._source_identity()

    def test_complete_tree_binds_native_sources_build_inputs_and_real_changes(self):
        before = self.inventory()
        self.assertEqual(before, {p: sha256(b).hexdigest() for p, b in self.inputs.items()})
        for name, raw in self.inputs.items():
            with self.subTest(input=name):
                path = self.root / name
                path.write_bytes(raw + b"\n")
                with self.assertRaisesRegex(ValueError, "source bytes differ from raw HEAD blob"):
                    self.inventory()
                path.write_bytes(raw)
                self.assertEqual(self.inventory(), before)
        # A newly retained native input needs no hand-maintained path allowlist.
        added = self.root / "examples/new-native.hepta"
        added.write_bytes(next(iter(self.inputs.values())))
        self.git("add", "examples/new-native.hepta")
        self.assertNotIn("examples/new-native.hepta", self.inventory())
        self.assertTrue(self.identity()["status"])
        self.git("commit", "--quiet", "-m", "retain new native input")
        self.assertIn("examples/new-native.hepta", self.inventory())
        (self.root / "generated-output.bin").write_bytes(b"not a source input")
        self.assertNotIn("generated-output.bin", self.inventory())

    def test_missing_tracked_native_input_is_not_silently_omitted(self):
        (self.root / "examples/hia_recursive_chain/core_v7.hepta").unlink()
        with self.assertRaises(FileNotFoundError):
            self.inventory()

    def test_tracked_symlink_cannot_bind_untracked_external_bytes(self):
        outside = self.parent / "outside.hepta"
        outside.write_bytes(b"outside the source tree")
        alias = self.root / "examples/external.hepta"
        alias.symlink_to(outside)
        self.git("add", "examples/external.hepta")
        self.git("commit", "--quiet", "-m", "inadmissible source symlink")
        with self.assertRaisesRegex(ValueError, "raw HEAD tree member"):
            self.inventory()

    def assert_hidden_source_change_refuses_before_discovery(self, flag):
        name = "examples/hia_recursive_chain/core_v7.hepta"
        before = self.inventory()
        self.git("update-index", flag, "--", name)
        # Index hints are harmless when the actual committed bytes still match.
        self.assertEqual(self.inventory(), before)
        (self.root / name).write_bytes(self.inputs[name] + b"\n")
        self.assertEqual(self.identity()["status"], "")
        self.assertNotEqual(self.git("rev-parse", "HEAD:" + name).strip(),
                            self.git("hash-object", "--no-filters", "--", name).strip())
        output = self.parent / "must-not-exist"
        with patch.object(gate, "ROOT", self.root), \
                patch.object(gate, "load_declared_suite") as discovery:
            with self.assertRaisesRegex(ValueError, "source bytes differ from raw HEAD blob"):
                gate.run(output)
            discovery.assert_not_called()
        self.assertFalse(output.exists())

    def test_assume_unchanged_cannot_hide_uncommitted_native_input(self):
        self.assert_hidden_source_change_refuses_before_discovery("--assume-unchanged")

    def test_skip_worktree_cannot_hide_uncommitted_native_input(self):
        self.assert_hidden_source_change_refuses_before_discovery("--skip-worktree")

    def test_replacement_commit_cannot_rebind_reported_source_identity(self):
        before = self.identity()
        name = "examples/hia_recursive_chain/core_v7.hepta"
        (self.root / name).write_bytes(self.inputs[name] + b"\n")
        self.git("add", name)
        self.git("commit", "--quiet", "-m", "replacement source")
        replacement = self.git("rev-parse", "HEAD").decode().strip()
        self.git("reset", "--hard", before["commit"])
        self.git("replace", before["commit"], replacement)
        self.assertEqual(self.identity(), before)
        self.assertEqual(self.inventory(), {p: sha256(b).hexdigest() for p, b in self.inputs.items()})

    def test_source_export_cannot_inherit_an_ancestor_git_inventory(self):
        child = self.root / "export"
        child.mkdir()
        with patch.object(gate, "ROOT", child), self.assertRaisesRegex(ValueError, "worktree root"):
            gate.inventory()


class VerifiedIncrementAdmissionTests(unittest.TestCase):
    def test_full_gate_includes_its_independent_adversarial_tests(self):
        self.assertEqual(MODULES.count("tests.test_hia_verified_increment_gate"), 1)
        self.assertEqual(len(MODULES), len(set(MODULES)))

    def test_retired_empty_performance_selector_is_explicit_and_never_counted(self):
        self.assertEqual(gate.RETIRED_EMPTY_SELECTORS, ("tests.test_hia_release_parity_tail_gate",))
        self.assertTrue(set(gate.RETIRED_EMPTY_SELECTORS).isdisjoint(MODULES))

    def test_clean_complete_outcome_and_source_are_necessary(self):
        self.assertTrue(accepted(fake_result()))
        self.assertFalse(accepted(fake_result(), source=False))
        self.assertFalse(accepted(fake_result(), worktree=False))
        self.assertFalse(accepted(fake_result(testsRun=1)))
        self.assertFalse(accepted(fake_result(testsRun=3)))

    def test_real_expected_failure_is_not_a_certificate(self):
        class Expected(unittest.TestCase):
            @unittest.expectedFailure
            def test_expected_failure(self):
                self.assertEqual(0, 1)
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(Expected)
        planned = _planned_test_ids(suite)
        result = unittest.TextTestRunner(
            stream=StringIO(), resultclass=_IdentityRecordingResult
        ).run(suite)
        self.assertTrue(result.wasSuccessful())  # Standard unittest semantics!
        self.assertEqual(result.testsRun, 1)
        self.assertEqual(len(result.expectedFailures), 1)
        self.assertEqual(tuple(result.started_ids), planned)
        self.assertEqual(tuple(result.finished_ids), planned)
        self.assertFalse(accepted(result, planned))

    def test_skipped_failed_unexpected_success_and_error_all_refuse(self):
        marker = unittest.FunctionTestCase(lambda: None)
        for key, value in (
            ("skipped", [(marker, "skipped a required compiler test")]),
            ("expectedFailures", [(marker, "false proof through expected failure")]),
            ("unexpectedSuccesses", [marker]),
            ("errors", [(marker, "synthetic error")]),
            ("failures", [(marker, "synthetic failure")]),
        ):
            with self.subTest(key=key):
                self.assertFalse(accepted(fake_result(**{key: value})))

    def test_matching_count_cannot_mask_missing_replaced_or_reordered_tests(self):
        for change in (
            {"started_ids": ["one", "other"]},
            {"started_ids": ["two", "one"]},
            {"finished_ids": ["one"]},
            {"finished_ids": ["two", "one"]},
            {"started_ids": ["one", "one"]},
            {"finished_ids": ["one", "one"]},
        ):
            with self.subTest(change=change):
                self.assertFalse(accepted(fake_result(**change)))

    def test_no_tests_duplicate_ids_or_noncanonical_plan_refuse(self):
        self.assertFalse(accepted(fake_result(testsRun=0, started_ids=[], finished_ids=[]), ()))
        self.assertFalse(accepted(fake_result(), ("one", "one")))
        self.assertFalse(accepted(fake_result(), ["one", "two"]))
        self.assertFalse(accepted(fake_result(), ("one", "")))

    def test_real_nested_suite_tracks_exact_order(self):
        class A(unittest.TestCase):
            def test_a(self): self.assertTrue(True)
            def test_b(self): self.assertTrue(True)
        class B(unittest.TestCase):
            def test_c(self): self.assertTrue(True)
        suite = unittest.TestSuite([
            unittest.defaultTestLoader.loadTestsFromTestCase(A),
            unittest.defaultTestLoader.loadTestsFromTestCase(B),
        ])
        planned = _planned_test_ids(suite)
        result = unittest.TextTestRunner(
            stream=StringIO(), resultclass=_IdentityRecordingResult
        ).run(suite)
        self.assertEqual(len(planned), 3)
        self.assertEqual(tuple(result.started_ids), planned)
        self.assertEqual(tuple(result.finished_ids), planned)
        self.assertTrue(accepted(result, planned))
        self.assertEqual(_ids_digest(planned), _ids_digest(result.started_ids))
        self.assertNotEqual(_ids_digest(planned), _ids_digest(tuple(reversed(planned))))


if __name__ == "__main__":
    unittest.main()
