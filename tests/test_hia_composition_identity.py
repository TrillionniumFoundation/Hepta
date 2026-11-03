"""Independent hostile-source and frozen-product controls for one composition.

Only temporary Git fixtures and copied identity dictionaries are mutated.
The production checkout, executables, solver and native bridge are not changed.
"""
from __future__ import annotations

import copy
from hashlib import sha256
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import z3

from hepta.hia_optimization import _solver_identity
from tools import qualify_hia_composition as composition


class CompositionIdentityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hepta-composition-identity-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = {"registered_source": "fixed"}
        self.tools = {"z3": _solver_identity(z3)}

    def git(self, *arguments):
        return subprocess.check_output(["git", *arguments], cwd=self.root, text=True,
                                       stderr=subprocess.PIPE).strip()

    def source_fixture(self):
        self.git("init", "-q")
        for name in ("hepta/hia_program.py", "tools/qualify_hia_composition.py"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("# registered fixture bytes\n")
        self.git("add", "hepta/hia_program.py", "tools/qualify_hia_composition.py")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "commit", "-q", "-m", "Register exact source fixture")

    def test_plan_copy_regressions_are_registered_once(self):
        name = "tests.test_hia_ndu_plan_copy"
        self.assertEqual(composition.CORE_TESTS.count(name), 1)
        suite = unittest.defaultTestLoader.loadTestsFromName(name)
        self.assertGreaterEqual(suite.countTestCases(), 4)

    def test_clean_materialized_source_is_bound_to_the_git_commit(self):
        self.source_fixture()
        with patch.object(composition, "ROOT", self.root):
            result = composition.source_identity()
        self.assertTrue(result["clean"])
        self.assertEqual(result["commit"], self.git("rev-parse", "HEAD"))
        self.assertEqual(result["materialized_files_sha256"]["hepta/hia_program.py"],
                         sha256((self.root / "hepta/hia_program.py").read_bytes()).hexdigest())

    def test_index_flags_cannot_attest_uncommitted_source_as_clean(self):
        self.source_fixture()
        path = self.root / "hepta/hia_program.py"
        registered = path.read_bytes()
        for flag, undo in (("--assume-unchanged", "--no-assume-unchanged"),
                           ("--skip-worktree", "--no-skip-worktree")):
            with self.subTest(flag=flag):
                self.git("update-index", flag, "hepta/hia_program.py")
                path.write_bytes(b"# hidden modified compiler bytes\n")
                self.assertEqual(self.git("status", "--porcelain", "--untracked-files=all"), "")
                with patch.object(composition, "ROOT", self.root), self.assertRaises(ValueError):
                    composition.source_identity()
                path.write_bytes(registered)
                self.git("update-index", undo, "hepta/hia_program.py")

    def test_source_drift_produces_false_instead_of_losing_failure_report(self):
        with patch.object(composition, "source_identity", side_effect=ValueError("source changed")):
            self.assertIs(composition.unchanged(self.source, self.tools), False)

    def test_actual_solver_binding_and_dynamic_library_identity_are_rechecked(self):
        original = copy.deepcopy(self.tools["z3"])
        with patch.object(composition, "source_identity", return_value=self.source):
            self.assertTrue(composition.unchanged(self.source, self.tools))
            for field in ("binding_sha256", "library_sha256"):
                changed = {**original, field: "0" * 64}
                with self.subTest(field=field), patch("hepta.hia_optimization._solver_identity", return_value=changed):
                    self.assertIs(composition.unchanged(self.source, self.tools), False)

    def test_frozen_manifest_and_native_product_drift_are_rejected(self):
        manifest = self.root / "identity.json"
        binary = self.root / "ndu-bridge"
        manifest.write_bytes(b'{"identity":"registered"}\n')
        binary.write_bytes(b"registered native product")
        originals = {path: path.read_bytes() for path in (manifest, binary)}
        frozen = {str(path): sha256(raw).hexdigest() for path, raw in originals.items()}
        with patch.object(composition, "source_identity", return_value=self.source):
            self.assertTrue(composition.unchanged(self.source, self.tools, frozen))
            for path in (manifest, binary):
                with self.subTest(path=path.name):
                    path.write_bytes(b"changed after build freeze")
                    self.assertIs(composition.unchanged(self.source, self.tools, frozen), False)
                    path.write_bytes(originals[path])
            binary.unlink()
            self.assertIs(composition.unchanged(self.source, self.tools, frozen), False)


if __name__ == "__main__":
    unittest.main()
