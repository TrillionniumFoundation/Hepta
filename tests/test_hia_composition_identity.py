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


    def source_reference_fixture(self, release="1.90.0"):
        """Executable version-protocol control, never a real compiler proof."""
        import sys
        root = self.root/"source-reference"
        binary = root/"bin/rustc"
        binary.parent.mkdir(parents=True, exist_ok=True)
        version = ("rustc "+release+" (fixture 2025-09-14)\n"
                   "binary: rustc\ncommit-hash: fixture-identity\n"
                   "commit-date: 2025-09-14\nhost: x86_64-unknown-linux-gnu\n"
                   "release: "+release+"\nLLVM version: 20.1.8")
        binary.write_text("#!"+sys.executable+"\nimport sys\nprint("+
                          repr(version)+" if '-vV' in sys.argv else "+repr(version.splitlines()[0])+")\n")
        binary.chmod(0o700)
        for name in ("lib/librustc_driver.fixture.so", "lib/libLLVM.fixture.so",
                     "lib/rustlib/x86_64-unknown-linux-gnu/lib/libstd.fixture.rlib"):
            path = root/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(("fixture:"+name).encode())
        return binary

    def test_source_reference_uses_complete_pin_and_has_no_implicit_fallback(self):
        from hepta.backend import RUST_VERSION
        self.assertEqual(RUST_VERSION, "1.90.0")
        binary = self.source_reference_fixture()
        frozen = composition.source_reference_identity(str(binary))
        self.assertEqual(frozen["path"], str(binary.resolve()))
        self.assertEqual(frozen["selected_argument"], str(binary))
        self.assertEqual(frozen["reference"]["sysroot_discovery"], "verified_compiler_prefix")
        self.assertEqual(len(frozen["sysroot_files_sha256"]), 3)
        for invalid in (None, "", str(self.root/"missing-rustc")):
            with self.subTest(selection=invalid), self.assertRaises(ValueError):
                composition.source_reference_identity(invalid)
        self.source_reference_fixture(release="1.95.0")
        with self.assertRaisesRegex(ValueError, "source-reference Rust identity rejected"):
            composition.source_reference_identity(str(binary))

    def test_source_reference_driver_sysroot_and_executable_drift_fail_closed(self):
        binary = self.source_reference_fixture()
        frozen = composition.source_reference_identity(str(binary))
        self.tools["source_rustc"] = frozen
        library = binary.parent.parent/"lib/librustc_driver.fixture.so"
        stdlib = binary.parent.parent/"lib/rustlib/x86_64-unknown-linux-gnu/lib/libstd.fixture.rlib"
        with patch.object(composition, "source_identity", return_value=self.source):
            self.assertTrue(composition.unchanged(self.source, self.tools))
            for path in (binary, library, stdlib):
                original = path.read_bytes()
                with self.subTest(path=str(path)):
                    path.write_bytes(original+b"\n# drift\n" if path == binary else original+b"drift")
                    self.assertIs(composition.unchanged(self.source, self.tools), False)
                    path.write_bytes(original)
            added = library.with_name("new-driver.so")
            added.write_bytes(b"added")
            self.assertIs(composition.unchanged(self.source, self.tools), False)
            added.unlink()
            original = stdlib.read_bytes()
            stdlib.unlink()
            self.assertIs(composition.unchanged(self.source, self.tools), False)
            stdlib.write_bytes(original)
            self.assertTrue(composition.unchanged(self.source, self.tools))

    def test_source_reference_sysroot_links_are_rejected(self):
        binary = self.source_reference_fixture()
        lib = binary.parent.parent/"lib"
        (lib/"linked-driver.so").symlink_to(lib/"librustc_driver.fixture.so")
        with self.assertRaisesRegex(ValueError, "sysroot links"):
            composition.source_reference_identity(str(binary))


    def test_regression_child_mode_does_not_require_full_composition_tool_flags(self):
        with patch("sys.argv", ["qualify_hia_composition.py", "--regression-output", "child.json"]), \
                patch.object(composition, "regression_suite", return_value=True) as run, \
                patch.object(composition, "qualify") as full:
            self.assertEqual(composition.main(), 0)
            run.assert_called_once_with(Path("child.json"))
            full.assert_not_called()


if __name__ == "__main__":
    unittest.main()
