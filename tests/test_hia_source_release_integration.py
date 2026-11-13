"""Narrow source/release union controls; not whole native delivery approval."""
from __future__ import annotations

import ast
import errno
import fcntl
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class SourceReleaseIntegrationSourceTests(unittest.TestCase):
    def test_explicit_resource_union_has_canonical_assets_and_unchanged_wire_roles(self):
        from hepta.hia_agent_contract import (
            DISCOVERY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_FILES,
            COMPILER_BUILD_FILES, PUBLICATION_BUILD_FILES, BACKEND_BUILD_FILES,
            EMITTER_BUILD_FILES, BYTE_WRAPPER_BUILD_FILES, MACHINE_OBJECT_BUILD_FILES,
            EXECUTION_OBSERVATION_BUILD_FILES, CONTINUATION_BUILD_FILES,
        )
        names = (tuple("docs/" + name for name in DISCOVERY_FILES)
                 + NATIVE_SOURCE_FILES + SOURCE_BUILD_FILES
                 + COMPILER_BUILD_FILES + PUBLICATION_BUILD_FILES + BACKEND_BUILD_FILES
                 + EMITTER_BUILD_FILES + BYTE_WRAPPER_BUILD_FILES + MACHINE_OBJECT_BUILD_FILES
                 + EXECUTION_OBSERVATION_BUILD_FILES + CONTINUATION_BUILD_FILES)
        self.assertEqual(len(names), len(set(names)))
        self.assertIn("examples/hia_bootstrap/selfhost.hepta", SOURCE_BUILD_FILES)
        self.assertIn("examples/hia_bootstrap/source_build_policy.hepta", SOURCE_BUILD_FILES)
        self.assertIn("examples/hia_bootstrap/core_json_cli_packer.hepta", COMPILER_BUILD_FILES)
        from tools.generate_hia_source_build import ROLE_NAMES
        self.assertEqual(ROLE_NAMES, ("source_build_policy.hepta", "selfhost.hepta",
                                      "source_build_packer.hepta"))
        self.assertTrue(all(name.endswith(".hepta")
                            for name in (*SOURCE_BUILD_FILES, *COMPILER_BUILD_FILES)))
        for name in names:
            with self.subTest(name=name):
                self.assertTrue((ROOT / name).is_file())
        tree = ast.parse((ROOT / "setup.py").read_text())
        functions = [node for node in tree.body
                     if isinstance(node, ast.FunctionDef) and node.name == "agent_resources"]
        self.assertEqual(len(functions), 1)
        namespace = {"ast": ast, "Path": Path, "ROOT": ROOT}
        module = ast.Module(body=functions, type_ignores=[])
        exec(compile(module, str(ROOT / "setup.py"), "exec"), namespace)
        self.assertEqual(namespace["agent_resources"](), names)
        includes = set((ROOT / "MANIFEST.in").read_text().splitlines())
        for name in names:
            with self.subTest(manifest=name):
                self.assertIn("include " + name, includes)

    def test_changed_builder_entrypoints_from_unrelated_directory(self):
        environment = {key: value for key, value in os.environ.items()
                       if key not in {"PYTHONPATH", "PYTHONHOME"}
                       and not key.startswith("HEPTA_")}
        paths = ("tools/build_hia_source_build.py", "tools/build_hia_core_json_cli.py",
                 "tools/build_hia_release_install.py", "tools/build_hia_release_selection.py")
        with tempfile.TemporaryDirectory(prefix="hia-source-release-help-") as directory:
            for name in paths:
                with self.subTest(name=name):
                    observed = subprocess.run(
                        [sys.executable, "-I", "-B", str(ROOT / name), "--help"],
                        cwd=directory, env=environment, capture_output=True,
                        text=True, timeout=30)
                    self.assertEqual(observed.returncode, 0, (observed.stdout, observed.stderr))
                    self.assertEqual(observed.stderr, "")
                    self.assertIn("--output", observed.stdout)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_conflicting_source_builder_inputs_refuse_before_any_io(self):
        from tests.test_hia_source_build import SourceBuilderNativeTests
        environment = {
            "HEPTA_HIA_SOURCE_BUILD_COLD_REPORT": "/missing/cold.json",
            "HEPTA_HIA_SOURCE_BUILD_DEVELOPMENT_MANIFEST": "/missing/development.json",
            "HEPTA_HIA_SOURCE_BUILD_OBSERVATIONS": "/must-not-create",
        }
        with (patch.dict(os.environ, environment, clear=True),
              patch.object(Path, "read_bytes", side_effect=AssertionError("early read")),
              patch.object(Path, "mkdir", side_effect=AssertionError("early output"))):
            with self.assertRaisesRegex(ValueError, "select one cold"):
                SourceBuilderNativeTests.setUpClass()

    def test_conflicting_public_compiler_inputs_refuse_before_any_io(self):
        from tests.test_hia_program_selfhost import SelfhostBuildNativeTests
        environment = {
            "HEPTA_HIA_SOURCE_BUILD_COLD_REPORT": "/missing/cold.json",
            "HEPTA_HIA_SELFHOST_BUILD_DEVELOPMENT_COMPILER": "/missing/compiler.bin",
            "HEPTA_HIA_SELFHOST_BUILD_EVIDENCE": "/must-not-create",
        }
        with (patch.dict(os.environ, environment, clear=True),
              patch.object(Path, "read_bytes", side_effect=AssertionError("early read")),
              patch.object(Path, "mkdir", side_effect=AssertionError("early output"))):
            with self.assertRaisesRegex(ValueError, "select exactly one matching"):
                SelfhostBuildNativeTests.setUpClass()

    def test_source_bundle_policy_preserves_both_name_spellings_and_closed_roles(self):
        from tests.test_hia_source_build import bundle, observe_policy, workspace
        from tools.generate_hia_source_build import ROLE_NAMES
        for name in ("x.hepta", "x.hiaasm", "a" * 117 + ".hepta",
                     "a" * 116 + ".hiaasm"):
            with self.subTest(admitted=name):
                wire = bundle([(name, 0o400, b"x")])
                self.assertEqual(observe_policy(wire, workspace(p0=1, p8=1, p16=1))[0], 0)
        for name in (".hepta", ".hiaasm", "x.HIAASM", "x.hia",
                     "a" * 117 + ".hiaasm"):
            with self.subTest(refused=name):
                wire = bundle([(name, 0o400, b"x")])
                self.assertEqual(observe_policy(wire, workspace(p0=1, p8=1, p16=1))[0], 16)
        for names in (ROLE_NAMES, tuple(name.replace(".hepta", ".hiaasm") for name in ROLE_NAMES)):
            wire = bundle([(name + ".bin", 0o400, b"x") for name in names])
            self.assertEqual(observe_policy(wire, workspace(p0=1, p8=2, p16=1))[0], 0)
        duplicate = [(ROLE_NAMES[0] + ".bin", 0o400, b"x"),
                     (ROLE_NAMES[0].replace(".hepta", ".hiaasm") + ".bin", 0o400, b"x"),
                     (ROLE_NAMES[2] + ".bin", 0o400, b"x")]
        self.assertEqual(observe_policy(bundle(duplicate), workspace(p0=1, p8=2, p16=1))[0], 16)


class PublicationUnionCustodyTests(unittest.TestCase):
    def assert_closed(self, fd):
        with self.assertRaises(OSError) as caught:
            os.fstat(fd)
        self.assertEqual(caught.exception.errno, errno.EBADF)

    def test_actual_returned_process_keeps_structured_refusal_and_never_replays(self):
        import hepta.artifact_publication_native as native
        from hepta.artifact_publication import PublicationRejected
        from tests.test_hia_program_selfhost import _test_executable
        code = _test_executable(bytes.fromhex("b83c000000bf0c0000000f05"))
        original_run = subprocess.run
        for operation in native.NATIVE_PUBLICATION_OPERATIONS:
            observed = []
            def inspect_and_run(argv, **kwargs):
                fd = int(argv[0].rsplit("/", 1)[1])
                observed.append(fd)
                self.assertEqual(fcntl.fcntl(fd, 1034) & 15, 15)
                self.assertEqual(os.pread(fd, len(code) + 1, 0), code)
                self.assertEqual(kwargs["pass_fds"], (fd,))
                return original_run(argv, **kwargs)
            with self.subTest(operation=operation):
                with (patch.object(native, "_validated_code", return_value=code),
                      patch.object(native.subprocess, "run", side_effect=inspect_and_run) as run):
                    with self.assertRaises(native.NativePublicationRefusal) as caught:
                        native._execute_native("selected", operation, "stage", "dest", b"")
                    self.assertIsInstance(caught.exception, PublicationRejected)
                    self.assertEqual(caught.exception.operation, operation)
                    self.assertEqual(caught.exception.returncode, 12)
                    self.assertEqual(str(caught.exception), "E_PUBLISH_RACE: native " + operation
                                     + " refused or I/O failed; no automatic replay")
                    run.assert_called_once()
                self.assertEqual(len(observed), 1)
                self.assert_closed(observed[0])

    def test_real_sealed_wrong_extent_or_bytes_refuse_before_child(self):
        import hepta.artifact_publication_native as native
        from hepta.artifact_publication import PublicationRejected
        code = b"captured-executable-fixture"
        write = os.write
        for changed in (code[:-1], bytes([code[0] ^ 1]) + code[1:]):
            descriptors = []
            def corrupt_real_write(fd, data):
                descriptors.append(fd)
                written = write(fd, changed)
                self.assertEqual(written, len(changed))
                return len(data)
            with self.subTest(changed=changed):
                with (patch.object(native, "_validated_code", return_value=code),
                      patch.object(native.os, "write", side_effect=corrupt_real_write),
                      patch.object(native.subprocess, "run") as run):
                    with self.assertRaisesRegex(PublicationRejected, "E_PUBLISH_NATIVE_CUSTODY"):
                        native._execute_native("selected", "withdraw", "stage", "dest", b"")
                    run.assert_not_called()
                self.assertEqual(len(descriptors), 1)
                self.assert_closed(descriptors[0])


if __name__ == "__main__":
    unittest.main()
