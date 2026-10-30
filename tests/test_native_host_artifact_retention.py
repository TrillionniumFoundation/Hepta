"""Artifact custody protocol controls; fake bytes here are never native qualification."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path, PureWindowsPath
import shutil
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hepta.clang_capture import CaptureResult
from tools import validate_native_host as module


CLANG_PROBE = ("HEPTA_CC_FAMILY clang\nHEPTA_CC_VERSION 20 1 8\n"
               "HEPTA_CC_SYSTEM Linux\nHEPTA_CC_MACHINE x86_64\nHEPTA_C_STANDARD 201112L\n")
ROLES = ("rust_object", "driver_O0", "driver_O2", "wrong_echo")
PAYLOADS = {role: b"fixture-only; never compiled or executed\x00" + role.encode() for role in ROLES}


def digest(data):
    return hashlib.sha256(data).hexdigest()


class NativeHostArtifactRetentionTests(unittest.TestCase):
    def fixture(self, root, *, directory=None):
        """Independent report bindings plus actual small, distinct fake files."""
        origin = root / "temporary originals"
        origin.mkdir()
        destination = directory or root / "retained artifacts"
        retained = module._new_retention(destination)
        system = "Windows" if os.name == "nt" else "Linux"
        names = (("matrix.obj", "host-matrix-O0.exe", "host-matrix-O2.exe", "wrong.exe")
                 if system == "Windows" else ("matrix.o", "host-matrix-O0", "host-matrix-O2", "wrong"))
        for role, name in zip(ROLES, names):
            path = origin / name
            path.write_bytes(PAYLOADS[role])
            path.chmod(0o644 if role == "rust_object" else 0o755)
            module._retain_binary(retained, path, role, digest(PAYLOADS[role]))
        retained["complete"] = True
        report = {
            "schema": module.SCHEMA, "status": "passed", "host": {"system": system},
            "native_object": {"artifact": str((origin / names[0]).resolve()),
                              "artifact_sha256": digest(PAYLOADS["rust_object"]),
                              "artifact_bytes": len(PAYLOADS["rust_object"])},
            "executable_sha256s": [digest(PAYLOADS["driver_O0"]), digest(PAYLOADS["driver_O2"])],
            "negative_control": {"artifact_sha256": digest(PAYLOADS["wrong_echo"])},
            "retained_binary_artifacts": retained,
        }
        return report, origin, destination

    def test_four_copies_bind_actual_bytes_modes_and_original_report_identities(self):
        with tempfile.TemporaryDirectory() as temporary:
            report, origin, destination = self.fixture(Path(temporary))
            retained = report["retained_binary_artifacts"]
            self.assertEqual(retained["directory"], str(destination.resolve()))
            self.assertEqual(len(retained["files"]), 4)
            self.assertEqual({row["role"] for row in retained["files"]}, set(ROLES))
            for row in retained["files"]:
                source, target = origin / row["name"], destination / row["name"]
                self.assertEqual(target.read_bytes(), PAYLOADS[row["role"]])
                self.assertEqual(row["original_path"], str(source.resolve()))
                self.assertEqual(row["bytes"], len(PAYLOADS[row["role"]]))
                self.assertEqual(row["sha256"], digest(PAYLOADS[row["role"]]))
                self.assertEqual(row["mode"], stat.S_IMODE(source.stat().st_mode))
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), row["mode"])
            module.validate_retained_binaries(report)
            module.validate_retained_binaries(report, directory=destination)
            # The original run_host temporary directory really disappears.
            shutil.rmtree(origin)
            module.validate_retained_binaries(report)
            module.validate_retained_binaries(report, directory=destination)

    def test_manifest_single_faults_cannot_claim_complete_bound_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            report, _, _ = self.fixture(Path(temporary))
            def first(value):
                return value["retained_binary_artifacts"]["files"][0]
            mutations = {
                "missing": lambda value: value["retained_binary_artifacts"]["files"].pop(),
                "duplicate": lambda value: value["retained_binary_artifacts"]["files"].append(copy.deepcopy(first(value))),
                "duplicate_role": lambda value: value["retained_binary_artifacts"]["files"][1].update(role="rust_object"),
                "unknown_role": lambda value: first(value).update(role="foreign_binary"),
                "wrong_name": lambda value: first(value).update(name="other.o"),
                "path_escape": lambda value: first(value).update(name="../matrix.o"),
                "absolute_name": lambda value: first(value).update(name="/tmp/matrix.o"),
                "wrong_origin": lambda value: first(value).update(original_path=str(Path(temporary) / "other" / "matrix.o")),
                "wrong_hash": lambda value: first(value).update(sha256="0" * 64),
                "wrong_object_bytes": lambda value: first(value).update(bytes=first(value)["bytes"] + 1),
                "bool_bytes": lambda value: first(value).update(bytes=True),
                "oversize_bytes": lambda value: first(value).update(bytes=module.MAX_NATIVE_BINARY_BYTES + 1),
                "special_mode": lambda value: first(value).update(mode=0o4755),
                "negative_mode": lambda value: first(value).update(mode=-1),
                "bool_mode": lambda value: first(value).update(mode=True),
                "incomplete": lambda value: value["retained_binary_artifacts"].update(complete=False),
                "non_boolean_complete": lambda value: value["retained_binary_artifacts"].update(complete=1),
                "wrong_object_reference": lambda value: value["native_object"].update(artifact_sha256="1" * 64),
                "wrong_driver_reference": lambda value: value["executable_sha256s"].reverse(),
                "wrong_negative_reference": lambda value: value["negative_control"].update(artifact_sha256="2" * 64),
            }
            for name, change in mutations.items():
                with self.subTest(fault=name):
                    value = copy.deepcopy(report)
                    change(value)
                    with self.assertRaises(ValueError):
                        module.validate_retained_binaries(value)

    def test_restored_archive_directory_preserves_original_path_bindings(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report, origin, directory = self.fixture(root)
            original = copy.deepcopy(report)
            restored = root / "restored elsewhere"
            shutil.move(str(directory), restored)
            shutil.rmtree(origin)
            module.validate_retained_binaries(report, directory=restored)
            self.assertEqual(report, original)
            self.assertFalse(directory.exists())

    def test_windows_origin_binding_uses_windows_path_rules_without_host_inference(self):
        # This exercises manifest spelling only, not Windows/MSVC execution.
        with tempfile.TemporaryDirectory() as temporary:
            report, _, _ = self.fixture(Path(temporary))
            report["host"]["system"] = "Windows"
            origin = PureWindowsPath("C:/Temp Folder/original")
            names = ("matrix.obj", "host-matrix-O0.exe", "host-matrix-O2.exe", "wrong.exe")
            report["native_object"]["artifact"] = str(origin / names[0])
            retained = report["retained_binary_artifacts"]
            retained["directory"] = str(PureWindowsPath("C:/Artifact Folder/native-artifacts"))
            for row, name in zip(retained["files"], names):
                row["name"], row["original_path"] = name, str(origin / name)
            module.validate_retained_binaries(report)
            for wrong in ("C:\\Other\\host-matrix-O0.exe", "C:\\Temp Folder\\original\\host-matrix-O2.exe",
                          "C:\\Temp Folder\\original\\host-matrix-O0"):
                with self.subTest(origin=wrong):
                    invalid = copy.deepcopy(report)
                    invalid["retained_binary_artifacts"]["files"][1]["original_path"] = wrong
                    with self.assertRaises(ValueError):
                        module.validate_retained_binaries(invalid)

    def test_actual_readback_rejects_tamper_missing_nonregular_and_changed_mode(self):
        for fault in ("tamper", "missing", "directory", "mode"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                report, _, destination = self.fixture(Path(temporary))
                target = destination / report["retained_binary_artifacts"]["files"][1]["name"]
                original_mode = stat.S_IMODE(target.stat().st_mode)
                if fault == "tamper":
                    data = target.read_bytes()
                    target.write_bytes(bytes([data[0] ^ 1]) + data[1:])
                elif fault == "missing":
                    target.unlink()
                elif fault == "directory":
                    target.unlink()
                    target.mkdir()
                else:
                    # Writable/read-only is portable, including Windows chmod.
                    target.chmod(0o444)
                    self.assertNotEqual(stat.S_IMODE(target.stat().st_mode), original_mode)
                try:
                    with self.assertRaises((OSError, ValueError)):
                        module.validate_retained_binaries(report, directory=destination)
                finally:
                    if fault == "mode":
                        target.chmod(original_mode)

    def test_wrong_source_hash_refuses_before_copy_or_manifest_publication(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "matrix.o"
            source.write_bytes(PAYLOADS["rust_object"])
            retained = module._new_retention(root / "retained")
            with self.assertRaises(ValueError):
                module._retain_binary(retained, source, "rust_object", "0" * 64)
            self.assertEqual(retained["files"], [])
            self.assertFalse(retained["complete"])
            self.assertEqual(list((root / "retained").iterdir()), [])

    def test_nonregular_and_oversize_sources_are_refused_without_destination_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            retained = module._new_retention(root / "retained")
            directory = root / "not-a-binary"
            directory.mkdir()
            with self.assertRaises((OSError, ValueError)):
                module._retain_binary(retained, directory, "rust_object", "0" * 64)
            oversize = root / "matrix.o"
            with oversize.open("wb") as stream:
                stream.truncate(module.MAX_NATIVE_BINARY_BYTES + 1)
            # The expected hash is correct: rejection must be about the bound,
            # not an accidental digest mismatch on the sparse zero-filled file.
            expected = hashlib.sha256()
            remaining = module.MAX_NATIVE_BINARY_BYTES + 1
            zeroes = bytes(65536)
            while remaining:
                size = min(remaining, len(zeroes))
                expected.update(zeroes[:size])
                remaining -= size
            with self.assertRaises(ValueError):
                module._retain_binary(retained, oversize, "rust_object", expected.hexdigest())
            # Symlink creation can require privileges on Windows. Directory
            # and bound controls above always run; a creatable link is tested
            # as a real filesystem link, never represented as native evidence.
            target = root / "real-source"
            target.write_bytes(PAYLOADS["rust_object"])
            link = root / "linked-source"
            try:
                os.symlink(target, link)
            except (OSError, NotImplementedError):
                self.assertFalse(link.exists())
            else:
                with self.assertRaises((OSError, ValueError)):
                    module._retain_binary(retained, link, "rust_object", digest(PAYLOADS["rust_object"]))
            self.assertEqual(retained["files"], [])
            self.assertEqual(list((root / "retained").iterdir()), [])

    def test_existing_retention_directory_and_destination_are_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "retained"
            retained = module._new_retention(directory)
            sentinel = directory / "matrix.o"
            sentinel.write_bytes(b"existing evidence must survive")
            source = root / "matrix.o"
            source.write_bytes(PAYLOADS["rust_object"])
            with self.assertRaises((OSError, ValueError)):
                module._new_retention(directory)
            with self.assertRaises((OSError, ValueError)):
                module._retain_binary(retained, source, "rust_object", digest(source.read_bytes()))
            self.assertEqual(sentinel.read_bytes(), b"existing evidence must survive")
            self.assertEqual(retained["files"], [])
            self.assertFalse(retained["complete"])

    def test_later_copy_failure_preserves_prior_bytes_with_incomplete_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            retained = module._new_retention(root / "retained")
            source = root / "matrix.o"
            source.write_bytes(PAYLOADS["rust_object"])
            module._retain_binary(retained, source, "rust_object", digest(source.read_bytes()))
            before = copy.deepcopy(retained)
            next_source = root / "host-matrix-O0"
            next_source.write_bytes(PAYLOADS["driver_O0"])
            (root / "retained" / "host-matrix-O0").mkdir()
            with self.assertRaises((OSError, ValueError)):
                module._retain_binary(retained, next_source, "driver_O0", digest(next_source.read_bytes()))
            self.assertEqual(retained, before)
            self.assertFalse(retained["complete"])
            self.assertEqual((root / "retained" / "matrix.o").read_bytes(), PAYLOADS["rust_object"])

    def test_cli_execution_failure_retains_partial_objects_without_qualification(self):
        # All compiler/native subprocess outcomes below are protocol fixtures.
        # The production run_host and CLI failure path themselves are exercised.
        def rust_object(_source, **kwargs):
            output = Path(kwargs["output"])
            output.write_bytes(PAYLOADS["rust_object"])
            return {"ok": True, "artifact": str(output.resolve()),
                    "artifact_sha256": digest(PAYLOADS["rust_object"]),
                    "artifact_bytes": len(PAYLOADS["rust_object"])}

        commands = []
        def compiler(argv, **_kwargs):
            commands.append(list(argv))
            if argv[-1] == "--version":
                return CaptureResult(0, "clang version 20.1.8\n", "")
            if argv[-1] == "-dumpmachine":
                return CaptureResult(0, "x86_64-unknown-linux-gnu\n", "")
            if "-E" in argv:
                return CaptureResult(0, CLANG_PROBE, "")
            if "-o" in argv:
                output = Path(argv[argv.index("-o") + 1])
                self.assertEqual(output.name, "host-matrix-O0")
                output.write_bytes(PAYLOADS["driver_O0"])
                return CaptureResult(0, "", "")
            self.assertEqual(len(argv), 1)
            self.assertEqual(Path(argv[0]).name, "host-matrix-O0")
            return CaptureResult(17, "", "fixture execution failed after successful build")

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "native-report.json"
            with (patch.object(sys, "argv", ["validate_native_host.py", "--cc", "clang", "--cc-family", "clang", "--output", str(output)]),
                  patch.object(module.shutil, "which", return_value=sys.executable),
                  patch.object(module.platform, "system", return_value="Linux"),
                  patch.object(module.platform, "machine", return_value="x86_64"),
                  patch.object(module, "run_bounded", side_effect=compiler),
                  patch.object(module, "analyze", return_value=SimpleNamespace(report={"ok": True}, program=None, rust="fixture")),
                  patch.object(module, "emit_header", return_value="/* protocol fixture */\n"),
                  patch.object(module, "compile_rust", side_effect=rust_object),
                  contextlib.redirect_stdout(io.StringIO())):
                self.assertEqual(module.main(), 1)
            report = json.loads(output.read_text())
            self.assertEqual(report["status"], "failed")
            self.assertNotIn("actual_reported_host_executed", report["claims"])
            observed = report["unqualified_observations"]
            retained = observed["retained_binary_artifacts"]
            self.assertFalse(retained["complete"])
            self.assertEqual({row["role"] for row in retained["files"]}, {"rust_object", "driver_O0"})
            self.assertEqual(Path(retained["directory"]), output.with_name(output.stem + "-artifacts").resolve())
            self.assertEqual(observed["commands"][-1]["returncode"], 17)
            for row in retained["files"]:
                self.assertEqual((Path(retained["directory"]) / row["name"]).read_bytes(), PAYLOADS[row["role"]])
                self.assertFalse(Path(row["original_path"]).exists())
            self.assertEqual(len(commands), 5)

    def test_cli_actual_retention_readback_failure_cannot_pass_or_erase_originals(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "native-report.json"
            directory = output.with_name(output.stem + "-artifacts")
            report, _, _ = self.fixture(root, directory=directory)
            report["commands"] = []
            report["claims"] = {"actual_reported_host_executed": True}
            # Deliberately tamper after the candidate says all four were copied.
            tampered = directory / report["retained_binary_artifacts"]["files"][2]["name"]
            tampered.write_bytes(b"changed after candidate creation")
            with (patch.object(sys, "argv", ["validate_native_host.py", "--output", str(output)]),
                  patch.object(module, "run_host", return_value=report) as runner,
                  patch.object(module, "validate_report") as abi_validator,
                  contextlib.redirect_stdout(io.StringIO())):
                self.assertEqual(module.main(), 1)
            runner.assert_called_once()
            abi_validator.assert_called_once_with(report)
            self.assertEqual(Path(runner.call_args.kwargs["artifact_directory"]), directory)
            failed = json.loads(output.read_text())
            self.assertEqual(failed["status"], "failed")
            self.assertNotIn("actual_reported_host_executed", failed["claims"])
            self.assertIn("retained_binary_artifacts", failed["unqualified_observations"])
            self.assertEqual(tampered.read_bytes(), b"changed after candidate creation")
            self.assertEqual(len(list(directory.iterdir())), 4)

    def test_cli_existing_success_report_and_artifacts_are_never_replaced(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "native-report.json"
            old_report = b'{"status":"passed","original":"preserve exact bytes"}\n'
            output.write_bytes(old_report)
            directory = output.with_name(output.stem + "-artifacts")
            directory.mkdir()
            sentinel = directory / "matrix.o"
            sentinel.write_bytes(b"previous attempt original artifact")
            with (patch.object(sys, "argv", ["validate_native_host.py", "--output", str(output)]),
                  patch.object(module.shutil, "which", return_value=sys.executable),
                  patch.object(module, "run_bounded", side_effect=AssertionError("no compiler process may start")) as invoke,
                  contextlib.redirect_stdout(io.StringIO())):
                try:
                    result = module.main()
                except (OSError, ValueError):
                    pass
                else:
                    self.assertEqual(result, 1)
            invoke.assert_not_called()
            self.assertEqual(output.read_bytes(), old_report)
            self.assertEqual(sentinel.read_bytes(), b"previous attempt original artifact")

    def test_cli_requires_its_own_manifest_directory_even_when_copy_bytes_match(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "native-report.json"
            directory = output.with_name(output.stem + "-artifacts")
            report, _, _ = self.fixture(root, directory=directory)
            report["retained_binary_artifacts"]["directory"] = str((root / "different attempt").resolve())
            # Offline restoration explicitly chooses a local mapping. A fresh
            # CLI qualification must bind the directory it actually produced.
            module.validate_retained_binaries(report, directory=directory)
            with (patch.object(sys, "argv", ["validate_native_host.py", "--output", str(output)]),
                  patch.object(module, "run_host", return_value=report),
                  patch.object(module, "validate_report"),
                  contextlib.redirect_stdout(io.StringIO())):
                self.assertEqual(module.main(), 1)
            failed = json.loads(output.read_text())
            self.assertEqual(failed["status"], "failed")
            self.assertNotIn("actual_reported_host_executed", failed["claims"])
            self.assertEqual(len(list(directory.iterdir())), 4)

    def test_cli_exclusive_report_write_preserves_a_concurrent_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "native-report.json"
            directory = output.with_name(output.stem + "-artifacts")
            report, _, _ = self.fixture(root, directory=directory)
            original_validator = module.validate_retained_binaries
            competing_report = b'{"original":"concurrent writer"}\n'
            def validate_then_publish(value, *, directory=None):
                original_validator(value, directory=directory)
                output.write_bytes(competing_report)
            with (patch.object(sys, "argv", ["validate_native_host.py", "--output", str(output)]),
                  patch.object(module, "run_host", return_value=report),
                  patch.object(module, "validate_report"),
                  patch.object(module, "validate_retained_binaries", side_effect=validate_then_publish),
                  contextlib.redirect_stdout(io.StringIO())):
                try:
                    result = module.main()
                except (OSError, ValueError):
                    pass
                else:
                    self.assertEqual(result, 1)
            self.assertEqual(output.read_bytes(), competing_report)
            self.assertEqual(len(list(directory.iterdir())), 4)


if __name__ == "__main__":
    unittest.main()
