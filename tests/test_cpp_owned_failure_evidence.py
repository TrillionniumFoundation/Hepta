"""Mocked failure-retention tests; these do not claim native qualification."""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import tools.validate_cpp_owned as qualifier


class OwnedFailureEvidenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hepta-owned-failure-evidence-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def assert_raw(self, record, channel, expected):
        self.assertEqual(base64.b64decode(record[channel + "_bytes_base64"]), expected)
        self.assertEqual(record[channel + "_bytes_sha256"], hashlib.sha256(expected).hexdigest())
        self.assertEqual(record[channel + "_bytes"], len(expected))
        self.assertEqual(record[channel], expected.decode("utf-8", errors="replace"))

    def test_completed_process_preserves_exact_non_utf8_bytes(self):
        with patch.object(qualifier.subprocess, "run", return_value=subprocess.CompletedProcess(
                ["mock-native"], 0, stdout=b"native\xff\x00\n", stderr=b"diagnostic\xfe")):
            record = qualifier._run(["mock-native"])
        self.assertEqual(record["status"], "completed")
        self.assert_raw(record, "stdout", b"native\xff\x00\n")
        self.assert_raw(record, "stderr", b"diagnostic\xfe")
        qualifier._process(record)

    def test_timeout_returns_partial_bytes_as_a_failed_command_record(self):
        timeout = subprocess.TimeoutExpired(["mock-native"], 120, output=b"prefix\xff", stderr=b"stderr\xfe")
        with patch.object(qualifier.subprocess, "run", side_effect=timeout):
            record = qualifier._run(["mock-native"])
        self.assertEqual(record["status"], "timeout")
        self.assertIsNone(record["returncode"])
        self.assertEqual(record["command"], ["mock-native"])
        self.assert_raw(record, "stdout", b"prefix\xff")
        self.assert_raw(record, "stderr", b"stderr\xfe")
        with self.assertRaises(ValueError):
            qualifier._process(record)

    def test_mid_build_and_execution_timeouts_retain_every_completed_stage(self):
        frontend = {"ok": True, "assumptions": [], "test_only_mock": True}
        analysis = SimpleNamespace(report=frontend, program=object(), checked=object(),
                                   project=SimpleNamespace(identity="mock-project"), c="/* explicit mock source */\n")
        graph = {"test_only_mock": "resource projection"}
        timeout = subprocess.TimeoutExpired(["mock-native-compiler"], 7,
                                             output=b"compile-prefix\xff", stderr=b"partial-error\xfe")
        for phase in ("compile", "execute"):
            with self.subTest(phase=phase):
                row = {}

                def compiler(source, **options):
                    if phase == "compile":
                        raise timeout
                    output = Path(options["output"])
                    output.write_bytes(b"explicit mocked artifact; never executed")
                    return {"ok": True, "artifact": str(output), "test_only_mock": True}

                with (patch.object(qualifier, "analyze_project", return_value=analysis),
                      patch.object(qualifier, "lower_resource_ir", return_value=graph),
                      patch.object(qualifier, "verify_resource_ir", return_value={"ok": True}),
                      patch.object(qualifier, "verify_resource_source", return_value={"ok": True}),
                      patch.object(qualifier, "compile_c", side_effect=compiler),
                      patch.object(qualifier.subprocess, "run", side_effect=timeout)):
                    with self.assertRaises((subprocess.TimeoutExpired, ValueError)):
                        qualifier._build(self.root / "unused.hepta", self.root / phase, "c",
                                         qualifier.cases()[:1], record=row)
                self.assertEqual(row["status"], "failed")
                self.assertEqual(row["stage"], "native_compile" if phase == "compile" else "native_execution")
                self.assertEqual(row["frontend"], frontend)
                self.assertEqual(row["resource_ir"], graph)
                self.assertTrue(row["source_binding"]["ok"])
                self.assertTrue(Path(row["compiled_source"]["path"]).is_file())
                if phase == "compile":
                    self.assertEqual(row["failure"]["status"], "timeout")
                    self.assert_raw(row["failure"], "stdout", b"compile-prefix\xff")
                    self.assert_raw(row["failure"], "stderr", b"partial-error\xfe")
                else:
                    self.assertTrue(row["native"]["ok"])
                    self.assertTrue(Path(row["artifact"]["path"]).is_file())
                    self.assertEqual(row["execution"]["status"], "timeout")
                    self.assert_raw(row["execution"], "stdout", b"compile-prefix\xff")
                    self.assert_raw(row["execution"], "stderr", b"partial-error\xfe")

    @staticmethod
    def mocked_migration(source, output, **options):
        Path(output).write_bytes((qualifier.EXAMPLE / "expected.hepta").read_bytes())
        return {"ok": True, "test_only_mock": True}

    @staticmethod
    def completed_reference(command):
        if "-o" in command:
            Path(command[-1]).write_bytes(b"explicit mocked reference artifact")
        return {"status": "completed", "command": [str(part) for part in command], "returncode": 0,
                **qualifier._captured_streams(b"{}\n", b"")}

    def test_qualification_preinstalls_backend_record_before_build_failure(self):
        def interrupted_build(*args, record, **options):
            record.update(frontend={"ok": True, "test_only_mock": True}, stage="source_binding", status="failed")
            raise RuntimeError("injected middle-of-build failure")

        with (patch.object(qualifier, "migrate_cpp_owned", side_effect=self.mocked_migration),
              patch.object(qualifier.shutil, "which", return_value=sys.executable),
              patch.object(qualifier, "_run", side_effect=self.completed_reference),
              patch.object(qualifier, "_build", side_effect=interrupted_build)):
            report = qualifier.qualify_cpp_owned(self.root)
        self.assertFalse(report["ok"])
        self.assertTrue(report["backends"]["rust"]["frontend"]["test_only_mock"])
        self.assertEqual(report["backends"]["rust"]["stage"], "source_binding")
        self.assertEqual(len(report["reference"]["commands"]), 3)
        self.assertIn("injected middle-of-build failure", report["diagnostics"][0]["message"])

    def test_reference_timeout_is_kept_in_command_list_before_rejection(self):
        timeout = subprocess.TimeoutExpired(["mock-clang"], 120, output=b"partial object\xff", stderr=b"partial diagnostic\xfe")
        with (patch.object(qualifier, "migrate_cpp_owned", side_effect=self.mocked_migration),
              patch.object(qualifier.shutil, "which", return_value=sys.executable),
              patch.object(qualifier.subprocess, "run", side_effect=timeout)):
            report = qualifier.qualify_cpp_owned(self.root)
        self.assertFalse(report["ok"])
        self.assertEqual(len(report["reference"]["commands"]), 1)
        command = report["reference"]["commands"][0]
        self.assertEqual(command["status"], "timeout")
        self.assert_raw(command, "stdout", b"partial object\xff")
        self.assert_raw(command, "stderr", b"partial diagnostic\xfe")
        self.assertNotIn("artifact", report["reference"])


if __name__ == "__main__":
    unittest.main()
