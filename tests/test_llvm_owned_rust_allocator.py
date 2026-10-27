"""Actual untimed Rust allocator observations and hostile receipt controls."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools import qualify_llvm_owned_rust_allocator as q


class AllocatorEvidenceFailureTests(unittest.TestCase):
    def test_observer_is_appended_without_rewriting_either_application(self):
        for backend, source in (("rust", "// generated prefix\n"),
                                ("handwritten_rust", q.frozen.RUST_REFERENCE)):
            for mode in q.MODES:
                with self.subTest(backend=backend, mode=mode):
                    instrumented = q.render(source, backend, mode)
                    self.assertEqual(instrumented[:len(source)], source)
                    self.assertIn("const HEPTA_OBSERVER_LEAK: bool = " + str(mode == "leak").lower(), instrumented)
        with patch.object(q.frozen, "SOURCE", q.frozen.SOURCE + "\n// stale import"):
            with self.assertRaisesRegex(ValueError, "changed after module import"):
                q.current_sources()

    def test_timeout_retains_exact_partial_stream_bytes(self):
        with tempfile.TemporaryDirectory(prefix="hepta-rust-observer-timeout-") as directory:
            executable = Path(directory) / "observer"
            executable.write_bytes(b"not executed: timeout unit control")
            row = {}
            error = subprocess.TimeoutExpired([str(executable)], 10, output=b"partial\xffstdout", stderr=b"partial\xfestderr")
            with patch.object(q.subprocess, "run", side_effect=error):
                with self.assertRaises(subprocess.TimeoutExpired):
                    q._execute(row, executable)
            self.assertEqual(row["execution"]["status"], "timeout")
            self.assertIsNone(row["execution"]["returncode"])
            for name, data in (("stdout", error.stdout), ("stderr", error.stderr)):
                stream = row["execution"][name]
                self.assertEqual(base64.b64decode(stream["base64"]), data)
                self.assertEqual(q.resolve(stream["file"]["path"]).read_bytes(), data)
                self.assertEqual(stream["file"]["sha256"], hashlib.sha256(data).hexdigest())

    def test_middle_timeout_keeps_completed_rows_and_attempts_rest_of_denominator(self):
        # Only a failing report is synthesized. No synthetic native execution
        # can qualify as a successful report or performance observation.
        fake_frontend = SimpleNamespace(
            report={"ok": True, "checks": {"rust_borrows_types": "rustc_checked"}},
            rust="// synthetic application for failure-retention unit test\n")

        def compile_stub(source, *, rustc, crate_type, output):
            Path(output).write_bytes(b"never executed: process mocked")
            return {"ok": True}

        def execute_stub(argv, **options):
            backend, mode = Path(argv[0]).name.split(".")
            if backend == "rust" and mode == "leak":
                raise subprocess.TimeoutExpired(argv, 10, output=b"partial\xff", stderr=b"timeout\xfe")
            data = b"".join(json.dumps(row).encode() + b"\n" for row in q.expected_observations(backend, mode))
            return subprocess.CompletedProcess(argv, 86 if mode == "leak" else 0, data, b"")

        with tempfile.TemporaryDirectory(prefix="hepta-rust-observer-failure-") as directory:
            output = Path(directory) / "failed.json"
            with (patch.object(q, "analyze", return_value=fake_frontend),
                  patch.object(q, "compile_rust", side_effect=compile_stub) as compiler,
                  patch.object(q.subprocess, "run", side_effect=execute_stub) as execution):
                report = q.qualify(output)
            self.assertFalse(report["ok"])
            self.assertEqual(report["status"], "failed")
            self.assertEqual((compiler.call_count, execution.call_count), (4, 4))
            self.assertEqual([row["status"] for row in report["rows"]],
                             ["completed", "failed", "completed", "completed"])
            self.assertEqual(report["rows"][1]["execution"]["status"], "timeout")
            self.assertIn("TimeoutExpired", report["rows"][1]["validation_error"])
            self.assertEqual(json.loads(output.read_text()), report)
            self.assertTrue(all(value is False for value in report["claims"].values()))
            with self.assertRaisesRegex(ValueError, "Not a passing"):
                q.validate_report(report)

    def test_compile_failure_retains_four_fixed_rows(self):
        fake_frontend = SimpleNamespace(
            report={"ok": True, "checks": {"rust_borrows_types": "rustc_checked"}}, rust="// failure unit input\n")
        with tempfile.TemporaryDirectory(prefix="hepta-rust-observer-build-failure-") as directory:
            output = Path(directory) / "failed.json"
            with (patch.object(q, "analyze", return_value=fake_frontend),
                  patch.object(q, "compile_rust", return_value={"ok": False, "diagnostics": [{"code": "fixture"}]}) as compiler):
                report = q.qualify(output)
            self.assertFalse(report["ok"])
            self.assertEqual(compiler.call_count, 4)
            self.assertEqual(len(report["rows"]), 4)
            self.assertTrue(all(row["status"] == "failed" and row["build"]["diagnostics"]
                                and row["execution"] is None for row in report["rows"]))


class AllocatorNativeTests(unittest.TestCase):
    def test_actual_both_baselines_refusal_recovery_and_compiled_leak_controls(self):
        with tempfile.TemporaryDirectory(prefix="hepta-rust-observer-native-") as directory:
            output = Path(directory) / "actual.json"
            report = q.qualify(output, rustc=os.environ.get("RUSTC"))
            self.assertTrue(report["ok"], json.dumps(report, indent=2))
            with (patch.object(q, "compile_rust", side_effect=AssertionError("validator must not compile")),
                  patch.object(q.subprocess, "run", side_effect=AssertionError("validator must not execute"))):
                self.assertTrue(q.validate_report(report))
            # Mutating the API's returned object must not change the verifier's
            # fixed protocol through shared mutable dictionary/list aliases.
            try:
                report["protocol"]["native_process_denominator"] = True
                with self.assertRaisesRegex(ValueError, "qualification scope differs"):
                    q.validate_report(report)
                self.assertEqual(type(q.PROTOCOL["native_process_denominator"]), int)
                self.assertEqual(q.PROTOCOL["native_process_denominator"], 4)
            finally:
                report["protocol"]["native_process_denominator"] = 4
            for row in report["rows"]:
                self.assertEqual(row["observations"], q.expected_observations(row["backend"], row["mode"]))
                baseline = q.resolve(report["baseline_sources"][row["backend"]]["path"]).read_bytes()
                emitted = q.resolve(row["instrumented_source"]["path"]).read_bytes()
                self.assertEqual(emitted[:len(baseline)], baseline)
                if row["mode"] == "normal":
                    self.assertEqual([x["allocations"] for x in row["observations"]], [7, 9, 0, 2])
                    self.assertTrue(all(x["live"] == 0 for x in row["observations"]))
                else:
                    self.assertEqual(row["execution"]["returncode"], 86)
                    self.assertEqual((row["observations"][0]["frees"], row["observations"][0]["live"]), (0, 7))

            mutations = {
                "drop_run": lambda r: r["rows"].pop(),
                "duplicate_backend": lambda r: r["rows"][2].update(backend="rust"),
                "performance_claim": lambda r: r["claims"].update(performance_measured=True),
                "extra_claim": lambda r: r["claims"].update(universal=True),
                "boolean_denominator": lambda r: r["protocol"].update(native_process_denominator=True),
                "no_actual_execution": lambda r: r["rows"][0]["execution"].update(status="not_started"),
                "boolean_returncode": lambda r: r["rows"][0]["execution"].update(returncode=False),
                "other_command": lambda r: r["rows"][0]["execution"].update(argv=["/bin/true"]),
                "wrong_executable": lambda r: r["rows"][0]["execution"].update(executable_sha256="0" * 64),
                "wrong_source": lambda r: r["rows"][0]["build"].update(rust_sha256="0" * 64),
                "wrong_flags": lambda r: r["rows"][0]["build"]["flags"].remove("overflow-checks=yes"),
                "wrong_tool": lambda r: r["rows"][0]["build"]["toolchain"].update(version="rustc 0.0.0"),
                "boolean_artifact_size": lambda r: r["rows"][0]["build"].update(artifact_bytes=True),
                "wrong_performance_protocol": lambda r: r.update(performance_protocol_sha256="0" * 64),
                "no_first_refusal": lambda r: r["rows"][0]["observations"].pop(2),
                "ignore_negative_exit": lambda r: r["rows"][1]["execution"].update(returncode=0),
                "extra_top_field": lambda r: r.update(unchecked=True),
            }
            for name, mutate in mutations.items():
                changed = copy.deepcopy(report)
                mutate(changed)
                with self.subTest(mutation=name), self.assertRaises(ValueError):
                    q.validate_report(changed)

            # Rehash the actual stream too: strict expected observations still
            # reject True standing in for the single real refusal.
            changed = copy.deepcopy(report)
            row = changed["rows"][0]
            row["observations"][0]["refusals"] = True
            data = b"".join(json.dumps(x).encode() + b"\n" for x in row["observations"])
            stdout = q.resolve(row["execution"]["stdout"]["file"]["path"])
            previous = stdout.read_bytes()
            try:
                row["execution"]["stdout"] = q._stream(data, stdout)
                with self.assertRaisesRegex(ValueError, "observations differ"):
                    q.validate_report(changed)
            finally:
                stdout.write_bytes(previous)

            # A consistent new source/file hash cannot replace fresh rendering
            # of the unchanged application plus the exact observer template.
            changed = copy.deepcopy(report)
            row = changed["rows"][0]
            emitted = q.resolve(row["instrumented_source"]["path"])
            previous = emitted.read_bytes()
            try:
                altered = previous.replace(b"HEPTA_OBSERVER_LEAK: bool = false", b"HEPTA_OBSERVER_LEAK: bool = true")
                self.assertNotEqual(previous, altered)
                emitted.write_bytes(altered)
                row["instrumented_source"] = q.identity(emitted)
                row["build"]["rust_sha256"] = q.sha(altered)
                with self.assertRaisesRegex(ValueError, "exact current source/observer composition"):
                    q.validate_report(changed)
            finally:
                emitted.write_bytes(previous)

            binary = q.resolve(report["rows"][0]["artifact"]["path"])
            previous = binary.read_bytes()
            try:
                binary.write_bytes(previous + b"tampered")
                with self.assertRaisesRegex(ValueError, "file identity/path differs"):
                    q.validate_report(report)
            finally:
                binary.write_bytes(previous)
            self.assertTrue(q.validate_report(report))


if __name__ == "__main__":
    unittest.main()
