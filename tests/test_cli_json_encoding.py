"""JSON transport controls. No native compiler or Hepta program is executed."""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from hepta.cli import output_json
from hepta.packages import load_package, verify_lock


ROOT = Path(__file__).resolve().parents[1]
ENCODINGS = ("ascii", "cp1252", "utf-8")


class CliJsonEncodingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="hepta-json-encoding-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def package(self, name="package-包裹-🌱", *, valid=True):
        root = self.root / name
        (root / "src").mkdir(parents=True)
        version = "0.1.0" if valid else "invalid"
        (root / "hepta.toml").write_text(
            f'[package]\nname = "demo"\nversion = "{version}"\n', encoding="utf-8"
        )
        (root / "src" / "main.hepta").write_text("module demo;\n", encoding="utf-8")
        return root

    def run_cli(self, encoding, *arguments, status=0):
        env = {**os.environ, "PYTHONIOENCODING": encoding + ":strict",
               "PYTHONDONTWRITEBYTECODE": "1"}
        proc = subprocess.run(
            [sys.executable, "-B", "-m", "hepta", *map(str, arguments)],
            cwd=ROOT, env=env, capture_output=True, timeout=20,
        )
        self.assertEqual(proc.returncode, status, repr((proc.stdout, proc.stderr)))
        self.assertEqual(proc.stderr, b"")
        return json.loads(proc.stdout.decode(encoding))

    def render(self, value, encoding):
        buffer = io.BytesIO()
        stream = io.TextIOWrapper(buffer, encoding=encoding, errors="strict", newline="\n")
        with contextlib.redirect_stdout(stream):
            output_json(value)
        stream.flush()
        result = buffer.getvalue()
        stream.close()
        return result

    def test_nested_unicode_round_trips_through_strict_streams(self):
        value = {"包裹": ["café", "🌱", "e\u0301", "العربية", "\n\t\"\\"],
                 "ok": True, "nothing": None, "count": 17}
        for encoding in ENCODINGS:
            with self.subTest(encoding=encoding):
                raw = self.render(value, encoding)
                self.assertTrue(raw.isascii())
                self.assertEqual(json.loads(raw), value)

    def test_surrogate_strings_round_trip_without_encoding_failure(self):
        # Python can carry lone surrogates in filesystem paths. JSON escapes
        # retain them without asking an output codec to encode them directly.
        value = {"path": "file-\udcff.hepta"}
        for encoding in ENCODINGS:
            with self.subTest(encoding=encoding):
                self.assertEqual(json.loads(self.render(value, encoding)), value)

    def test_ascii_report_format_is_unchanged(self):
        value = {"z": [1, False], "a": "quote:\" newline:\n backslash:\\"}
        expected = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("ascii")
        for encoding in ENCODINGS:
            with self.subTest(encoding=encoding):
                self.assertEqual(self.render(value, encoding), expected)

    def test_lock_success_reports_unicode_path_and_actual_snapshot(self):
        root = self.package()
        original_inputs = {p.relative_to(root): p.read_bytes()
                           for p in root.rglob("*") if p.is_file()}
        first_bytes = None
        for encoding in ENCODINGS:
            with self.subTest(encoding=encoding):
                report = self.run_cli(encoding, "lock", root)
                self.assertEqual(report["schema"], "hepta.package-lock.v1")
                self.assertTrue(report["ok"])
                self.assertEqual(report["path"], str(root / "Hepta.lock"))
                self.assertEqual(report["snapshot"], verify_lock(load_package(root)))
                written = (root / "Hepta.lock").read_bytes()
                self.assertEqual(json.loads(written), report["snapshot"])
                if first_bytes is not None:
                    self.assertEqual(written, first_bytes)
                first_bytes = written
                self.assertEqual({p: (root / p).read_bytes() for p in original_inputs}, original_inputs)
                self.assertEqual({p.relative_to(root) for p in root.rglob("*") if p.is_file()},
                                 set(original_inputs) | {Path("Hepta.lock")})

    def test_ascii_lock_path_control(self):
        root = self.package("ascii-package")
        for encoding in ENCODINGS:
            with self.subTest(encoding=encoding):
                report = self.run_cli(encoding, "lock", root)
                self.assertTrue(report["ok"])
                self.assertEqual(report["snapshot"], verify_lock(load_package(root)))

    def test_package_rejections_keep_their_diagnostic_and_exit_status(self):
        root = self.package(valid=False)
        original = {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
        for command in ("lock", "check", "inspect"):
            for encoding in ENCODINGS:
                with self.subTest(command=command, encoding=encoding):
                    flags = [] if command == "lock" else ["--frontend-only"]
                    report = self.run_cli(encoding, command, root, *flags, status=1)
                    self.assertFalse(report["ok"])
                    self.assertEqual(report["status"], "rejected")
                    self.assertEqual(len(report["diagnostics"]), 1)
                    diagnostic = report["diagnostics"][0]
                    self.assertEqual(diagnostic["code"], "E_PACKAGE_VERSION")
                    self.assertEqual(diagnostic["phase"], "package")
                    self.assertEqual(diagnostic["span"]["path"], str(root / "hepta.toml"))
        self.assertEqual({p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}, original)

    def test_missing_manifest_rejection_preserves_unicode_path(self):
        root = self.root / "missing-缺失-🌱"
        for encoding in ENCODINGS:
            with self.subTest(encoding=encoding):
                report = self.run_cli(encoding, "lock", root, status=1)
                self.assertEqual(report["status"], "rejected")
                diagnostic = report["diagnostics"][0]
                self.assertEqual(diagnostic["code"], "E_PACKAGE_MANIFEST")
                self.assertEqual(diagnostic["span"]["path"], str(root / "hepta.toml"))
        self.assertFalse(root.exists())

    def test_driver_error_preserves_unicode_message_and_exit_status(self):
        request = self.root / "missing-request-缺失-🌱.json"
        for encoding in ENCODINGS:
            with self.subTest(encoding=encoding):
                # The missing request fails before parsing or validating any
                # source; this does not exercise patch application or native code.
                report = self.run_cli(encoding, "patch", self.root / "unused.hepta",
                                      "--request", request, status=2)
                self.assertFalse(report["ok"])
                self.assertEqual(report["status"], "error")
                diagnostic = report["diagnostics"][0]
                self.assertEqual(diagnostic["code"], "E_DRIVER")
                self.assertEqual(diagnostic["phase"], "driver")
                self.assertIn(str(request), diagnostic["message"])
        self.assertEqual(list(self.root.iterdir()), [])

    def test_frontend_only_success_preserves_unicode_report_path(self):
        root = self.package()
        for command in ("check", "inspect"):
            for encoding in ENCODINGS:
                with self.subTest(command=command, encoding=encoding):
                    report = self.run_cli(encoding, command, root, "--frontend-only")
                    self.assertTrue(report["ok"])
                    self.assertEqual(report["status"], "frontend_only")
                    self.assertEqual(report["path"], str(root / "src" / "main.hepta"))
                    self.assertEqual(report["diagnostics"], [])

    def test_locked_refusal_keeps_stale_lock_diagnostic(self):
        root = self.package()
        self.run_cli("utf-8", "lock", root)
        lock_bytes = (root / "Hepta.lock").read_bytes()
        (root / "src" / "main.hepta").write_text("module changed;\n", encoding="utf-8")
        for command in ("check", "inspect"):
            for encoding in ENCODINGS:
                with self.subTest(command=command, encoding=encoding):
                    report = self.run_cli(encoding, command, root, "--locked", "--frontend-only", status=1)
                    self.assertEqual(report["status"], "rejected")
                    diagnostic = report["diagnostics"][0]
                    self.assertEqual(diagnostic["code"], "E_LOCK_STALE")
                    self.assertEqual(diagnostic["span"]["path"], str(root / "Hepta.lock"))
        self.assertEqual((root / "Hepta.lock").read_bytes(), lock_bytes)


if __name__ == "__main__":
    unittest.main()
