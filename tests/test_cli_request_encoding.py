"""Patch request transport only; no source parsing or native validation runs."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TEXT = "café / 中文 / 🌱 / e\u0301 / \r\n"

# Capture the CLI-to-protocol boundary, without entering either transaction.
# ASCII output isolates request-file decoding from stdout encoding behavior.
CAPTURE = r'''
import contextlib, io, json, locale, sys
from unittest.mock import patch
from hepta import cli
captured = []
def receive(path, request, **options):
    captured.append(request)
    return {"ok": False, "applied": False}
stream = io.StringIO()
with patch("hepta.cli.apply_patch", side_effect=receive) as v1, \
     patch("hepta.protocol.apply_project_patch", side_effect=receive) as v2, \
     contextlib.redirect_stdout(stream):
    status = cli.main(sys.argv[1:])
print(json.dumps({"status": status, "requests": captured,
                  "v1_calls": v1.call_count, "v2_calls": v2.call_count,
                  "file_encoding": locale.getpreferredencoding(False),
                  "report": json.loads(stream.getvalue())}, ensure_ascii=True))
'''


class CliRequestEncodingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-request-encoding-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source.hepta"
        # Intentionally not parseable. Every real protocol control must reject
        # before parsing this input, let alone invoking a compiler.
        self.source.write_bytes(b"this source must not be parsed\n")
        self.request = self.root / "request.json"

    def write_request(self, value, *, escaped=False, newline="\n"):
        text = json.dumps(value, ensure_ascii=escaped, indent=2)
        self.request.write_bytes(text.replace("\n", newline).encode("utf-8"))

    def invoke(self, *, utf8=False, capture=False):
        env = {**os.environ, "LC_ALL": "C", "LANG": "C",
               "PYTHONCOERCECLOCALE": "0", "PYTHONUTF8": "1" if utf8 else "0",
               "PYTHONIOENCODING": "ascii:strict", "PYTHONDONTWRITEBYTECODE": "1"}
        args = ["patch", str(self.source), "--request", str(self.request)]
        command = [sys.executable, "-B", "-c", CAPTURE, *args] if capture else [sys.executable, "-B", "-m", "hepta", *args]
        proc = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, timeout=20)
        self.assertEqual(proc.stderr, b"", repr(proc.stderr))
        self.assertTrue(proc.stdout.isascii())
        self.assertEqual(self.source.read_bytes(), b"this source must not be parsed\n")
        return proc.returncode, json.loads(proc.stdout)

    def assert_rejected(self, report, code, *, schema=None):
        self.assertFalse(report["ok"])
        self.assertEqual(report["diagnostics"][0]["code"], code, report)
        if schema:
            self.assertEqual(report["schema"], schema)
            self.assertEqual(report["status"], "rejected")
            self.assertFalse(report["applied"])

    def assert_forwarded(self, schema):
        value = {"schema": schema, "replacement_body": "{ /* " + TEXT + " */ }",
                 "target": "目录.hepta", "extra": [TEXT, {"鍵": TEXT}]}
        for utf8 in (False, True):
            for escaped in (False, True):
                for newline in ("\n", "\r\n"):
                    with self.subTest(utf8=utf8, escaped=escaped, newline=repr(newline)):
                        self.write_request(value, escaped=escaped, newline=newline)
                        status, report = self.invoke(utf8=utf8, capture=True)
                        self.assertEqual(status, 0, report)
                        self.assertEqual(report["status"], 1, report)
                        self.assertEqual(report["requests"], [value], report)
                        self.assertEqual(report["v1_calls"], int(schema == "hepta.patch.v1"))
                        self.assertEqual(report["v2_calls"], int(schema == "hepta.patch.v2"))
                        encoding = report["file_encoding"].lower().replace("-", "_")
                        if not utf8 and os.name == "posix":
                            self.assertIn(encoding, {"ascii", "ansi_x3.4_1968", "us_ascii"})

    def test_v1_forwards_exact_unicode_values(self):
        self.assert_forwarded("hepta.patch.v1")

    def test_v2_forwards_exact_unicode_values(self):
        self.assert_forwarded("hepta.patch.v2")

    def test_v1_unicode_schema_refusal_is_not_a_driver_failure(self):
        self.write_request({"schema": "hepta.patch.v1", "note": TEXT})
        status, report = self.invoke()
        self.assertEqual(status, 1, report)
        self.assert_rejected(report, "E_PATCH_SCHEMA", schema="hepta.patch.v1")

    def test_v2_unicode_schema_refusal_is_not_a_driver_failure(self):
        self.write_request({"schema": "hepta.patch.v2", "note": TEXT})
        status, report = self.invoke()
        self.assertEqual(status, 1, report)
        self.assert_rejected(report, "E_PATCH_SCHEMA", schema="hepta.patch.v2")

    def test_v1_unicode_request_reaches_source_identity_check(self):
        self.write_request({"schema": "hepta.patch.v1", "expected_source_sha256": "0" * 64,
                            "expected_interface_sha256": "0" * 64, "symbol": "answer",
                            "replacement_body": "{ /* " + TEXT + " */ return 0; }"})
        status, report = self.invoke()
        self.assertEqual(status, 1, report)
        self.assert_rejected(report, "E_STALE_SOURCE", schema="hepta.patch.v1")

    def test_ascii_schema_refusals_are_unchanged(self):
        for value in (None, [], "text", 42, True, {}, {"schema": "hepta.patch.v1"}, {"schema": "hepta.patch.v2"}):
            with self.subTest(value=value):
                self.write_request(value)
                status, report = self.invoke()
                self.assertEqual(status, 1, report)
                self.assert_rejected(report, "E_PATCH_SCHEMA")

    def test_invalid_json_retains_driver_diagnostic(self):
        self.request.write_bytes('{"note": "中文",'.encode("utf-8"))
        status, report = self.invoke()
        self.assertEqual(status, 2, report)
        self.assert_rejected(report, "E_DRIVER")
        self.assertIn("Expecting", report["diagnostics"][0]["message"])

    def test_non_utf8_and_bom_inputs_remain_rejected(self):
        for raw in (b'{"note":"caf\xe9"}', b'\xef\xbb\xbf{}', b'\xff\xfe{\x00}\x00'):
            with self.subTest(raw=raw):
                self.request.write_bytes(raw)
                for utf8 in (False, True):
                    status, report = self.invoke(utf8=utf8)
                    self.assertEqual(status, 2, report)
                    self.assert_rejected(report, "E_DRIVER")


if __name__ == "__main__":
    unittest.main()
