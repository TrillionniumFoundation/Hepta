"""Patch publication must preserve the exact candidate UTF-8 bytes.

ModelTextWrites uses real files with an explicit Windows text-stream newline
policy and frontend-only validation doubles. NativePatchBytes does not replace
validation or staging and requires the actual pinned Rust compiler.
"""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.backend import sha256
from hepta.modules import load_project
from hepta.parser import parse
from hepta.pipeline import analyze, analyze_project, interface_hash
from hepta.protocol import apply_patch, apply_project_patch

RUSTC = os.environ.get("RUSTC")
HAS_RUST = bool(RUSTC and Path(RUSTC).is_file())
REAL_TEMPFILE = tempfile.NamedTemporaryFile
ENDINGS = ("\n", "\r\n", "\r", "mixed")


def windows_text_default(*args, **kwargs):
    # The real text stream applies Windows' default conversion on every host.
    # Explicit binary mode or an explicit newline policy is respected.
    if "b" not in kwargs.get("mode", "w+b"):
        kwargs.setdefault("newline", "\r\n")
    return REAL_TEMPFILE(*args, **kwargs)


class PatchFixture:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-patch-bytes-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.entry = self.root / "main.hepta"
        self.target = self.root / "dep.hepta"

    def prepare(self, version, ending="\r\n"):
        lines = ["// π 汉字 😀 before", "pub fn value() -> i64 effects {} { return 7; }",
                 "fn sibling() -> i64 effects {} { return 93; }", "// after π"]
        endings = ("\r\n", "\n", "\r", "") if ending == "mixed" else (ending,) * 4
        text = "".join(line + end for line, end in zip(lines, endings))
        if version == 1:
            self.target = self.entry
        else:
            self.target = self.root / "dep.hepta"
            self.entry.write_bytes(b"import dep; fn main() -> i32 effects {} { return 0; }\r\n")
        self.target.write_bytes(text.encode("utf-8"))
        body = "{\n    /* replacement π */\r\n    return 8;\n}"
        request = self.request(version, body)
        return text.encode("utf-8"), text.replace("{ return 7; }", body, 1).encode("utf-8"), request

    def request(self, version, body):
        text = self.target.read_bytes().decode("utf-8")
        request = {"schema": "hepta.patch.v" + str(version),
                   "expected_source_sha256": sha256(self.target.read_bytes()),
                   "symbol": "value", "replacement_body": body}
        if version == 1:
            request["expected_interface_sha256"] = interface_hash(parse(text))
        else:
            project = load_project(self.entry)
            request.update(expected_project_sha256=project.identity, target="dep.hepta",
                           expected_interface_sha256=interface_hash(project.program))
        return request

    def invoke(self, version, request, *, apply=True):
        function = apply_patch if version == 1 else apply_project_patch
        return function(self.entry, request, apply=apply, rustc=RUSTC)

    def assert_clean(self):
        self.assertEqual(list(self.root.glob("*.hepta-lock")), [])
        self.assertEqual(list(self.root.glob(".hepta-patch-*")), [])

    def assert_committed(self, version, report, expected):
        self.assertTrue(report["ok"], report)
        self.assertTrue(report["applied"], report)
        self.assertEqual(report["status"], "applied")
        self.assertEqual(self.target.read_bytes(), expected)
        self.assertEqual(report["after_sha256"], sha256(expected))
        if version == 1:
            self.assertEqual(report["validation"]["source_sha256"], sha256(expected))
        else:
            self.assertEqual(report["project_candidate_sha256"], load_project(self.entry).identity)
            # Windows temp paths may use 8.3 aliases; project keys are resolved.
            canonical_target = str(self.target.resolve())
            self.assertEqual(report["target"], canonical_target)
            self.assertEqual(report["validation"]["project"]["sources"][canonical_target], sha256(expected))
        self.assert_clean()


class ModelTextWrites(PatchFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        stack = self.enterContext(ExitStack())
        stack.enter_context(patch("hepta.protocol.tempfile.NamedTemporaryFile", side_effect=windows_text_default))
        stack.enter_context(patch("hepta.protocol.analyze", side_effect=lambda *a, **kw: analyze(*a, **kw, native=False)))
        stack.enter_context(patch("hepta.pipeline.analyze_project", side_effect=lambda *a, **kw: analyze_project(*a, **kw, native=False)))

    def matrix(self, version):
        for ending in ENDINGS:
            with self.subTest(ending=ending):
                _, expected, request = self.prepare(version, ending)
                untouched = self.entry.read_bytes() if version == 2 else None
                report = self.invoke(version, request)
                self.assertEqual(report["validation"]["status"], "frontend_only")
                self.assert_committed(version, report, expected)
                if version == 2:
                    self.assertEqual(self.entry.read_bytes(), untouched)

    def test_v1_windows_text_model_preserves_candidate_bytes(self):
        self.matrix(1)

    def test_v2_windows_text_model_preserves_candidate_bytes(self):
        self.matrix(2)

    def dry_run(self, version):
        before, expected, request = self.prepare(version)
        with patch("hepta.protocol.tempfile.NamedTemporaryFile", side_effect=AssertionError("dry run wrote staging")):
            result = self.invoke(version, request, apply=False)
        self.assertTrue(result["ok"], result)
        self.assertFalse(result["applied"])
        self.assertEqual(result["after_sha256"], sha256(expected))
        self.assertEqual(self.target.read_bytes(), before)
        self.assert_clean()

    def test_v1_dry_run_does_not_stage(self):
        self.dry_run(1)

    def test_v2_dry_run_does_not_stage(self):
        self.dry_run(2)

    def stale(self, version):
        before, _, request = self.prepare(version)
        request["expected_source_sha256"] = "0" * 64
        result = self.invoke(version, request)
        self.assertFalse(result["ok"], result)
        self.assertEqual(result["diagnostics"][0]["code"], "E_STALE_SOURCE")
        self.assertEqual(self.target.read_bytes(), before)
        self.assert_clean()

    def test_v1_stale_source_never_writes(self):
        self.stale(1)

    def test_v2_stale_source_never_writes(self):
        self.stale(2)

    def invalid(self, version):
        before, _, request = self.prepare(version)
        request["replacement_body"] = "{ return true; }"
        result = self.invoke(version, request)
        self.assertFalse(result["ok"], result)
        self.assertFalse(result["applied"])
        self.assertEqual(self.target.read_bytes(), before)
        self.assert_clean()

    def test_v1_invalid_candidate_never_writes(self):
        self.invalid(1)

    def test_v2_invalid_candidate_never_writes(self):
        self.invalid(2)

    def failed_replace(self, version):
        before, _, request = self.prepare(version)
        with patch("hepta.protocol.os.replace", side_effect=OSError("controlled replace failure")):
            if version == 1:
                with self.assertRaises(OSError):
                    self.invoke(version, request)
            else:
                result = self.invoke(version, request)
                self.assertFalse(result["ok"], result)
                self.assertEqual(result["diagnostics"][0]["code"], "E_PATCH_PROJECT")
        self.assertEqual(self.target.read_bytes(), before)
        self.assert_clean()

    def test_v1_failed_replace_keeps_original_and_cleans_staging(self):
        self.failed_replace(1)

    def test_v2_failed_replace_keeps_original_and_cleans_staging(self):
        self.failed_replace(2)


@unittest.skipUnless(HAS_RUST, "Real pinned RUSTC required; modeled writes are separate tests")
class NativePatchBytes(PatchFixture, unittest.TestCase):
    def native_matrix(self, version):
        for ending in ENDINGS:
            with self.subTest(ending=ending):
                before, expected, request = self.prepare(version, ending)
                untouched = self.entry.read_bytes() if version == 2 else None
                mode = self.target.stat().st_mode
                preview = self.invoke(version, request, apply=False)
                self.assertTrue(preview["ok"], preview)
                self.assertEqual(self.target.read_bytes(), before)
                report = self.invoke(version, request)
                self.assertEqual(report["validation"]["checks"]["rust_borrows_types"], "rustc_checked")
                self.assertEqual(preview["after_sha256"], report["after_sha256"])
                self.assert_committed(version, report, expected)
                self.assertEqual(self.target.stat().st_mode, mode)
                if version == 2:
                    self.assertEqual(self.entry.read_bytes(), untouched)

    def test_v1_real_native_validation_and_exact_host_write(self):
        self.native_matrix(1)

    def test_v2_real_native_validation_and_exact_host_write(self):
        self.native_matrix(2)

    def cli(self, version):
        _, expected, request = self.prepare(version)
        request_file = self.root / "request.json"
        request_file.write_bytes(json.dumps(request).encode("utf-8"))
        process = subprocess.run([sys.executable, "-B", "-m", "hepta", "patch", str(self.entry),
                                  "--request", str(request_file), "--apply", "--rustc", RUSTC],
                                 capture_output=True, text=True, timeout=120)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        report = json.loads(process.stdout)
        self.assertEqual(report["validation"]["checks"]["rust_borrows_types"], "rustc_checked")
        self.assert_committed(version, report, expected)

    def test_v1_real_native_public_cli_bytes(self):
        self.cli(1)

    def test_v2_real_native_public_cli_bytes(self):
        self.cli(2)

    def repeated(self, version):
        _, expected, first = self.prepare(version)
        self.assert_committed(version, self.invoke(version, first), expected)
        second = self.request(version, "{\r\nreturn 9;\r\n}")
        parsed = parse(expected.decode("utf-8"))
        span = next(fn.body_span for fn in parsed.functions if fn.name == "value")
        text = expected.decode("utf-8")
        updated = (text[:span.start] + second["replacement_body"] + text[span.end:]).encode("utf-8")
        self.assert_committed(version, self.invoke(version, second), updated)
        stale = self.invoke(version, first)
        self.assertFalse(stale["ok"])
        self.assertEqual(self.target.read_bytes(), updated)

    def test_v1_native_successive_receipts_are_reusable(self):
        self.repeated(1)

    def test_v2_native_successive_receipts_are_reusable(self):
        self.repeated(2)

    def native_refusal(self, version):
        self.prepare(version)
        self.target.write_bytes(("fn pair(a: mut [u8], b: mut [u8]) -> Unit effects {panic,write} "
                                 "{ a[0]=1; b[0]=2; }\r\n"
                                 "pub fn value() -> Unit effects {panic,write} {}\r\n").encode())
        before = self.target.read_bytes()
        request = self.request(version, "{ let mut x: [u8; 2] = [0,0]; pair(mut x, mut x); }")
        result = self.invoke(version, request)
        self.assertFalse(result["ok"], result)
        self.assertFalse(result["applied"])
        self.assertEqual(result["validation"]["checks"]["rust_borrows_types"], "rejected")
        self.assertIn("E0499", {d["code"] for d in result["diagnostics"]})
        self.assertEqual(self.target.read_bytes(), before)
        self.assert_clean()

    def test_v1_native_borrow_rejection_still_blocks_write(self):
        self.native_refusal(1)

    def test_v2_native_borrow_rejection_still_blocks_write(self):
        self.native_refusal(2)


if __name__ == "__main__":
    unittest.main()
