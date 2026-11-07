#!/usr/bin/env python3
"""Exact regression tests for profile-only evidence scope and safe publication."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


matrix = load("profile_publication_matrix", HERE / "run_matrix.py")
build = load("profile_publication_build", HERE / "build.py")
guard = load("profile_publication_guard", HERE / "publication_guard.py")
verifier = load("profile_publication_verifier", HERE / "verify_profile_result.py")
summary_path = HERE / "perf_sample_summary.py"
summary = load("profile_publication_samples", summary_path) if summary_path.is_file() else None


class ProfileClaimLimitTests(unittest.TestCase):
    def test_profile_only_claim_limit_is_explicit(self):
        helper = getattr(matrix, "profile_claim_limit", None)
        self.assertTrue(callable(helper), "run_matrix.py must expose the frozen claim-limit builder")
        claim = helper(True)
        self.assertIn("profile-only", claim)
        self.assertIn("not full target", claim)
        self.assertIn("not production", claim)
        self.assertIn("not performance qualification", claim)
        self.assertNotIn("216-workload qualification", claim)

    def test_full_matrix_claim_limit_does_not_claim_profile_only(self):
        helper = getattr(matrix, "profile_claim_limit", None)
        self.assertTrue(callable(helper), "run_matrix.py must expose the frozen claim-limit builder")
        self.assertNotIn("profile-only", helper(False))


class BuildReceiptPrivacyTests(unittest.TestCase):
    def test_build_receipt_redacts_pem_static_key_and_github_token(self):
        sanitizer = getattr(build, "sanitize_public_build_receipt", None)
        self.assertTrue(callable(sanitizer), "build.py must sanitize public receipt strings before writing")
        pem = "-----BEGIN PRIVATE KEY-----\nFAKE_PRIVATE_MATERIAL\n-----END PRIVATE KEY-----"
        static = "-----BEGIN OpenVPN Static key V1-----\nFAKE_STATIC_MATERIAL\n-----END OpenVPN Static key V1-----"
        token = "github_pat_" + "a" * 32
        aws = "aws_secret_access_key=" + "b" * 32
        original = {
            "ok": True,
            "commands": [{"argv": ["tool", pem, static, token, aws]}],
            "runner": {"GITHUB_SHA": "0123456789abcdef0123456789abcdef01234567"},
        }
        safe = sanitizer(original)
        encoded = json.dumps(safe, sort_keys=True)
        self.assertNotIn("BEGIN PRIVATE KEY", encoded)
        self.assertNotIn("BEGIN OpenVPN Static key", encoded)
        self.assertNotIn(token, encoded)
        self.assertNotIn("FAKE_PRIVATE_MATERIAL", encoded)
        self.assertNotIn("FAKE_STATIC_MATERIAL", encoded)
        self.assertNotIn(aws, encoded)
        self.assertEqual(safe["ok"], True)
        receipt = safe.get("public_redactions", {})
        self.assertEqual(receipt.get("schema"), "hepta.openvpn-hia.public-redactions.v1")
        self.assertEqual(receipt.get("count"), 4)
        self.assertEqual(len(receipt.get("entries", [])), 4)
        self.assertTrue(all(re.fullmatch(r"[0-9a-f]{64}", item.get("sha256", "")) for item in receipt["entries"]))

    def test_sanitized_build_receipt_passes_the_same_publication_guard(self):
        sanitizer = getattr(build, "sanitize_public_build_receipt", None)
        self.assertTrue(callable(sanitizer), "build.py must sanitize public receipt strings before writing")
        secret = "-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----"
        safe = sanitizer({"ok": False, "failure": secret})
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "build.json").write_text(json.dumps(safe, sort_keys=True) + "\n")
            result = guard.inspect(root)
        self.assertTrue(result["safe_to_upload"])
        self.assertEqual(result["files_scanned"], 1)


class PerfSampleSummaryTests(unittest.TestCase):
    def test_perf_samples_are_stream_summarized_without_publishing_raw_stacks(self):
        self.assertIsNotNone(summary, "perf_sample_summary.py must exist")
        raw = (
            b"openvpn 123/123 [001] 1.000: cpu-clock: 0x111\n"
            b"openvpn 456/456 [001] 1.001: cpu-clock: 0x222\n"
            b"0x111 ovpn_peer_get [ovpn]\n"
            b"0x222 private_stack_frame [kernel.kallsyms]\n"
        )
        result = summary.summarize_perf_script_bytes(raw, client_pid=123, server_pid=456)
        self.assertEqual(result["schema"], "hepta.openvpn-hia.perf-sample-summary.v1")
        self.assertEqual(result["sample_headers"], 2)
        self.assertEqual(result["openvpn_sample_headers_by_role"], {"client": 1, "server": 1})
        self.assertEqual(result["kernel_symbol_lines"], 2)
        self.assertEqual(result["ovpn_symbol_lines"], 1)
        self.assertEqual(result["raw_stdout_bytes"], len(raw))
        self.assertEqual(result["raw_stdout_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertFalse(result["raw_sample_content_published"])
        self.assertNotIn("private_stack_frame", json.dumps(result))
        self.assertLess(len(json.dumps(result).encode()), 64 * 1024 * 1024)


    def test_profile_verifier_binds_bounded_sample_summary_to_profile_counters(self):
        digest = "a" * 64
        summary = {
            "schema": "hepta.openvpn-hia.perf-sample-summary.v1",
            "raw_stdout_sha256": digest,
            "raw_stdout_bytes": 1234,
            "sample_headers": 2,
            "openvpn_sample_headers_by_role": {"client": 1, "server": 1},
            "kernel_symbol_lines": 2,
            "ovpn_symbol_lines": 1,
            "raw_sample_content_published": False,
            "perf_exit_code": 0,
            "perf_timed_out": False,
            "raw_stderr_sha256": "b" * 64,
            "raw_stderr_bytes": 0,
        }
        profile = {
            "raw_samples_sha256": digest,
            "raw_samples_bytes": 1234,
            "actual_sample_headers": 2,
            "openvpn_sample_headers_by_role": {"client": 1, "server": 1},
            "kernel_symbol_lines": 2,
            "ovpn_symbol_lines": 1,
            "raw_sample_content_published": False,
        }
        verifier.verify_sample_summary(summary, profile)
        with self.assertRaisesRegex(ValueError, "disagrees with the profile receipt"):
            verifier.verify_sample_summary({**summary, "sample_headers": 3}, profile)
        with self.assertRaisesRegex(ValueError, "must remain private"):
            verifier.verify_sample_summary({**summary, "raw_sample_content_published": True}, profile)


if __name__ == "__main__":
    unittest.main(verbosity=2)
