# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Adversarial reconciliation checks using retained original native receipts."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("reconcile", ROOT / "tools/hia_original_reconcile.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
EVIDENCE = ROOT / "tests/fixtures/hia-original-reconciliation"


class OriginalReconcileTests(unittest.TestCase):
    def inputs(self):
        return [json.loads((EVIDENCE / name).read_bytes()) for name in (
            "cutover-binding.json", "original-cutover-status.json", "original-cutover-output.json")]

    def test_original_failed_cutover_is_known_but_not_success_or_complete_rollback(self):
        report = m.reconcile(*self.inputs())
        self.assertTrue(report["terminal_reconciled"])
        self.assertEqual(report["state"], "failed")
        self.assertTrue(report["rollback_files_restored"])
        self.assertFalse(report["rollback_complete"])
        self.assertFalse(report["automatic_retry_authorized"])
        self.assertFalse(report["later_live_state_establishes_original_success"])

    def test_job_and_nonce_substitution_refused(self):
        for key in ("job_id", "launch_nonce"):
            with self.subTest(key=key):
                binding, status, output = self.inputs()
                status[key] = "0" * 32
                with self.assertRaises(m.ReconciliationError):
                    m.reconcile(binding, status, output)

    def test_missing_durable_publication_never_reconciles(self):
        for key in ("output_complete", "output_durable", "terminal_publication_confirmed"):
            with self.subTest(key=key):
                binding, status, output = self.inputs()
                status[key] = False
                with self.assertRaises(m.ReconciliationError):
                    m.reconcile(binding, status, output)

    def test_contradictory_terminal_flags_refused(self):
        binding, status, output = self.inputs()
        status["cancelled"] = True
        with self.assertRaises(m.ReconciliationError):
            m.reconcile(binding, status, output)

    def test_output_nonce_and_numeric_types_cannot_contradict_terminal(self):
        binding, status, output = self.inputs()
        output["launch_nonce"] = "f" * 32
        with self.assertRaises(m.ReconciliationError):
            m.reconcile(binding, status, output)
        for value in (0.0, False):
            binding, status, output = self.inputs()
            status["log_bytes"]["stderr"]["seen"] = value
            with self.assertRaises(m.ReconciliationError):
                m.reconcile(binding, status, output)

    def test_explicit_non_authoritative_terminal_cannot_be_reconciled(self):
        for value in (False, None, 0, 1, "true"):
            with self.subTest(value=value):
                binding, status, output = self.inputs()
                status["status_authoritative"] = value
                with self.assertRaises(m.ReconciliationError):
                    m.reconcile(binding, status, output)
        binding, status, output = self.inputs()
        status["status_authoritative"] = True
        self.assertTrue(m.reconcile(binding, status, output)["terminal_reconciled"])

    def test_matching_output_nonce_and_mcp_envelopes_preserve_the_original(self):
        binding, status, output = self.inputs()
        output["launch_nonce"] = binding["launch_nonce"]
        direct = m.reconcile(binding, status, output)
        text_envelope = {"content": [{"type": "text", "text": json.dumps(status)}]}
        structured_envelope = {"content": [], "structuredContent": output}
        wrapped = m.reconcile(binding, text_envelope, structured_envelope)
        for field in ("original", "state", "exit_code", "output", "rollback_complete"):
            self.assertEqual(wrapped[field], direct[field])
        self.assertNotEqual(wrapped["input_sha256"], direct["input_sha256"])

    def test_counts_require_exact_integers_and_exact_seen_stored_fields(self):
        for stream in ("stdout", "stderr"):
            for field in ("seen", "stored", "extra"):
                with self.subTest(stream=stream, field=field):
                    binding, status, output = self.inputs()
                    counts = status["log_bytes"][stream]
                    counts[field] = 0 if field == "extra" else float(counts[field])
                    with self.assertRaises(m.ReconciliationError):
                        m.reconcile(binding, status, output)

    def test_cancelled_worker_keeps_partial_binary_output_without_domain_success(self):
        binding, status, output = self.inputs()
        binding["kind"] = "hia_worker"
        status.update(state="cancelled", exit_code=143, cancelled=True, timed_out=False)
        streams = {"stdout": b'partial worker output:\n{"incomplete":', "stderr": b"cancelled\xff\n"}
        for name, raw in streams.items():
            output[name] = {"offset": 0, "next_offset": len(raw), "size": len(raw), "eof": True,
                            "bytes_hex": raw.hex(), "text": raw.decode("utf-8", "replace")}
            status["log_bytes"][name] = {"seen": len(raw), "stored": len(raw)}
        report = m.reconcile(binding, status, output)
        self.assertTrue(report["terminal_reconciled"])
        self.assertEqual(report["state"], "cancelled")
        self.assertNotIn("domain_status", report)
        self.assertNotIn("request_sha256", report)
        self.assertFalse(report["automatic_retry_authorized"])
        for name, raw in streams.items():
            self.assertEqual(report["output"][name], {"bytes": len(raw), "sha256": m.sha(raw)})

    def test_output_truncation_and_cursor_tampering_refused(self):
        for change in ("eof", "next_offset", "text", "bytes_hex"):
            with self.subTest(change=change):
                binding, status, output = self.inputs()
                output["stdout"][change] = {"eof": False, "next_offset": 1,
                    "text": "", "bytes_hex": "00"}[change]
                with self.assertRaises(m.ReconciliationError):
                    m.reconcile(binding, status, output)

    def test_changed_result_file_is_refused(self):
        binding, status, output = self.inputs()
        result = json.loads(output["stdout"]["text"])
        result["rollback"]["complete"] = True
        with self.assertRaises(m.ReconciliationError):
            m.reconcile(binding, status, output, result)

    def test_unchanged_is_a_completed_domain_outcome(self):
        values = [json.loads((EVIDENCE / name).read_bytes()) for name in (
            "evaluate-binding.json", "original-evaluate-status.json", "original-evaluate-output.json")]
        report = m.reconcile(*values)
        self.assertEqual(report["domain_outcome"], "unchanged")
        self.assertFalse(report["domain_result"]["adopted"])
        self.assertFalse(report["no_duplicate_operation_proved"])
        self.assertFalse(report["economic_costs_complete"])
        self.assertEqual(report["request_sha256"],
            "c752a30e7565b3bf10bd210354088605d2c529923e2802dd646ac72ce89c2a0c")
        self.assertEqual(report["profile_sha256"],
            "9aa23fc9d98a7ebf8db12cb8825d5d9ef5cba0233f4f71fa19a1d8c51907239b")

    def active(self):
        return {"audit_recorded": True, "backend": "systemd", "job_id": "original", "state": "running",
            "systemd": {"LoadState": "loaded", "ActiveState": "active", "SubState": "running",
                "ExecMainPID": "123", "InvocationID": "a" * 32,
                "Description": "Hepta Runtime job original " + "b" * 32}}

    def test_c81_verified_systemd_projection_binds_nonce_and_incarnation(self):
        identity = m.active_identity(self.active(), "original")
        self.assertEqual(identity["launch_nonce"], "b" * 32)
        self.assertEqual(identity["invocation_id"], "a" * 32)

    def test_explicit_live_authority_must_be_the_boolean_true(self):
        for value in (False, None, 0, 1, "true"):
            with self.subTest(value=value):
                state = self.active()
                state["status_authoritative"] = value
                with self.assertRaises(m.ReconciliationError):
                    m.active_identity(state, "original")
        state = self.active()
        state["status_authoritative"] = True
        self.assertEqual(m.active_identity(state, "original"), m.active_identity(self.active(), "original"))

    def test_owner_unknown_and_contradictory_nonce_are_refused(self):
        for change in ("state", "nonce", "description", "invocation", "audit", "status_authoritative"):
            with self.subTest(change=change):
                state = self.active()
                if change == "state": state["state"] = "owner_unknown"
                elif change == "nonce": state["launch_nonce"] = "c" * 32
                elif change == "description": state["systemd"]["Description"] += " extra"
                elif change == "invocation": state["systemd"]["InvocationID"] = ""
                elif change == "status_authoritative": state["status_authoritative"] = False
                else: state["audit_recorded"] = False
                with self.assertRaises(m.ReconciliationError):
                    m.active_identity(state, "original")


if __name__ == "__main__":
    unittest.main()
