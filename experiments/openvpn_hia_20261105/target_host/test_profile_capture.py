#!/usr/bin/env python3
"""Regression for the real target's truncated perf-record finalization.

Artifact #13484017940 recorded 2,178 real samples and 672 samples from the
C-user OpenVPN client, but the recorder was SIGTERM'd after a 3-second
post-traffic wait (exit -15, timed_out=true). The raw profile therefore
failed despite containing partial samples. These tests exercise the bounded
recorder wait only; they do not qualify a target profile or tunnel.
"""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("run_matrix", HERE / "run_matrix.py")
matrix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(matrix)

verify_spec = importlib.util.spec_from_file_location("verify_result", HERE / "verify_result.py")
verify = importlib.util.module_from_spec(verify_spec)
verify_spec.loader.exec_module(verify)


class ProfileRecorderWaitTests(unittest.TestCase):
    def test_grace_includes_recording_shutdown_margin_after_traffic(self):
        self.assertEqual(matrix.profile_record_grace_seconds(10, 15), 15)
        self.assertEqual(matrix.profile_record_grace_seconds(10, 5), 15)
        self.assertEqual(matrix.profile_record_grace_seconds(10, 20), 20)

    def test_grace_rejects_invalid_workload_or_plan_values(self):
        for workload, configured in ((0, 15), (True, 15), (10, True), (10, 4), (10, 121)):
            with self.subTest(workload=workload, configured=configured):
                with self.assertRaises(ValueError):
                    matrix.profile_record_grace_seconds(workload, configured)

    def test_c_and_hia_userspace_profiles_require_client_process_samples(self):
        for arm in ("c-user", "hia-user"):
            with self.subTest(arm=arm):
                self.assertTrue(matrix.profile_process_sample_required(arm))

    def test_dco_profile_is_qualified_by_kernel_samples_not_userspace_pid(self):
        self.assertFalse(matrix.profile_process_sample_required("c-dco"))

    def test_unknown_profile_arm_is_rejected(self):
        with self.assertRaises(ValueError):
            matrix.profile_process_sample_required("unknown")

    def test_hia_profile_symbol_counter_requires_both_non_epoch_packet_id_hotspots(self):
        report = "\n".join([
            "  1.25% openvpn [.] ovpn_hia_packet_id_read",
            "  0.75% openvpn [.] ovpn_hia_packet_id_write",
            "  0.50% openvpn [.] ovpn_hia_packet_id_read_epoch",
            "  9.00% openvpn [.] ovpn_read",
            "  3.00% openvpn [.] hia_packet_id_read",
        ])
        self.assertEqual(matrix.hia_profile_symbol_lines(report), 2)
        self.assertEqual(matrix.hia_profile_symbol_lines(
            "  0.75% openvpn [.] ovpn_hia_packet_id_read_epoch"), 0)
        self.assertEqual(matrix.hia_profile_symbol_lines("  9.00% openvpn [.] ovpn_read"), 0)

    def test_independent_verifier_recomputes_hia_profile_hotspots(self):
        report = "\n".join([
            "  1.25% openvpn [.] ovpn_hia_packet_id_read",
            "  0.75% openvpn [.] ovpn_hia_packet_id_write",
        ])
        verify.verify_hia_profile_hotspot({"hia_profile_symbol_lines": 2}, report, "hia-user")
        with self.assertRaises(ValueError):
            verify.verify_hia_profile_hotspot({"hia_profile_symbol_lines": 1}, report, "hia-user")
        with self.assertRaises(ValueError):
            verify.verify_hia_profile_hotspot(
                {"hia_profile_symbol_lines": 2},
                "  1.25% openvpn [.] ovpn_hia_packet_id_read_epoch",
                "hia-user")
        verify.verify_hia_profile_hotspot({}, report, "c-dco")


if __name__ == "__main__":
    unittest.main(verbosity=2)
