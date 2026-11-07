#!/usr/bin/env python3
"""Unit tests for the isolated target-host profile-only inventory and verifier."""
import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


matrix = load("profile_only_matrix", HERE / "run_matrix.py")
verifier = load("profile_only_verifier", HERE / "verify_profile_result.py")


class ProfileOnlyInventoryTests(unittest.TestCase):
    def setUp(self):
        self.plan = json.loads((HERE / "plan.json").read_text())

    def test_default_inventory_remains_exactly_65_cases_and_216_workloads(self):
        tasks = matrix.build_tasks(self.plan)
        self.assertEqual(len(tasks), 65)
        self.assertEqual(sum(row["kind"] == "performance" for row in tasks), 54)
        self.assertEqual(
            sum(row["kind"] == "performance" for row in tasks)
            * len(self.plan["performance"]["workloads"]),
            216,
        )
        self.assertEqual(len(matrix.select_tasks(tasks, None)), 65)

    def test_profile_only_selects_only_hia_user_and_kernel_dco(self):
        tasks = matrix.select_tasks(matrix.build_tasks(self.plan), "profile")
        self.assertEqual([row["id"] for row in tasks], ["profile-hia-user", "profile-c-dco"])
        self.assertEqual({row["kind"] for row in tasks}, {"profile"})
        self.assertEqual({row["arms"]["server"] for row in tasks}, {"c-dco"})
        self.assertEqual([row["arms"]["client"] for row in tasks], ["hia-user", "c-dco"])

    def test_profile_only_never_accepts_a_performance_subset(self):
        with self.assertRaises(ValueError):
            matrix.select_tasks(matrix.build_tasks(self.plan), "performance")

    def test_hia_profile_requires_both_exported_non_epoch_hotspots(self):
        profile = {
            "actual_samples_present": True,
            "actual_sample_headers": 100,
            "kernel_symbol_lines": 10,
            "openvpn_sample_headers_by_role": {"client": 20, "server": 0},
            "hia_profile_symbol_lines": 2,
        }
        report = "\n".join([
            "  1.25% openvpn [.] ovpn_hia_packet_id_read",
            "  0.75% openvpn [.] ovpn_hia_packet_id_write",
        ])
        verifier.verify_profile_samples(profile, report, "hia-user")
        with self.assertRaises(ValueError):
            verifier.verify_profile_samples(
                {**profile, "hia_profile_symbol_lines": 1},
                report,
                "hia-user",
            )
        with self.assertRaises(ValueError):
            verifier.verify_profile_samples(
                profile,
                "  1.25% openvpn [.] ovpn_hia_packet_id_read_epoch",
                "hia-user",
            )

    def test_profile_record_command_uses_frozen_sampling_budget(self):
        profile = self.plan["profile"]
        command = matrix.profile_record_argv(
            "/usr/bin/perf", [0, 2], "/tmp/profile.perf.data",
            profile["seconds"], profile,
        )
        self.assertEqual(command[command.index("--freq") + 1], str(profile["frequency_hz"]))
        self.assertEqual(command[command.index("--call-graph") + 1], profile["call_graph"])
        self.assertEqual(command[-1], str(profile["seconds"] + 1))

    def test_profile_record_command_rejects_invalid_frequency(self):
        profile = {**self.plan["profile"], "frequency_hz": 0}
        with self.assertRaises(ValueError):
            matrix.profile_record_argv(
                "/usr/bin/perf", [0, 2], "/tmp/profile.perf.data",
                profile["seconds"], profile,
            )

    def test_profile_sampling_verifier_rejects_plan_mismatch(self):
        profile = {
            "sampling": {
                "frequency_hz": self.plan["profile"]["frequency_hz"],
                "duration_seconds": self.plan["profile"]["seconds"],
                "call_graph": self.plan["profile"]["call_graph"],
            }
        }
        verifier.verify_profile_sampling(profile, self.plan["profile"])
        with self.assertRaises(ValueError):
            verifier.verify_profile_sampling(
                {**profile, "sampling": {**profile["sampling"], "frequency_hz": 99}},
                self.plan["profile"],
            )

    def test_kernel_dco_profile_requires_ovpn_symbols(self):
        profile = {
            "actual_samples_present": True,
            "actual_sample_headers": 100,
            "kernel_symbol_lines": 20,
            "ovpn_symbol_lines": 4,
            "openvpn_sample_headers_by_role": {"client": 0, "server": 0},
        }
        verifier.verify_profile_samples(profile, "", "c-dco")
        with self.assertRaises(ValueError):
            verifier.verify_profile_samples({**profile, "ovpn_symbol_lines": 0}, "", "c-dco")

    def test_real_target_profile_counterexample_missing_read_hotspot_is_rejected(self):
        # Exact failure shape from target run 42321606601: real PID/kernel
        # samples existed, but the HIA-user perf report sampled only write.
        profile = {
            "actual_samples_present": True,
            "actual_sample_headers": 12338,
            "kernel_symbol_lines": 174126,
            "openvpn_sample_headers_by_role": {"client": 5043, "server": 0},
            "hia_profile_symbol_lines": 1,
        }
        report = (
            "  0.02% openvpn-hia openvpn-hia "
            "[.] ovpn_hia_packet_id_write - -\\n"
        )
        with self.assertRaisesRegex(
            ValueError, "lacks both exported non-epoch packet-ID hotspots"
        ):
            verifier.verify_profile_samples(profile, report, "hia-user")

    def test_profile_sampling_budget_is_large_enough_for_rare_hotspots(self):
        profile = self.plan["profile"]
        self.assertGreaterEqual(profile["seconds"], 90)
        self.assertGreaterEqual(profile["frequency_hz"], 997)
        command = matrix.profile_record_argv(
            "/usr/bin/perf", [0, 2], "/tmp/profile.perf.data",
            profile["seconds"], profile,
        )
        self.assertEqual(
            command[command.index("--freq") + 1],
            str(profile["frequency_hz"]),
        )
        self.assertEqual(command[-2:], ["sleep", str(profile["seconds"] + 1)])


if __name__ == "__main__":
    unittest.main(verbosity=2)
