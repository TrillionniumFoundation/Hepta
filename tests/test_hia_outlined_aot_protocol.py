"""Frozen outline campaign cannot hide arms, cohorts, tails or costs."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import unittest

from tools import qualify_hia_outlined_aot as campaign
from tools import qualify_hia_reduction_release as release
from tools import qualify_hia_empty_reduction as empty


class OutlineProtocolTests(unittest.TestCase):
    @staticmethod
    def cohort():
        spec = campaign.specification()
        rows = [
            {"workload": workload, "group": group["name"], "backend": arm,
             "n": n, "seed": seed, "calls": calls, "times_ns": [1000] * spec["samples"]}
            for workload in spec["historical_profile"]["workloads"] for group in spec["groups"]
            for arm in campaign.ARMS for n in group["sizes"] for seed in group["seeds"]
            for calls in spec["batch_loads"]
        ]
        return spec, rows

    def test_all_old_lengths_loads_thresholds_and_both_strong_rust_arms_remain(self):
        spec, rows = self.cohort()
        old = release.specification(release.INDUCTION_PROFILE)
        wrapper = empty.specification(empty.WRAPPER_PROFILE)
        self.assertEqual(spec["historical_profile"], old)
        self.assertEqual(spec["performance_gate"], {"median_ratio_maximum": 1.10, "p95_ratio_maximum": 1.20, "p99_ratio_maximum": 1.20})
        self.assertEqual(spec["groups"][2]["sizes"], wrapper["groups"][-1]["sizes"])
        self.assertEqual(spec["groups"][2]["seeds"], wrapper["groups"][-1]["seeds"])
        self.assertEqual(spec["batch_loads"], [1, 16, 64])
        self.assertEqual(set(spec["arms"]), set(release.ARMS) | {campaign.WRAPPER, campaign.CANDIDATE})
        self.assertEqual(len(rows), spec["timing_requests"])
        self.assertEqual(sum(len(r["times_ns"]) for r in rows), spec["timed_batches"])
        self.assertEqual(sum(r["calls"] * len(r["times_ns"]) for r in rows), spec["timed_kernel_calls"])
        observed = campaign.assess(rows, spec)
        self.assertEqual(observed["candidate_rust_comparisons_total"], 372)
        self.assertEqual(len(observed["comparisons"]), 930)
        self.assertTrue(observed["candidate_all_registered_rust_gates_passed"])

    def test_one_tail_failure_stays_visible_in_its_own_load(self):
        spec, rows = self.cohort()
        changed = next(r for r in rows if r["backend"] == campaign.CANDIDATE
                       and r["group"] == "prospective_lengths" and r["calls"] == 1)
        changed["times_ns"][-1] = 1201
        observed = campaign.assess(rows, spec)
        self.assertFalse(observed["candidate_all_registered_rust_gates_passed"])
        failed = [r for r in observed["comparisons"] if not r["passed"]]
        self.assertEqual(len(failed), 5)
        self.assertTrue(all(r["calls"] == 1 and r["group"] == "prospective_lengths" for r in failed))
        self.assertFalse(observed["full_lifecycle_net_benefit_established"])

    def test_missing_rust_arm_duplicate_row_changed_sample_and_relaxed_gate_fail(self):
        spec, rows = self.cohort()
        for bad in (rows[:-1], rows + [rows[0]], [r for r in rows if r["backend"] != "rust_byte_release"]):
            with self.assertRaises(ValueError):
                campaign.assess(bad, spec)
        for key in ("median_ratio_maximum", "p95_ratio_maximum", "p99_ratio_maximum"):
            changed = deepcopy(spec); changed["performance_gate"][key] = 2.0
            with self.subTest(gate=key), self.assertRaises(ValueError):
                campaign.assess(rows, changed)
        changed = deepcopy(rows); changed[0]["times_ns"][0] = True
        with self.assertRaises(ValueError):
            campaign.assess(changed, spec)

    def test_committed_protocol_matches_executable_registration(self):
        path = Path(__file__).resolve().parents[1] / "benchmarks/hia_outlined_aot/PROTOCOL.json"
        self.assertEqual(json.loads(path.read_text()), campaign.specification())


if __name__ == "__main__":
    unittest.main()
