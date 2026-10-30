"""Closed denominators and conservative accounting; synthetic controls, no timing."""
from __future__ import annotations

import copy
from hashlib import sha256
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from hepta.hia_crc_linear import LABELS, candidates
from hepta.hia_program import verify_program
from tools import qualify_hia_crc_linear_economics as study
from tools import qualify_hia_crc_context_reuse as prior


def fixture():
    p = study.protocol()
    samples = []
    for phase, trial, workload, arm in study.historical.schedule(p):
        index = study.ARMS.index(arm)
        labels = ({"baseline"} if arm == "fresh_child_baseline" else {study.STATIC[arm]} if arm in study.STATIC
            else {"linear_ieee", "linear_castagnoli"} if workload == "mixed_alternating"
            else {"linear_ieee"} if workload == "ieee" else {"linear_castagnoli"})
        samples.append({"phase": phase, "trial": trial, "workload": workload, "arm": arm,
            "status": "completed", "calls": 4096, "completed_requests": 16,
            "contexts": [{}] * (16 if arm == "fresh_child_baseline" else 1),
            "loaded_candidates": sorted(labels), "kernel_ns": 10000 + 100 * index + trial,
            "native_outer_wall_ns": 20000 + 100 * index + trial,
            "arm_host_wall_ns": 30000 + 100 * index + trial})
    bank = {"candidates": {name: {"preparation_wall_ns": 1000 + index,
        "code": {"sha256": sha256(name.encode()).hexdigest()}} for index, name in enumerate(LABELS)}}
    return p, samples, bank


class CRCLinearEconomicsTests(unittest.TestCase):
    def test_exact_old_work_and_all_six_fixed_candidates_remain_registered(self):
        p = study.protocol()
        old = prior.protocol(3)
        for name in ("data", "calls_per_trace", "bytes_per_request", "requests_per_trace", "trials_per_phase",
                     "max_study_wall_ns", "context_limits", "reference_reuse"):
            self.assertEqual(p[name], old[name], name)
        self.assertEqual(p["candidate_core_sha256"], {name: verify_program(doc).sha256 for name, doc in candidates().items()})
        self.assertEqual(set(study.STATIC.values()), set(LABELS))
        self.assertIn("linear_dual", study.STATIC.values())
        self.assertEqual(len(list(study.historical.schedule(p))), 96)
        self.assertEqual(sum(16 if key[3] == "fresh_child_baseline" else 1 for key in study.historical.schedule(p)), 276)
        for phase in ("training", "validation"):
            self.assertEqual(prior.phase_input(p, phase), prior.phase_input(old, phase))

    def test_all_arms_deliver_the_same_crc_inputs_and_fixed_work(self):
        p = study.protocol()
        payload = prior.phase_input(p, "validation")
        for workload in p["workloads"]:
            baseline = study.requests(p, payload, workload, "coalesced_baseline")
            semantic = lambda rows: [{k: v for k, v in row.items() if k != "candidate"} for row in rows]
            for arm in study.ARMS:
                rows = study.requests(p, payload, workload, arm)
                self.assertEqual(semantic(rows), semantic(baseline))
                self.assertEqual(sum(len(row["values"]) for row in rows), 4096)

    def test_missing_duplicate_wrong_work_and_unknown_costs_are_rejected(self):
        p, samples, bank = fixture()
        malformed = [samples[:-1], [*samples[:-1], samples[0]]]
        for field, bad in (("calls", 4095), ("trial", True), ("kernel_ns", None), ("arm_host_wall_ns", 1),
                           ("loaded_candidates", ["baseline", "baseline"]), ("unknown_native_measurements", ["incomplete"])):
            rows = copy.deepcopy(samples)
            rows[0][field] = bad
            malformed.append(rows)
        for rows in malformed:
            with self.assertRaises((ValueError, KeyError, TypeError)):
                study.analyze(rows, p, bank)

    def test_kernel_gain_cannot_hide_host_loss_or_cold_preparation(self):
        p, samples, bank = fixture()
        for row in samples:
            if row["arm"] in study.NEW_ARMS:
                row["kernel_ns"] = 5000
                row["arm_host_wall_ns"] = 50000
        analysis = study.analyze(samples, p, bank)
        charged = study.charge(analysis, p, analysis["delivered_host_sum_ns"] + 100000, outer_verified=True)
        self.assertFalse(charged["complete_cost_cold_gate_passed"])
        for group in charged["groups"]:
            for row in group["new_candidate_contrasts"].values():
                self.assertGreater(row["kernel_saving_ns_per_call"], 0)
                self.assertLess(row["full_host_saving_vs_fastest_legacy_ns"], 0)
                self.assertLess(row["cold_candidate_net_vs_fastest_legacy_ns"], 0)
                self.assertIsNotNone(row["conditional_break_even_calls_full_charge"])
        self.assertFalse(charged["break_even_is_observed_profit"])

    def test_strong_static_dual_is_included_in_dispatch_baseline(self):
        p, samples, bank = fixture()
        for row in samples:
            if row["arm"] == "coalesced_linear_dual":
                row.update(kernel_ns=50, native_outer_wall_ns=75, arm_host_wall_ns=100)
            if row["arm"] == "coalesced_poly_dispatch":
                row.update(kernel_ns=60, native_outer_wall_ns=80, arm_host_wall_ns=150)
        analysis = study.analyze(samples, p, bank)
        self.assertTrue(all(row["dispatch_host_increment_over_all_six_fixed_ns"] == -50 for row in analysis["groups"]))
        self.assertFalse(study.charge(analysis, p, analysis["delivered_host_sum_ns"])["inner_cold_gate_passed"])

    def test_actual_outer_cost_is_required_and_can_reverse_inner_gate(self):
        p, samples, bank = fixture()
        for row in samples:
            if row["arm"] == "coalesced_poly_dispatch":
                row.update(kernel_ns=50, native_outer_wall_ns=75, arm_host_wall_ns=100)
        analysis = study.analyze(samples, p, bank)
        inner = study.charge(analysis, p, analysis["delivered_host_sum_ns"])
        self.assertTrue(inner["inner_cold_gate_passed"])
        self.assertFalse(inner["complete_cost_cold_gate_passed"])
        outer = study.charge(analysis, p, analysis["delivered_host_sum_ns"] + 100000, outer_verified=True)
        self.assertFalse(outer["complete_cost_cold_gate_passed"])
        with self.assertRaises(ValueError):
            study.charge(analysis, p, analysis["delivered_host_sum_ns"] - 1)

    def test_negative_gain_has_no_break_even_and_all_preparation_stays_charged(self):
        p, samples, bank = fixture()
        analysis = study.analyze(samples, p, bank)
        self.assertEqual(analysis["additional_three_image_preparation_component_ns"], 1003 + 1004 + 1005)
        result = study.charge(analysis, p, analysis["delivered_host_sum_ns"] + 100000, outer_verified=True)
        self.assertEqual(result["shared_non_delivery_charge_ns"], 100000)
        for group in result["groups"]:
            for row in group["new_candidate_contrasts"].values():
                self.assertLess(row["kernel_saving_vs_fastest_legacy_ns"], 0)
                self.assertIsNone(row["conditional_break_even_calls_full_charge"])
                self.assertIsNone(row["conditional_break_even_calls_additional_three_image_component"])

    def test_failed_native_prefix_keeps_observed_work_and_cost(self):
        class FailedBank:
            def prepare_trace(self, plan):
                return SimpleNamespace(sha256="b" * 64, images=(0,), expected=())

            def oracle_reference_statistics(self):
                return {"misses": 64, "capacity_bypasses": 0, "failed_computations": 0}

            def run(self, trace, *, report):
                report.update(status="failed", outer_wall_ns=500,
                    prefix={"complete": False, "completed_requests": [{"calls": 3, "kernel_ns": 100}]},
                    loaded_inventory=[{"candidate": "baseline"}])
                raise RuntimeError("injected native failure after an observed prefix")

        p = study.protocol()
        row = {}
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with self.assertRaisesRegex(RuntimeError, "observed prefix"):
                study.deliver(FailedBank(), p, bytes(4096), ("training", 0, "ieee", "coalesced_baseline"),
                              directory, row, {"misses": 64})
            retained = json.loads((directory / "OBSERVATION.json").read_bytes())
            self.assertEqual((retained["calls"], retained["kernel_ns"], retained["native_outer_wall_ns"]), (3, 100, 500))
            self.assertEqual(retained["status"], "failed")
            self.assertTrue((directory / "00.native.json").is_file())


if __name__ == "__main__":
    unittest.main()
