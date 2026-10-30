"""Registered controls cannot turn batching or missing costs into NDU value."""
from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import qualify_hia_crc_context as study


def observations():
    p = study.protocol()
    rows = []
    timings = {"fresh_child_baseline": 10000, "coalesced_baseline": 1000,
               "coalesced_ieee_only": 800, "coalesced_castagnoli_only": 850,
               "coalesced_poly_dispatch": 700}
    for phase, trial, workload, arm in study.schedule(p):
        plan = study.requests(p, bytes(65536), workload, arm)
        rows.append({"phase": phase, "trial": trial, "workload": workload, "arm": arm,
            "status": "completed", "native_outer_wall_ns": timings[arm], "calls": 65536,
            "completed_requests": 64, "context_count": 64 if arm == "fresh_child_baseline" else 1,
            "loaded_candidates": sorted({r["candidate"] for r in plan})})
    return rows


CODES = {"baseline": "a" * 64, "ieee_guard": "b" * 64, "castagnoli_guard": "c" * 64}


class CRCContextStudyTests(unittest.TestCase):
    def test_frozen_protocol_controls_full_210_observations_and_2856_contexts(self):
        p = study.protocol()
        rows = observations()
        self.assertEqual(len(set(study.schedule(p))), 210)
        self.assertEqual(sum(r["context_count"] for r in rows), 2856)
        self.assertLessEqual(2856, p["context_limits"]["contexts_per_bank"])
        self.assertEqual(p["context_limits"]["calls"], p["calls_per_trace"])
        self.assertFalse(p["claims"]["NDU_incremental_value_established"])

    def test_same_phase_bytes_modes_and_poly_sequence_for_every_arm(self):
        p = study.protocol()
        data = bytes(range(256)) * 256
        for workload in p["workloads"]:
            plans = [study.requests(p, data, workload, arm) for arm in p["arms"]]
            signatures = [[{k: v for k, v in r.items() if k != "candidate"} for r in plan] for plan in plans]
            self.assertTrue(all(s == signatures[0] for s in signatures))
            self.assertEqual(sum(len(r["values"]) for r in plans[0]), 65536)

    def test_batching_gain_does_not_hide_cold_loss_or_become_ndu_evidence(self):
        result = study.analyze(observations(), 5000, CODES)
        self.assertTrue(all(r["batching_lower_envelope_ns"] > 0 for r in result["rows"]))
        self.assertTrue(all(r["cold_net_lower_envelope_ns"] < 0 for r in result["rows"]))
        self.assertFalse(result["economic_gate_passed"])
        self.assertFalse(result["NDU_incremental_value_established"])
        self.assertFalse(result["online_admission_authorized"])
        self.assertFalse(result["break_even_is_observed_profit"])

    def test_positive_constructed_control_still_grants_no_execution_authority(self):
        result = study.analyze(observations(), 10, CODES)
        self.assertTrue(result["economic_gate_passed"])
        self.assertFalse(result["online_admission_authorized"])
        self.assertFalse(result["NDU_incremental_value_established"])
        identical = {name: "a" * 64 for name in CODES}
        self.assertFalse(study.analyze(observations(), 10, identical)["economic_gate_passed"])

    def test_strong_static_control_and_validation_regression_prevent_acceptance(self):
        rows = observations()
        # It is insufficient to beat the unoptimized baseline if a static
        # specialized version already performs better on the same held-out job.
        for row in rows:
            if row["phase"] == "validation" and row["arm"] == "coalesced_ieee_only":
                row["native_outer_wall_ns"] = 600
        result = study.analyze(rows, 10, CODES)
        self.assertFalse(result["economic_gate_passed"])
        self.assertTrue(any(r["guarded_increment_lower_envelope_ns"] < 0 for r in result["rows"]))

    def test_missing_duplicate_relabelled_or_incomplete_observations_reject(self):
        rows = observations()
        for changed in (rows[:-1], rows[:-1] + [copy.deepcopy(rows[0])]):
            with self.assertRaises(ValueError): study.analyze(changed, 1, CODES)
        for field, value in (("status", "failed"), ("calls", 65535), ("context_count", 99),
                             ("completed_requests", 63), ("native_outer_wall_ns", True),
                             ("loaded_candidates", ["baseline", "ieee_guard", "castagnoli_guard"]),
                             ("trial", False), ("calls", 65536.0), ("completed_requests", 64.0),
                             ("context_count", 64.0), ("loaded_candidates", ["baseline", "baseline"])):
            changed = copy.deepcopy(rows)
            changed[0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                study.analyze(changed, 1, CODES)
        for cost in (0, True, -1, 1.5):
            with self.assertRaises(ValueError): study.analyze(rows, cost, CODES)

    def test_dirty_source_refuses_before_capture_compiler_or_native_measurement(self):
        with tempfile.TemporaryDirectory(prefix="crc-study-refusal-") as temporary, \
                patch.object(study, "_source_state", return_value={"head": "a" * 40, "status": " M source.py"}), \
                patch.object(study, "_capture_and_compare") as capture, patch.object(study, "build_bank") as build:
            report = study.qualify(clang="clang", cc="gcc", output=Path(temporary) / "out", expected_source="a" * 40)
            self.assertFalse(report["qualified"])
            self.assertEqual(report["contexts_attempted"], 0)
            self.assertEqual(report["samples"], [])
            capture.assert_not_called()
            build.assert_not_called()


if __name__ == "__main__":
    unittest.main()
