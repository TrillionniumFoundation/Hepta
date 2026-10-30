"""The new cost boundary cannot turn reference reuse into unmeasured NDU gain."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import qualify_hia_crc_context_reuse as study


CODES = {"baseline": "a" * 64, "ieee_guard": "b" * 64, "castagnoli_guard": "c" * 64}


def observations():
    p = study.protocol()
    costs = {"fresh_child_baseline": 10000, "coalesced_baseline": 1000,
             "coalesced_ieee_only": 800, "coalesced_castagnoli_only": 850,
             "coalesced_poly_dispatch": 700}
    rows = []
    for phase, trial, workload, arm in study.schedule(p):
        plan = study.requests(p, bytes(p["calls_per_trace"]), workload, arm)
        rows.append({"phase": phase, "trial": trial, "workload": workload, "arm": arm,
            "status": "completed", "calls": p["calls_per_trace"],
            "completed_requests": p["requests_per_trace"],
            "context_count": p["requests_per_trace"] if arm == "fresh_child_baseline" else 1,
            "loaded_candidates": sorted({r["candidate"] for r in plan}),
            "native_outer_wall_ns": costs[arm], "arm_host_wall_ns": costs[arm] + 100})
    return rows


class CRCReferenceStudyTests(unittest.TestCase):
    def test_new_complete_matrix_and_old_protocol_are_independent(self):
        p = study.protocol()
        self.assertEqual(len(set(study.schedule(p))), 60)
        self.assertEqual(sum(r["context_count"] for r in observations()), 240)
        self.assertEqual(p["max_study_wall_ns"], 300_000_000_000)
        old = study.historical.protocol()
        self.assertEqual(old["expected_observations"], 210)
        self.assertEqual(old["max_study_wall_ns"], 120_000_000_000)
        self.assertFalse(p["historical_protocol"]["superseded"])

    def test_all_arms_have_identical_public_inputs_and_reference_rule(self):
        p = study.protocol()
        self.assertTrue(p["reference_reuse"]["enabled_for_every_arm"])
        for workload in p["workloads"]:
            plans = [study.requests(p, bytes(range(256)) * 16, workload, arm) for arm in p["arms"]]
            public = [[{k: v for k, v in r.items() if k != "candidate"} for r in plan] for plan in plans]
            self.assertTrue(all(plan == public[0] for plan in public))
            self.assertEqual(sum(len(r["values"]) for r in plans[0]), 4096)

    def test_v2_zero_prefix_is_disclosed_and_v3_has_32_distinct_nonzero_chunks(self):
        old = study.protocol(2)
        old_data = {phase: study.phase_input(old, phase) for phase in ("training", "validation")}
        old_result = study.input_diversity(old, old_data)
        self.assertFalse(old_result["phases_distinct"])
        self.assertEqual(old_result["zero_chunks"], 32)
        new = study.protocol(3)
        new_data = {phase: study.phase_input(new, phase) for phase in ("training", "validation")}
        new_result = study.input_diversity(new, new_data)
        self.assertTrue(new_result["phases_distinct"])
        self.assertEqual((new_result["unique_chunks"], new_result["zero_chunks"]), (32, 0))
        self.assertEqual(new_data["training"], study.phase_input(new, "training"))
        self.assertFalse(new_result["independent_statistical_confirmation"])
        for field in ("arms", "requests_per_trace", "calls_per_trace", "bytes_per_request",
                      "trials_per_phase", "max_study_wall_ns", "economic_gate", "sampling"):
            self.assertEqual(new[field], old[field])
        with self.assertRaisesRegex(ValueError, "diverse input admission"):
            study.input_diversity(new, old_data)
        with self.assertRaisesRegex(ValueError, "diverse input admission"):
            study.input_diversity(new, {"training": new_data["training"], "validation": new_data["training"]})

    def test_native_only_win_cannot_hide_host_lookup_and_evidence_cost(self):
        rows = observations()
        for row in rows:
            if row["arm"] == "coalesced_poly_dispatch":
                row["arm_host_wall_ns"] = 2000
        result = study.analyze(rows, 1, CODES)
        self.assertTrue(result["native_only_diagnostic"]["economic_gate_passed"])
        self.assertFalse(result["economic_gate_passed"])
        self.assertEqual(result["observation_cost_metric"], "arm_host_wall_ns")
        self.assertFalse(result["NDU_incremental_value_established"])
        self.assertFalse(result["end_to_end_cache_speedup_established"])
        self.assertFalse(result["public_preregistration_claim"])

    def test_missing_host_cost_missing_sample_and_unpriced_setup_reject(self):
        for rows in (observations()[:-1], observations()):
            if len(rows) == 60:
                del rows[0]["arm_host_wall_ns"]
            with self.assertRaises(ValueError):
                study.analyze(rows, 1, CODES)
        for cost in (True, -1, 0, 1.2):
            with self.assertRaises(ValueError):
                study.analyze(observations(), cost, CODES)
        for value in (True, 0, 1.2):
            rows = observations()
            rows[0]["arm_host_wall_ns"] = value
            with self.assertRaises(ValueError):
                study.analyze(rows, 1, CODES)

    def test_dirty_source_refuses_before_any_capture_proof_build_or_context(self):
        with tempfile.TemporaryDirectory(prefix="crc-reference-refusal-") as temporary, \
                patch.object(study, "_source_state", return_value={"head": "a" * 40, "status": " M source.py"}), \
                patch.object(study.historical, "_capture_and_compare") as capture, \
                patch.object(study, "build_bank") as build:
            report = study.qualify(clang="clang", cc="gcc", output=Path(temporary) / "out", expected_source="a" * 40)
            self.assertFalse(report["qualified"])
            self.assertEqual(report["contexts_attempted"], 0)
            capture.assert_not_called()
            build.assert_not_called()


if __name__ == "__main__":
    unittest.main()
