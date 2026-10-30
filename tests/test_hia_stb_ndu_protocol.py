"""Frozen controls, work denominators and failure accounting without timings."""
from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import qualify_hia_stb_ndu as study


class StbProtocolTests(unittest.TestCase):
    def test_complete_work_denominator_and_unseen_input_domains(self):
        p = study.protocol()
        vectors = study.input_vectors(p)
        self.assertEqual(len(vectors), 5)
        self.assertEqual(len({study.digest(v) for v in vectors.values()}), 5)
        self.assertEqual(p["expected_actual_kernel_calls"], 184 * 4096 * 4096)
        self.assertEqual(p["arms"], list(study.ARMS))
        self.assertIn("guard_8_10", p["targets"])
        self.assertFalse(p["claims"]["production_demand_established"])

    def test_independent_dp_agrees_with_exhaustive_supplied_finite_paths(self):
        for length in (1, 2, 3):
            costs = [{label: 10 + ((i + j) % 4) for j, label in enumerate(study.LABELS)} for i in range(length)]
            model = {"costs": costs, "remaining_ns": 1000}
            self.assertEqual(study.light_dp(model), min(study.plans(model), key=study.plan_key))
            self.assertEqual(len(study.plans(model)), 4**length)
        model["remaining_ns"] = 0
        self.assertIsNone(study.light_dp(model))

    def test_exact_ties_do_not_prefer_an_arbitrary_native_id(self):
        model = {"costs": [{label: 1 for label in study.LABELS}] * 3, "remaining_ns": 100}
        expected = min(study.plans(model), key=study.plan_key)
        self.assertEqual(study.light_dp(model), expected)
        self.assertEqual(expected["targets"], ["baseline"] * 3)

    def test_feedback_cannot_read_another_arm_or_unobserved_validation_timing(self):
        calibration = {"latency_ns": {"8": {label: 10 + i for i, label in enumerate(study.LABELS)}}}
        before = study.estimates(calibration, [], 8)
        after = study.estimates(calibration, [{"target": "guard_8", "parameter": 8, "delivery_ns": 1}], 8)
        self.assertEqual(before["guard_8"], 11)
        self.assertEqual(after["guard_8"], 1)
        self.assertEqual(after["guard_10"], before["guard_10"])

    def test_failed_native_prefix_is_retained_without_replay(self):
        class Trace:
            sha256 = "a" * 64
            requests = []
            expected = []
            images = []
        class Bank:
            def prepare_trace(self, request): return Trace()
            def run(self, trace, report):
                report.update(status="failed", raw_stdout_base64="cHJlZml4", outer_wall_ns=101,
                              owned_child_cleanup="confirmed")
                raise RuntimeError("native failed after entered prefix")
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            with self.assertRaises(RuntimeError):
                study.deliver(Bank(), study.protocol(), list(range(8)), 8, "baseline", folder, 0, tiny=True)
            import json
            raw = json.loads((folder / "0000.native.json").read_bytes())
            observed = json.loads((folder / "0000.observation.json").read_bytes())
            self.assertEqual(raw["raw_stdout_base64"], "cHJlZml4")
            self.assertEqual(raw["outer_wall_ns"], 101)
            self.assertIn("error", observed)
            self.assertGreater(observed["delivery_ns"], 0)

    def test_required_finalization_cost_cannot_cross_budget_and_still_qualify(self):
        report = {"qualified": True, "status": "all-registered-deliveries-completed",
                  "ledger": [{"label": "source_after", "wall_ns": 8}], "episodes": [{"complete": True}]}
        p = {"study_budget_ns": 100}
        self.assertTrue(study.final_budget(report, p, 100))
        self.assertTrue(report["qualified"])
        self.assertFalse(study.final_budget(report, p, 101))
        self.assertFalse(report["qualified"])
        self.assertEqual(report["status"], "study-budget-exceeded")
        self.assertEqual(report["ledger"], [{"label": "source_after", "wall_ns": 8}])
        self.assertEqual(report["episodes"], [{"complete": True}])
        self.assertFalse(study.final_budget(report, p, 103, result_encoding_observed=True))
        self.assertTrue(report["study_budget"]["initial_result_encoding_included"])
        self.assertEqual(report["budget_overrun"]["wall_ns"], 103)

    def test_preparation_native_calls_are_separate_and_unknown_is_not_zero(self):
        report = {"stage": "study", "bank": {"candidates": {label: {
            "native_differential": {"cases_executed": 64}} for label in study.LABELS}}}
        partial = study.preparation_native_calls(report)
        self.assertEqual(partial["known_calls"], 256)
        self.assertIsNone(partial["total_calls"])
        self.assertFalse(partial["complete"])
        report["baseline_bank"] = {"candidates": {"baseline": {"native_differential": {"cases_executed": 64}}}}
        complete = study.preparation_native_calls(report)
        self.assertTrue(complete["complete"])
        self.assertEqual(complete["total_calls"], 320)

    def test_source_binding_checks_raw_blobs_and_does_not_admit_dirty_tree(self):
        with patch.object(study.subprocess, "check_output", side_effect=[b"a" * 40 + b"\n", b" M source\n"]):
            with self.assertRaisesRegex(ValueError, "clean checkout"):
                study.sources("a" * 40)

    def test_actual_native_protocol_is_bounded_and_does_not_call_dp_online(self):
        # A transport-contract unit double only; it is never used in a study
        # or called an actual NDU observation. The separate qualification
        # stage executes its real protocol probe through RecordedSession.
        p = study.protocol()
        m = {"costs": [{label: 10 + i for i, label in enumerate(study.LABELS)}] * 3,
             "remaining_ns": 1000, "support_sha256": "b" * 64,
             "proofs": {label: "c" * 64 for label in study.LABELS}}
        selected = min(study.plans(m), key=study.plan_key)
        class ContractOnly:
            def evaluate(self, request):
                self.request = request
                return {"advisory_candidate_id": selected["id"], "pareto_candidate_ids": [selected["id"]]}
        bridge = ContractOnly()
        with patch.object(study, "light_dp", side_effect=AssertionError("host policy answered for native")):
            actual, _ = study.native_plan(m, p, 1, bridge)
        self.assertEqual(actual, selected)
        self.assertEqual(len(bridge.request["candidates"]), 65)
        self.assertEqual(bridge.request["candidates"][-1]["id"], "abstain")
        self.assertEqual(bridge.request["candidates"][-1]["terminal_q32"], 0)


if __name__ == "__main__":
    unittest.main()
