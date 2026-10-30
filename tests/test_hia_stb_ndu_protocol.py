"""Frozen controls, work denominators and failure accounting without timings."""
from __future__ import annotations

import copy
import hashlib
import json
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


class RetainedFormalAnalysisTests(unittest.TestCase):
    """Replay actual complete frozen observations through the real wrapper."""
    @classmethod
    def setUpClass(cls):
        cls.path = Path(__file__).parent / "fixtures/hia_stb_ndu/failed_formal_analysis_f7cc8721.json"
        raw = cls.path.read_bytes()
        if len(raw) > 250000 or hashlib.sha256(raw).hexdigest() != "b9d6d605c42c7d2462e88acead3098092e02f4038f8d76b4a4e312d79513526f":
            raise AssertionError("retained actual-analysis regression fixture differs")
        cls.fixture = json.loads(raw)
        cls.retained = cls.fixture["report"]

    def before_analysis(self):
        value = copy.deepcopy(self.retained)
        final = value["ledger"].pop()
        self.assertEqual(final["label"], "post-policy.analysis")
        self.assertEqual(final["status"], "failed")
        self.assertEqual(final["error"], "KeyError: 'wall_ns'")
        self.assertEqual(final["wall_ns"], 145660)
        return value

    def test_real_measured_wrapper_freezes_closed_costs_without_reading_its_running_row(self):
        report = self.before_analysis()
        closed = copy.deepcopy(report["ledger"])
        result = study.analyze_measured(report, report["protocol"])
        self.assertEqual(report["ledger"][:-1], closed)
        self.assertEqual(report["ledger"][-1]["status"], "completed")
        self.assertGreater(report["ledger"][-1]["wall_ns"], 0)
        self.assertEqual(result["closed_policy_cost_ledger_sha256"], study.digest(closed))
        self.assertEqual(report["analysis_cost_ledger_sha256"], study.digest(closed))
        self.assertFalse(report["qualified"])
        self.assertEqual(report["analysis_error"], {"message": "'wall_ns'", "type": "KeyError"})
        self.assertEqual(self.fixture["provenance"]["original_result_sha256"],
                         "411a8eabb85adbee5334afe0c684b42de39367f2b74ae3caa515ec7674465ae9")

    def test_all_frozen_cost_outputs_and_negative_gates_replay_from_actual_observations(self):
        report = self.before_analysis()
        result = study.analyze_measured(report, report["protocol"])
        self.assertEqual(set(result), {
            "standalone_measured_ns", "baseline_only_standalone_ns", "closed_policy_cost_ledger_sha256",
            "common_charged_once_per_arm_ns", "complete_search_preparation_ns", "baseline_only_preparation_ns",
            "native_build_inclusive_ns", "historical_native_build_allocation_ns", "new_native_build_performed",
            "same_model_audit", "candidate_cold_observed_net_gate", "ndu_warm_observed_net_gate",
            "ndu_build_inclusive_observed_net_gate", "same_model_algorithmic_improvement_established",
            "candidate_opportunity_is_NDU_increment", "statistical_superiority_established",
            "actual_kernel_calls", "actual_kernel_calls_scope", "additional_preparation_native_calls",
            "final_encoding_and_outer_startup"})
        # Exact nanoseconds from the retained failed formal run, independently
        # totaled from its closed outer-stage ledger; no new timing samples.
        self.assertEqual(result["standalone_measured_ns"], {"fixed": 21926017907,
            "feedback-greedy": 21886944486, "light-dp": 21857009664, "native-ndu": 22119350998})
        self.assertEqual(result["baseline_only_standalone_ns"], 7460339565)
        self.assertEqual(result["common_charged_once_per_arm_ns"], 2713188898)
        self.assertEqual(result["complete_search_preparation_ns"], 17098466394)
        self.assertEqual(result["baseline_only_preparation_ns"], 2692269412)
        self.assertEqual(result["historical_native_build_allocation_ns"], 28548912666)
        self.assertEqual(result["native_build_inclusive_ns"], 50668263664)
        self.assertEqual(result["actual_kernel_calls"], 3087007744)
        self.assertEqual(result["actual_kernel_calls_scope"],
                         "registered calibration plus policy/baseline deliveries only")
        self.assertEqual(result["final_encoding_and_outer_startup"],
                         "see actual external process receipt; not assigned zero")
        self.assertEqual(result["additional_preparation_native_calls"], report["preparation_native_calls"])
        self.assertEqual(result["additional_preparation_native_calls"]["total_calls"], 320)
        self.assertEqual(len(result["same_model_audit"]), 32)
        self.assertEqual({(row["group"], row["epoch"]) for row in result["same_model_audit"]},
                         {(group, epoch) for group in range(4) for epoch in range(8)})
        self.assertTrue(all(row["same_choice"] and row["modeled_regret_ns"] == 0
                            and row["native"] == row["same_model_dp"] for row in result["same_model_audit"]))
        for key in ("candidate_cold_observed_net_gate", "ndu_warm_observed_net_gate",
                    "ndu_build_inclusive_observed_net_gate", "new_native_build_performed",
                    "same_model_algorithmic_improvement_established", "candidate_opportunity_is_NDU_increment",
                    "statistical_superiority_established"):
            self.assertIs(result[key], False)

    def test_missing_unknown_negative_or_inflight_stage_cost_never_becomes_zero(self):
        for alteration in ("missing", "unknown", "negative", "running"):
            with self.subTest(alteration=alteration):
                report = self.before_analysis()
                row = next(row for row in report["ledger"] if row["label"] == "candidate.prepare_bank")
                if alteration == "missing": del row["wall_ns"]
                elif alteration == "unknown": row["wall_ns"] = None
                elif alteration == "negative": row["wall_ns"] = -1
                else: row["status"] = "running"
                with self.assertRaisesRegex(ValueError, "closed, known nonnegative"):
                    study.analyze_measured(report, report["protocol"])
                self.assertEqual(report["ledger"][-1]["status"], "failed")
                self.assertGreater(report["ledger"][-1]["wall_ns"], 0)

    def test_missing_preparation_or_inconsistent_total_wall_rejects(self):
        report = self.before_analysis()
        report["ledger"] = [row for row in report["ledger"] if row["label"] != "baseline.prepare_bank"]
        with self.assertRaisesRegex(ValueError, "cost stage missing or duplicated"):
            study.analyze_measured(report, report["protocol"])
        report = self.before_analysis()
        report["wall_ns_before_analysis_and_final_encoding"] = sum(row["wall_ns"] for row in report["ledger"]) - 1
        with self.assertRaisesRegex(ValueError, "exceed the complete pre-analysis wall"):
            study.analyze_measured(report, report["protocol"])

    def test_same_total_calls_cannot_replace_a_missing_registered_arm(self):
        report = self.before_analysis()
        first, second = report["episodes"][:2]
        second.update(group=first["group"], arm=first["arm"])
        with self.assertRaisesRegex(ValueError, "group/arm must occur exactly once"):
            study.analyze_measured(report, report["protocol"])

    def test_each_delivery_and_calibration_denominator_is_required(self):
        report = self.before_analysis()
        report["episodes"][0]["observations"][0]["calls"] -= 1
        report["episodes"][0]["observations"][1]["calls"] += 1
        with self.assertRaisesRegex(ValueError, "delivery identity, count or actual cost"):
            study.analyze_measured(report, report["protocol"])
        report = self.before_analysis()
        report["calibration"]["rows"][1] = copy.deepcopy(report["calibration"]["rows"][0])
        with self.assertRaisesRegex(ValueError, "candidate/parameter calibration denominator"):
            study.analyze_measured(report, report["protocol"])

    def test_retained_failed_analysis_is_not_accepted_as_a_closed_policy_cost(self):
        report = copy.deepcopy(self.retained)
        with self.assertRaisesRegex(ValueError, "closed, known nonnegative"):
            study.analyze(report, report["protocol"], cost_ledger=tuple(report["ledger"]))
        self.assertFalse(report["qualified"])
        self.assertEqual(report["ledger"][-1]["wall_ns"], 145660)


if __name__ == "__main__":
    unittest.main()
