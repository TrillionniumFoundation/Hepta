"""Independent campaign-level false-positive and failed-attempt checks.

These are deliberately controlled transport/campaign interventions. They do
not stand in for the frozen native campaign or its measured performance.
"""
from contextlib import ExitStack, redirect_stdout
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
from io import StringIO
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from experiments.hia_ndu_feedback_20261106 import model
from experiments.hia_ndu_feedback_20261106.workload import NativeCache
from hepta.hia_ndu_dynamic import DynamicError
from tests.test_hia_ndu_feedback_workload import ScriptedTransport
from tools import qualify_hia_ndu_feedback as campaign


class NoProcessBackend:
    def __init__(self, *args, **kwargs):
        self.calls = 0

    def evaluate(self, *args, **kwargs):
        self.calls += 1
        return model.scalar_backend(*args, **kwargs)

    def close(self):
        return {"started": False, "calls": self.calls, "startup_ns": 0,
                "close_ns": 0, "returncode": 0}


def record(arm, *, family="adaptive", seed=12007, native=True, dimension=384,
           repetition=0, status="completed", delivered=3, wall=100):
    return {"scenario": family, "seed": seed, "arm": arm,
            "native_workload": native, "dimension": dimension,
            "repetition": repetition, "planned_requests": 3,
            "delivered": delivered, "steps": [], "status": status,
            "errors": [], "search_transitions": 0, "backend_calls": 0,
            "workload_wall_ns": wall, "episode_wall_ns": wall,
            "actual_cost": wall, "realized_discounted_utility_q32": 42,
            "authority": "DENY_ALL", "production_activation": False}


class FeedbackCampaignTests(unittest.TestCase):
    @staticmethod
    def protocol():
        return json.loads(campaign.PROTOCOL.read_text())

    def test_failed_partial_transport_remains_in_aggregate_workload_wall(self):
        workers = []

        def make_worker(*args, **kwargs):
            with patch("experiments.hia_ndu_feedback_20261106.workload.JsonProcess",
                       ScriptedTransport):
                worker = NativeCache(*args, **kwargs)
            worker.process.fail_command = "run"
            workers.append(worker)
            return worker

        scenario = replace(model.SCENARIOS["adaptive"],
                           initial_budget=500000000, initial_deadline=500000000)
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(campaign, "NativeCache", side_effect=make_worker):
                result = campaign.episode(
                    scenario, 12007, "state-greedy", fixed_action=0,
                    inputs={"workload_binary": {"path": "test-binary"},
                            "workload_manifest": {"path": "test-manifest"}},
                    output=Path(directory), native=True, n=2, repeats=4,
                    cap=20000)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["planned_requests"], 3)
        self.assertEqual((result["delivered"], result["missing_requests"]), (0, 3))
        attempts = result["workload_attempts"]
        self.assertEqual(len(attempts), 1)
        self.assertEqual(attempts[0]["status"], "failed")
        spent = sum(a["workload_wall_ns"] for a in attempts)
        self.assertGreater(spent, 0)
        self.assertEqual(result["workload_wall_ns"], spent,
                         "Partial failed native work disappeared from the aggregate")
        self.assertGreaterEqual(result["episode_wall_ns"], spent)
        self.assertEqual(workers[0].process.close_calls, 1)

    def test_failed_search_keeps_original_request_denominator_and_charges_allowance(self):
        result = campaign.episode(
            model.SCENARIOS["adaptive"], 12007, "same-objective",
            fixed_action=0, inputs={}, output=Path("unused"), native=False,
            n=0, repeats=4, cap=1, remaining_transitions=1)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["planned_requests"], 3)
        self.assertEqual((result["delivered"], result["missing_requests"]), (0, 3))
        self.assertGreater(result["search_transitions"], 0)
        self.assertLessEqual(result["search_transitions"], 1)
        self.assertEqual(result["steps"], [])

    def test_failed_native_backup_keeps_previously_performed_search_work(self):
        class FailSecondBackend(NoProcessBackend):
            def evaluate(self, *args, **kwargs):
                self.calls += 1
                if self.calls == 2:
                    raise DynamicError("injected native backup failure")
                return model.scalar_backend(*args, **kwargs)

        with patch.object(campaign, "LazyBackend", FailSecondBackend):
            result = campaign.episode(
                model.SCENARIOS["adaptive"], 12007, "dynamic-ndu",
                fixed_action=0, inputs={}, output=Path("unused"), native=False,
                n=0, repeats=4, cap=20000)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["steps"], [])
        self.assertEqual(result["planned_requests"], 3)
        self.assertGreater(result["search_transitions"], 0,
                           "Native failure erased search expansions already performed")
        self.assertGreater(result["backend_calls"], 0,
                           "Native failure erased the preceding completed backup")

    def test_non_oracle_dispatch_does_not_call_post_execution_oracle(self):
        scenario = model.SCENARIOS["adaptive"]
        with patch.object(model, "independent_oracle",
                          side_effect=AssertionError("oracle leaked into dispatch")):
            result = campaign.episode(
                scenario, 12007, "state-greedy", fixed_action=0,
                inputs={}, output=Path("unused"), native=False, n=0,
                repeats=4, cap=20000)
        self.assertEqual(result["status"], "completed")
        before = deepcopy(result)
        original = model.independent_oracle
        with patch.object(model, "independent_oracle", wraps=original) as called:
            audit = campaign.audit_episode(scenario, result, 20000)
        self.assertEqual(called.call_count, len(result["steps"]))
        self.assertFalse(audit["online_controller_access"])
        self.assertEqual(result, before)

    def test_oracle_audit_rejects_corrupted_same_objective_value(self):
        scenario = model.SCENARIOS["adaptive"]
        result = campaign.episode(
            scenario, 12007, "same-objective", fixed_action=0,
            inputs={}, output=Path("unused"), native=False, n=0,
            repeats=4, cap=20000)
        self.assertEqual(result["status"], "completed")
        result["steps"][0]["decision"]["value_q32"] += 1
        audit = campaign.audit_episode(scenario, result, 20000)
        self.assertFalse(audit["rows"][0]["same_objective_agrees"])

    def test_missing_cells_cannot_shrink_planned_denominator_or_pass_delivery(self):
        p = self.protocol()
        summary = campaign.summarize([], p, {"value_build_wall_ns": 1,
                                           "value_all_build_attempts_wall_ns": 1})
        expected = len(p["holdout_seeds"]) * len(p["native_dimensions"]) * p["native_repetitions"] * p["horizon"]
        for family in p["environments"]:
            table = summary["tables"]["native"][family]["dynamic-ndu"]
            self.assertEqual(table["planned_requests"], expected,
                             "No observations cannot reduce the registered request inventory")
        self.assertTrue(summary["paired_comparisons"])
        self.assertTrue(all(not c["dynamic_all_delivered"] for c in summary["paired_comparisons"]))

    def test_duplicate_replica_cannot_replace_a_missing_paired_cell(self):
        p = self.protocol()
        p["holdout_seeds"] = [12007]
        p["native_dimensions"] = [384]
        p["native_repetitions"] = 2
        rows = [record("dynamic-ndu", repetition=0, wall=1),
                record("dynamic-ndu", repetition=0, wall=1),
                record("fixed", repetition=0, wall=1000),
                record("fixed", repetition=1, wall=1000)]
        try:
            summary = campaign.summarize(rows, p, {"value_build_wall_ns": 1,
                                                 "value_all_build_attempts_wall_ns": 1})
        except ValueError:
            return  # An explicit rejected inventory is also a safe result.
        pair = next(c for c in summary["paired_comparisons"]
                    if c["environment"] == "adaptive" and c["dynamic_minus_control"] == "fixed")
        self.assertFalse(pair["dynamic_all_delivered"],
                         "Duplicate repetition falsely filled the registered inventory")
        self.assertEqual(pair.get("independent_seed_count", 0), 0,
                         "Unmatched paired cells were treated as complete IID seeds")

    def make_frozen_case(self, directory):
        directory = Path(directory)
        p = self.protocol()
        p.update(training_seeds=[211], holdout_seeds=[12007],
                 native_repetitions=1, calibration_dimensions=[2, 4],
                 native_dimensions=[3])
        protocol = directory / "PROTOCOL.json"
        protocol.write_text(json.dumps(p, sort_keys=True))
        inputs = {}
        for prefix in ("workload", "value"):
            binary = directory / (prefix + ".bin")
            binary.write_bytes(b"controlled test input")
            manifest = directory / (prefix + ".manifest.json")
            manifest.write_text(json.dumps({"binary_sha256": sha256(binary.read_bytes()).hexdigest(),
                                            "build_cost": {"wall_ns": 1}}))
            inputs[prefix + "_binary"] = campaign.identity(binary)
            inputs[prefix + "_manifest"] = campaign.identity(manifest)
        frozen = {"schema": "hepta.hia.ndu.feedback-freeze.v1",
                  "source": {"commit": "controlled-source"}, "protocol": p,
                  "protocol_sha256": sha256(protocol.read_bytes()).hexdigest(),
                  "inputs": inputs,
                  "build_receipts": {prefix: json.loads(Path(inputs[prefix + "_manifest"]["path"]).read_text())
                                     for prefix in ("workload", "value")},
                  "build_attempt_ledger": None,
                  "scenarios": {k: campaign.asdict(v) for k, v in model.SCENARIOS.items()},
                  "python": campaign.sys.version, "platform": campaign.platform.platform(),
                  "allowed_cpus": sorted(campaign.os.sched_getaffinity(0))
                      if hasattr(campaign.os, "sched_getaffinity") else None}
        registration = directory / "REGISTRATION.json"
        registration.write_text(json.dumps(frozen))
        return protocol, registration, frozen

    def test_registration_protocol_tamper_is_rejected_before_campaign_io(self):
        with tempfile.TemporaryDirectory() as directory:
            protocol, registration, frozen = self.make_frozen_case(directory)
            frozen["protocol"]["holdout_seeds"] = [77777]
            registration.write_text(json.dumps(frozen))
            output = Path(directory) / "results"
            with ExitStack() as stack:
                stack.enter_context(patch.object(campaign, "PROTOCOL", protocol))
                stack.enter_context(patch.object(campaign, "source_identity", return_value=frozen["source"]))
                stack.enter_context(patch.object(campaign, "LazyBackend", NoProcessBackend))
                stack.enter_context(patch.object(model, "wiring_probes", return_value={"all_passed": True}))
                stack.enter_context(patch.object(model, "degeneration_probe", return_value={"all_passed": True}))
                calibration = stack.enter_context(patch.object(campaign, "calibrate",
                    side_effect=AssertionError("tampered protocol reached calibration")))
                stack.enter_context(redirect_stdout(StringIO()))
                with self.assertRaisesRegex(ValueError, "protocol"):
                    campaign.run(SimpleNamespace(registration=registration, output=output))
                calibration.assert_not_called()
                self.assertFalse(output.exists())

    def test_positive_timings_cannot_override_failed_mechanism_or_oracle_gates(self):
        for bad_gate in ("wiring", "oracle", "input-postflight"):
            with self.subTest(bad_gate=bad_gate), tempfile.TemporaryDirectory() as directory:
                protocol, registration, frozen = self.make_frozen_case(directory)
                output = Path(directory) / "results"

                def cheap_episode(scenario, seed, arm, **kwargs):
                    if bad_gate == "input-postflight":
                        Path(frozen["inputs"]["value_binary"]["path"]).write_bytes(b"changed after preflight")
                    return record(arm, family=scenario.name, seed=seed,
                                  native=kwargs["native"], dimension=kwargs["n"],
                                  wall=1 if arm == "dynamic-ndu" else 100000)

                with ExitStack() as stack:
                    stack.enter_context(patch.object(campaign, "PROTOCOL", protocol))
                    stack.enter_context(patch.object(campaign, "source_identity", return_value=frozen["source"]))
                    stack.enter_context(patch.object(campaign, "LazyBackend", NoProcessBackend))
                    stack.enter_context(patch.object(model, "wiring_probes",
                        return_value={"all_passed": bad_gate != "wiring"}))
                    stack.enter_context(patch.object(model, "degeneration_probe", return_value={"all_passed": True}))
                    stack.enter_context(patch.object(campaign, "calibrate", return_value={"models": {}, "wall_ns": 1}))
                    stack.enter_context(patch.object(campaign, "derived_native_scenario", side_effect=lambda base, *a: base))
                    stack.enter_context(patch.object(model, "select_fixed", return_value={
                        "action": 0, "all_candidates": [{"training_search_transitions": 0}]}))
                    stack.enter_context(patch.object(campaign, "episode", side_effect=cheap_episode))
                    stack.enter_context(patch.object(campaign, "audit_episode", return_value={
                        "rows": [{"same_objective_required": True,
                                  "same_objective_agrees": bad_gate != "oracle",
                                  "fixed_preference_ablation": None}], "wall_ns": 1}))
                    stack.enter_context(redirect_stdout(StringIO()))
                    campaign.run(SimpleNamespace(registration=registration, output=output))
                report = json.loads((output / "RESULT.json").read_text())
                self.assertIsNone(report["fatal_error"])
                self.assertEqual(report["retained_episode_count"], report["planned_episode_count"])
                self.assertTrue(all(c["observed_online_gain_ns"] > 0
                                    for c in report["paired_comparisons"]))
                self.assertFalse(report["checks"]["independent_net_gain"],
                                 "Favorable timings overrode a failed scientific gate")
                self.assertTrue(report["no_go_for_advantage_claim"])

    def test_build_ledger_cannot_reprice_a_valid_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "build.json"
            receipt.write_text(json.dumps({"build_cost": {"wall_ns": 93}}))
            info = campaign.identity(receipt)
            content = {"schema": "hepta.hia.ndu.feedback-build-attempts.v1",
                       "attempts": [{"receipt": info, "build_cost": {"wall_ns": 1}}]}
            with self.assertRaisesRegex(ValueError, "cost"):
                campaign.validate_build_ledger(content, info["sha256"])

    def test_build_ledger_refuses_negative_or_boolean_time_even_when_receipt_matches(self):
        for wall in (-1, True):
            with self.subTest(wall=wall), tempfile.TemporaryDirectory() as directory:
                receipt = Path(directory) / "build.json"
                cost = {"wall_ns": wall}
                receipt.write_text(json.dumps({"build_cost": cost}))
                info = campaign.identity(receipt)
                content = {"schema": "hepta.hia.ndu.feedback-build-attempts.v1",
                           "attempts": [{"receipt": info, "build_cost": cost}]}
                with self.assertRaisesRegex(ValueError, "nonnegative integer"):
                    campaign.validate_build_ledger(content, info["sha256"])

    def test_build_ledger_requires_admitted_build_once_and_retains_failed_attempt_cost(self):
        with tempfile.TemporaryDirectory() as directory:
            attempts = []
            for index, (status, wall) in enumerate((("failed", 19), ("success", 31))):
                receipt = Path(directory) / f"build-{index}.json"
                cost = {"wall_ns": wall}
                receipt.write_text(json.dumps({"status": status, "build_cost": cost}))
                attempts.append({"receipt": campaign.identity(receipt), "build_cost": cost})
            content = {"schema": "hepta.hia.ndu.feedback-build-attempts.v1", "attempts": attempts}
            expected = attempts[1]["receipt"]["sha256"]
            valid = campaign.validate_build_ledger(content, expected)
            self.assertEqual(sum(r["build_cost"]["wall_ns"] for r in valid["attempts"]), 50)
            missing = {**content, "attempts": attempts[:1]}
            with self.assertRaisesRegex(ValueError, "omits"):
                campaign.validate_build_ledger(missing, expected)
            duplicated = {**content, "attempts": attempts + [deepcopy(attempts[1])]}
            with self.assertRaisesRegex(ValueError, "duplicated"):
                campaign.validate_build_ledger(duplicated, expected)


if __name__ == "__main__":
    unittest.main()
