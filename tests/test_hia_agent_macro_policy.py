"""Macro control admissions and evidence gates; fixtures are not economic results."""
from copy import deepcopy
import contextlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_agent_macro_policy import (ACTIONS, COMPARISON_SCHEMA, PHASES,
    STATE_SCHEMA, MacroPolicyRejected, advise_macro, assess_macro_comparison,
    digest, ledger_totals, wire)
from hepta.hia_ndu_optimizer import OptimizationRejected


def entry(identity="m1", phase="model", wall=1000, tokens=100, status="completed"):
    return {"id": identity, "phase": phase, "status": status, "wall_ns": wall,
            "model_tokens": tokens, "receipt_sha256": digest(identity)}


def state():
    return {"schema": STATE_SCHEMA, "context_sha256": "1"*64, "objective_sha256": "2"*64,
            "agent_sha256": "3"*64, "installation": {"worker_sha256": "4"*64,
            "backend_sha256": "5"*64, "catalog_sha256": "6"*64}, "generation": 1,
            "budget": {"wall_ns": 10_000_000_000, "model_tokens": 10000},
            "ledger": [entry()], "stop_remaining_ns": 900_000_000,
            "plans": [{"id": "measure", "actions": ["evaluate", "stop"],
            "remaining_cost_ns": 100000, "uncertainty_ns": 10, "model_tokens": 0,
            "support_sha256": "7"*64}]}


def registration(data):
    data["registration_sha256"] = digest({key: data[key] for key in (
        "agent_sha256", "objective_sha256", "budget", "task_inventory", "minimum_gain_ns")})
    for arm in data.get("arms", []):
        arm["registration_sha256"] = data["registration_sha256"]
    return data


def comparison():
    result = {"schema": COMPARISON_SCHEMA, "registration_sha256": "1"*64,
              "agent_sha256": "2"*64, "objective_sha256": "3"*64,
              "budget": {"wall_ns": 1_000_000_000, "model_tokens": 100000},
              "task_inventory": [], "minimum_gain_ns": 1, "arms": []}
    for i in range(8):
        result["task_inventory"].append({"id": "task" + str(i), "input_sha256": digest([i, "input"]),
            "qualification": "synthetic_fixture", "qualification_receipt_sha256": digest([i, "qualification"])})
    for arm, cost in (("fixed", 110), ("greedy", 100), ("ordinary", 90), ("ndu", 80)):
        observations = []
        for task in result["task_inventory"]:
            ledger = [entry("model", "model", cost, 100), entry("use", "future_use", cost, 0)]
            observations.append({"task_id": task["id"], "input_sha256": task["input_sha256"],
                "qualification_receipt_sha256": task["qualification_receipt_sha256"],
                "status": "completed", "result_receipt_sha256": digest([arm, task["id"]]), "correct": True,
                "ledger": ledger, "phase_inventory": {phase: {"performed": phase in {"model", "future_use"},
                "receipt_sha256": digest([phase, arm, task["id"]])} for phase in PHASES},
                "native_ndu_receipts": [digest(["native", task["id"]])] if arm == "ndu" else []})
        result["arms"].append({"strategy": arm, "agent_sha256": result["agent_sha256"],
            "registration_sha256": "1"*64, "budget": deepcopy(result["budget"]), "observations": observations})
    return registration(result)


class MacroAdviceTests(unittest.TestCase):
    def test_missing_native_bridge_is_blocked_and_charged(self):
        data = state()
        before = deepcopy(data)
        result = advise_macro(wire(data))
        self.assertEqual(result["reason"], "native_bridge_unavailable")
        self.assertFalse(result["native_ndu_evaluated"])
        self.assertGreater(result["ledger_entry"]["wall_ns"], 0)
        self.assertEqual(len(result["next_state"]["ledger"]), 2)
        self.assertEqual(data, before)
        self.assertFalse(result["net_benefit_established"])

    def test_unknown_cost_never_becomes_free(self):
        for field in ("wall_ns", "model_tokens", "receipt_sha256"):
            data = state()
            data["ledger"][0][field] = None
            with self.subTest(field=field), patch("hepta.hia_agent_macro_policy._native_rank") as rank:
                result = advise_macro(wire(data), bridge={"binary": "unused"})
                self.assertEqual(result["reason"], "unknown_observed_costs")
                rank.assert_not_called()

    def test_exhausted_lifecycle_budget_cannot_be_renewed(self):
        data = state()
        data["budget"]["wall_ns"] = 1
        with patch("hepta.hia_agent_macro_policy._native_rank") as rank:
            first = advise_macro(wire(data), bridge={})
            second = advise_macro(wire(first["next_state"]), bridge={})
            rank.assert_not_called()
        self.assertEqual(first["reason"], "lifecycle_budget_exhausted")
        self.assertGreater(second["observed_costs"]["observed_wall_ns"], first["observed_costs"]["observed_wall_ns"])

    def test_real_adapter_boundary_is_explicit_and_snapshot_bound(self):
        # Mock only the process boundary; this proves orchestration, not NDU use.
        data = state()
        response = {"advisory_recommendation": "measure"}
        with patch("hepta.hia_agent_macro_policy._native_rank", return_value=(response, {"binary_sha256": "8"*64})) as rank:
            result = advise_macro(wire(data), bridge={"binary": "bound", "build_receipt": "bound"})
        self.assertEqual(rank.call_count, 1)
        self.assertEqual(result["next_action"], "evaluate")
        request = rank.call_args.args[1]
        self.assertEqual(request["schema"], "hepta.hia.ndu-request.v1")
        self.assertNotEqual(request["objective_sha256"], data["objective_sha256"])
        self.assertEqual(result["state_sha256"], digest(data))
        self.assertFalse(result["execution_authorized"])
        self.assertEqual(result["authority"], "DENY_ALL")

    def test_native_failure_remains_in_costed_next_state(self):
        with patch("hepta.hia_agent_macro_policy._native_rank", side_effect=OptimizationRejected("source identity differs")):
            result = advise_macro(wire(state()), bridge={})
        self.assertEqual(result["reason"], "native_evaluator_rejected")
        self.assertGreater(result["observed_costs"]["failed_attempt_wall_ns"], 0)
        self.assertEqual(result["selected_id"], "abstain")

    def test_ledger_identity_is_reserved_before_native_work(self):
        data = state()
        data["ledger"][0]["id"] = "controller.1"
        with patch("hepta.hia_agent_macro_policy._native_rank") as rank:
            with self.assertRaisesRegex(MacroPolicyRejected, "id collision"):
                advise_macro(wire(data), bridge={})
            rank.assert_not_called()

    def test_malformed_native_response_is_a_retained_rejection(self):
        with patch("hepta.hia_agent_macro_policy._native_rank", side_effect=TypeError("invalid response field")):
            result = advise_macro(wire(state()), bridge={})
        self.assertEqual(result["reason"], "native_evaluator_rejected")
        self.assertEqual(result["ledger_entry"]["status"], "rejected")
        self.assertFalse(result["recursive_utility_evaluated"])

    def test_native_runtime_overrun_abstains_without_refund(self):
        data = state()
        data["budget"]["wall_ns"] = 1_000_000
        with patch("hepta.hia_agent_macro_policy.time.perf_counter_ns", side_effect=[0, 10, 2_000_000, 2_000_010]), patch(
            "hepta.hia_agent_macro_policy._native_rank", return_value=({"advisory_recommendation": "measure"}, {})):
            result = advise_macro(wire(data), bridge={})
        self.assertEqual(result["reason"], "budget_exhausted_after_native")
        self.assertEqual(result["selected_id"], "abstain")
        self.assertGreater(result["observed_costs"]["observed_wall_ns"], data["budget"]["wall_ns"])

    def test_plan_model_token_overrun_is_hard_violation(self):
        data = state()
        data["plans"][0]["model_tokens"] = data["budget"]["model_tokens"]
        with patch("hepta.hia_agent_macro_policy._native_rank", return_value=({"advisory_recommendation": None}, {})) as rank:
            advise_macro(wire(data), bridge={})
        self.assertTrue(rank.call_args.args[1]["candidates"][1]["hard_violation"])

    def test_mutable_duplicate_and_nonfinite_inputs_rejected(self):
        for raw in (state(), b'{"schema":1,"schema":2}', b'{"a":NaN}', b'[' * 40 + b']' * 40):
            with self.subTest(raw=str(raw)[:40]), self.assertRaises(MacroPolicyRejected):
                advise_macro(raw)

    def test_malformed_plans_and_boolean_costs_are_not_admitted(self):
        mutations = [lambda d: d["plans"][0].update(actions=["stop", "emit"]),
                     lambda d: d["plans"][0].update(actions=["arbitrary-code", "stop"]),
                     lambda d: d["plans"][0].update(remaining_cost_ns=True),
                     lambda d: d["plans"][0].update(uncertainty_ns=-1),
                     lambda d: d["plans"].append(deepcopy(d["plans"][0])),
                     lambda d: d["installation"].update(worker_sha256="0"*64)]
        for mutation in mutations:
            data = state()
            mutation(data)
            with self.subTest(mutation=str(mutation)), self.assertRaises(MacroPolicyRejected):
                advise_macro(wire(data))

    def test_duplicate_attempts_and_receipts_cannot_be_double_charged(self):
        for extra in (entry(), dict(entry(), id="different")):
            with self.assertRaises(MacroPolicyRejected):
                ledger_totals([entry(), extra])

    def test_failed_search_and_unknown_completion_are_preserved(self):
        rows = [entry("bad", "search", 200, 0, "failed"), entry("uncertain", "adoption", 50, 0, "unknown")]
        totals = ledger_totals(rows)
        self.assertEqual(totals["failed_attempt_wall_ns"], 200)
        self.assertEqual(totals["observed_wall_ns"], 250)
        self.assertFalse(totals["complete"])


class MacroComparisonTests(unittest.TestCase):
    def test_synthetic_success_never_closes_real_task_requirement(self):
        result = assess_macro_comparison(wire(comparison()))
        self.assertGreater(result["ndu_saving_ns"], 0)
        self.assertFalse(result["observed_scope_positive"])
        self.assertEqual(sum(reason.startswith("synthetic_task:") for reason in result["reasons"]), 8)

    def test_declared_real_evidence_remains_unauthenticated(self):
        data = comparison()
        for task in data["task_inventory"]:
            task["qualification"] = "real_agent_task"
        registration(data)
        result = assess_macro_comparison(wire(data))
        self.assertTrue(result["reported_arithmetic_positive"])
        self.assertFalse(result["observed_scope_positive"])
        self.assertFalse(result["economic_benefit_established"])
        self.assertEqual(result["p1_acceptance"], "HOLD")
        self.assertIn("original_receipts_not_independently_authenticated", result["reasons"])
        self.assertFalse(result["input_receipts_authenticated"])
        self.assertFalse(result["execution_authorized"])
        self.assertEqual(result["best_control"], "ordinary")

    def test_same_agent_and_same_budget_are_required(self):
        for field, value in (("agent_sha256", "9"*64), ("budget", {"wall_ns": 1, "model_tokens": 2}),
                             ("registration_sha256", "8"*64)):
            data = comparison()
            data["arms"][3][field] = value
            with self.subTest(field=field), self.assertRaises(MacroPolicyRejected):
                assess_macro_comparison(wire(data))

    def test_task_denominator_cannot_be_reduced(self):
        for mutation in (lambda d: d["arms"][3]["observations"].pop(),
                         lambda d: d["arms"][2]["observations"][1].update(task_id="task0"),
                         lambda d: d["arms"].pop()):
            data = comparison()
            mutation(data)
            with self.assertRaises(MacroPolicyRejected):
                assess_macro_comparison(wire(data))

    def test_failed_task_is_retained_and_blocks_win(self):
        data = comparison()
        data["arms"][3]["observations"][0].update(status="failed", correct=False)
        result = assess_macro_comparison(wire(data))
        self.assertIn("ndu:undelivered_task:task0", result["reasons"])
        self.assertEqual(result["registered_tasks"], 8)
        self.assertEqual(len(result["arm_costs"]["ndu"]), 8)

    def test_incomplete_fast_control_is_not_a_completed_gain(self):
        data = comparison()
        for arm in data["arms"][:3]:
            for row in arm["observations"]:
                row.update(status="failed", correct=False)
        result = assess_macro_comparison(wire(data))
        self.assertGreater(result["raw_ndu_wall_difference_ns"], 0)
        qualified = result["completed_comparison"]
        self.assertFalse(qualified["eligible"])
        self.assertEqual(qualified["complete_controls"], [])
        self.assertIsNone(qualified["best_complete_control"])
        self.assertIsNone(qualified["ndu_saving_ns"])
        self.assertEqual(sum(len(rows) for rows in result["arm_costs"].values()), 32)

    def test_partial_control_set_does_not_skip_strong_ordinary(self):
        data = comparison()
        data["arms"][2]["observations"][0].update(status="failed", correct=False)
        qualified = assess_macro_comparison(wire(data))["completed_comparison"]
        self.assertEqual(qualified["complete_controls"], ["fixed", "greedy"])
        self.assertEqual(qualified["best_complete_control"], "greedy")
        self.assertFalse(qualified["eligible"])
        self.assertIsNone(qualified["ndu_saving_ns"])

    def test_unknown_cost_or_missing_use_invalidates_completed_comparison(self):
        for mutation in (
            lambda row: row["ledger"][0].update(wall_ns=None),
            lambda row: row.update(result_receipt_sha256=None),
            lambda row: row["ledger"][1].update(wall_ns=0),
            lambda row: row["ledger"][0].update(model_tokens=100001),
        ):
            data = comparison()
            mutation(data["arms"][3]["observations"][0])
            qualified = assess_macro_comparison(wire(data))["completed_comparison"]
            self.assertFalse(qualified["eligible"])
            self.assertFalse(qualified["arm_eligibility"]["ndu"]["eligible"])
            self.assertIsNone(qualified["ndu_saving_ns"])

    def test_complete_comparison_preserves_arithmetic_without_attestation(self):
        result = assess_macro_comparison(wire(comparison()))
        qualified = result["completed_comparison"]
        self.assertTrue(qualified["eligible"])
        self.assertEqual(qualified["best_complete_control"], "ordinary")
        self.assertEqual(qualified["ndu_saving_ns"], 160)
        self.assertFalse(result["economic_benefit_established"])
        self.assertEqual(result["p1_acceptance"], "HOLD")

    def test_missing_phase_cannot_be_assumed_zero(self):
        data = comparison()
        data["arms"][3]["observations"][0]["phase_inventory"].pop("adoption")
        with self.assertRaises(MacroPolicyRejected):
            assess_macro_comparison(wire(data))

    def test_declared_unperformed_phase_cannot_hide_costs(self):
        data = comparison()
        data["arms"][3]["observations"][0]["phase_inventory"]["model"]["performed"] = False
        with self.assertRaises(MacroPolicyRejected):
            assess_macro_comparison(wire(data))

    def test_unknown_model_or_adoption_cost_blocks_win(self):
        data = comparison()
        row = data["arms"][3]["observations"][0]
        row["ledger"][0]["wall_ns"] = None
        row["ledger"].append(entry("adopt", "adoption", None, 0))
        row["phase_inventory"]["adoption"]["performed"] = True
        result = assess_macro_comparison(wire(data))
        self.assertIn("ndu:unknown_costs:task0", result["reasons"])

    def test_failed_search_reverses_apparent_gain(self):
        data = comparison()
        row = data["arms"][3]["observations"][0]
        row["ledger"].append(entry("loser", "search", 10000, 0, "failed"))
        row["phase_inventory"]["search"]["performed"] = True
        result = assess_macro_comparison(wire(data))
        self.assertLess(result["ndu_saving_ns"], 0)
        self.assertIn("no_full_cost_advantage_over_best_control", result["reasons"])

    def test_no_real_native_value_call_blocks_ndu_claim(self):
        data = comparison()
        data["arms"][3]["observations"][0]["native_ndu_receipts"] = []
        result = assess_macro_comparison(wire(data))
        self.assertIn("ndu:no_native_value_evaluation:task0", result["reasons"])

    def test_forecast_future_use_cannot_replace_observed_use(self):
        data = comparison()
        row = data["arms"][3]["observations"][0]
        row["ledger"] = row["ledger"][:1]
        row["phase_inventory"]["future_use"]["performed"] = False
        result = assess_macro_comparison(wire(data))
        self.assertIn("ndu:no_observed_downstream_use:task0", result["reasons"])

    def test_registration_or_input_drift_is_rejected(self):
        for mutation in (lambda d: d["task_inventory"][0].update(input_sha256="9"*64),
                         lambda d: d["arms"][3]["observations"][0].update(input_sha256="9"*64)):
            data = comparison()
            mutation(data)
            with self.assertRaises(MacroPolicyRejected):
                assess_macro_comparison(wire(data))

    def test_over_budget_work_is_retained_as_failure(self):
        data = comparison()
        data["arms"][3]["observations"][0]["ledger"][0]["model_tokens"] = 100001
        result = assess_macro_comparison(wire(data))
        self.assertIn("ndu:budget_exceeded:task0", result["reasons"])


class MacroEntryTests(unittest.TestCase):
    def test_discovery_is_source_bound_and_example_costs_are_unknown(self):
        from hepta.hia_agent_macro_discovery import macro_policy_guidance
        installation = state()["installation"]
        guidance = macro_policy_guidance(installation)
        self.assertEqual(guidance["installation"], installation)
        self.assertFalse(guidance["native_profile"]["recursive_utility_evaluated"])
        self.assertFalse(guidance["mcp_tool_registered"])
        result = advise_macro(wire(guidance["state_example"]))
        self.assertEqual(result["reason"], "unknown_observed_costs")
        installation["worker_sha256"] = "9" * 64
        self.assertNotEqual(guidance["installation"], installation)

    def test_cli_rejects_fifo_and_oversized_file_before_reading(self):
        from hepta.hia_agent_macro_policy import MAX_INPUT_BYTES
        from tools.hia_agent_macro_policy import _read_input
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence"
            with path.open("wb") as stream:
                stream.truncate(MAX_INPUT_BYTES + 1)
            with self.assertRaises(MacroPolicyRejected):
                _read_input(path)
            path.unlink()
            os.mkfifo(path)
            with self.assertRaises(MacroPolicyRejected):
                _read_input(path)

    def test_cli_output_never_overwrites_a_file_or_symlink_target(self):
        from tools.hia_agent_macro_policy import main
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, target, link = root / "state.json", root / "retained.json", root / "link.json"
            source.write_bytes(wire(state()))
            target.write_bytes(b"keep")
            link.symlink_to(target)
            for output in (target, link):
                with contextlib.redirect_stderr(io.StringIO()):
                    code = main(["advise", "--input", str(source), "--output", str(output)])
                self.assertEqual(code, 2)
                self.assertEqual(target.read_bytes(), b"keep")


if __name__ == "__main__":
    unittest.main()
