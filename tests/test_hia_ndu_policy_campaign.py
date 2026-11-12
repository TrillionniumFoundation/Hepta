"""Adversarial controls for the complete-policy audit runner.

Native adapters in this module are explicitly injected scalar test doubles.
Their positive controls test campaign accounting, never native qualification.
No historical campaign, protocol, evidence or implementation is changed here.
"""
from collections import Counter
from contextlib import ExitStack, redirect_stdout
from copy import deepcopy
from dataclasses import asdict, replace
from fractions import Fraction
from hashlib import sha256
from io import StringIO
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from experiments.hia_ndu_feedback_20261106 import model, policy_audit
from tools import qualify_hia_ndu_policy_audit as campaign


class ScalarTransportControl:
    def __init__(self, inputs, log):
        self.arm = Path(log).stem
        self.backend = None
        self.closed = 0

    def evaluate(self, *args, **kwargs):
        if self.backend is None:
            self.backend = SimpleNamespace(calls=0)
        self.backend.calls += 1
        return model.scalar_backend(*args, **kwargs)

    def close(self):
        self.closed += 1
        return {"started": self.backend is not None,
                "calls": self.backend.calls if self.backend is not None else 0,
                "startup_ns": 0, "close_ns": 0,
                "returncode": 0 if self.backend is not None else None,
                "call_wall_ns": 0}


def _fixture(scenario=None, identity="unit-profile"):
    scenario = scenario or model.Scenario("campaign-control", horizon=1,
        request_p0_z0_num=1, request_p0_z0_den=2,
        request_p0_z1_num=1, request_p0_z1_den=2,
        signal_correct_num=1, signal_correct_den=2)
    graph = campaign.graph_record(policy_audit.build_graph(scenario))
    return {"id": identity, "scenario": asdict(scenario), "graph": graph,
            "graph_sha256": model.digest(graph), "states": len(graph["nodes"]),
            "edges": graph["edges"]}


def _ledger():
    return {arm: {key: 0 for key in ("transitions", "planning_wall_ns",
        "policy_evaluation_wall_ns", "completed", "failed", "not_run")}
        for arm in campaign.ARMS}


def _frozen_case(directory, items):
    """A small controlled registration, with real local byte identities."""
    directory = Path(directory)
    p = campaign.read(campaign.PROTOCOL)
    p["expected_profiles"] = len(items)
    totals = {"profiles": len(items), "states": sum(x["states"] for x in items),
        "edges": sum(x["edges"] for x in items),
        "maximum_profile_states": max(x["states"] for x in items),
        "maximum_profile_edges": max(x["edges"] for x in items)}
    p["structural_preflight"].update({k: v for k, v in totals.items() if k != "profiles"})
    protocol_path = directory / "protocol.json"
    protocol_path.write_text(json.dumps(p, sort_keys=True), encoding="utf-8")
    binary = directory / "unit-nonexecutable.bin"
    binary.write_bytes(b"explicit scalar campaign control, never executed")
    manifest = directory / "unit-manifest.json"
    campaign.write(manifest, {"schema": "hepta.hia.ndu-build.v1",
        "binary_sha256": sha256(binary.read_bytes()).hexdigest(),
        "original_rust_sources_unchanged": True,
        "all_original_non_manifest_inputs_unchanged": True, "build_inputs_unchanged": True})
    frozen = {"schema": "hepta.hia.ndu.policy-audit-freeze.v1",
        "source": {"commit": "1" * 40, "tree": "2" * 40, "files": {}},
        "protocol": p, "protocol_sha256": sha256(protocol_path.read_bytes()).hexdigest(),
        "inputs": {"value_binary": campaign.common.identity(binary),
                   "value_manifest": campaign.common.identity(manifest)},
        "profiles": deepcopy(items), "inventory": totals, "freeze_wall_ns": 1,
        "authority": "DENY_ALL"}
    registration = directory / "registration.json"
    campaign.write(registration, frozen)
    return SimpleNamespace(registration=registration, output=directory / "result"), frozen, protocol_path


def _bound_fixture(stack, frozen, protocol_path):
    stack.enter_context(patch.object(campaign, "PROTOCOL", protocol_path))
    stack.enter_context(patch.object(campaign, "protocol", return_value=deepcopy(frozen["protocol"])))
    stack.enter_context(patch.object(campaign, "source", return_value=deepcopy(frozen["source"])))
    stack.enter_context(patch.object(campaign, "inventory",
        return_value=(deepcopy(frozen["profiles"]), deepcopy(frozen["inventory"]))))
    stack.enter_context(redirect_stdout(StringIO()))


class PolicyCampaignTests(unittest.TestCase):
    def test_pure_prior_is_dynamic_when_current_belief_already_is_prior(self):
        # This is a supplied-state attribution counterexample, not a claim of
        # natural reachability under the original campaign's initial prior.
        scenario = model.Scenario("pure-prior-control", horizon=2,
            initial_budget=24, initial_deadline=24, initial_resident=0,
            prior0_num=43, prior0_den=64)
        state = model.Observation(0, 1, 0, 0, 11, 24, 43, 64)
        with patch.object(model, "independent_oracle", side_effect=AssertionError("oracle leaked")):
            dynamic = campaign.decide(scenario, state, "same-objective")
            pure = campaign.decide(scenario, state, "prior-belief-only")
            joint = campaign.decide(scenario, state, "no-adaptation")
        self.assertEqual((dynamic["action"], pure["action"], joint["action"]), (1, 1, 0))
        for key in ("candidate_values_q32", "planned_value_q32", "preference",
                    "original_observation", "planning_observation"):
            self.assertEqual(pure[key], dynamic[key])
        self.assertNotEqual(pure["preference"], joint["preference"])

    def test_pure_prior_changes_only_belief_fields_and_keeps_numeric_preference_rule(self):
        scenario = model.Scenario("pure-prior", horizon=2, initial_budget=24, initial_deadline=24)
        state = model.Observation(0, 1, 0, 0, 11, 24, 43, 64)
        real_plan = model.plan
        with patch.object(model, "plan", wraps=real_plan) as invoked:
            answer = campaign.decide(scenario, state, "prior-belief-only")
        supplied_scenario, supplied_state, supplied_arm = invoked.call_args.args
        self.assertEqual(supplied_scenario, scenario)
        self.assertEqual(supplied_state, replace(state, belief_num=1, belief_den=2))
        self.assertEqual(supplied_arm, "same-objective")
        self.assertEqual(answer["original_observation"], asdict(state))
        self.assertEqual(answer["planning_observation"], asdict(supplied_state))
        self.assertEqual(answer["preference"], model.preferences(scenario, state))

    def test_fixed_policy_is_selected_once_ex_ante_not_reselected_by_root_state(self):
        item = _fixture()
        p, ledger = campaign.read(campaign.PROTOCOL), _ledger()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with patch.object(campaign.common, "LazyBackend", ScalarTransportControl):
                result = campaign.audit_profile(item, p, {}, directory, ledger)
            rows = campaign.read(directory / "STATE_RESULTS.json.gz")
        self.assertEqual(result["status"], "passed")
        fixed = result["model_optimal_fixed"]
        self.assertEqual((fixed["arm"], fixed["fixed_action"], fixed["value_q32"]),
                         ("fixed-direct", -1, 14 * model.Q32))
        self.assertEqual(fixed["all_candidate_values_q32"], {
            "fixed-direct": 14 * model.Q32,
            "fixed-cache-0": 25 * model.Q32 // 2,
            "fixed-cache-1": 25 * model.Q32 // 2})
        by_id = {r["id"]: r for r in rows}
        statewise_selection = sum((Fraction(*root["probability"]) * max(
            by_id[root["state_id"]]["arms"][a]["whole_policy_value_q32"]
            for a in campaign.FIXED) for root in item["graph"]["roots"]), Fraction())
        self.assertEqual(statewise_selection, 15 * model.Q32)
        self.assertLess(fixed["value_q32"], statewise_selection)
        for key in ("all_candidate_planning_wall_ns", "all_candidate_evaluation_wall_ns"):
            self.assertGreater(fixed[key], 0)

    def test_runner_keeps_whole_policy_regret_distinct_from_first_action_regret(self):
        scenario = model.Scenario("continuation-control", horizon=2, initial_resident=0,
            prior0_num=1, prior0_den=1, request_p0_z0_num=1, request_p0_z0_den=1,
            signal_correct_num=1, signal_correct_den=1, dynamic_preferences=False)
        item, real_decide = _fixture(scenario), campaign.decide
        def delayed_failure(s, obs, arm, **kwargs):
            answer = real_decide(s, obs, "same-objective" if arm == "wrong-forecast" else arm, **kwargs)
            if arm == "wrong-forecast":
                answer["arm"] = arm
                if obs.step:
                    answer.update(action=None, selected_action="abstain",
                                  planned_value_q32=answer["candidate_values_q32"]["abstain"])
            return answer
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with patch.object(campaign.common, "LazyBackend", ScalarTransportControl), \
                    patch.object(campaign, "decide", side_effect=delayed_failure):
                result = campaign.audit_profile(item, campaign.read(campaign.PROTOCOL), {}, directory, _ledger())
            rows = campaign.read(directory / "STATE_RESULTS.json.gz")
        root = next(r for r in rows if r["observation"]["step"] == 0)
        comparator = root["arms"]["wrong-forecast"]
        self.assertEqual(comparator["first_action_conditional_regret_q32"], 0)
        self.assertGreater(comparator["whole_policy_regret_q32"], 0)
        self.assertEqual(result["policies"]["wrong-forecast"]["value_q32"], -73 * model.Q32 // 8)
        self.assertEqual(result["policies"]["wrong-forecast"]["expected_delivered"], [1, 1])

    def test_native_flag_with_no_actual_value_call_cannot_qualify_a_state(self):
        real_decide = campaign.decide
        def skipped_native(scenario, state, arm, **kwargs):
            answer = real_decide(scenario, state, "same-objective" if arm == "dynamic-ndu" else arm, **kwargs)
            if arm == "dynamic-ndu":
                answer.update(arm=arm, native_backend_used=True)
                self.assertEqual(answer["search"]["backend_calls"], 0)
            return answer
        item, ledger = _fixture(), _ledger()
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(campaign.common, "LazyBackend", ScalarTransportControl), \
                    patch.object(campaign, "decide", side_effect=skipped_native):
                result = campaign.audit_profile(item, campaign.read(campaign.PROTOCOL), {}, Path(temporary), ledger)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["planned_cells"], item["states"] * len(campaign.ARMS))
        self.assertEqual(result["policies"]["dynamic-ndu"]["status"], "not_run")
        self.assertEqual((ledger["dynamic-ndu"]["completed"], ledger["dynamic-ndu"]["failed"],
                          ledger["dynamic-ndu"]["not_run"]), (0, 1, item["states"] - 1))

    def test_native_failure_retains_prior_success_failed_work_and_missing_denominator(self):
        workers = []
        class FailedSecond(ScalarTransportControl):
            def __init__(self, *args):
                super().__init__(*args)
                workers.append(self)
            def evaluate(self, *args, **kwargs):
                result = super().evaluate(*args, **kwargs)
                if self.arm == "dynamic-ndu" and self.backend.calls == 2:
                    raise ValueError("injected malformed second native reply")
                return result
        item, ledger = _fixture(), _ledger()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with patch.object(campaign.common, "LazyBackend", FailedSecond):
                result = campaign.audit_profile(item, campaign.read(campaign.PROTOCOL), {}, directory, ledger)
            rows = campaign.read(directory / "STATE_RESULTS.json.gz")
            journal = [json.loads(line) for line in (directory / "dynamic-ndu.attempts.jsonl").read_text().splitlines()]
        self.assertEqual(result["status"], "failed")
        self.assertEqual(len(rows), item["states"])
        self.assertEqual(len(journal), item["states"])
        self.assertEqual(Counter(r["status"] for r in journal),
                         Counter(completed=1, failed=1, not_run=item["states"] - 2))
        self.assertEqual(result["policies"]["dynamic-ndu"]["status"], "not_run")
        self.assertEqual(ledger["dynamic-ndu"]["transitions"], 8)
        self.assertGreater(ledger["dynamic-ndu"]["planning_wall_ns"], 0)
        self.assertTrue(all(w.closed == 1 for w in workers))
        self.assertEqual(sum(result["cell_status_counts"].values()), result["planned_cells"])

    def test_shared_arm_budget_exhaustion_never_evaluates_a_partial_policy(self):
        item, p, ledger = _fixture(), campaign.read(campaign.PROTOCOL), _ledger()
        ledger["dynamic-ndu"]["transitions"] = p["per_arm_transition_cap"] - 4
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with patch.object(campaign.common, "LazyBackend", ScalarTransportControl):
                result = campaign.audit_profile(item, p, {}, directory, ledger)
            rows = campaign.read(directory / "STATE_RESULTS.json.gz")
        self.assertEqual(ledger["dynamic-ndu"]["transitions"], p["per_arm_transition_cap"])
        self.assertEqual((ledger["dynamic-ndu"]["completed"], ledger["dynamic-ndu"]["not_run"]),
                         (1, item["states"] - 1))
        self.assertEqual(result["status"], "failed")
        self.assertTrue(all("whole_policy_value_q32" not in r["arms"]["dynamic-ndu"] for r in rows))

    def test_profile_omissions_and_false_denominators_are_rejected_before_native(self):
        for mutation in ("state-count", "edge-count", "omit-node", "omit-action"):
            item = _fixture()
            if mutation == "state-count":
                item["states"] -= 1
            elif mutation == "edge-count":
                item["edges"] += 1
            elif mutation == "omit-node":
                item["graph"]["nodes"].pop()
            else:
                del item["graph"]["nodes"][0]["actions"]["abstain"]
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                with patch.object(campaign.common, "LazyBackend") as native, \
                        patch.object(campaign, "decide") as decide:
                    with self.assertRaises(ValueError):
                        campaign.audit_profile(item, campaign.read(campaign.PROTOCOL), {}, Path(temporary), _ledger())
                    native.assert_not_called()
                    decide.assert_not_called()

    def test_tampered_registration_is_rejected_before_any_profile_or_native_launch(self):
        for mutation in ("inventory", "profile-id", "scenario-with-new-graph", "omit-node-with-new-hash", "input-bytes"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                args, canonical, protocol_path = _frozen_case(temporary, [_fixture()])
                altered = deepcopy(canonical)
                if mutation == "inventory":
                    altered["inventory"]["states"] -= 1
                elif mutation == "profile-id":
                    altered["profiles"][0]["id"] = "unregistered-profile"
                elif mutation == "scenario-with-new-graph":
                    changed = replace(model.Scenario(**altered["profiles"][0]["scenario"]), prior0_num=0)
                    altered["profiles"][0] = _fixture(changed)
                elif mutation == "omit-node-with-new-hash":
                    item = altered["profiles"][0]
                    item["graph"]["nodes"].pop()
                    item["graph_sha256"] = model.digest(item["graph"])
                    item["states"] -= 1
                else:
                    Path(altered["inputs"]["value_binary"]["path"]).write_bytes(b"changed bytes")
                args.registration.write_text(json.dumps(altered), encoding="utf-8")
                with ExitStack() as stack:
                    _bound_fixture(stack, canonical, protocol_path)
                    audit = stack.enter_context(patch.object(campaign, "audit_profile"))
                    native = stack.enter_context(patch.object(campaign.common, "LazyBackend"))
                    self.assertEqual(campaign.run(args), 1)
                    audit.assert_not_called()
                    native.assert_not_called()
                report = campaign.read(args.output / "RESULT.json")
                self.assertEqual(report["status"], "rejected")

    def test_interrupted_native_profile_keeps_completed_cells_and_only_future_profiles_not_run(self):
        workers = []
        class InterruptedSecond(ScalarTransportControl):
            def __init__(self, *args):
                super().__init__(*args)
                workers.append(self)
            def evaluate(self, *args, **kwargs):
                result = super().evaluate(*args, **kwargs)
                if self.arm == "dynamic-ndu" and self.backend.calls == 2:
                    raise KeyboardInterrupt("injected partial native interruption")
                return result
        items = [_fixture(identity="first"), _fixture(identity="future")]
        with tempfile.TemporaryDirectory() as temporary:
            args, frozen, protocol_path = _frozen_case(temporary, items)
            with ExitStack() as stack:
                _bound_fixture(stack, frozen, protocol_path)
                stack.enter_context(patch.object(campaign.common, "LazyBackend", InterruptedSecond))
                self.assertEqual(campaign.run(args), 1)
            report = campaign.read(args.output / "RESULT.json")
            partial = campaign.read(args.output / "first/PARTIAL.json.gz")
            journal = [json.loads(line) for line in (args.output / "first/dynamic-ndu.attempts.jsonl").read_text().splitlines()]
            self.assertEqual(report["status"], "failed")
            self.assertEqual([p["id"] for p in report["missing_profiles"]], ["future"])
            self.assertEqual(report["profiles"][0]["id"], "first")
            self.assertEqual(report["profiles"][0]["status"], "interrupted")
            self.assertGreater(report["retained_states"], 0)
            self.assertEqual(Counter(r["status"] for r in journal), Counter(completed=1, interrupted=1))
            self.assertEqual(len(partial["rows"]), items[0]["states"])
            self.assertEqual(report["planned_cells"], sum(x["states"] for x in items) * len(campaign.ARMS))
            self.assertGreater(report["per_arm_ledgers"]["dynamic-ndu"]["transitions"], 0)
        self.assertTrue(workers)
        self.assertTrue(all(w.closed == 1 for w in workers))

    def test_postflight_source_change_retains_results_and_refuses_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            args, frozen, protocol_path = _frozen_case(temporary, [_fixture()])
            with ExitStack() as stack:
                _bound_fixture(stack, frozen, protocol_path)
                changed = {**frozen["source"], "commit": "3" * 40}
                stack.enter_context(patch.object(campaign, "source", side_effect=[frozen["source"], changed]))
                stack.enter_context(patch.object(campaign.common, "LazyBackend", ScalarTransportControl))
                self.assertEqual(campaign.run(args), 1)
            report = campaign.read(args.output / "RESULT.json")
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["checks"]["source_and_inputs_unchanged"])
        self.assertEqual(report["retained_states"], frozen["inventory"]["states"])
        self.assertEqual(report["profiles"][0]["status"], "passed")

    def test_source_inventory_binds_the_campaign_regression_file(self):
        def committed_bytes(argv, **kwargs):
            return (campaign.ROOT / argv[-1].removeprefix("HEAD:")).read_bytes()
        with patch.object(campaign.common, "source_identity", return_value={"files": {}}), \
                patch.object(campaign.subprocess, "check_output", side_effect=committed_bytes):
            observed = campaign.source()
        relative = "tests/test_hia_ndu_policy_campaign.py"
        self.assertEqual(observed["files"][relative], sha256((campaign.ROOT / relative).read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
