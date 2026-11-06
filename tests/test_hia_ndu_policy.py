"""Independent finite-oracle, resource, budget, split, and native-path checks."""
from copy import deepcopy
from contextlib import redirect_stdout
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hepta.hia_ndu_dynamic import DynamicError, JsonProcess, digest, validate_model
from hepta.hia_ndu_policy import (PolicyBudgetExhausted, TransitionBudget, policy, propose_generation,
                                  select, validate_plan, validate_policy)
from hepta.hia_ndu_module_costs import ARMS, module_models, read_cost_report, validate_cost_report
from tools.qualify_hia_ndu_dynamic import control_model, independent_exact_minimum
from tools.qualify_hia_ndu_policy_evolution import PROTOCOL, validate_protocol
from tools import qualify_hia_ndu_policy_evolution as experiment
from tools import qualify_hia_stb_service as service


class PolicyWitnessTests(unittest.TestCase):
    def test_complete_search_matches_independent_bottom_up(self):
        for seed in range(60):
            model = control_model(objects=1 + seed % 4, horizon=1 + seed % 5, seed=seed)
            result = select(model, policy(width=256), max_transitions=4096)
            self.assertTrue(result["search_complete"])
            self.assertEqual(result["plan"]["total_ns"], independent_exact_minimum(model), seed)
            self.assertFalse(result["native_ndu_evaluated"])
            self.assertEqual(result["authority"], "DENY_ALL")

    def test_approximate_policy_never_claims_its_own_oracle(self):
        for seed in range(24):
            model = control_model(objects=3, horizon=4, seed=seed)
            result = select(model, policy(width=2, lookahead=4, retention_weight=2), max_transitions=4096)
            self.assertFalse(result["search_complete"])
            self.assertGreater(result["search"]["beam_pruned"], 0)
            self.assertGreaterEqual(result["plan"]["total_ns"], independent_exact_minimum(model))
            for plan in result["candidate_plans"]:
                self.assertEqual(validate_plan(model, plan), plan)

    def test_quota_and_epoch_invalidations_are_preserved(self):
        model = control_model(objects=2, horizon=3)
        model.update(ready_mask=1, ready_epochs=[1, 0], memory_quota_bytes=64)
        model["artifacts"][0]["epochs"] = [2, 2, 3]
        result = select(model, policy(width=4))
        for plan in result["candidate_plans"]:
            for step in plan["actions"]:
                self.assertLessEqual(step["ready_after"].bit_count(), 1)
            self.assertEqual(plan["actions"][0]["invalidated"], 1)
        with self.assertRaises(DynamicError):
            select(model, policy(), fixed_mask=3)

    def test_policy_exact_types_and_unknown_fields(self):
        for key, value in (("width", True), ("lookahead", 1.0), ("retention_weight", False), ("width", 0)):
            candidate = policy()
            candidate[key] = value
            with self.assertRaises(DynamicError):
                validate_policy(candidate)
        candidate = policy()
        candidate["execute"] = True
        with self.assertRaises(DynamicError):
            validate_policy(candidate)

    def test_complete_plan_cannot_lie_about_time_or_types(self):
        model = control_model(objects=2, horizon=3)
        plan = select(model, policy())["plan"]
        for edit in (lambda p: p["actions"].pop(),
                     lambda p: p.update(total_ns=0),
                     lambda p: p["actions"][0].update(ready_after=True),
                     lambda p: p["actions"][0].update(total_ns=float(p["actions"][0]["total_ns"])),
                     lambda p: p["actions"][0].update(execution_authorized=True)):
            changed = deepcopy(plan)
            edit(changed)
            with self.assertRaises(DynamicError):
                validate_plan(model, changed)

    def test_exhaustion_does_not_return_partial_advice(self):
        model = control_model(objects=3, horizon=4)
        reference = select(model, policy(width=2), max_transitions=4096)
        count = reference["search"]["transitions"]
        with self.assertRaises(PolicyBudgetExhausted):
            select(model, policy(width=2), max_transitions=count - 1)
        self.assertEqual(select(model, policy(width=2), max_transitions=count)["plan"], reference["plan"])

    def test_value_tie_and_unaffordable_task_abstain(self):
        model = control_model(objects=1, horizon=2)
        model["completion_value_ns"] = 0
        self.assertEqual(select(model, policy())["status"], "abstain")
        model["budget_ns"] = 0
        self.assertEqual(select(model, policy())["candidate_plans"], [])

    def test_training_charges_losers_and_binds_only_supplied_models(self):
        models = [control_model(objects=2, horizon=3, seed=i) for i in range(3)]
        before = deepcopy(models)
        candidates = [policy(width=2, lookahead=h, retention_weight=1) for h in (0, 1, 2)]
        result = propose_generation(models, policy(width=2), candidates,
                                    max_transitions=4096, generation_budget=100000)
        expected = sum(o["search"]["transitions"] for c in result["candidates"] for o in c["observations"])
        self.assertEqual(result["transitions"], expected)
        self.assertEqual(result["training_model_sha256"], [digest(validate_model(m)) for m in models])
        self.assertFalse(result["final_holdout_used"])
        self.assertEqual(models, before)
        with self.assertRaises(PolicyBudgetExhausted):
            propose_generation(models, policy(width=2), candidates,
                               max_transitions=4096, generation_budget=expected - 1)
        self.assertEqual(propose_generation(models, policy(width=2), candidates,
            max_transitions=4096, generation_budget=expected)["transitions"], expected)

    def test_training_input_is_bounded_before_iteration(self):
        class Trap:
            def __iter__(self):
                raise AssertionError("unbounded iterator executed")
        with self.assertRaises(DynamicError):
            propose_generation(Trap(), policy(), [policy()], max_transitions=4096, generation_budget=10)

    def test_result_candidate_does_not_alias_model_or_selected_plan(self):
        model = control_model(objects=2, horizon=3)
        before = deepcopy(model)
        result = select(model, policy())
        saved = deepcopy(result["plan"])
        result["candidate_plans"][0]["actions"][0]["total_ns"] = 0
        self.assertEqual(result["plan"], saved)
        self.assertEqual(model, before)

    def test_registration_rejects_leakage_and_boolean_grid(self):
        p = json.loads(PROTOCOL.read_bytes())
        validate_protocol(p)
        p["final_holdout_seeds"][0] = p["training_seeds"][0]
        with self.assertRaisesRegex(DynamicError, "leakage"):
            validate_protocol(p)
        p = json.loads(PROTOCOL.read_bytes())
        p["lookahead_values"][1] = True
        with self.assertRaises(DynamicError):
            validate_protocol(p)


def synthetic_cost_report():
    """Unit fixture only. Never emitted as a native measurement receipt."""
    observations = []
    for group in range(4):
        for index, arm in enumerate(ARMS):
            observations.append({"group": group, "arm": arm, "cases": 257, "samples": 41,
                "repeats": 128, "calls": 257 * 6 * 41 * 128, "checksum": 123,
                "batch_ns": [1000 + group * 100 + sample * 7 + index * 11 for sample in range(41)],
                "load_ns": 80 + index, "first_request_ns": 100,
                "cold_delivery_ns": 180 + index, "peak_rss_kib": 1024})
    return {"schema": "hepta.hia.stb-service.report.v1", "ok": True,
        "status": "completed", "stage": "study", "source_before": {"head": "a" * 40},
        "source_after": {"head": "a" * 40}, "protocol": {"arms": list(ARMS), "groups": 4,
            "samples": 41, "evaluation_pairs": 257, "repeats": 128},
        "vm_observations": 257 * 6, "native_functional_observations": 8 * 257 * 6,
        "observations": observations, "builds": {a: {"wall_ns": 1234} for a in ARMS},
        "whole_wall_ns": 123456, "pgo": {"evaluation_rows_used": 0}}


class WholeLifecycleBudgetTests(unittest.TestCase):
    def test_failed_search_still_consumes_actual_search_work(self):
        budget = TransitionBudget(5)
        with self.assertRaises(PolicyBudgetExhausted):
            select(control_model(objects=2, horizon=3, seed=60), policy(width=2),
                   max_transitions=4096, total_budget=budget, budget_phase="failed-final")
        self.assertEqual(budget.transitions, 5)
        self.assertEqual(budget.remaining, 0)
        self.assertEqual(budget.snapshot()["phases"], [{"phase": "failed-final", "transitions": 5}])

    def test_training_all_selection_and_final_share_one_hard_limit(self):
        p = json.loads(PROTOCOL.read_bytes())
        training = [control_model(objects=2, horizon=2, seed=61)]
        selections = [[control_model(objects=2, horizon=2, seed=seed)] for seed in (62, 63, 64)]
        final = [control_model(objects=2, horizon=2, seed=65)]
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            reference = directory / "reference"
            reference.mkdir()
            budget = TransitionBudget(2_000_000)
            evolved = experiment.evolve(training, selections, p, reference, total_budget=budget)
            result = experiment.evaluate(final, evolved["policy"], 4096,
                                         total_budget=budget, budget_phase="final")
            training_work = sum(g["proposal"]["transitions"] for g in evolved["generations"])
            selection_work = sum(g[key]["search_transitions"] for g in evolved["generations"]
                                 for key in ("incumbent_selection", "candidate_selection"))
            required = training_work + selection_work + result["search_transitions"]
            self.assertEqual(budget.transitions, required)
            self.assertEqual(evolved["transitions"], training_work + selection_work)
            self.assertEqual(sum(row["transitions"] for row in budget.snapshot()["phases"]), required)
            phases = {row["phase"]: row["transitions"] for row in budget.snapshot()["phases"]}
            for generation, row in enumerate(evolved["generations"], 1):
                for label, key in (("incumbent-selection", "incumbent_selection"),
                                   ("candidate-selection", "candidate_selection")):
                    self.assertEqual(phases[f"generation-{generation}/{label}"],
                                     row[key]["search_transitions"])
            # Exact allowance succeeds; one fewer transition must fail during
            # final search. No new credit is issued after training/selection.
            for limit in (required, required - 1):
                output = directory / str(limit)
                output.mkdir()
                bounded = TransitionBudget(limit)
                value = experiment.evolve(training, selections, p, output, total_budget=bounded)
                if limit == required:
                    experiment.evaluate(final, value["policy"], 4096,
                                        total_budget=bounded, budget_phase="final")
                else:
                    with self.assertRaises(PolicyBudgetExhausted):
                        experiment.evaluate(final, value["policy"], 4096,
                                            total_budget=bounded, budget_phase="final")
                self.assertEqual(bounded.transitions, limit)
                self.assertEqual(bounded.remaining, 0)

    def test_campaign_controller_ledgers_and_oracle_role_reconcile(self):
        # Tiny synthetic models exercise the runner ledger without consuming
        # any registered final holdout or claiming native measurements.
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            p = json.loads(PROTOCOL.read_bytes())
            model = control_model(objects=1, horizon=1, seed=66)
            source = {"commit": "a" * 40}
            registration = {"schema": "hepta.hia.ndu.policy-evolution-freeze.v1",
                "protocol": p, "source": source, "native": None, "module_costs": None,
                "python": sys.version, "cpu_affinity": None,
                "models": {"training": [model], "selection": [[model]] * 3, "final": [model]}}
            path = directory / "registration.json"
            path.write_text(json.dumps(registration))
            output = directory / "campaign"
            with patch.object(experiment, "source_identity", return_value=source), \
                 patch.object(experiment, "models_for", return_value=[model]), \
                 redirect_stdout(io.StringIO()):
                code = experiment.run(SimpleNamespace(registration=str(path), output=str(output)))
            result = json.loads((output / "RESULT.json").read_bytes())
            self.assertEqual(code, 0, result.get("error"))
            ledgers = result["controller_transition_budgets"]
            self.assertEqual(set(ledgers), set(p["controller_arms"]))
            self.assertNotIn("exact", ledgers)
            self.assertEqual(result["arms"]["exact"]["role"], "independent exact oracle control")
            for name, ledger in ledgers.items():
                expected = result["arms"][name]["search_transitions"]
                if name == "learned-value":
                    expected += result["learning"]["ordinary"]["transitions"]
                elif name == "evolved-policy":
                    expected += result["learning"]["evolution"]["transitions"]
                self.assertEqual(ledger["limit"], 2_000_000)
                self.assertEqual(ledger["transitions"], expected)
                self.assertEqual(ledger["remaining"], ledger["limit"] - expected)
                self.assertEqual(sum(row["transitions"] for row in ledger["phases"]), expected)


class MeasuredCostInputTests(unittest.TestCase):
    def test_formal_import_rejects_summary_only_and_text_images(self):
        # Reproduce the reviewed bypass: valid scalar table, matching hashes,
        # and eight non-ELF files, but no original measurement evidence.
        for include_inventory in (False, True):
            with self.subTest(include_inventory=include_inventory), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                report = synthetic_cost_report()
                report["protocol"] = service.specification()
                report["claims"] = {"whole_language_soundness": False,
                    "all_input_translation_refinement": False, "performance_superiority": False,
                    "native_allocation_counters_measured": False,
                    "human_effort_measured": False, "production_authorized": False}
                for arm in ARMS:
                    image = directory / (arm + ".so")
                    image.write_bytes(b"adversarial unit fixture, not an ELF: " + arm.encode())
                    identity = service.identity(image)
                    report["builds"][arm]["artifact"] = identity
                    if arm == "hia":
                        report["builds"][arm]["receipt"] = {"ok": True,
                            "output": str(image), "artifact_sha256": identity["sha256"],
                            "artifact_bytes": identity["bytes"]}
                if include_inventory:
                    # A self-consistent shallow inventory still cannot stand
                    # in for upgrade, VM, commands, PGO, and native observations.
                    report.update(tools={}, host={})
                    (directory / "registration.json").write_text(json.dumps({
                        "protocol": report["protocol"], "source": report["source_before"],
                        "tools": {}, "host": {}}))
                    report["evidence_inventory"] = service.evidence_inventory(directory)
                path = directory / "report.json"
                path.write_text(json.dumps(report))
                # Isolate evidence admission from an unrelated dirty-checkout
                # refusal, so this regression cannot pass for the wrong reason.
                with patch.object(service, "snapshot", return_value=report["source_before"]):
                    with self.assertRaisesRegex(DynamicError, "complete native study readback failed"):
                        read_cost_report(path, expected_source=report["source_before"]["head"])

    def test_module_evidence_drift_before_completion_fails_campaign(self):
        # This tests control flow with a mocked external readback, not a native
        # measurement. A valid preflight cannot authorize stale final results.
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            p = json.loads(PROTOCOL.read_bytes())
            model = control_model(objects=1, horizon=1)
            source = {"commit": "a" * 40}
            bank = {"report": {"path": str(directory / "report.json")},
                    "native_report": {"whole_wall_ns": 123}, "qualification": {"verified": True}}
            registration = {"schema": "hepta.hia.ndu.policy-evolution-freeze.v1",
                "protocol": p, "source": source, "native": None, "module_costs": bank,
                "python": sys.version, "cpu_affinity": None,
                "models": {"training": [model], "selection": [[model]] * 3, "final": [model]}}
            path = directory / "registration.json"
            path.write_text(json.dumps(registration))
            output = directory / "campaign"
            with patch.object(experiment, "source_identity", return_value=source), \
                 patch.object(experiment, "module_models", return_value=[model]), \
                 patch.object(experiment, "read_cost_report", side_effect=[deepcopy(bank),
                     DynamicError("study evidence changed after preflight")]) as readback, \
                 redirect_stdout(io.StringIO()):
                code = experiment.run(SimpleNamespace(registration=str(path), output=str(output)))
            result = json.loads((output / "RESULT.json").read_bytes())
            self.assertEqual(readback.call_count, 2)
            self.assertEqual(code, 1)
            self.assertEqual(result["status"], "FAILED")
            self.assertIn("study evidence changed after preflight", result["error"])

    def test_missing_failed_or_incomparable_native_rows_refuse(self):
        for edit in (lambda r: r.update(ok=False), lambda r: r["observations"].pop(),
                     lambda r: r["observations"][0].update(calls=1),
                     lambda r: r["observations"][0]["batch_ns"].__setitem__(0, True),
                     lambda r: r["observations"][0].update(checksum=124),
                     lambda r: r["pgo"].update(evaluation_rows_used=1)):
            r = synthetic_cost_report()
            edit(r)
            with self.assertRaises(DynamicError):
                validate_cost_report(r)

    def test_module_model_uses_real_cost_fields_with_declared_split(self):
        bank = {"native_report": synthetic_cost_report(), "report": {"sha256": "b" * 64},
                "artifacts": {a: {"bytes": 4096, "sha256": "c" * 64} for a in ARMS}}
        training = module_models(bank, 24, split="training")
        final = module_models(bank, 24, split="final")
        self.assertEqual(training[0]["direct_ns"], [1000, 1007, 1014, 1021])
        self.assertEqual(final[0]["direct_ns"], [1200, 1207, 1214, 1221])
        self.assertEqual(training[0]["artifacts"][0]["prepare_ns"], 81)
        self.assertTrue(set(m["observation_digest"] for m in training).isdisjoint(
            m["observation_digest"] for m in final))
        for model in final:
            self.assertEqual(select(model, policy(width=2))["plan"]["total_ns"], independent_exact_minimum(model))


class NativeCostBoundaryTests(unittest.TestCase):
    """Mocked transport boundary probes, never native performance evidence."""
    def frozen_native(self, directory, *, completed=True, target="absent"):
        binary, manifest = directory / "image", directory / "build-receipt.json"
        binary.write_bytes(b"unit fixture; never executed")
        manifest.write_text(json.dumps({"schema": "hepta.hia.ndu-build.v1", "build_cost": {
            "wall_ns": 999999999, "completed": completed, "target_cache_at_start": target}}))
        return {key: {"path": str(path), "sha256": sha256(path.read_bytes()).hexdigest()}
                for key, path in (("binary", binary), ("manifest", manifest))}

    def empty_arms(self):
        return {name: {"rows": []} for name in ("beam", "learned-value", "evolved-policy")}

    def test_native_identity_drift_at_close_cannot_replace_build_cost(self):
        for changed in ("manifest", "binary"):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                native = self.frozen_native(directory)
                def close():
                    path = Path(native[changed]["path"])
                    if changed == "manifest":
                        value = json.loads(path.read_bytes())
                        value["build_cost"]["wall_ns"] = 0
                        path.write_text(json.dumps(value))
                    else:
                        path.write_bytes(b"changed during session")
                    return 17
                with patch.object(experiment, "JsonProcess") as constructor:
                    constructor.return_value.returncode = 0
                    constructor.return_value.close.side_effect = close
                    with self.assertRaisesRegex(DynamicError, "native artifact changed during experiment"):
                        experiment.native_ablation(native, [], directory, self.empty_arms())
                self.assertEqual(json.loads((directory / "native-session-close.json").read_bytes())["returncode"], 0)

    def test_incomplete_or_reused_build_is_refused_before_launch(self):
        for completed, target in ((False, "absent"), (True, "existing")):
            with self.subTest(completed=completed, target=target), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                native = self.frozen_native(directory, completed=completed, target=target)
                with patch.object(experiment, "JsonProcess") as constructor:
                    with self.assertRaisesRegex(DynamicError, "completed native build with a fresh target required"):
                        experiment.native_ablation(native, [], directory, self.empty_arms())
                    constructor.assert_not_called()

    def test_nonzero_killed_or_missing_exit_is_not_a_completed_session(self):
        for returncode in (1, -9, None, False):
            with self.subTest(returncode=returncode), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                native = self.frozen_native(directory)
                with patch.object(experiment, "JsonProcess") as constructor:
                    constructor.return_value.returncode = returncode
                    constructor.return_value.close.return_value = 17
                    with self.assertRaisesRegex(DynamicError, "native planner did not exit cleanly"):
                        experiment.native_ablation(native, [], directory, self.empty_arms())
                retained = json.loads((directory / "native-session-close.json").read_bytes())
                self.assertEqual(retained["returncode"], returncode)
                self.assertEqual(retained["close_ns"], 17)


@unittest.skipUnless(os.environ.get("HEPTA_DYNAMIC_POLICY_BINARY") and os.environ.get("HEPTA_DYNAMIC_POLICY_MANIFEST"),
                     "source-pinned supplied-path native bridge is optional")
class OriginalNduSuppliedPathTests(unittest.TestCase):
    def test_policy_candidates_native_ablation_and_refusals(self):
        with tempfile.TemporaryDirectory() as temporary:
            process = JsonProcess(os.environ["HEPTA_DYNAMIC_POLICY_BINARY"],
                os.environ["HEPTA_DYNAMIC_POLICY_MANIFEST"], role="--planner-stream",
                log=Path(temporary) / "frames.jsonl")
            try:
                for seed in range(8):
                    model = control_model(objects=3, horizon=4, seed=seed)
                    advice = select(model, policy(width=2, lookahead=2, retention_weight=1))
                    paths = [[a["ready_after"] for a in p["actions"]] for p in advice["candidate_plans"]]
                    plain, _ = process.evaluate(model, "supplied", paths=paths)
                    native, _ = process.evaluate(model, "supplied_ndu", paths=paths)
                    self.assertEqual(plain["bundle"], native["bundle"])
                    self.assertEqual(plain["pareto_candidate_ids"], native["pareto_candidate_ids"])
                    self.assertEqual(native["search"]["transitions"], 0)
                    self.assertIsNotNone(native["ndu_evaluation"])
                for paths in ([[]], [[True] * 4], [[0] * 4, [0] * 4]):
                    with self.assertRaises(DynamicError):
                        process.evaluate(model, "supplied_ndu", paths=paths)
                # Native separately rejects an over-quota candidate even when
                # the caller bypasses the Python proposal generator.
                model.update(ready_mask=0, ready_epochs=[0] * 3, memory_quota_bytes=64)
                with self.assertRaises(DynamicError):
                    process.evaluate(model, "supplied_ndu", paths=[[7] * 4])
            finally:
                process.close()


if __name__ == "__main__":
    unittest.main()
