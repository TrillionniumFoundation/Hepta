#!/usr/bin/env python3
"""Freeze and execute the four NDU feedback gates with original native values.

Successful execution is separate from positive benefit. Every planned cell,
failed attempt and scientific audit remains in the evidence. No deployment.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, replace
from fractions import Fraction
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import platform
import random
import statistics
import subprocess
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.hia_ndu_feedback_20261106 import model
from experiments.hia_ndu_feedback_20261106.native import NativeValueBackend
from experiments.hia_ndu_feedback_20261106.workload import NativeCache, calibrate

PROTOCOL = ROOT / "benchmarks/hia_ndu_feedback/PROTOCOL.json"
NATIVE_ARMS = ("fixed-preference-ndu", "dynamic-ndu", "dynamic-ndu-gated", "dynamic-ndu-priced")


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")


def identity(path):
    p = Path(path).resolve(strict=True)
    return {"path": str(p), "bytes": p.stat().st_size, "sha256": sha256(p.read_bytes()).hexdigest()}


def source_identity():
    def git(*args):
        return subprocess.check_output(["git", "--no-replace-objects", *args], cwd=ROOT,
            env={k: v for k, v in os.environ.items() if not k.startswith("GIT_")}).decode().strip()
    if git("status", "--porcelain"):
        raise ValueError("source must be committed and clean before freezing or running")
    names = git("ls-files", "hepta", "experiments/hia_ndu_feedback_20261106",
                "rust/hia-ndu-value", "rust/hia-ndu-dynamic-model", "benchmarks/hia_ndu_feedback",
                "tools/build_hia_ndu_bridge.py", "tools/build_hia_ndu_value_bridge.py",
                "tools/qualify_hia_ndu_feedback.py", "tools/qualify_hia_ndu_compute_price.py", "tools/qualify_hia_ndu_witnesses.py",
                "benchmarks/hia_ndu_feedback_state_coverage", "tests/test_hia_ndu_feedback.py",
                "tests/test_hia_ndu_feedback_workload.py", "tests/test_hia_ndu_feedback_campaign.py",
                "tests/test_hia_ndu_compute_price.py", "tests/test_hia_ndu_economical.py",
                "tests/test_hia_ndu_compute_debit.py",
                "tests/test_hia_ndu_feedback_coverage.py").splitlines()
    files = {}
    for name in names:
        raw = (ROOT / name).read_bytes()
        expected = git("rev-parse", "HEAD:" + name)
        observed = __import__("hashlib").sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        if expected != observed:
            raise ValueError("canonical source bytes differ: " + name)
        files[name] = sha256(raw).hexdigest()
    return {"commit": git("rev-parse", "HEAD"), "tree": git("rev-parse", "HEAD^{tree}"), "files": files}


def validate_protocol(p):
    if p.get("schema") != "hepta.hia.ndu.feedback-protocol.v1" or tuple(p["arms"]) != model.ARMS:
        raise ValueError("protocol identity or arm inventory")
    train, final = p["training_seeds"], p["holdout_seeds"]
    if (any(type(s) is not int or s < 0 for s in train + final)
            or len(set(train + final)) != len(train + final) or not train or not final):
        raise ValueError("split leakage or malformed seeds")
    if set(p["environments"]) != set(model.SCENARIOS) or p["horizon"] != 3:
        raise ValueError("registered environments or horizon")
    if set(p["calibration_dimensions"]) & set(p["native_dimensions"]):
        raise ValueError("native dimension split leakage")
    if p["additional_diagnostic_arm"] != "dynamic-ndu-gated":
        raise ValueError("compute gate control missing")
    for key in ("native_repetitions", "calibration_samples", "native_kernel_repeats",
                "native_episode_budget_ns", "max_transitions_per_decision", "max_transitions_per_arm"):
        if type(p[key]) is not int or p[key] <= 0:
            raise ValueError("invalid protocol bound: " + key)
    return p


def validate_build_ledger(content, expected_manifest_sha):
    if (type(content) is not dict or content.get("schema") != "hepta.hia.ndu.feedback-build-attempts.v1"
            or type(content.get("attempts")) is not list or not 1 <= len(content["attempts"]) <= 100):
        raise ValueError("invalid build attempt ledger")
    seen = set()
    for row in content["attempts"]:
        info = row["receipt"]
        if identity(info["path"]) != info or info["sha256"] in seen:
            raise ValueError("build attempt identity changed or duplicated")
        seen.add(info["sha256"])
        cost = json.loads(Path(info["path"]).read_text())["build_cost"]
        if row["build_cost"] != cost or type(cost["wall_ns"]) is not int or cost["wall_ns"] < 0:
            raise ValueError("build attempt cost differs from receipt or is not nonnegative integer")
    if expected_manifest_sha not in seen:
        raise ValueError("build ledger omits the admitted value build")
    return content


def freeze(args):
    p = validate_protocol(json.loads(PROTOCOL.read_text()))
    inputs = {name: identity(getattr(args, name)) for name in
              ("workload_binary", "workload_manifest", "value_binary", "value_manifest")}
    receipts = {}
    for prefix in ("workload", "value"):
        receipt = json.loads(Path(inputs[prefix + "_manifest"]["path"]).read_text())
        if receipt["binary_sha256"] != inputs[prefix + "_binary"]["sha256"]:
            raise ValueError("build/binary mismatch")
        receipts[prefix] = receipt
    ledger = None
    if args.build_attempt_ledger:
        ledger = {"identity": identity(args.build_attempt_ledger),
                  "content": json.loads(Path(args.build_attempt_ledger).read_text())}
        validate_build_ledger(ledger["content"], inputs["value_manifest"]["sha256"])
    write(args.output, {"schema": "hepta.hia.ndu.feedback-freeze.v1", "source": source_identity(),
        "protocol": p, "protocol_sha256": sha256(PROTOCOL.read_bytes()).hexdigest(), "inputs": inputs,
        "scenarios": {k: asdict(v) for k, v in model.SCENARIOS.items()},
        "created_unix_ns": time.time_ns(), "python": sys.version, "platform": platform.platform(),
        "allowed_cpus": sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None,
        "build_receipts": receipts, "build_attempt_ledger": ledger,
        "authority": "DENY_ALL", "production_activation": False})
    print(json.dumps({"registration": str(args.output), "source": source_identity()["commit"]}))


class LazyBackend:
    def __init__(self, inputs, log):
        self.inputs, self.log, self.backend = inputs, log, None

    def evaluate(self, *args, **kwargs):
        if self.backend is None:
            self.backend = NativeValueBackend(self.inputs["value_binary"]["path"],
                self.inputs["value_manifest"]["path"], log=self.log)
        return self.backend.evaluate(*args, **kwargs)

    def close(self):
        if self.backend is None:
            return {"started": False, "calls": 0, "startup_ns": 0, "close_ns": 0, "returncode": None}
        self.backend.close()
        if self.backend.returncode != 0:
            raise ValueError("native value process failed on close")
        return {"started": True, "calls": self.backend.calls, "startup_ns": self.backend.startup_ns,
                "close_ns": self.backend.close_ns, "returncode": self.backend.returncode,
                "call_wall_ns": self.backend.total_call_ns}


def decide(scenario, observation, arm, backend, fixed_action, cap):
    if arm == "dynamic-ndu-gated":
        if not hasattr(model, "plan_gated"):
            raise ValueError("registered compute-value gate is not implemented")
        return model.plan_gated(scenario, observation, backend=backend, max_transitions=cap,
                                )
    return model.plan(scenario, observation, arm, backend=backend, fixed_action=fixed_action,
                      max_transitions=cap)


def derived_native_scenario(base, calibration, n, p):
    points = sorted(int(k) for k in calibration["models"])
    lower, upper = points[0], points[-1]
    fraction = max(0.0, min(1.0, (n - lower) / (upper - lower)))
    def prediction(key):
        if key == "retire":
            return round(statistics.median(calibration["models"][str(v)]["retire_ns"] for v in points))
        left = calibration["models"][str(lower)][key + "_ns"] / lower**2
        right = calibration["models"][str(upper)][key + "_ns"] / upper**2
        return max(1, round((left + fraction * (right - left)) * n**2))
    direct, hot = prediction("direct"), prediction("packed")
    if hot > direct:
        raise ValueError("training forecast cannot support the registered hot<=direct candidate model")
    return replace(base, direct_cost=direct, hot_cost=hot, load_cost=prediction("prepare"),
                   retire_cost=prediction("retire"), cost_unit=max(1, direct // 6),
                   initial_budget=p["native_episode_budget_ns"], initial_deadline=p["native_episode_budget_ns"],
                   cost_unit_label="observed online controller plus workload nanoseconds")


def episode(scenario, seed, arm, *, fixed_action, inputs, output, native, n, repeats, cap,
            remaining_transitions=2000000, decision_function=None, compute_profile=None):
    """Keep partial failures and cleanup in the original planned denominator."""
    began = time.monotonic_ns()
    result = {"scenario": scenario.name, "seed": seed, "arm": arm, "native_workload": native,
              "planned_requests": scenario.horizon, "delivered": 0, "steps": [], "status": "running",
              "errors": [], "failed_search_transitions": 0,
              "authority": "DENY_ALL", "production_activation": False}
    backend, worker, online_started = None, None, None
    env = model.FeedbackEnvironment(scenario, seed)
    try:
        if compute_profile is not None:
            from experiments.hia_ndu_feedback_20261106.compute_debit import (
                dispatch_after_compute, validate_profile)
            from experiments.hia_ndu_feedback_20261106.compute_plan import plan as compute_plan
            validate_profile(compute_profile, scenario)
            if not native:
                raise ValueError("observed compute-resource debits require the real-workload route")
            result["compute_debit_profile"] = asdict(compute_profile)
            result["hard_realtime_guarantee"] = False
        if arm in NATIVE_ARMS:
            backend = LazyBackend(inputs, output / "values.jsonl")
        if native:
            worker = NativeCache(inputs["workload_binary"]["path"], inputs["workload_manifest"]["path"],
                                 output / "workload.jsonl", n=n, seed=seed)
            if scenario.initial_resident >= 0:
                worker._ask({"command": "prepare", "id": scenario.initial_resident, "epoch": 1})
            if worker.resident != scenario.initial_resident:
                raise ValueError("initial cache does not match observed state")
        online_started = time.monotonic_ns()
        while not env.done:
            step_start = time.monotonic_ns()
            observation = env.observe()
            spent = sum(r["decision"]["search"]["transitions"] for r in result["steps"])
            allowance = min(cap, remaining_transitions-spent)
            if allowance <= 0:
                raise model.SearchBudgetExhausted("controller lifecycle budget exhausted before next decision")
            try:
                if compute_profile is not None and decision_function is None:
                    selected = compute_plan(scenario, observation, arm, backend=backend,
                        fixed_action=fixed_action, max_transitions=allowance, compute_profile=compute_profile)
                else:
                    selected = (decision_function or decide)(scenario, observation, arm, backend, fixed_action, allowance)
            except Exception as error:
                consumed = getattr(error, "search_stats", {}).get("transitions",
                    getattr(error, "transitions", allowance if isinstance(error, model.SearchBudgetExhausted) else 0))
                result["failed_search_transitions"] += consumed
                result["failed_search_statistics"] = getattr(error, "search_stats", {})
                if hasattr(error, "cost_receipt"):
                    result["failed_controller_cost_receipt"] = error.cost_receipt
                raise
            decision_elapsed = time.monotonic_ns() - step_start
            row = {"decision": selected, "observed_decision_wall_ns": decision_elapsed}
            result["steps"].append(row)
            if compute_profile is not None:
                def execute_guarded(remaining, action):
                    if remaining.resident != worker.resident:
                        raise ValueError("observed/physical cache diverged before dispatch")
                    return worker.execute(action, remaining.request, repeats=repeats,
                        vector_seed=(seed * 131 + remaining.step * 17) & 0xffffffff,
                        expected_state_digest=worker.state_digest)
                try:
                    row.update(dispatch_after_compute(env, selected, compute_profile,
                        step_started_ns=step_start, execute=execute_guarded))
                except BaseException as error:
                    if hasattr(error, "compute_debit_receipt"):
                        row["compute_debit"] = error.compute_debit_receipt
                    raise
                if worker.resident != row["outcome"]["resident_after"]:
                    raise ValueError("selected/physical/next observed action mismatch")
            elif selected["action"] is None:
                row["outcome"] = env.step(None, actual_cost=decision_elapsed if native else 0)
            elif native:
                if decision_elapsed > min(observation.budget, observation.deadline):
                    row["outcome"] = env.step(None, actual_cost=decision_elapsed)
                    row["outcome"]["status"] = "controller_deadline_exceeded"
                    row["selected_action_was_not_executed"] = True
                else:
                    if observation.resident != worker.resident:
                        raise ValueError("observed/physical cache diverged before dispatch")
                    actual = worker.execute(selected["action"], observation.request, repeats=repeats,
                        vector_seed=(seed * 131 + observation.step * 17) & 0xffffffff,
                        expected_state_digest=worker.state_digest)
                    row["native_execution"] = actual
                    row["outcome"] = env.step(selected["action"], actual_cost=time.monotonic_ns()-step_start)
                    if worker.resident != row["outcome"]["resident_after"]:
                        raise ValueError("selected/physical/next observed action mismatch")
            else:
                row["outcome"] = env.step(selected["action"])
            result["delivered"] += int(row["outcome"]["delivered"])
        result["status"] = "completed" if result["delivered"] == scenario.horizon else "incomplete"
    except BaseException as error:
        result["status"] = "failed"
        result["errors"].append({"type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()})
    finally:
        result["online_wall_ns"] = 0 if online_started is None else time.monotonic_ns()-online_started
        for label, obj in (("workload_close", worker), ("native_close", backend)):
            if obj is not None:
                try:
                    result[label] = obj.close()
                except BaseException as error:
                    result["status"] = "failed"
                    result["errors"].append({"type": type(error).__name__, "message": str(error), "phase": label})
        if worker is not None:
            result["workload_attempts"] = worker.rows
            result["workload_startup_ns"] = worker.startup_ns
        result["episode_wall_ns"] = time.monotonic_ns() - began
        result["search_transitions"] = result["failed_search_transitions"] + sum(r["decision"]["search"]["transitions"] for r in result["steps"])
        result["backend_calls"] = result.get("failed_search_statistics", {}).get("backend_calls", 0) + sum(
            r["decision"]["search"]["backend_calls"] for r in result["steps"])
        result["backend_call_count_scope"] = "attempted value calls, including failed search; native_close.calls counts exchanges completed by the transport"
        result["actual_cost"] = sum(r.get("outcome", {}).get("cost", 0) for r in result["steps"])
        result["workload_wall_ns"] = sum(r["workload_wall_ns"] for r in worker.rows) if worker is not None else 0
        result["cost_with_outcome_record_ns"] = result["actual_cost"] if native else None
        result["online_cost_outside_outcome_records_ns"] = max(0, result["online_wall_ns"]-result["actual_cost"]) if native else None
        result["cost_accounting_note"] = "episode_wall retains every failed/partial action; workload_wall uses all worker attempts; online remainder includes failed planning, between-step bookkeeping and actions without an outcome"
        utility = 0
        for r in reversed(result["steps"]):
            outcome = r.get("outcome")
            if outcome:
                utility = outcome["reward_q32"] + model.mul_q32(outcome["discount_q32"], utility)
        result["realized_discounted_utility_q32"] = utility if result["status"] != "failed" else None
        result["realized_utility_scope"] = "pathwise registered reward/discount; not an unbiased nested-risk objective sample"
        result["online_budget_scope"] = "observation through decision and dispatch; initialization/cleanup are additionally included in episode wall"
        result["missing_requests"] = scenario.horizon-result["delivered"]
    return result


def audit_episode(scenario, result, cap):
    if result.get("compute_debit_profile") is not None or any(
            step.get("decision", {}).get("compute_debit") is not None for step in result["steps"]):
        raise ValueError("v1 oracle audit cannot qualify the compute-resource model; a profile-aware independent audit is required")
    began = time.monotonic_ns()
    rows = []
    for step in result["steps"]:
        choice = step["decision"]
        obs = model.Observation(**choice["observation"])
        oracle = model.independent_oracle(scenario, obs, max_transitions=cap)
        chosen = choice["selected_action"] or "abstain"
        conditional = oracle["candidate_values_q32"].get(chosen)
        regret = None if conditional is None else oracle["value_q32"]-conditional
        priced = result["arm"] in ("same-objective-priced", "dynamic-ndu-priced")
        gate = choice.get("compute_gate", {})
        same_target = (result["arm"] in ("same-objective", "dynamic-ndu", "dynamic-ndu-gated", "exact-oracle")
                       or priced and gate.get("invoke") is True)
        matches = (oracle.get("eligibility", {}).get(chosen, conditional is not None)
                   and conditional == oracle["value_q32"] and choice["value_q32"] == oracle["value_q32"]) if same_target else None
        fixed_ablation = None
        priced_incumbent_agrees = None
        priced_bound_valid = None
        if priced:
            priced_bound_valid = (type(gate.get("invoke")) is bool
                                  and type(gate.get("optimal_upper_q32")) is int
                                  and oracle["value_q32"] <= gate["optimal_upper_q32"])
            if gate.get("invoke") is False:
                greedy = model.plan(scenario, obs, "state-greedy", max_transitions=cap)
                priced_incumbent_agrees = (choice["action"], choice["value_q32"], choice["candidate_values_q32"]) == (
                    greedy["action"], greedy["value_q32"], greedy["candidate_values_q32"])
        if result["arm"] in ("dynamic-ndu", "dynamic-ndu-gated"):
            fixed = model.plan(scenario, obs, "fixed-preference-ndu", backend=model.scalar_backend,
                               max_transitions=cap)
            fixed_ablation = {"scope": "offline scalar implementation of fixed numerical preference, same belief/model/search",
                "action": fixed["selected_action"], "dynamic_action": choice["selected_action"],
                "action_changes": fixed["action"] != choice["action"],
                "numeric_preferences_change": fixed["preference"] != choice["preference"],
                "fixed_selected_external_value_q32": oracle["candidate_values_q32"].get(fixed["selected_action"])}
        rows.append({"state_digest": obs.state_digest, "oracle_value_q32": oracle["value_q32"],
                     "oracle_action": oracle["selected_action"], "selected_conditional_regret_q32": regret,
                     "same_objective_required": same_target, "same_objective_agrees": matches,
                     "canonical_action_agrees": choice["action"] == oracle["action"],
                     "priced_incumbent_agrees": priced_incumbent_agrees,
                     "priced_optimal_upper_valid": priced_bound_valid,
                     "fixed_preference_ablation": fixed_ablation,
                     "search_transitions": oracle["search"]["transitions"]})
    return {"rows": rows, "wall_ns": time.monotonic_ns()-began,
            "online_controller_access": False, "authority": "DENY_ALL"}


def paired_intervals(differences):
    """Resample seed-level paired means, not correlated repetitions as IID."""
    if not differences:
        return None
    rng = random.Random(530771)
    boot = sorted(statistics.mean(rng.choices(differences, k=len(differences))) for _ in range(2000))
    return {"paired_mean_difference_ns": statistics.mean(differences),
            "exploratory_bootstrap_95_ns": [boot[49], boot[1949]], "independent_seed_count": len(differences),
            "scope": "exploratory finite generated-input study; shared-host timing and small sample"}


def summarize(rows, p, offline):
    tables, comparisons = {}, []
    for native in (False, True):
        category = "native" if native else "model"
        tables[category] = {}
        for family in p["environments"]:
            tables[category][family] = {}
            for arm in [*p["arms"], p["additional_diagnostic_arm"]]:
                cells = [r for r in rows if r["native_workload"] is native and r["scenario"] == family and r["arm"] == arm]
                expected = {(seed, dimension, repetition) for seed in p["holdout_seeds"]
                            for dimension in (p["native_dimensions"] if native else [0])
                            for repetition in range(p["native_repetitions"] if native else 1)}
                observed = [(r["seed"], r["dimension"], r["repetition"]) for r in cells]
                tables[category][family][arm] = {"episodes": len(cells),
                    "planned_episodes": len(expected), "missing_cells": len(expected-set(observed)),
                    "duplicate_cells": len(observed)-len(set(observed)),
                    "unexpected_cells": len(set(observed)-expected),
                    "planned_requests": len(expected)*p["horizon"],
                    "delivered": sum(r["delivered"] for r in cells),
                    "failed_episodes": sum(r["status"] == "failed" for r in cells),
                    "incomplete_episodes": sum(r["status"] != "completed" for r in cells),
                    "episode_wall_ns": sum(r["episode_wall_ns"] for r in cells),
                    "workload_wall_ns": sum(r["workload_wall_ns"] for r in cells),
                    "actual_cost": sum(r["actual_cost"] for r in cells),
                    "search_transitions": sum(r["search_transitions"] for r in cells),
                    "backend_calls": sum(r["backend_calls"] for r in cells),
                    "unique_numeric_preferences": sorted({(step["decision"]["preference"]["price_q32"],
                        step["decision"]["preference"]["discount_q32"], step["decision"]["preference"]["risk_q32"])
                        for r in cells for step in r["steps"]}),
                    "compute_gate_skips": sum(not step["decision"].get("compute_gate", {}).get("invoke", True)
                        for r in cells for step in r["steps"]),
                    "realized_path_utility_q32": None if any(r["realized_discounted_utility_q32"] is None for r in cells)
                        else sum(r["realized_discounted_utility_q32"] for r in cells)}
            if native:
                for arm in p["arms"]:
                    if arm in ("dynamic-ndu", "exact-oracle"):
                        continue
                    diffs = []
                    for seed in p["holdout_seeds"]:
                        a = [r for r in rows if r["native_workload"] and r["scenario"] == family and r["seed"] == seed and r["arm"] == "dynamic-ndu"]
                        b = [r for r in rows if r["native_workload"] and r["scenario"] == family and r["seed"] == seed and r["arm"] == arm]
                        expected_keys = {(n, repeat) for n in p["native_dimensions"] for repeat in range(p["native_repetitions"])}
                        a_map = {(r["dimension"], r["repetition"]): r for r in a}
                        b_map = {(r["dimension"], r["repetition"]): r for r in b}
                        if (len(a) == len(a_map) == len(b) == len(b_map) == len(expected_keys)
                                and set(a_map) == set(b_map) == expected_keys):
                            diffs.append(statistics.mean(a_map[key]["episode_wall_ns"]-b_map[key]["episode_wall_ns"] for key in expected_keys))
                    row = {"environment": family, "dynamic_minus_control": arm, **(paired_intervals(diffs) or {})}
                    dynamic, control = tables[category][family]["dynamic-ndu"], tables[category][family][arm]
                    row["dynamic_all_delivered"] = (dynamic["delivered"] == dynamic["planned_requests"]
                        and dynamic["planned_requests"] > 0 and dynamic["missing_cells"] == dynamic["duplicate_cells"] == dynamic["unexpected_cells"] == 0)
                    row["control_all_delivered"] = (control["delivered"] == control["planned_requests"]
                        and control["missing_cells"] == control["duplicate_cells"] == control["unexpected_cells"] == 0)
                    row["observed_online_gain_ns"] = control["episode_wall_ns"]-dynamic["episode_wall_ns"]
                    additional_build = 0 if arm in NATIVE_ARMS else offline["value_all_build_attempts_wall_ns"]
                    row["observed_lifecycle_gain_by_deployments_ns"] = {
                        str(count): row["observed_online_gain_ns"]*count - additional_build
                        for count in p["deployment_counts"]}
                    row["allocated_additional_build_ns"] = additional_build
                    row["allocation_scope"] = "matched episode cohorts repeated; conservative allocation of all recorded value build attempts including failures versus non-native controls; value build also cancels versus fixed-preference NDU; shared calibration/workload build cancel; unknown historical costs excluded"
                    comparisons.append(row)
    return {"tables": tables, "paired_comparisons": comparisons}


def run(args):
    outer = time.monotonic_ns()
    frozen = json.loads(Path(args.registration).read_text())
    p = validate_protocol(frozen["protocol"])
    if p != json.loads(PROTOCOL.read_text()):
        raise ValueError("registered protocol content differs from its frozen source")
    if frozen["scenarios"] != {k: asdict(v) for k, v in model.SCENARIOS.items()}:
        raise ValueError("registered scenario content differs from its frozen source")
    if frozen["source"] != source_identity() or frozen["protocol_sha256"] != sha256(PROTOCOL.read_bytes()).hexdigest():
        raise ValueError("frozen source/protocol mismatch")
    for item in frozen["inputs"].values():
        if identity(item["path"]) != item:
            raise ValueError("frozen input changed")
    for prefix in ("value", "workload"):
        if frozen["build_receipts"][prefix] != json.loads(Path(frozen["inputs"][prefix+"_manifest"]["path"]).read_text()):
            raise ValueError("registered build cost content differs from its frozen receipt")
    ledger = frozen.get("build_attempt_ledger")
    if ledger:
        if identity(ledger["identity"]["path"]) != ledger["identity"]:
            raise ValueError("frozen development ledger changed")
        if ledger["content"] != json.loads(Path(ledger["identity"]["path"]).read_text()):
            raise ValueError("registered development ledger content differs from its file")
        validate_build_ledger(ledger["content"], frozen["inputs"]["value_manifest"]["sha256"])
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=False)
    inputs = frozen["inputs"]
    write(output / "REGISTRATION.json", frozen)
    offline, rows, audit_rows = {}, [], []
    gates = {}
    fatal = None
    try:
        with_values = LazyBackend(inputs, output / "gate-values.jsonl")
        try:
            began = time.monotonic_ns()
            gates["wiring"] = model.wiring_probes(with_values)
            gates["degeneration"] = model.degeneration_probe(with_values)
            offline["mechanism_gates_wall_ns"] = time.monotonic_ns()-began
        finally:
            gates["native_close"] = with_values.close()
        write(output / "GATES.json", gates)
        calibration = calibrate(inputs["workload_binary"]["path"], inputs["workload_manifest"]["path"],
            output / "calibration", dimensions=p["calibration_dimensions"], seeds=p["training_seeds"],
            samples=p["calibration_samples"], repeats=p["native_kernel_repeats"])
        write(output / "CALIBRATION.json", calibration)
        offline["calibration_wall_ns"] = calibration["wall_ns"]
        scenarios = {name: model.SCENARIOS[name] for name in p["environments"]}
        native_scenarios = {(name, n): derived_native_scenario(base, calibration, n, p)
                            for name, base in scenarios.items() for n in p["native_dimensions"]}
        choices = {}
        began = time.monotonic_ns()
        for name, scenario in scenarios.items():
            choices[(False, name, 0)] = model.select_fixed(scenario, p["training_seeds"])
        for (name, n), scenario in native_scenarios.items():
            choices[(True, name, n)] = model.select_fixed(scenario, p["training_seeds"])
        offline["fixed_selection_wall_ns"] = time.monotonic_ns()-began
        write(output / "TRAINING.json", [{"native": k[0], "environment": k[1], "n": k[2], "selection": v} for k, v in choices.items()])
        write(output / "SCENARIOS.json", {"model": {k: asdict(v) for k, v in scenarios.items()},
              "native": [{"environment": k[0], "n": k[1], "scenario": asdict(v)} for k, v in native_scenarios.items()]})
        arms = [*p["arms"], p["additional_diagnostic_arm"]]
        planned = []
        for native in (False, True):
            for index, name in enumerate(p["environments"]):
                for n in p["native_dimensions"] if native else [0]:
                    for si, seed in enumerate(p["holdout_seeds"]):
                        for repeat in range(p["native_repetitions"] if native else 1):
                            rotation = (index + si + repeat) % len(arms)
                            order = arms[rotation:] + arms[:rotation]
                            if (si + repeat) % 2:
                                order = list(reversed(order))
                            planned.extend({"native": native, "environment": name, "n": n, "seed": seed,
                                            "repeat": repeat, "arm": arm} for arm in order)
        write(output / "PLANNED.json", planned)
        work_budgets = {arm: 0 for arm in arms}
        work_budgets["fixed"] = sum(c["training_search_transitions"] for choice in choices.values()
                                     for c in choice["all_candidates"])
        for index, cell in enumerate(planned):
            native, name, n, seed, arm = [cell[k] for k in ("native", "environment", "n", "seed", "arm")]
            scenario = native_scenarios[(name, n)] if native else scenarios[name]
            directory = output / "episodes" / f"{index:04d}"
            directory.mkdir(parents=True)
            remaining = p["max_transitions_per_arm"]-work_budgets[arm]
            result = episode(scenario, seed, arm, fixed_action=choices[(native, name, n)]["action"],
                inputs=inputs, output=directory, native=native, n=n, repeats=p["native_kernel_repeats"],
                cap=p["max_transitions_per_decision"], remaining_transitions=remaining)
            result.update(cell_index=index, dimension=n, repetition=cell["repeat"])
            work_budgets[arm] += result["search_transitions"]
            if work_budgets[arm] > p["max_transitions_per_arm"]:
                raise ValueError("controller lifecycle transition budget exceeded")
            write(directory / "RESULT.json", result)
            rows.append(result)
            # Diagnostics run only after execution; their cost never hides in a controller.
            audit = audit_episode(scenario, result, p["max_transitions_per_decision"])
            audit.update(cell_index=index, arm=arm, scenario=name)
            write(directory / "ORACLE_AUDIT.json", audit)
            audit_rows.append(audit)
            if index % 16 == 0 or index + 1 == len(planned):
                print(json.dumps({"completed": index+1, "planned": len(planned), "failures": sum(r["status"] == "failed" for r in rows)}), flush=True)
        offline["oracle_audit_wall_ns"] = sum(a["wall_ns"] for a in audit_rows)
        offline["transition_budgets"] = work_budgets
        began = time.monotonic_ns()
        diagnostics = []
        for family, scenario in scenarios.items():
            for seed in p["holdout_seeds"]:
                for arm in p["model_diagnostic_arms"]:
                    item = model.run_episode(scenario, seed, arm, max_transitions=p["max_transitions_per_decision"])
                    item["post_execution_audit"] = audit_episode(scenario, item, p["max_transitions_per_decision"])
                    diagnostics.append(item)
        offline["model_error_diagnostics_wall_ns"] = time.monotonic_ns()-began
        write(output / "MODEL_DIAGNOSTICS.json", {"scope": "registered deliberate forecast/preference interventions; no retuning",
              "episodes": diagnostics, "wall_ns": offline["model_error_diagnostics_wall_ns"],
              "gradient_updates": 0, "U_or_Z_used_as_gradient": False,
              "parameter_gradient_claim": "not applicable: no differentiable model or policy parameters are trained in this qualification"})
    except BaseException as error:
        fatal = {"type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()}
    for prefix in ("workload", "value"):
        receipt = frozen["build_receipts"][prefix]
        offline[prefix + "_build_wall_ns"] = receipt["build_cost"]["wall_ns"]
        offline[prefix + "_build_cost"] = receipt["build_cost"]
    offline["value_all_build_attempts_wall_ns"] = (sum(row["build_cost"]["wall_ns"] for row in ledger["content"]["attempts"])
        if ledger else offline["value_build_wall_ns"])
    offline["value_build_attempts"] = ledger["content"]["attempts"] if ledger else "only supplied successful build known"
    offline["unknown_costs"] = ["historical engineering", "human review", "monetary fees", "energy", "long-term operation"]
    input_errors = []
    for name, item in inputs.items():
        try:
            if identity(item["path"]) != item:
                input_errors.append(name + " changed")
        except Exception as error:
            input_errors.append(name + ": " + str(error))
    try:
        source_unchanged = source_identity() == frozen["source"]
    except Exception as error:
        source_unchanged = False
        input_errors.append("source: " + str(error))
    checks = {
        "wiring_passed": gates.get("wiring", {}).get("all_passed", False),
        "same_objective_values_actions_agree": bool(audit_rows) and all(r["same_objective_agrees"] is not False for a in audit_rows for r in a["rows"]),
        "all_planned_cells_retained": fatal is None and len(rows) == len(planned),
        "all_requests_delivered": bool(rows) and all(r["status"] == "completed" for r in rows),
        "source_unchanged": source_unchanged,
        "frozen_inputs_unchanged": not input_errors,
    }
    summary = summarize(rows, p, offline)
    checks["independent_net_gain"] = fatal is None and all(checks.values()) and bool(summary["paired_comparisons"]) and all(
        c["dynamic_all_delivered"] and c["control_all_delivered"] and min(c["observed_lifecycle_gain_by_deployments_ns"].values()) > 0
        for c in summary["paired_comparisons"])
    result = {"schema": "hepta.hia.ndu.feedback-result.v1", "source": frozen["source"],
        "status": "failed" if fatal else "completed", "fatal_error": fatal, "checks": checks,
        "input_postflight_errors": input_errors,
        "numeric_preference_contribution": {"offline_observations": sum(r["fixed_preference_ablation"] is not None for a in audit_rows for r in a["rows"]),
            "numeric_changes": sum(bool(r["fixed_preference_ablation"] and r["fixed_preference_ablation"]["numeric_preferences_change"]) for a in audit_rows for r in a["rows"]),
            "action_changes": sum(bool(r["fixed_preference_ablation"] and r["fixed_preference_ablation"]["action_changes"]) for a in audit_rows for r in a["rows"]),
            "scope": "post-execution same-belief fixed-numerical-preference scalar counterfactual; no online access"},
        "planned_episode_count": (len(p["environments"])*len(p["holdout_seeds"])*(len(p["arms"])+1)
            *(1 + len(p["native_dimensions"])*p["native_repetitions"])),
        "retained_episode_count": len(rows), "offline_costs": offline, **summary,
        "wall_before_report_ns": time.monotonic_ns()-outer, "authority": "DENY_ALL",
        "production_activation": False, "full_lifecycle_cost_known": False,
        "no_go_for_advantage_claim": not checks["independent_net_gain"]}
    write(output / "RESULT.json", result)
    print(json.dumps({"status": result["status"], "checks": checks, "output": str(output)}), flush=True)
    return 1 if fatal else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    freezing = commands.add_parser("freeze")
    freezing.add_argument("--output", type=Path, required=True)
    freezing.add_argument("--build-attempt-ledger", type=Path)
    for name in ("workload-binary", "workload-manifest", "value-binary", "value-manifest"):
        freezing.add_argument("--"+name, type=Path, required=True)
    running = commands.add_parser("run")
    running.add_argument("--registration", type=Path, required=True)
    running.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "freeze":
        freeze(args)
        return 0
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
