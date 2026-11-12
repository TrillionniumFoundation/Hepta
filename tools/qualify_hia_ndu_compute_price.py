#!/usr/bin/env python3
"""Prospectively measure stopping unnecessary planning with trained cost prices."""
from __future__ import annotations
import argparse
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
import statistics
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools import qualify_hia_ndu_feedback as common
from experiments.hia_ndu_feedback_20261106 import model
from experiments.hia_ndu_feedback_20261106.economical import priced_plan

PROTOCOL = ROOT / "benchmarks/hia_ndu_feedback/COMPUTE_PRICE_PROTOCOL.json"
ARMS = ("state-greedy", "same-objective", "same-objective-priced", "dynamic-ndu", "dynamic-ndu-priced")


def validate_protocol(p, prior, calibration):
    if p.get("schema") != "hepta.hia.ndu.compute-price-protocol.v1" or tuple(p["arms"]) != ARMS:
        raise ValueError("computation protocol identity or arm inventory")
    old = common.validate_protocol(prior["protocol"])
    train, final = p["training_seeds"], p["holdout_seeds"]
    if (not train or not final or any(type(x) is not int or x < 0 for x in train+final)
        or len(set(train+final)) != len(train+final)
        or set(final) & set(old["holdout_seeds"])
        or train != old["training_seeds"] or train != calibration["training_seeds"]):
        raise ValueError("training/holdout identity or split leakage")
    if (set(p["environments"]) != set(model.SCENARIOS) or len(p["environments"]) != len(model.SCENARIOS)
        or p["horizon"] != 3 or calibration["training_dimensions"] != [192, 640]
        or p["dimension"] in calibration["training_dimensions"] + old["native_dimensions"]
        or calibration["future_measurement_access"] is not False
        or calibration["repeats"] != p["kernel_repeats"]):
        raise ValueError("calibration scope, final dimension, horizon or environments")
    for key in ("dimension", "repetitions", "kernel_repeats", "episode_budget_ns",
                "max_transitions_per_decision", "max_transitions_per_arm"):
        if type(p[key]) is not int or p[key] <= 0:
            raise ValueError("invalid protocol bound: " + key)
    return p


def planned_cells(p):
    plans = []
    for fi, name in enumerate(p["environments"]):
        for si, seed in enumerate(p["holdout_seeds"]):
            for repeat in range(p["repetitions"]):
                offset = (fi+si+repeat) % len(p["arms"])
                arms = p["arms"][offset:] + p["arms"][:offset]
                if (si+repeat) % 2:
                    arms = list(reversed(arms))
                plans.extend({"environment": name, "seed": seed, "repeat": repeat, "arm": arm} for arm in arms)
    return plans


def scenarios_from_training(p, prior, calibration):
    forecast_protocol = {**prior["protocol"], "native_episode_budget_ns": p["episode_budget_ns"]}
    return {name: common.derived_native_scenario(model.SCENARIOS[name], calibration, p["dimension"], forecast_protocol)
            for name in p["environments"]}


def source():
    state = common.source_identity()
    # source_identity covers the entire research package, including economical.
    state["compute_runner_sha256"] = sha256(Path(__file__).read_bytes()).hexdigest()
    return state


def freeze(args):
    prior = json.loads(Path(args.prior_registration).read_text())
    calibration = json.loads(Path(args.calibration).read_text())
    p = validate_protocol(json.loads(PROTOCOL.read_text()), prior, calibration)
    if common.identity(args.calibration)["sha256"] != p["original_calibration_sha256"]:
        raise ValueError("calibration is not the independently audited original training bytes")
    for item in prior["inputs"].values():
        if common.identity(item["path"]) != item:
            raise ValueError("admitted native input changed")
    common.write(args.output, {"schema": "hepta.hia.ndu.compute-price-freeze.v1",
        "source": source(), "protocol": p, "inputs": prior["inputs"],
        "prior_registration": common.identity(args.prior_registration),
        "calibration": common.identity(args.calibration), "created_unix_ns": time.time_ns(),
        "authority": "DENY_ALL"})


def train_prices(scenarios, p, inputs, output):
    began = time.monotonic_ns()
    backend = common.LazyBackend(inputs, output / "training-values.jsonl")
    rows, prices, errors = [], {}, []
    spent = {arm: 0 for arm in ("state-greedy", "same-objective", "dynamic-ndu")}
    status = "failed"
    close = None
    try:
        for name, scenario in scenarios.items():
            buckets = {}
            for seed in p["training_seeds"]:
                env = model.FeedbackEnvironment(scenario, seed)
                while not env.done:
                    obs = env.observe()
                    decisions = {}
                    for arm in ("state-greedy", "same-objective", "dynamic-ndu"):
                        started = time.monotonic_ns()
                        trial = {"environment": name, "seed": seed, "observation": asdict(obs), "arm": arm,
                                 "status": "failed", "decision": None, "search_transitions": 0}
                        rows.append(trial)
                        allowance = min(p["max_transitions_per_decision"], p["max_transitions_per_arm"]-spent[arm])
                        try:
                            if allowance <= 0:
                                raise model.SearchBudgetExhausted("training lifecycle allowance exhausted", transitions=0)
                            result = model.plan(scenario, obs, arm, backend=backend if arm == "dynamic-ndu" else None,
                                                max_transitions=allowance)
                            trial.update(status="completed", decision=result,
                                         search_transitions=result["search"]["transitions"])
                        except BaseException as error:
                            trial["error"] = {"type": type(error).__name__, "message": str(error)}
                            trial["search_transitions"] = getattr(error, "search_stats", {}).get("transitions",
                                getattr(error, "transitions", max(0, allowance)
                                    if isinstance(error, model.SearchBudgetExhausted) else 0))
                            raise
                        finally:
                            trial["wall_ns"] = time.monotonic_ns()-started
                            spent[arm] += trial["search_transitions"]
                        elapsed = trial["wall_ns"]
                        depth = scenario.horizon-obs.step
                        buckets.setdefault((arm, depth), []).append(elapsed)
                        decisions[arm] = result
                    # All prices see the same public observation; the behavior
                    # policy is fixed before measuring any of these prices.
                    env.step(decisions["state-greedy"]["action"])
            prices[name] = {arm: {str(depth): round(statistics.median(buckets[(arm, depth)]))
                           for depth in range(1, scenario.horizon+1)}
                           for arm in ("state-greedy", "same-objective", "dynamic-ndu")}
        status = "completed"
    except BaseException as error:
        errors.append({"type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()})
    finally:
        try:
            close = backend.close()
        except BaseException as error:
            status = "failed"
            errors.append({"phase": "native_close", "type": type(error).__name__, "message": str(error)})
    result = {"status": status, "errors": errors, "prices": prices, "all_trials": rows, "native_close": close,
            "transition_ledgers": spent,
            "wall_ns": time.monotonic_ns()-began, "holdout_used": False,
            "price_is_physical_guarantee": False, "authority": "DENY_ALL"}
    common.write(output / "TRAINING_PRICES.json", result)
    return result


def run(args):
    started = time.monotonic_ns()
    f = json.loads(Path(args.registration).read_text())
    p = f["protocol"]
    if p != json.loads(PROTOCOL.read_text()) or f["source"] != source():
        raise ValueError("frozen computation protocol/source changed")
    for item in [*f["inputs"].values(), f["prior_registration"], f["calibration"]]:
        if common.identity(item["path"]) != item:
            raise ValueError("frozen computation input changed")
    calibration = json.loads(Path(f["calibration"]["path"]).read_text())
    prior = json.loads(Path(f["prior_registration"]["path"]).read_text())
    validate_protocol(p, prior, calibration)
    if f["calibration"]["sha256"] != p["original_calibration_sha256"]:
        raise ValueError("registered calibration differs from original training identity")
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=False)
    common.write(output / "REGISTRATION.json", f)
    plans = planned_cells(p)
    common.write(output / "PLANNED.json", plans)
    totals = {arm: 0 for arm in p["arms"]}
    rows, audits, audit_errors = [], [], []
    fatal, training_identity, training, price_freeze_identity = None, None, None, None
    phase = "scenario_preparation"
    try:
        scenarios = scenarios_from_training(p, prior, calibration)
        common.write(output / "SCENARIOS.json", {name: asdict(s) for name, s in scenarios.items()})
        phase = "price_training"
        training = train_prices(scenarios, p, f["inputs"], output)
        totals = {arm: sum(row["search_transitions"] for row in training["all_trials"]
                          if row["arm"] == arm.removesuffix("-priced")) for arm in p["arms"]}
        if training["status"] != "completed":
            raise ValueError("price training failed; every trial and its elapsed cost is retained")
        training_identity = common.identity(output / "TRAINING_PRICES.json")
        common.write(output / "PRICE_FREEZE.json", {"training": training_identity,
            "prices": training["prices"], "before_any_final_execution": True, "authority": "DENY_ALL"})
        price_freeze_identity = common.identity(output / "PRICE_FREEZE.json")
        phase = "final_execution"
        for index, cell in enumerate(plans):
            name, arm = cell["environment"], cell["arm"]
            scenario = scenarios[name]
            directory = output / "episodes" / f"{index:04d}"
            directory.mkdir(parents=True)
            def decide(s, obs, requested_arm, backend, fixed_action, cap):
                if requested_arm.endswith("-priced"):
                    underlying = requested_arm.removesuffix("-priced")
                    depth = str(s.horizon-obs.step)
                    result = priced_plan(s, obs, underlying, backend=backend,
                        forecast_control_ns=training["prices"][name][underlying][depth],
                        greedy_forecast_ns=max(training["prices"][name]["state-greedy"][str(k)]
                                               for k in range(1, int(depth)+1)), max_transitions=cap)
                    result["arm"] = requested_arm
                    return result
                return common.decide(s, obs, requested_arm, backend, fixed_action, cap)
            row = common.episode(scenario, cell["seed"], arm, fixed_action=0,
                inputs=f["inputs"], output=directory, native=True, n=p["dimension"], repeats=p["kernel_repeats"],
                cap=p["max_transitions_per_decision"], remaining_transitions=p["max_transitions_per_arm"]-totals[arm],
                decision_function=decide)
            row.update(cell_index=index, dimension=p["dimension"], repetition=cell["repeat"])
            totals[arm] += row["search_transitions"]
            common.write(directory / "RESULT.json", row)
            rows.append(row)
            # A diagnostic failure cannot remove an executed outcome or silently
            # truncate the remaining final schedule.
            audit_started = time.monotonic_ns()
            try:
                audit = common.audit_episode(scenario, row, p["max_transitions_per_decision"])
                common.write(directory / "ORACLE_AUDIT.json", audit)
                audits.append(audit)
            except BaseException as error:
                failure = {"cell_index": index, "type": type(error).__name__, "message": str(error),
                           "wall_ns": time.monotonic_ns()-audit_started, "traceback": traceback.format_exc()}
                audit_errors.append(failure)
                common.write(directory / "ORACLE_AUDIT_FAILURE.json", failure)
            if index % 15 == 0 or index+1 == len(plans):
                print(json.dumps({"completed": index+1, "planned": len(plans),
                                  "incomplete": sum(r["status"] != "completed" for r in rows)}), flush=True)
    except BaseException as error:
        fatal = {"phase": phase, "type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()}
    tables = {}
    for name in p["environments"]:
        tables[name] = {}
        for arm in p["arms"]:
            selected = [r for r in rows if r["scenario"] == name and r["arm"] == arm]
            tables[name][arm] = {"planned_episodes": len(p["holdout_seeds"])*p["repetitions"],
                "observed_episodes": len(selected), "planned_requests": len(p["holdout_seeds"])*p["repetitions"]*p["horizon"],
                "delivered": sum(r["delivered"] for r in selected),
                "episode_wall_ns": sum(r["episode_wall_ns"] for r in selected),
                "workload_wall_ns": sum(r["workload_wall_ns"] for r in selected),
                "backend_calls": sum(r["backend_calls"] for r in selected),
                "gate_skips": sum(not step["decision"].get("compute_gate", {}).get("invoke", True)
                    for r in selected for step in r["steps"]),
                "search_transitions": sum(r["search_transitions"] for r in selected)}
    postflight_errors = []
    try:
        if source() != f["source"]:
            postflight_errors.append("source identity changed")
    except BaseException as error:
        postflight_errors.append("source: " + str(error))
    for item in [*f["inputs"].values(), f["prior_registration"], f["calibration"],
                 *([training_identity, price_freeze_identity] if price_freeze_identity else [])]:
        try:
            if common.identity(item["path"]) != item:
                postflight_errors.append("input changed: " + item["path"])
        except BaseException as error:
            postflight_errors.append(item["path"] + ": " + str(error))
    bound = len(rows) == len(plans) and all(
        (r["cell_index"], r["scenario"], r["seed"], r["repetition"], r["arm"], r["dimension"], r["planned_requests"])
        == (i, c["environment"], c["seed"], c["repeat"], c["arm"], p["dimension"], p["horizon"])
        for i, (r, c) in enumerate(zip(rows, plans)))
    checks = {"all_cells_retained": bound,
              "all_requests_delivered": bound and sum(r["delivered"] for r in rows) == len(plans)*p["horizon"]
                  and all(r["status"] == "completed" and r["delivered"] == p["horizon"] for r in rows),
              "source_and_binary_unchanged": not postflight_errors,
              "training_completed_and_frozen": training_identity is not None and training["status"] == "completed",
              "ordinary_and_native_same_objective_agree": not audit_errors and len(audits) == len(plans)
                  and all(x["same_objective_agrees"] is not False
                          and x.get("priced_incumbent_agrees") is not False
                          and x.get("priced_optimal_upper_valid") is not False
                          for a in audits for x in a["rows"]),
              "transitions_with_training_within_same_allowance": all(v <= p["max_transitions_per_arm"] for v in totals.values())}
    comparisons = []
    for name in p["environments"]:
        for priced in ("same-objective-priced", "dynamic-ndu-priced"):
            for control in (priced.removesuffix("-priced"), "state-greedy"):
                differences = []
                for seed in p["holdout_seeds"]:
                    pairs = []
                    for repeat in range(p["repetitions"]):
                        a = next((r for r in rows if (r["scenario"], r["seed"], r["repetition"], r["arm"])
                                  == (name, seed, repeat, priced)), None)
                        b = next((r for r in rows if (r["scenario"], r["seed"], r["repetition"], r["arm"])
                                  == (name, seed, repeat, control)), None)
                        if a is not None and b is not None:
                            pairs.append(a["episode_wall_ns"]-b["episode_wall_ns"])
                    if len(pairs) == p["repetitions"]:
                        differences.append(statistics.mean(pairs))
                comparisons.append({"environment": name, "priced_arm": priced, "control": control,
                    "positive_difference_means_priced_is_slower": True, "paired": common.paired_intervals(differences)})
    common.write(output / "RESULT.json", {"schema": "hepta.hia.ndu.compute-price-result.v1", "source": f["source"],
        "status": "failed" if fatal else "completed", "fatal_error": fatal, "postflight_errors": postflight_errors,
        "checks": checks, "tables": tables, "paired_comparisons": comparisons,
        "training_wall_ns": training["wall_ns"] if training else None,
        "price_freeze": price_freeze_identity, "training_identity": training_identity,
        "planned_episode_count": len(plans), "retained_episode_count": len(rows),
        "planned_request_count": len(plans)*p["horizon"], "delivered_request_count": sum(r["delivered"] for r in rows),
        "not_run_cells": [{"cell_index": i, **cell} for i, cell in enumerate(plans) if i not in {r["cell_index"] for r in rows}],
        "transition_ledgers": totals, "post_execution_audit_wall_ns": sum(a["wall_ns"] for a in audits)+sum(a["wall_ns"] for a in audit_errors),
        "audit_errors": audit_errors, "historical_build_and_calibration_costs": "Reuse prior registration and calibration receipts; this study does not erase or repay those costs.",
        "wall_before_report_ns": time.monotonic_ns()-started, "authority": "DENY_ALL",
        "unique_NDU_advantage_claim": False, "production_activation": False})
    print(json.dumps({"checks": checks, "tables": tables, "fatal_error": fatal}), flush=True)
    return 0 if fatal is None and all(checks.values()) else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    cmds = parser.add_subparsers(dest="command", required=True)
    frozen = cmds.add_parser("freeze")
    frozen.add_argument("--prior-registration", type=Path, required=True)
    frozen.add_argument("--calibration", type=Path, required=True)
    frozen.add_argument("--output", type=Path, required=True)
    running = cmds.add_parser("run")
    running.add_argument("--registration", type=Path, required=True)
    running.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    return freeze(args) if args.command == "freeze" else run(args)


if __name__ == "__main__":
    raise SystemExit(main())
