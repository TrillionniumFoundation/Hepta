#!/usr/bin/env python3
"""Frozen bounded policy learning/evolution beside the existing NDU controls.

This extends the finite dynamic-cache experiment. Forecast model costs and
observed host computation costs are never relabelled as native delivery time.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_ndu_dynamic import DynamicError, JsonProcess, digest, validate_model, wire
from hepta.hia_ndu_policy import policy, propose_generation, select, validate_plan
from hepta.hia_ndu_module_costs import read_cost_report, module_models
from tools.qualify_hia_ndu_dynamic import control_model, independent_exact_minimum

PROTOCOL = ROOT / "benchmarks/hia_ndu_policy_evolution/PROTOCOL.json"


def write(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")


def _check(condition, reason):
    if not condition:
        raise DynamicError("policy experiment: " + reason)


def validate_protocol(p):
    _check(type(p) is dict and p.get("schema") == "hepta.hia.ndu.policy-evolution-protocol.v1", "protocol schema")
    _check(p["generations"] == len(p["selection_seeds"]) == 3, "three registered generations")
    groups = [p["training_seeds"], *p["selection_seeds"], p["final_holdout_seeds"]]
    _check(all(type(g) is list and g and all(type(v) is int and v >= 0 for v in g) for g in groups), "seed inventories")
    all_seeds = [v for g in groups for v in g]
    _check(len(all_seeds) == len(set(all_seeds)), "train/selection/final leakage")
    _check(p["objects"] == 3 and p["horizon"] == 4 and p["quota_items"] == 2, "registered model shape")
    _check(p["per_task_transition_cap"] == 4096 and p["per_learned_arm_training_transition_cap"] == 2000000, "registered work budgets")
    _check(type(p["beam_width"]) is int and p["beam_width"] == 2, "registered beam width")
    _check(all(type(v) is int for v in [*p["lookahead_values"], *p["retention_weights"]]), "exact policy-grid integers")
    _check(p["lookahead_values"] == [0, 1, 2, 4] and p["retention_weights"] == [0, 1, 2, 4], "registered candidate family")
    _check(p["arms"] == ["fixed-direct", "greedy", "beam", "learned-value", "evolved-policy", "exact"], "complete control inventory")
    return p


def models_for(seeds, p):
    result = []
    for seed in seeds:
        model = control_model(objects=p["objects"], horizon=p["horizon"], seed=seed)
        model["memory_quota_bytes"] = 64 * p["quota_items"]
        # The task generator's initial state must meet this shared quota too.
        bits = [i for i in range(p["objects"]) if model["ready_mask"] & (1 << i)]
        model["ready_mask"] = sum(1 << i for i in bits[:p["quota_items"]])
        model["ready_epochs"] = [1 if model["ready_mask"] & (1 << i) else 0 for i in range(p["objects"])]
        result.append(validate_model(model))
    return result


def source_identity():
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    def git(*args):
        return subprocess.check_output(["git", "--no-replace-objects", "-C", str(ROOT), *args], env=env).decode().strip()
    _check(git("status", "--porcelain") == "", "source must be committed and clean")
    paths = git("ls-files", "hepta", "rust/hia-ndu-dynamic-model", "tools/qualify_hia_ndu_dynamic.py", "tools/qualify_hia_ndu_policy_evolution.py", "benchmarks/hia_ndu_policy_evolution", "tests/test_hia_ndu_policy.py").splitlines()
    inputs = {p: sha256((ROOT / p).read_bytes()).hexdigest() for p in paths}
    # Canonical object binding does not trust assume-unchanged/worktree status.
    for p in paths:
        expected = git("rev-parse", "HEAD:" + p)
        data = (ROOT / p).read_bytes()
        observed = __import__("hashlib").sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        _check(observed == expected, "worktree differs from canonical Git blob: " + p)
    return {"commit": git("rev-parse", "HEAD"), "tree": git("rev-parse", "HEAD^{tree}"), "files": inputs}


def freeze(args):
    p = validate_protocol(json.loads(PROTOCOL.read_bytes()))
    source = source_identity()
    groups = {"training": models_for(p["training_seeds"], p),
              "selection": [models_for(g, p) for g in p["selection_seeds"]],
              "final": models_for(p["final_holdout_seeds"], p)}
    module = None
    if args.module_report:
        module = read_cost_report(args.module_report, expected_source=source["commit"])
        groups = {"training": module_models(module, len(p["training_seeds"]), split="training"),
                  "selection": [module_models(module, len(g), split="selection-" + str(i))
                                for i, g in enumerate(p["selection_seeds"])],
                  "final": module_models(module, len(p["final_holdout_seeds"]), split="final")}
    native = None
    _check(bool(args.native_binary) == bool(args.native_manifest), "native binary and manifest must be supplied together")
    if args.native_binary:
        native = {name: {"path": str(Path(path).resolve()), "sha256": sha256(Path(path).read_bytes()).hexdigest()}
                  for name, path in (("binary", args.native_binary), ("manifest", args.native_manifest))}
    write(args.output, {"schema": "hepta.hia.ndu.policy-evolution-freeze.v1", "protocol": p,
        "source": source, "models": groups, "native": native, "module_costs": module,
        "python": sys.version, "platform": platform.platform(),
        "cpu_affinity": sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None,
        "authority": "DENY_ALL", "production_activation": False})


def evaluate(models, configuration, cap, *, fixed_mask=None):
    started = time.perf_counter_ns()
    rows = []
    for model in models:
        row = select(model, configuration, max_transitions=cap, fixed_mask=fixed_mask)
        _check(row["plan"] is not None, "complete delivery required; abstention retained as failure")
        validate_plan(model, row["plan"])
        rows.append(row)
    return {"policy": configuration, "rows": rows,
        "modeled_cost_ns": sum(r["plan"]["total_ns"] for r in rows),
        "wall_ns": time.perf_counter_ns() - started,
        "search_transitions": sum(r["search"]["transitions"] for r in rows)}


def mutation_bank(current, p):
    # A mutation changes one parameter to an adjacent registered value.
    bank = []
    for field, values in (("lookahead", p["lookahead_values"]), ("retention_weight", p["retention_weights"])):
        index = values.index(current[field])
        for neighbor in (index - 1, index + 1):
            if 0 <= neighbor < len(values):
                candidate = dict(current)
                candidate[field] = values[neighbor]
                bank.append(candidate)
    # Joint move permits leaving a zero-feature/zero-weight initialization.
    if current["lookahead"] == current["retention_weight"] == 0:
        bank.append(policy(width=p["beam_width"], lookahead=1, retention_weight=1))
    return bank


def evolve(training, selections, p, output):
    current = policy(width=p["beam_width"])
    used, generations = 0, []
    started = time.perf_counter_ns()
    for index, selection in enumerate(selections):
        proposal = propose_generation(training, current, mutation_bank(current, p),
            max_transitions=p["per_task_transition_cap"],
            generation_budget=p["per_learned_arm_training_transition_cap"] - used)
        used += proposal["transitions"]
        previous = evaluate(selection, current, p["per_task_transition_cap"])
        candidate = evaluate(selection, proposal["proposed"], p["per_task_transition_cap"])
        # New unseen selection tasks are consumed exactly once at this gate.
        # The test never weakens resource checks or chooses a new proposal.
        changed = proposal["proposed"] != current
        accepted = changed and candidate["modeled_cost_ns"] < previous["modeled_cost_ns"] and all(
            after["plan"]["total_ns"] <= before["plan"]["total_ns"]
            for before, after in zip(previous["rows"], candidate["rows"]))
        row = {"generation": index + 1, "proposal": proposal,
            "selection_model_sha256": [digest(m) for m in selection],
            "incumbent_selection": previous, "candidate_selection": candidate,
            "accepted_for_next_research_generation": accepted,
            "gate": "strict aggregate modeled improvement, no per-task modeled regression, independent complete witness validation",
            "full_cost_benefit_established": False,
            "production_activation": False}
        generations.append(row)
        write(output / f"generation-{index + 1:02}.json", row)
        if accepted:
            current = proposal["proposed"]
    return {"policy": current, "generations": generations, "transitions": used,
            "wall_ns": time.perf_counter_ns() - started}


def native_ablation(native, models, output, arms):
    if native is None:
        return {"status": "BLOCKED", "reason": "no source-pinned dynamic native bridge supplied at freeze", "native_ndu_evaluated": False}
    for value in native.values():
        _check(sha256(Path(value["path"]).read_bytes()).hexdigest() == value["sha256"], "native artifact changed after freeze")
    started = time.perf_counter_ns()
    process = JsonProcess(native["binary"]["path"], native["manifest"]["path"],
                          role="--planner-stream", log=output / "native-frames.jsonl")
    rows = []
    close_ns = None
    try:
        for arm in ("beam", "learned-value", "evolved-policy"):
            for index, (model, result) in enumerate(zip(models, arms[arm]["rows"])):
                paths = [[a["ready_after"] for a in plan["actions"]]
                         for plan in result["candidate_plans"]]
                _check(1 <= len(paths) <= 4, "frozen strategy must supply bounded native candidates")
                pair = {}
                order = ("supplied", "supplied_ndu") if index % 2 == 0 else ("supplied_ndu", "supplied")
                for mode in order:
                    answer, receipt = process.evaluate(model, mode, paths=paths)
                    pair[mode] = {"answer": answer, "receipt": receipt}
                a, b = pair["supplied"]["answer"], pair["supplied_ndu"]["answer"]
                _check(a["bundle"] == b["bundle"], "NDU ablation candidate bundles differ")
                _check(a["pareto_candidate_ids"] == b["pareto_candidate_ids"], "scalar ranking identity failed")
                _check(a["search"]["transitions"] == b["search"]["transitions"] == 0,
                       "supplied path must not run native search or exact oracle")
                rows.append({"arm": arm, "index": index, "model_sha256": digest(model),
                    "candidate_paths": paths, "candidate_set_sha256": digest(a["bundle"]),
                    "candidate_generation_wall_ns": result["wall_ns"],
                    "candidate_generation_search": result["search"], "order": order,
                    "controls": pair,
                    "native_incremental_roundtrip_ns": pair["supplied_ndu"]["receipt"]["outer_call_ns"] - pair["supplied"]["receipt"]["outer_call_ns"]})
    finally:
        close_ns = process.close()
    manifest = json.loads(Path(native["manifest"]["path"]).read_bytes())
    return {"status": "COMPLETED", "rows": rows, "wall_ns": time.perf_counter_ns() - started,
            "native_ndu_evaluated": True, "equal_candidate_and_ranking_cases": len(rows),
            "independent_decision_quality_gain": False, "close_ns": close_ns,
            "native_build_cost": manifest["build_cost"],
            "scope": "frozen policy candidates replayed independently; same scalar model and identical candidate sets; no oracle on native path",
            "cost_note": "candidate generation and build are common once; service/roundtrip measurements include both controls; no application delivery timing"}


def run(args):
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=False)
    started = time.perf_counter_ns()
    registration_bytes = Path(args.registration).read_bytes()
    r = json.loads(registration_bytes)
    report = {"schema": "hepta.hia.ndu.policy-evolution-result.v1", "status": "FAILED",
              "registration_sha256": sha256(registration_bytes).hexdigest(),
              "production_activation": False, "safety_certificate": False, "authority": "DENY_ALL"}
    try:
        _check(r["schema"] == "hepta.hia.ndu.policy-evolution-freeze.v1", "registration schema")
        p = validate_protocol(r["protocol"])
        _check(r["protocol"] == json.loads(PROTOCOL.read_bytes()), "protocol changed")
        _check(source_identity() == r["source"], "source changed after freeze")
        _check(r["python"] == sys.version, "Python changed after freeze")
        if r["cpu_affinity"] is not None:
            _check(sorted(os.sched_getaffinity(0)) == r["cpu_affinity"], "CPU affinity changed")
        expected = {"training": models_for(p["training_seeds"], p),
                    "selection": [models_for(g, p) for g in p["selection_seeds"]],
                    "final": models_for(p["final_holdout_seeds"], p)}
        module = r.get("module_costs")
        if module is not None:
            fresh = read_cost_report(module["report"]["path"], expected_source=r["source"]["commit"])
            _check(fresh == module, "module cost evidence changed")
            expected = {"training": module_models(module, len(p["training_seeds"]), split="training"),
                        "selection": [module_models(module, len(g), split="selection-" + str(i))
                                      for i, g in enumerate(p["selection_seeds"])],
                        "final": module_models(module, len(p["final_holdout_seeds"]), split="final")}
            report["module_cost_input"] = {key: value for key, value in module.items() if key != "native_report"}
            report["module_study_whole_wall_ns"] = module["native_report"]["whole_wall_ns"]
        _check(r["models"] == expected, "model inventory changed")
        write(output / "REGISTRATION.json", r)
        train = r["models"]["training"]
        grid = [policy(width=p["beam_width"], lookahead=h, retention_weight=w)
                for h in p["lookahead_values"] for w in p["retention_weights"]]
        learned = propose_generation(train, policy(width=p["beam_width"]), grid,
            max_transitions=p["per_task_transition_cap"],
            generation_budget=p["per_learned_arm_training_transition_cap"])
        write(output / "LEARNED.json", learned)
        evolution = evolve(train, r["models"]["selection"], p, output)
        write(output / "EVOLUTION.json", evolution)
        # The final data become visible only after BOTH learning paths are frozen.
        final = r["models"]["final"]
        arms = {"fixed-direct": (policy(width=1), 0), "greedy": (policy(width=1), None),
            "beam": (policy(width=p["beam_width"]), None),
            "learned-value": (learned["proposed"], None), "evolved-policy": (evolution["policy"], None),
            "exact": (policy(width=1 << p["objects"]), None)}
        report["arms"] = {}
        for name, (configuration, fixed) in arms.items():
            observed = evaluate(final, configuration, p["per_task_transition_cap"], fixed_mask=fixed)
            report["arms"][name] = observed
        audit_started = time.perf_counter_ns()
        minima = [independent_exact_minimum(model) for model in final]
        for name, result in report["arms"].items():
            result["oracle_regret_ns"] = [row["plan"]["total_ns"] - minimum for row, minimum in zip(result["rows"], minima)]
            _check(all(gap >= 0 for gap in result["oracle_regret_ns"]), "witness beats independent exact oracle")
            write(output / (name + ".json"), result)
        _check(all(gap == 0 for gap in report["arms"]["exact"]["oracle_regret_ns"]), "complete search differs from independent oracle")
        report["independent_oracle"] = {"minima_ns": minima, "wall_ns": time.perf_counter_ns() - audit_started,
                                        "used_in_training_or_selection": False}
        report["native_ablation"] = native_ablation(r["native"], final, output, report["arms"])
        report["learning"] = {"ordinary": learned, "evolution": evolution}
        report["cost_ledger"] = {"ordinary_training_wall_ns": learned["training_wall_ns"],
            "evolution_training_and_selection_wall_ns": evolution["wall_ns"],
            "final_controller_wall_ns_by_arm": {k: v["wall_ns"] for k, v in report["arms"].items()},
            "independent_oracle_wall_ns": report["independent_oracle"]["wall_ns"],
            "native_paired_qualification_wall_ns": report["native_ablation"].get("wall_ns"),
            "native_build_wall_ns": report["native_ablation"].get("native_build_cost", {}).get("wall_ns"),
            "measured_module_study_whole_wall_ns": report.get("module_study_whole_wall_ns"),
            "nesting": "phase values overlap enclosing campaign; do not sum nested walls",
            "prediction_cost_unit": "modeled ns, separate from observed controller wall",
            "human_review_seconds": None, "maintenance_seconds": None}
        report["research_findings"] = {"accepted_generations": sum(g["accepted_for_next_research_generation"] for g in evolution["generations"]),
            "native_application_benefit_established": False, "ndu_independent_value_established": False,
            "rsi_full_cost_improvement_established": False,
            "reason": "finite-model policy qualification; real delivery and maintenance costs remain unmeasured"}
        _check(source_identity() == r["source"], "source changed during experiment")
        report["status"] = "COMPLETED_FINITE_MODEL_ONLY"
    except BaseException as error:
        report["error"] = type(error).__name__ + ": " + str(error)
    finally:
        report["campaign_wall_ns_before_final_serialization"] = time.perf_counter_ns() - started
        report["cost_boundary"] = {"model_costs_are_observed_workload_times": False,
            "lost_candidates_in_training_cost": True, "independent_audit_cost_retained": True,
            "native_build_and_human_maintenance_costs": "not measured by this model campaign",
            "required_final_outer_wall": "caller measures enclosing command including this final report serialization",
            "global_task_budget": "same per-task search cap and same per-learned-arm training cap; unused budget is not padded"}
        write(output / "RESULT.json", report)
    print(json.dumps({"status": report["status"], "result": str(output / "RESULT.json"),
                      "findings": report.get("research_findings"), "error": report.get("error")}, sort_keys=True))
    return 0 if report["status"] == "COMPLETED_FINITE_MODEL_ONLY" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    f = commands.add_parser("freeze")
    f.add_argument("--module-report", help="completed same-source stb-service native study; use real candidate costs")
    f.add_argument("--native-binary")
    f.add_argument("--native-manifest")
    f.add_argument("--output", required=True)
    r = commands.add_parser("run")
    r.add_argument("--registration", required=True)
    r.add_argument("--output", required=True)
    args = parser.parse_args()
    return freeze(args) if args.command == "freeze" else run(args)


if __name__ == "__main__":
    raise SystemExit(main())
