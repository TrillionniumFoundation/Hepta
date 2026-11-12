#!/usr/bin/env python3
"""Freeze all-action reachability and audit complete policies under one objective."""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict, replace
import gzip
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools import qualify_hia_ndu_feedback as common
from experiments.hia_ndu_feedback_20261106 import coverage, model, policy_audit

PROTOCOL = ROOT / "benchmarks/hia_ndu_feedback_state_coverage/POLICY_PROTOCOL.json"
BASE_MODEL_SHA256 = "56b335e5a7fc205e4ad955faf3eece2a63d43c097f71d5fb4af6d84ee1081b79"
FIXED = {"fixed-direct": -1, "fixed-cache-0": 0, "fixed-cache-1": 1}
NATIVE = ("fixed-preference-ndu", "dynamic-ndu")
ARMS = (*FIXED, "state-greedy", "ordinary-mpc", "same-objective", *NATIVE,
        "wrong-forecast", "prior-belief-only", "no-adaptation", "exact-oracle")


def rational(value):
    return [value.numerator, value.denominator]


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "xt", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, separators=(",", ":"), allow_nan=False)
        stream.write("\n")


def read(path):
    path = Path(path)
    with (gzip.open if path.suffix == ".gz" else open)(path, "rt", encoding="utf-8") as stream:
        return json.load(stream)


def source():
    result = common.source_identity()
    paths = [Path(__file__), ROOT / ".github/workflows/hia-ndu-feedback.yml",
             *sorted((ROOT / "tests").glob("test_hia_ndu_policy*.py")),
             *sorted((ROOT / "tests").glob("test_hia_ndu_feedback_ci_paths.py"))]
    for path in paths:
        name, raw = str(path.relative_to(ROOT)), path.read_bytes()
        if raw != subprocess.check_output(["git", "--no-replace-objects", "cat-file", "blob", "HEAD:"+name], cwd=ROOT,
                env={k: v for k, v in os.environ.items() if not k.startswith("GIT_")}):
            raise ValueError("policy audit source differs from committed bytes: " + name)
        result["files"][name] = sha256(raw).hexdigest()
    return result


def protocol():
    p = read(PROTOCOL)
    expected = {"horizon": 3, "initial_residents": [-1, 0, 1],
                "initial_resource_pairs": [[12, 24], [24, 12], [24, 24]], "load_costs": [4, 8]}
    if (p.get("schema") != "hepta.hia.ndu.policy-audit-protocol.v1" or tuple(p["arms"]) != ARMS
        or tuple(p["native_arms"]) != NATIVE or p["environments"] != ["adaptive", "fixed", "misleading"]
        or p["natural_support"] != expected or p["expected_profiles"] != 54
        or p["per_decision_transition_cap"] != 20000 or p["per_arm_transition_cap"] != 20000000
        or p["graph_limits"] != {"max_states": 10000, "max_edges": 100000}):
        raise ValueError("registered policy inventory, profile or resource bound changed")
    if (p["base_model_sha256"] != BASE_MODEL_SHA256 or
            sha256((ROOT / "experiments/hia_ndu_feedback_20261106/model.py").read_bytes()).hexdigest() != BASE_MODEL_SHA256):
        raise ValueError("frozen v1 model bytes changed")
    return p


def graph_record(graph):
    ids = {s: model.digest({"scenario": graph["scenario_digest"], "observation": asdict(s)}) for s in graph["nodes"]}
    return {"scenario_digest": graph["scenario_digest"], "edges": graph["edges"],
        "roots": [{"probability": rational(mass), "state_id": ids[s]} for mass, s in graph["roots"]],
        "nodes": [{"id": ids[s], "observation": asdict(s), "actions": {
            model.action_name(a): [{"probability": rational(mass), "state_id": ids[child]} for mass, child in successors]
            for a, successors in graph["nodes"][s].items()}} for s in sorted(ids, key=ids.get)]}


def inventory(p):
    profiles = []
    for identity, scenario in coverage.natural_profiles(p):
        graph = graph_record(policy_audit.build_graph(scenario, **p["graph_limits"]))
        profiles.append({"id": identity, "scenario": asdict(scenario), "graph": graph,
                         "graph_sha256": model.digest(graph), "states": len(graph["nodes"]), "edges": graph["edges"]})
    totals = {"profiles": len(profiles), "states": sum(r["states"] for r in profiles),
        "edges": sum(r["edges"] for r in profiles), "maximum_profile_states": max(r["states"] for r in profiles),
        "maximum_profile_edges": max(r["edges"] for r in profiles)}
    if totals["profiles"] != p["expected_profiles"] or any(totals[k] != p["structural_preflight"][k]
        for k in ("states", "edges", "maximum_profile_states", "maximum_profile_edges")):
        raise ValueError("graph inventory differs from disclosed structural preflight")
    return profiles, totals


def check_inputs(frozen):
    for info in frozen["inputs"].values():
        if common.identity(info["path"]) != info:
            raise ValueError("frozen native input changed: " + info["path"])
    coverage.bind_native_inputs(frozen["inputs"]["value_binary"]["path"], frozen["inputs"]["value_manifest"]["path"])


def freeze(args):
    began = time.monotonic_ns()
    p, before = protocol(), source()
    inputs = {name: common.identity(getattr(args, name)) for name in ("value_binary", "value_manifest")}
    profiles, totals = inventory(p)
    frozen = {"schema": "hepta.hia.ndu.policy-audit-freeze.v1", "source": before, "protocol": p,
        "protocol_sha256": sha256(PROTOCOL.read_bytes()).hexdigest(), "inputs": inputs,
        "build_receipt": read(inputs["value_manifest"]["path"]), "profiles": profiles, "inventory": totals,
        "created_unix_ns": time.time_ns(), "freeze_wall_ns": time.monotonic_ns()-began,
        "freeze_command_policy_decisions": 0, "authority": "DENY_ALL"}
    check_inputs(frozen)
    if source() != before:
        raise ValueError("source changed while freezing all-action inventory")
    write(args.output, frozen)
    print(json.dumps({"registration": str(args.output), "source": before["commit"], **totals}), flush=True)


def decide(scenario, observation, arm, *, backend=None, cap=20000):
    """Pure-belief intervention changes no numerical preference or physical state."""
    planning = (replace(observation, belief_num=scenario.prior0_num, belief_den=scenario.prior0_den)
                if arm == "prior-belief-only" else observation)
    target = "fixed" if arm in FIXED else "same-objective" if arm == "prior-belief-only" else arm
    answer = model.plan(scenario, planning, target, backend=backend, max_transitions=cap, fixed_action=FIXED.get(arm, 0))
    if arm == "prior-belief-only" and answer["preference"] != model.preferences(scenario, observation):
        error = ValueError("pure belief intervention changed numeric preferences")
        error.search_stats = answer["search"]
        raise error
    belief = answer.get("planning_belief", [planning.belief_num, planning.belief_den])
    planning = replace(planning, belief_num=belief[0], belief_den=belief[1])
    return {"status": "completed", "arm": arm, "action": answer["action"], "selected_action": answer["selected_action"],
        "planned_value_q32": answer["value_q32"], "candidate_values_q32": answer["candidate_values_q32"],
        "preference": answer["preference"], "original_observation": asdict(observation),
        "planning_observation": asdict(planning), "planning_belief": belief,
        "search": answer["search"], "controller_wall_ns": answer["controller_wall_ns"],
        "native_backend_used": answer["native_backend_used"]}


def factorial(values):
    names = ("dynamic-ndu", "prior-belief-only", "fixed-preference-ndu", "no-adaptation")
    if not all(a in values for a in names):
        return {"status": "not_run", "reason": "incomplete factorial policies"}
    dynamic, prior, fixed, joint = (values[a] for a in names)
    return {"status": "completed", "policy_values_q32": {a: values[a] for a in names},
        "belief_gain_with_dynamic_preferences_q32": dynamic-prior,
        "belief_gain_with_fixed_preferences_q32": fixed-joint,
        "preference_gain_with_current_belief_q32": dynamic-fixed,
        "preference_gain_with_prior_belief_q32": prior-joint,
        "interaction_q32": dynamic-prior-fixed+joint,
        "historical_no_adaptation_scope": "joint belief and numerical-preference intervention"}


def audit_profile(item, p, inputs, directory, ledger):
    began = time.monotonic_ns()
    scenario = model.Scenario(**item["scenario"])
    graph = policy_audit.build_graph(scenario, **p["graph_limits"])
    raw = graph_record(graph)
    if (model.digest(raw) != item["graph_sha256"] or raw != item["graph"]
            or item["states"] != len(graph["nodes"]) or item["edges"] != graph["edges"]):
        raise ValueError("reconstructed graph differs from frozen all-action inventory")
    write(directory / "GRAPH.json.gz", raw)
    states = {node["id"]: model.Observation(**node["observation"]) for node in raw["nodes"]}
    rows = {node["id"]: {"id": node["id"], "observation": node["observation"],
        "legal_actions": sorted(node["actions"]), "arms": {a: {"status": "not_run"} for a in ARMS}} for node in raw["nodes"]}
    costs, evaluations, summaries, errors = {}, {}, {}, []
    for arm in ARMS:
        arm_start = time.monotonic_ns()
        backend = common.LazyBackend(inputs, directory / (arm+".jsonl")) if arm in NATIVE else None
        broken = False
        initial_transitions = ledger[arm]["transitions"]
        close = None
        try:
            with (directory / (arm+".attempts.jsonl")).open("x", encoding="utf-8") as journal:
                for identity, state in states.items():
                    cell = rows[identity]["arms"][arm]
                    allowance = min(p["per_decision_transition_cap"], p["per_arm_transition_cap"]-ledger[arm]["transitions"])
                    started = time.monotonic_ns()
                    try:
                        if allowance <= 0 or broken:
                            cell["reason"] = "arm_transition_budget_exhausted" if allowance <= 0 else "native_process_failed"
                            ledger[arm]["not_run"] += 1
                            continue
                        calls_before = backend.backend.calls if backend is not None and backend.backend is not None else 0
                        cell = decide(scenario, state, arm, backend=backend, cap=allowance)
                        rows[identity]["arms"][arm] = cell
                        if arm in NATIVE:
                            calls_after = backend.backend.calls if backend.backend is not None else 0
                            cell["native_call_range"] = [calls_before+1, calls_after]
                            if (not cell["native_backend_used"] or calls_after <= calls_before
                                    or calls_after-calls_before != cell["search"]["backend_calls"]):
                                raise ValueError("native planning calls were not retained")
                        ledger[arm]["completed"] += 1
                    except Exception as error:
                        cell.update(status="failed", error={"type": type(error).__name__, "message": str(error)},
                            search=getattr(error, "search_stats", cell.get("search", {"transitions": getattr(error, "transitions", 0)})))
                        ledger[arm]["failed"] += 1
                        broken = arm in NATIVE
                    except BaseException as error:
                        cell.update(status="interrupted", error={"type": type(error).__name__, "message": str(error)},
                            search=getattr(error, "search_stats", cell.get("search", {"transitions": 0, "partial_expansions_unknown": True})))
                        ledger[arm]["failed"] += 1
                        raise
                    finally:
                        cell["observed_planning_wall_ns"] = time.monotonic_ns()-started
                        ledger[arm]["planning_wall_ns"] += cell["observed_planning_wall_ns"]
                        ledger[arm]["transitions"] += cell.get("search", {}).get("transitions", 0)
                        journal.write(json.dumps({"state_id": identity, **cell}, sort_keys=True, allow_nan=False)+"\n")
                        journal.flush()
        finally:
            if backend is not None:
                try:
                    native_calls = backend.backend.calls if backend.backend is not None else 0
                    close = backend.close()
                    if close["calls"] != native_calls or (native_calls and (not close["started"] or close["returncode"] != 0)):
                        raise ValueError("native cleanup receipt contradicts admitted process/call history")
                except Exception as error:
                    errors.append({"arm": arm, "phase": "native_close", "type": type(error).__name__, "message": str(error)})
            costs[arm] = {"planning_wall_including_native_cleanup_ns": time.monotonic_ns()-arm_start,
                "search_transitions": ledger[arm]["transitions"]-initial_transitions, "native_close": close}
            write(directory / (arm+".cost.json"), costs[arm])
            if sys.exc_info()[0] is not None:
                write(directory / "PARTIAL.json.gz", {"status": "interrupted", "arm": arm, "rows": list(rows.values()),
                    "costs": costs, "ledgers": ledger, "errors": errors, "exception_type": sys.exc_info()[0].__name__,
                    "planned_states": item["states"], "planned_cells": item["states"]*len(ARMS),
                    "wall_before_partial_ns": time.monotonic_ns()-began})
        started = time.monotonic_ns()
        complete = all(row["arms"][arm]["status"] == "completed" for row in rows.values())
        try:
            if not complete:
                summaries[arm] = {"status": "not_run", "reason": "incomplete policy decisions"}
                continue
            chosen = {states[k]: row["arms"][arm]["action"] for k, row in rows.items()}
            evaluated = policy_audit.evaluate_policy(scenario, graph, chosen.__getitem__)
            evaluations[arm] = evaluated
            summaries[arm] = {"status": "completed", "value_q32": evaluated["value_q32"],
                "expected_delivered": rational(evaluated["expected_delivered"]), "expected_cost": rational(evaluated["expected_cost"])}
        except Exception as error:
            summaries[arm] = {"status": "failed", "error": {"type": type(error).__name__, "message": str(error)}}
        finally:
            costs[arm]["policy_evaluation_wall_ns"] = time.monotonic_ns()-started
            costs[arm]["policy_evaluation_state_visits"] = len(states) if complete else 0
            ledger[arm]["policy_evaluation_wall_ns"] += costs[arm]["policy_evaluation_wall_ns"]
    checks = {"all_cells_completed": all(r["arms"][a]["status"] == "completed" for r in rows.values() for a in ARMS),
        "all_whole_policies_evaluated": len(evaluations) == len(ARMS), "native_cleanup_passed": not errors,
        "same_objective_exact_actions_and_values": True, "same_objective_whole_policy_values": True,
        "all_regrets_nonnegative": True}
    for identity, row in rows.items():
        state, oracle = states[identity], row["arms"]["exact-oracle"]
        values = {}
        for arm, cell in row["arms"].items():
            if arm in evaluations:
                values[arm] = cell["whole_policy_value_q32"] = evaluations[arm]["state_values"][state]
            if cell["status"] == oracle["status"] == "completed":
                cell["first_action_conditional_regret_q32"] = oracle["planned_value_q32"]-oracle["candidate_values_q32"][cell["selected_action"]]
                if arm in values:
                    cell["whole_policy_regret_q32"] = oracle["planned_value_q32"]-values[arm]
                checks["all_regrets_nonnegative"] &= all(cell[k] >= 0 for k in ("first_action_conditional_regret_q32", "whole_policy_regret_q32") if k in cell)
        for arm in ("same-objective", "dynamic-ndu"):
            cell = row["arms"][arm]
            checks["same_objective_exact_actions_and_values"] &= (cell["status"] == oracle["status"] == "completed" and
                all(cell[k] == oracle[k] for k in ("action", "planned_value_q32", "candidate_values_q32")))
            checks["same_objective_whole_policy_values"] &= (arm in values and "exact-oracle" in values and values[arm] == values["exact-oracle"] == oracle.get("planned_value_q32"))
        row["whole_policy_factorial"] = factorial(values)
    selected, selection_started = {"status": "not_run", "reason": "incomplete fixed candidates"}, time.monotonic_ns()
    if all(arm in evaluations for arm in FIXED):
        best = max(FIXED, key=lambda a: (evaluations[a]["value_q32"], -FIXED[a]))
        selected = {"status": "completed", "arm": best, "fixed_action": FIXED[best], **summaries[best],
            "all_candidate_values_q32": {a: evaluations[a]["value_q32"] for a in FIXED},
            "selection_rule": "one full-policy ex-ante choice per profile; known-law model reference",
            "all_candidate_planning_wall_ns": sum(costs[a]["planning_wall_including_native_cleanup_ns"] for a in FIXED),
            "all_candidate_evaluation_wall_ns": sum(costs[a]["policy_evaluation_wall_ns"] for a in FIXED)}
    selected["selection_wall_ns"] = time.monotonic_ns()-selection_started
    profile_values = {a: v["value_q32"] for a, v in evaluations.items()}
    write(directory / "STATE_RESULTS.json.gz", list(rows.values()))
    result = {"id": item["id"], "scenario": item["scenario"], "status": "passed" if all(checks.values()) else "failed",
        "checks": checks, "errors": errors, "planned_states": item["states"], "retained_states": len(rows),
        "planned_cells": item["states"]*len(ARMS), "cell_status_counts": dict(Counter(c["status"] for r in rows.values() for c in r["arms"].values())),
        "policies": summaries, "model_optimal_fixed": selected, "factorial": factorial(profile_values), "costs": costs,
        "profile_wall_before_manifest_ns": time.monotonic_ns()-began,
        "artifacts": [common.identity(path) for path in sorted(directory.iterdir()) if path.is_file()], "authority": "DENY_ALL"}
    write(directory / "SUMMARY.json", result)
    return result


def run(args):
    began = time.monotonic_ns()
    output = Path(args.output)
    try:
        registration = common.identity(args.registration)
        frozen = read(args.registration)
        if (frozen.get("schema") != "hepta.hia.ndu.policy-audit-freeze.v1" or frozen["source"] != source()
            or frozen["protocol"] != protocol() or frozen["protocol_sha256"] != sha256(PROTOCOL.read_bytes()).hexdigest()):
            raise ValueError("policy registration source/protocol changed")
        check_inputs(frozen)
        p = frozen["protocol"]
        profiles, totals = inventory(p)
        if frozen["profiles"] != profiles or frozen["inventory"] != totals:
            raise ValueError("frozen profile/state inventory differs from deterministic complete graph")
    except Exception as error:
        output.mkdir(parents=True, exist_ok=False)
        result = {"schema": "hepta.hia.ndu.policy-audit-result.v1", "status": "rejected", "phase": "registration",
            "error": {"type": type(error).__name__, "message": str(error)}, "native_calls": 0,
            "wall_before_report_ns": time.monotonic_ns()-began, "authority": "DENY_ALL"}
        write(output / "RESULT.json", result)
        print(json.dumps(result), flush=True)
        return 1
    output.mkdir(parents=True, exist_ok=False)
    write(output / "REGISTRATION.json.gz", frozen)
    ledger = {arm: {key: 0 for key in ("transitions", "planning_wall_ns", "policy_evaluation_wall_ns", "completed", "failed", "not_run")} for arm in ARMS}
    results, fatal = [], None
    try:
        for item in frozen["profiles"]:
            directory = output / item["id"]
            directory.mkdir()
            try:
                result = audit_profile(item, p, frozen["inputs"], directory, ledger)
            except Exception as error:
                result = {"id": item["id"], "status": "failed", "planned_states": item["states"], "retained_states": 0,
                    "planned_cells": item["states"]*len(ARMS), "error": {"type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()},
                    "frozen_state_denominator": [node["id"] for node in item["graph"]["nodes"]]}
                write(directory / "FAILED.json", result)
            except BaseException as error:
                partial_path = directory / "PARTIAL.json.gz"
                partial = read(partial_path) if partial_path.exists() else {"rows": []}
                result = {"id": item["id"], "status": "interrupted", "planned_states": item["states"],
                    "retained_states": len(partial["rows"]), "planned_cells": item["states"]*len(ARMS),
                    "cell_status_counts": dict(Counter(c["status"] for r in partial["rows"] for c in r["arms"].values())),
                    "error": {"type": type(error).__name__, "message": str(error)},
                    "artifacts": [common.identity(path) for path in sorted(directory.iterdir()) if path.is_file()]}
                write(directory / "INTERRUPTED.json", result)
                results.append(result)
                raise
            results.append(result)
            print(json.dumps({"profile": item["id"], "status": result["status"], "done": len(results), "planned": len(frozen["profiles"])}), flush=True)
    except BaseException as error:
        fatal = {"type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()}
    postflight = []
    try:
        if source() != frozen["source"] or common.identity(args.registration) != registration:
            postflight.append("source or registration changed")
        check_inputs(frozen)
    except Exception as error:
        postflight.append(str(error))
    done = {r["id"] for r in results}
    missing = [{"id": item["id"], "planned_states": item["states"], "planned_cells": item["states"]*len(ARMS),
        "status": "not_run", "reason": "interrupted before profile", "state_ids": [n["id"] for n in item["graph"]["nodes"]]}
        for item in frozen["profiles"] if item["id"] not in done]
    checks = {"complete_profile_inventory": len(results) == p["expected_profiles"],
        "all_profiles_passed": bool(results) and all(r["status"] == "passed" for r in results),
        "source_and_inputs_unchanged": not postflight,
        "arm_transition_bounds_respected": all(r["transitions"] <= p["per_arm_transition_cap"] for r in ledger.values())}
    result = {"schema": "hepta.hia.ndu.policy-audit-result.v1", "source": frozen["source"], "registration": registration,
        "status": "passed" if fatal is None and all(checks.values()) else "failed", "checks": checks, "fatal_error": fatal,
        "postflight_errors": postflight, "planned_profiles": p["expected_profiles"], "retained_profiles": len(results),
        "planned_states": frozen["inventory"]["states"], "planned_cells": frozen["inventory"]["states"]*len(ARMS),
        "retained_states": sum(r["retained_states"] for r in results), "profiles": results, "missing_profiles": missing,
        "per_arm_ledgers": ledger, "freeze_wall_ns": frozen["freeze_wall_ns"], "wall_before_report_ns": time.monotonic_ns()-began,
        "cost_scope": "All current audit planning, graph construction, policy validation/evaluation, fixed selection, native startup/logging/cleanup included in outer wall; nested costs are not additive. Original build receipt retained; historical engineering, failed builds absent from that receipt, energy and monetary costs remain unknown.",
        "scope": p["scope"], "native_timing_is_advantage_endpoint": False, "full_lifecycle_cost_known": False,
        "ndu_exclusive_advantage_established": False, "production_activation": False, "authority": "DENY_ALL"}
    write(output / "RESULT.json", result)
    print(json.dumps({"status": result["status"], "checks": checks, "output": str(output)}), flush=True)
    return 0 if result["status"] == "passed" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    preflight = commands.add_parser("preflight")
    preflight.add_argument("--output", type=Path, required=True)
    freezing = commands.add_parser("freeze")
    freezing.add_argument("--value-binary", type=Path, required=True)
    freezing.add_argument("--value-manifest", type=Path, required=True)
    freezing.add_argument("--output", type=Path, required=True)
    running = commands.add_parser("run")
    running.add_argument("--registration", type=Path, required=True)
    running.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "preflight":
        began = time.monotonic_ns()
        profiles, totals = inventory(protocol())
        write(args.output, {"scope": "structure-only; no policy decision or value evaluation", **totals,
            "profiles": [{k: row[k] for k in ("id", "states", "edges", "graph_sha256")} for row in profiles],
            "wall_ns": time.monotonic_ns()-began})
        return 0
    if args.command == "freeze":
        freeze(args)
        return 0
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
