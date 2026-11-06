#!/usr/bin/env python3
"""Loss-preserving historical index and strict, conditional paired cost assessment.

No model calls, network requests, training, native builds or production activation.
An accepted report checks supplied evidence; it never authenticates its observer.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from fractions import Fraction
import hashlib
import json
from math import comb
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MAX_BYTES = 4 * 1024 * 1024
ARMS = {
    "agent_factorial": ("hia_full", "ordinary_full", "hia_patch", "ordinary_patch"),
    "ndu_increment": ("ndu", "mle_exact_dp", "lightweight", "fixed"),
}
CONTRASTS = {
    "agent_factorial": (("hia_full", "ordinary_full"), ("hia_patch", "ordinary_patch")),
    "ndu_increment": (("ndu", "mle_exact_dp"), ("ndu", "lightweight"), ("ndu", "fixed")),
}
METRICS = ("elapsed_ns", "input_tokens", "output_tokens", "cached_tokens",
           "billed_micro_usd", "human_review_ns", "repair_ns",
           "failed_attempt_ns", "peak_rss_bytes")
STATUSES = {"success", "failure", "refused", "cancelled", "missing"}
HEX = re.compile(r"^[0-9a-f]{64}$")


class ControlsRejected(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ControlsRejected(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def wire(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def _duplicates(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def read_json(raw):
    require(type(raw) is bytes and len(raw) <= MAX_BYTES, "expected bounded immutable JSON bytes")
    def constant(_):
        raise ControlsRejected("nonfinite JSON constant")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_duplicates, parse_constant=constant)
    except (UnicodeError, ValueError, RecursionError) as error:
        if isinstance(error, ControlsRejected):
            raise
        raise ControlsRejected("invalid bounded JSON") from error


def shape(value, keys, label):
    require(type(value) is dict and set(value) == set(keys), label + ": missing or extra fields")


def number(value, label):
    require(type(value) is int and 0 <= value <= (1 << 63) - 1, label + ": expected nonnegative integer")
    return value


def sha(value, label):
    require(type(value) is str and HEX.fullmatch(value) is not None, label + ": expected SHA256")
    return value


def ledger(value):
    """Unknown is null, not zero. Phase times are nested in elapsed, never added."""
    shape(value, METRICS, "cost ledger")
    result = {}
    for name, metric in value.items():
        shape(metric, ("status", "value", "evidence"), name)
        require(type(metric["evidence"]) is str and 1 <= len(metric["evidence"]) <= 2000,
                name + ": evidence or unknown reason is mandatory")
        status, amount = metric["status"], metric["value"]
        require(status in {"measured", "not_applicable", "unknown"}, name + ": invalid cost status")
        if status == "unknown":
            require(amount is None, name + ": unknown cost must remain null")
        else:
            number(amount, name)
            if status == "not_applicable":
                require(amount == 0, name + ": not-applicable cost must explicitly be zero")
        result[name] = amount
    if result["elapsed_ns"] is not None:
        for name in ("human_review_ns", "repair_ns", "failed_attempt_ns"):
            require(result[name] is None or result[name] <= result["elapsed_ns"],
                    name + ": phase exceeds enclosing elapsed time")
    return result


def _total(values):
    return None if any(value is None for value in values) else sum(values)


def _sign(wins, losses):
    count = wins + losses
    return Fraction(sum(comb(count, k) for k in range(wins, count + 1)), 2 ** count)


def assess_campaign(protocol_raw, results_raw):
    """Check preregistration, complete factorial cells and all strong controls.

    Time comparisons use enclosing per-cell elapsed plus enclosing setup once.
    Nested review/repair/failure times remain visible but are not added again.
    Independent units are task families, never cells, states or repeated seeds.
    """
    protocol, results = read_json(protocol_raw), read_json(results_raw)
    shape(protocol, ("schema", "study", "arms", "tasks", "information_digest",
                     "candidate_bank_digest", "model_identity_digest", "hardware_digest",
                     "setup_policy", "clock_policy", "minimum_independent_units", "minimum_gain_ns",
                     "minimum_gain_ppm", "maximum_peak_rss_bytes", "maximum_cell_elapsed_ns"), "protocol")
    require(protocol["schema"] == "hepta.hia.deliverable-controls.protocol.v1", "unsupported protocol")
    study = protocol["study"]
    require(study in ARMS, "language and planner studies must remain separate")
    require(protocol["arms"] == list(ARMS[study]), "missing, extra or reordered strong-control arm")
    for name in ("information_digest", "candidate_bank_digest", "model_identity_digest", "hardware_digest"):
        sha(protocol[name], name)
    require(protocol["setup_policy"] == "full_charge_each_standalone_arm", "unregistered amortization")
    require(protocol["clock_policy"] == "disjoint_cells_with_enclosing_phase_clocks", "overlapping elapsed clocks")
    require(type(protocol["minimum_independent_units"]) is int and
            8 <= protocol["minimum_independent_units"] <= 128, "require at least eight independent units")
    for name in ("minimum_gain_ns", "minimum_gain_ppm", "maximum_peak_rss_bytes", "maximum_cell_elapsed_ns"):
        require(number(protocol[name], name) > 0, name + ": positive preregistered threshold required")
    require(protocol["minimum_gain_ppm"] <= 1_000_000, "gain ppm exceeds one million")
    tasks = protocol["tasks"]
    require(type(tasks) is list and 1 <= len(tasks) <= 128, "bounded nonempty preregistered tasks required")
    task_map = {}
    for task in tasks:
        shape(task, ("id", "independent_unit", "kind", "input_digest", "expected_output_digest"), "task")
        for key in ("id", "independent_unit", "kind"):
            require(type(task[key]) is str and 1 <= len(task[key]) <= 128, "invalid task identity")
        for key in ("input_digest", "expected_output_digest"):
            sha(task[key], key)
        require(task["id"] not in task_map, "duplicate preregistered task")
        task_map[task["id"]] = task
    require(list(task_map) == sorted(task_map), "task registration order must be canonical")
    shape(results, ("schema", "protocol_sha256", "setup", "cells"), "results")
    require(results["schema"] == "hepta.hia.deliverable-controls.results.v1", "unsupported result schema")
    require(results["protocol_sha256"] == digest(protocol_raw), "preregistration changed after freezing")
    shape(results["setup"], ARMS[study], "setup arms")
    setup = {arm: ledger(cost) for arm, cost in results["setup"].items()}
    cells = results["cells"]
    require(type(cells) is list and len(cells) == len(tasks) * 4, "every planned cell must be retained")
    indexed, costs = {}, {}
    for cell in cells:
        shape(cell, ("task", "arm", "status", "input_digest", "output_digest",
                     "information_digest", "candidate_bank_digest", "model_identity_digest",
                     "hardware_digest", "attempts", "ndu_native_calls", "costs"), "cell")
        key = (cell["task"], cell["arm"])
        require(cell["task"] in task_map and cell["arm"] in ARMS[study] and key not in indexed,
                "extra or duplicate cell")
        require(cell["status"] in STATUSES, "unsupported cell outcome")
        require(cell["input_digest"] == task_map[cell["task"]]["input_digest"], "task input drift")
        for name in ("information_digest", "candidate_bank_digest", "model_identity_digest", "hardware_digest"):
            require(cell[name] == protocol[name], "unequal controls: " + name)
        number(cell["attempts"], "attempt count")
        number(cell["ndu_native_calls"], "native call count")
        require(cell["status"] == "missing" or cell["attempts"] > 0, "observed cell has no attempt")
        require(cell["status"] != "missing" or cell["attempts"] == 0, "missing cell has attempts")
        require(cell["arm"] == "ndu" or cell["ndu_native_calls"] == 0, "control arm invoked NDU")
        if cell["status"] == "success":
            require(cell["output_digest"] == task_map[cell["task"]]["expected_output_digest"], "success differs from registered oracle")
        elif cell["output_digest"] is not None:
            sha(cell["output_digest"], "failed output digest")
        indexed[key], costs[key] = cell, ledger(cell["costs"])
        if cell["status"] == "missing":
            require(all(metric["status"] == "unknown" for metric in cell["costs"].values()),
                    "missing work must retain unknown costs")
    expected_keys = {(task, arm) for task in task_map for arm in ARMS[study]}
    require(set(indexed) == expected_keys, "planned cells missing")
    totals = {}
    for arm in ARMS[study]:
        rows = [indexed[task, arm] for task in task_map]
        values = [setup[arm], *(costs[task, arm] for task in task_map)]
        totals[arm] = {
            "planned": len(tasks), "outcomes": dict(Counter(row["status"] for row in rows)),
            "attempts_including_failed": sum(row["attempts"] for row in rows),
            "ndu_native_calls": sum(row["ndu_native_calls"] for row in rows),
            "elapsed_ns_including_setup": _total([row["elapsed_ns"] for row in values]),
            "billed_micro_usd_including_setup": _total([row["billed_micro_usd"] for row in values]),
            "all_cost_fields_known": all(all(value is not None for value in row.values()) for row in values),
            "unknown_cost_fields": [{"scope": "setup" if i == 0 else tasks[i - 1]["id"],
                                     "fields": sorted(k for k, v in row.items() if v is None)}
                                    for i, row in enumerate(values) if any(v is None for v in row.values())],
        }
    comparisons = []
    groups = sorted({task["independent_unit"] for task in tasks})
    alpha = Fraction(1, 20 * len(CONTRASTS[study]))
    for candidate, control in CONTRASTS[study]:
        quality = Counter(wins=0, losses=0, ties=0)
        timing = Counter(wins=0, losses=0, ties=0, unknown=0)
        for task in task_map:
            c, b = indexed[task, candidate]["status"] == "success", indexed[task, control]["status"] == "success"
            quality["wins" if c > b else "losses" if c < b else "ties"] += 1
        for group in groups:
            identifiers = [task["id"] for task in tasks if task["independent_unit"] == group]
            c = _total([costs[t, candidate]["elapsed_ns"] for t in identifiers])
            b = _total([costs[t, control]["elapsed_ns"] for t in identifiers])
            # A failed task cannot become a fast success by returning early.
            complete = all(indexed[t, arm]["status"] == "success" for t in identifiers for arm in (candidate, control))
            timing["unknown" if c is None or b is None or not complete else "wins" if c < b else "losses" if c > b else "ties"] += 1
        p = _sign(timing["wins"], timing["losses"])
        ctotal, btotal = totals[candidate], totals[control]
        complete = ctotal["all_cost_fields_known"] and btotal["all_cost_fields_known"]
        gain = (btotal["elapsed_ns_including_setup"] - ctotal["elapsed_ns_including_setup"]) if complete else None
        strictly_faster = (complete and gain >= protocol["minimum_gain_ns"] and
                           gain * 1_000_000 >= protocol["minimum_gain_ppm"] * btotal["elapsed_ns_including_setup"])
        no_money_regression = complete and ctotal["billed_micro_usd_including_setup"] <= btotal["billed_micro_usd_including_setup"]
        comparisons.append({"candidate": candidate, "control": control,
                            "correctness_by_task": dict(quality), "elapsed_by_independent_unit": dict(timing),
                            "total_elapsed_gain_ns": gain,
                            "one_sided_sign_p": {"numerator": p.numerator, "denominator": p.denominator},
                            "multiplicity_adjusted_alpha": {"numerator": alpha.numerator, "denominator": alpha.denominator},
                            "conditional_cost_evidence_passed": bool(complete and strictly_faster and no_money_regression
                                and len(groups) >= protocol["minimum_independent_units"]
                                and timing["unknown"] == 0 and p <= alpha)})
    reasons = []
    if any(cell["status"] != "success" for cell in cells):
        reasons.append("unfinished_or_incorrect_cells_retained")
    if not all(value["all_cost_fields_known"] for value in totals.values()):
        reasons.append("unknown_full_lifecycle_cost")
    if any(values["peak_rss_bytes"] is not None and values["peak_rss_bytes"] > protocol["maximum_peak_rss_bytes"]
           for values in [*setup.values(), *costs.values()]):
        reasons.append("registered_memory_limit_exceeded")
    if any(values["elapsed_ns"] is not None and values["elapsed_ns"] > protocol["maximum_cell_elapsed_ns"]
           for values in costs.values()):
        reasons.append("registered_cell_deadline_exceeded")
    if len(groups) < protocol["minimum_independent_units"]:
        reasons.append("too_few_independent_units")
    if study == "ndu_increment" and totals["ndu"]["ndu_native_calls"] == 0:
        reasons.append("no_actual_ndu_invocation")
    if not all(row["conditional_cost_evidence_passed"] for row in comparisons):
        reasons.append("strong_control_threshold_not_met")
    return {"schema": "hepta.hia.deliverable-controls.assessment.v1", "study": study,
            "protocol_sha256": digest(protocol_raw), "results_sha256": digest(results_raw),
            "planned_cells": len(cells), "independent_units": len(groups), "arms": totals,
            "contrasts": comparisons, "reasons": reasons, "conditional_observed_advantage": not reasons,
            "observer_authenticated": False, "task_independence_verified": False,
            "population_advantage_established": False, "production_activation_allowed": False,
            "authority": "DENY_ALL", "phase_time_policy": "nested phases never added to enclosing elapsed"}


def historical_summary(base=HERE):
    manifest = read_json((base / "HISTORY.json").read_bytes())
    require(manifest["schema"] == "hepta.hia.deliverable-controls.history.v1", "invalid history index")
    verified, documents = [], {}
    for record in manifest["records"]:
        path = base / record["path"]
        require(path.resolve().is_relative_to(base.resolve()), "history path escapes its directory")
        raw = path.read_bytes()
        require(len(raw) == record["bytes"] and digest(raw) == record["sha256"], "historical source bytes changed: " + record["id"])
        blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        require(blob == record["git_blob_sha1"], "historical Git blob mismatch")
        require(record["id"] not in documents, "duplicate historical record")
        documents[record["id"]] = read_json(raw) if path.suffix == ".json" else raw.decode()
        verified.append({k: record[k] for k in ("id", "source_commit", "sha256", "url")})
    r6 = documents["round6-results.json"]
    old = documents["frontier-20261030.json"]
    agent = {}
    for name, cohort in r6["ai"].items():
        require(cohort["complete"] is True and cohort["missing_cells"] == [], "historical factorial incomplete")
        require(len(cohort["arms"]) == 4, "historical factorial lost an arm")
        signatures = {(row["language"], row["interface"]) for row in cohort["arms"]}
        require(signatures == {("assembly", "full"), ("rust", "full"), ("assembly", "patch"), ("rust", "patch")}, "historical arm changed")
        require(all(row["correct"] == row["planned"] == row["observed"] for row in cohort["arms"]), "historical outcome changed")
        agent[name] = {"observed_cells": cohort["observed_cells"], "underlying_tasks": cohort["arms"][0]["planned"],
                       "four_arm_correctness": "tie", "arms": cohort["arms"],
                       "preparation_wall_ns": cohort["preparation_wall_ns"], "raw_evidence": cohort["evidence"],
                       "full_lifecycle_cost_known": False, "statistical_independent_units_verified": False}
    legacy_main = [cell for cell in old["cells"] if cell["stage"] == "main"]
    legacy = {"planned_main_cells": len(legacy_main), "successful_main_cells": sum(cell["correct"] for cell in legacy_main),
              "all_main_outcomes": legacy_main, "arms": old["arms"], "bootstrap": old["bootstrap"],
              "whole_service_lifecycle_usage_complete": old["bootstrap"]["whole_service_lifecycle_usage_complete"],
              "reinterpret_as_round6": False}
    ndu = {name: {k: cohort[k] for k in ("status", "native_equal_rankings", "native_paired_cases",
                    "native_ndu_evaluated", "ndu_increment_ns", "cost_ledger", "generations", "findings", "arms", "evidence")}
           for name, cohort in r6["ndu"].items()}
    policy = documents["ndu-policy-descriptive-summary.json"]
    policy_summary = {key: policy[key] for key in ("profiles", "states", "cell_status_counts", "costs_by_arm",
                    "state_comparisons", "full_lifecycle_cost_known", "ndu_exclusive_advantage_established", "checks", "result")}
    return {"schema": "hepta.hia.deliverable-controls.history-summary.v1", "verified_sources": verified,
            "agent_factorial_round6": agent, "agent_prior_failures": legacy, "ndu_round6": ndu,
            "ndu_policy_closure": policy_summary, "ndu_policy_blockers": documents["ndu-policy-blocker-disposition.json"],
            "other_negative_reports": [record for record in verified if record["id"].endswith(".md")],
            "raw_evidence_status": "Source-owned summaries copied byte-for-byte; original large raw artifacts are indexed, not newly archived or rerun.",
            "pooling": "No pooling across source revisions, languages, interfaces, tasks, episodes or model states.",
            "new_model_calls": 0, "new_native_ndu_calls": 0, "full_cost_advantage_established": False,
            "authority": "DENY_ALL", "production_activation_allowed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--protocol", type=Path)
    parser.add_argument("--results", type=Path)
    args = parser.parse_args()
    require(bool(args.protocol) == bool(args.results), "provide both protocol and results")
    require(not args.output.exists(), "output already exists; preserve previous attempts")
    if args.protocol:
        report = assess_campaign(args.protocol.read_bytes(), args.results.read_bytes())
    else:
        from compute_oracle import audit_compute_costs
        report = {"schema": "hepta.hia.deliverable-controls.run.v1", "historical": historical_summary(),
                  "native_free_compute_audit": audit_compute_costs(),
                  "new_agent_campaign_executed": False, "new_ndu_native_campaign_executed": False}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("xb") as stream:
        stream.write(wire(report))
    print(json.dumps({"output": str(args.output), "sha256": digest(args.output.read_bytes()),
                      "new_model_calls": 0, "new_native_ndu_calls": 0}))


if __name__ == "__main__":
    main()
