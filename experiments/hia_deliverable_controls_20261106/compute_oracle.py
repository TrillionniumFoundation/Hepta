"""Independent exhaustive source-model oracle with explicit compute debits.

This never imports the production graph compiler, native NDU, pruning or the
reference schedule scorer. It compares whole winner sets to the ordinary exact
DP. Supplied nanoseconds/Q32 values are declared models, not measured speedups.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
from itertools import product
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
Q32 = 1 << 32


def exhaustive_costed(model, *, current_invocation_ns=0):
    if type(current_invocation_ns) is not int or current_invocation_ns < 0:
        raise ValueError("nonnegative current invocation cost required")
    variants = {v["id"]: v for v in model["variants"]}
    names = sorted(k for k, v in variants.items() if v["status"] == "verified")
    horizon = len(model["baseline"]["latency_ns"])
    if len(names) > 3 or not 1 <= horizon <= 4:
        raise ValueError("independent oracle bound exceeded")
    sets = [frozenset(name for name, bit in zip(names, mask) if bit)
            for mask in product((0, 1), repeat=len(names))]
    sets = [ready for ready in sets if sum(variants[n]["resident_bytes"] for n in ready) <= model["memory_budget_bytes"]]
    reversible = model["schema"].endswith(".v3")
    best, winners, feasible, visited, min_ns = 0, set(), 0, 0, None
    for schedule in product(sets, repeat=horizon):
        visited += 1
        old = frozenset(model["initial_ready"])
        legal = True
        last_change = -1
        for i, ready in enumerate(schedule):
            if not reversible and not old <= ready:
                legal = False
                break
            if ready != old:
                last_change = i
            old = ready
        if not legal:
            continue
        stop_at = min(last_change + 1, horizon - 1)
        cost = current_invocation_ns
        debit = current_invocation_ns * Q32 // 1_000_000
        old = frozenset(model["initial_ready"])
        for i, ready in enumerate(schedule):
            transition = sum(variants[n]["preparation_ns"] for n in ready - old)
            if reversible:
                transition += sum(variants[n]["eviction_ns"] for n in old - ready)
            if 0 < i <= stop_at:
                transition += model.get("future_decision_cost_ns", 0)
            delivery = min([model["baseline"]["latency_ns"][i]] + [variants[n]["latency_ns"][i] for n in ready])
            delivery += sum(variants[n]["holding_ns"][i] for n in ready)
            cost += transition + delivery
            debit += transition * Q32 // 1_000_000 + delivery * Q32 // 1_000_000
            old = ready
        if cost > model["budget_ns"]:
            continue
        feasible += 1
        min_ns = cost if min_ns is None else min(min_ns, cost)
        value = model["completion_value_ns"] * Q32 // 1_000_000 - debit
        if value > best:
            best, winners = value, set()
        if value == best:
            winners.add(tuple(tuple(sorted(s)) for s in schedule))
    return {"best_value_q32": best, "winning_schedules": sorted(winners),
            "visited_complete_schedules": visited, "feasible_schedules": feasible,
            "minimum_feasible_cost_ns": min_ns, "abstain_is_optimal": best == 0}


def audit_compute_costs():
    from hepta.hia_ndu_stateful import invocation_gate
    from tools.qualify_hia_ndu_stateful import fixtures
    from tools.qualify_hia_ndu_costed import costed_fixtures, residency_fixtures
    from tools.qualify_hia_ndu_stateful_reference import exact_dp_control

    started = time.monotonic_ns()
    models = fixtures() + costed_fixtures() + residency_fixtures()
    cases, gate_cases = [], []
    visited, boundary_cases, future_compute_sensitive_cases = 0, 0, 0
    for model in models:
        independent = exhaustive_costed(model)
        reference = exact_dp_control(model)
        expected = sorted(tuple(tuple(names) for names in row["schedule"]) for row in reference["winners"])
        assert independent["best_value_q32"] == reference["best_value_q32"], model["name"]
        assert independent["winning_schedules"] == expected, model["name"] + " winner set"
        visited += independent["visited_complete_schedules"]
        if model.get("future_decision_cost_ns", 0):
            uncharged = deepcopy(model)
            uncharged["future_decision_cost_ns"] = 0
            cheaper = exhaustive_costed(uncharged)
            assert cheaper["best_value_q32"] >= independent["best_value_q32"]
            if cheaper["best_value_q32"] != independent["best_value_q32"]:
                future_compute_sensitive_cases += 1
        minimum = independent["minimum_feasible_cost_ns"]
        if minimum is not None and minimum > 0:
            for budget in (minimum - 1, minimum):
                boundary = deepcopy(model)
                boundary["budget_ns"] = budget
                first, second = exhaustive_costed(boundary), exact_dp_control(boundary)
                assert first["best_value_q32"] == second["best_value_q32"], model["name"] + " boundary"
                boundary_cases += 1
            boundary = deepcopy(model)
            boundary["budget_ns"] = minimum
            charged = exhaustive_costed(boundary, current_invocation_ns=1)
            assert charged["feasible_schedules"] == 0, model["name"] + " omitted current compute debit"
            boundary_cases += 1
        cases.append({"name": model["name"], "schema": model["schema"],
                      "future_decision_cost_ns": model.get("future_decision_cost_ns", 0),
                      "best_value_q32": independent["best_value_q32"],
                      "winning_schedule_count": len(independent["winning_schedules"]),
                      "visited_complete_schedules": independent["visited_complete_schedules"],
                      "ordinary_dp_agreement": True})
        for current in (0, 1, 1_000_000, 100_000_000):
            gate = invocation_gate(model, invocation_cost_ns=current)
            after_pay = exhaustive_costed(model, current_invocation_ns=current)
            checked = not gate["invoke"] and gate["incumbent_delivery_ns"] <= model["budget_ns"]
            if checked:
                assert after_pay["minimum_feasible_cost_ns"] is None or after_pay["minimum_feasible_cost_ns"] >= gate["incumbent_delivery_ns"], model["name"] + " unsound skip"
            gate_cases.append({"name": model["name"], "current_invocation_ns": current,
                               "invoke": gate["invoke"], "reason": gate["reason"], "safe_skip_checked": checked})
    sources = [Path(__file__), ROOT / "hepta/hia_ndu_stateful.py",
               ROOT / "tools/qualify_hia_ndu_stateful.py", ROOT / "tools/qualify_hia_ndu_costed.py",
               ROOT / "tools/qualify_hia_ndu_stateful_reference.py"]
    return {"schema": "hepta.hia.deliverable-controls.compute-audit.v1", "status": "passed",
            "scope": "source-model agreement, integer budget/Q32 rounding and invocation-gate counterexamples",
            "cases": cases, "gate_cases": gate_cases, "boundary_cases": boundary_cases,
            "visited_complete_schedules": visited, "future_compute_sensitive_cases": future_compute_sensitive_cases, "audit_wall_ns": time.monotonic_ns() - started,
            "source_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
            "native_ndu_calls": 0, "model_calls": 0, "training_runs": 0,
            "sample_independence_claim": False, "actual_wall_time_budget_guarantee": False,
            "ndu_advantage_established": False, "authority": "DENY_ALL", "production_activation_allowed": False}
