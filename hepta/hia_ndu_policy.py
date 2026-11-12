"""Bounded search policies over the existing dynamic-cache model.

Only the search order/beam retention changes. Legal actions, ownership, epochs,
and cost arithmetic belong to ``hia_ndu_dynamic``. This module cannot execute
an artifact, attest native NDU use, or issue an adoption/safety credential.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import time

from .hia_ndu_dynamic import (DynamicError, action, call_cost, digest, fields,
                              integer, live_mask, resident_bytes, validate_model, wire)

POLICY_SCHEMA = "hepta.hia.ndu.search-policy.v1"
PLAN_SCHEMA = "hepta.hia.ndu.search-policy-advice.v1"
MAX_TRANSITIONS = 1_000_000


class PolicyBudgetExhausted(DynamicError):
    """No truncated search result is returned as a complete plan."""


class TransitionBudget:
    """One controller's search allowance, shared across its entire lifecycle.

    Count each considered search action as it happens, including work before
    a failed search. Input checking, witness replay, compilation, and native
    ranking remain separately observed wall costs rather than fake transitions.
    """
    def __init__(self, maximum):
        integer(maximum, "controller lifecycle transition budget", 100_000_000)
        self.maximum = maximum
        self.transitions = 0
        self.phases = []

    @property
    def remaining(self):
        return self.maximum - self.transitions

    def take(self, phase):
        if self.transitions >= self.maximum:
            raise PolicyBudgetExhausted("controller lifecycle transition budget exhausted")
        self.transitions += 1
        if self.phases and self.phases[-1]["phase"] == phase:
            self.phases[-1]["transitions"] += 1
        else:
            self.phases.append({"phase": phase, "transitions": 1})

    def snapshot(self):
        return {"limit": self.maximum, "transitions": self.transitions,
                "remaining": self.remaining, "phases": deepcopy(self.phases),
                "unit": "considered search actions, including failed and losing candidates",
                "scope": "training, all generation selection, and final policy search",
                "other_costs": "input checking, witness replay, builds, native ranking, and audits are charged as wall time"}


def policy(*, width=4, lookahead=0, retention_weight=0):
    return {"schema": POLICY_SCHEMA, "width": width, "lookahead": lookahead,
            "retention_weight": retention_weight}


def validate_policy(raw):
    fields(raw, "schema width lookahead retention_weight", "search policy")
    if type(raw["schema"]) is not str or raw["schema"] != POLICY_SCHEMA:
        raise DynamicError("unsupported search policy")
    integer(raw["width"], "beam width", 256)
    integer(raw["lookahead"], "lookahead", 12)
    integer(raw["retention_weight"], "retention weight", 8)
    if raw["width"] == 0:
        raise DynamicError("beam width must be positive")
    return deepcopy(raw)


@dataclass
class _Budget:
    maximum: int
    transitions: int = 0
    total: TransitionBudget | None = None
    phase: str = "search"

    def take(self):
        if self.transitions >= self.maximum:
            raise PolicyBudgetExhausted("complete policy transition budget exhausted")
        if self.total is not None:
            self.total.take(self.phase)
        self.transitions += 1


def _potential(model, batch, ready, lookahead):
    """One search feature: reusable forecast saving before announced invalidation.

    This is a heuristic, not a lower bound. It never admits a resource action.
    No future observed runtime or exact-oracle value enters the feature.
    """
    total = 0
    stop = min(len(model["targets"]), batch + 1 + lookahead)
    for future in range(batch + 1, stop):
        ready = live_mask(model, future, ready)
        if ready & (1 << model["targets"][future]):
            total += max(0, model["direct_ns"][future] - model["packed_ns"][future])
    return total


def _finish(model, path):
    ready, actions = model["ready_mask"], []
    for batch, target in enumerate(path):
        step = action(model, batch, ready, target)
        actions.append(step)
        ready = target
    current = call_cost(model, model["session_ready"])
    total = current + model["decision"]["close_ns"] + sum(a["total_ns"] for a in actions)
    return {"actions": actions, "current_committed_ns": current,
            "close_ns": model["decision"]["close_ns"], "total_ns": total}


def validate_plan(raw_model, plan):
    """Replay a complete candidate with the existing independent resource owner.

    This establishes only a witness in the supplied forecast model. It is not
    an exact-optimum proof, machine-code proof, or physical deadline guarantee.
    """
    model = validate_model(raw_model)
    fields(plan, "actions current_committed_ns close_ns total_ns", "policy plan")
    if type(plan["actions"]) is not list or len(plan["actions"]) != len(model["targets"]):
        raise DynamicError("policy must supply the complete horizon")
    path = []
    for step in plan["actions"]:
        if type(step) is not dict or "ready_after" not in step:
            raise DynamicError("malformed policy action")
        integer(step["ready_after"], "resident action", (1 << len(model["artifacts"])) - 1)
        path.append(step["ready_after"])
    expected = _finish(model, path)
    if wire(expected) != wire(plan) or expected["total_ns"] > model["budget_ns"]:
        raise DynamicError("policy witness differs from resource arithmetic or budget")
    return expected


def select(raw_model, raw_policy, *, max_transitions=MAX_TRANSITIONS, fixed_mask=None,
           total_budget=None, budget_phase="search"):
    """Search one fixed candidate universe under an explicit work cap.

    ``width=1, lookahead=0`` is the greedy control. ``width>=legal masks``
    retains every resident state and is exact for the scalar additive model.
    Smaller beams are approximate even when they happen to match the oracle.
    A fixed-mask arm follows the same transition arithmetic without fitting.
    """
    started = time.perf_counter_ns()
    model, configuration = validate_model(raw_model), validate_policy(raw_policy)
    integer(max_transitions, "maximum transitions", MAX_TRANSITIONS)
    if total_budget is not None and type(total_budget) is not TransitionBudget:
        raise DynamicError("exact controller transition budget required")
    if type(budget_phase) is not str or not 1 <= len(budget_phase) <= 256:
        raise DynamicError("bounded search budget phase required")
    budget = _Budget(max_transitions, total=total_budget, phase=budget_phase)
    masks = [m for m in range(1 << len(model["artifacts"]))
             if resident_bytes(model, m) <= model["memory_quota_bytes"]]
    if fixed_mask is not None:
        integer(fixed_mask, "fixed resident mask", (1 << len(model["artifacts"])) - 1)
        if fixed_mask not in masks:
            raise DynamicError("fixed resident mask exceeds quota")
    paths = [(0, model["ready_mask"], ())]
    states, discarded = 0, 0
    for batch in range(len(model["targets"])):
        best = {}
        for prefix_cost, ready, prefix in paths:
            states += 1
            targets = [fixed_mask] if fixed_mask is not None else masks
            for target in targets:
                budget.take()
                step = action(model, batch, ready, target)
                row = (prefix_cost + step["total_ns"], target, (*prefix, target))
                previous = best.get(target)
                if previous is None or (row[0], row[2]) < (previous[0], previous[2]):
                    best[target] = row
        paths = sorted(best.values(), key=lambda row: (
            row[0] - configuration["retention_weight"] * _potential(
                model, batch, row[1], configuration["lookahead"]), row[0], row[1], row[2]))
        discarded += max(0, len(paths) - configuration["width"])
        paths = paths[:configuration["width"]]
    proposals = [_finish(model, row[2]) for row in paths]
    feasible = [p for p in proposals if p["total_ns"] <= model["budget_ns"]]
    chosen = min(feasible, key=lambda p: (p["total_ns"], tuple(
        a["ready_after"] for a in p["actions"]))) if feasible else None
    if chosen is not None:
        chosen = validate_plan(model, chosen)
    # Abstain remains an explicit outcome, including a completion-value tie.
    if chosen is not None and model["completion_value_ns"] <= (
            chosen["total_ns"] - chosen["current_committed_ns"] - chosen["close_ns"]):
        chosen = None
    return {"schema": PLAN_SCHEMA, "model_sha256": digest(model),
            "policy": configuration, "fixed_mask": fixed_mask,
            "plan": chosen, "candidate_plans": deepcopy(feasible), "status": "advisory" if chosen is not None else "abstain",
            "search": {"states": states, "transitions": budget.transitions,
                       "beam_pruned": discarded, "max_transitions": max_transitions,
                       "legal_mask_count": len(masks)},
            "search_complete": fixed_mask is None and configuration["width"] >= len(masks),
            "wall_ns": time.perf_counter_ns() - started,
            "native_ndu_evaluated": False, "authority": "DENY_ALL",
            "safety_certificate": False, "execution_authorized": False}


def propose_generation(training_models, incumbent, candidates, *, max_transitions,
                       generation_budget, total_budget=None, budget_phase="training"):
    """Fit a finite search-policy mutation using training tasks only.

    This is empirical policy search, not self-authorized code rewriting. Every
    candidate sees exactly the same ordered training model inventory. The
    shared training work budget includes losing candidates and the incumbent.
    A caller must independently validate any winner on untouched tasks.
    """
    started = time.perf_counter_ns()
    if type(budget_phase) is not str or not 1 <= len(budget_phase) <= 200:
        raise DynamicError("bounded training budget phase required")
    if type(training_models) is not list or not 1 <= len(training_models) <= 256:
        raise DynamicError("one to 256 training models required")
    models = [validate_model(m) for m in training_models]
    integer(max_transitions, "maximum transitions", MAX_TRANSITIONS)
    incumbent = validate_policy(incumbent)
    if type(candidates) is not list or not candidates or len(candidates) > 64:
        raise DynamicError("one to 64 bounded policy candidates required")
    integer(generation_budget, "generation transition budget", 100_000_000)
    configurations = [incumbent]
    for candidate in candidates:
        configuration = validate_policy(candidate)
        if configuration not in configurations:
            configurations.append(configuration)
    used, rows = 0, []
    for candidate_index, configuration in enumerate(configurations):
        observations = []
        for model in models:
            remaining = generation_budget - used
            if remaining <= 0:
                raise PolicyBudgetExhausted("generation training budget exhausted")
            result = select(model, configuration, max_transitions=min(max_transitions, remaining),
                            total_budget=total_budget,
                            budget_phase=f"{budget_phase}/candidate-{candidate_index}")
            used += result["search"]["transitions"]
            if result["plan"] is None:
                raise DynamicError("training candidate did not deliver the declared complete task")
            observations.append({"model_sha256": result["model_sha256"],
                "cost_ns": result["plan"]["total_ns"], "search": result["search"],
                "wall_ns": result["wall_ns"]})
        rows.append({"policy": configuration, "modeled_cost_ns": sum(
            r["cost_ns"] for r in observations), "observations": observations})
    # Stable ties retain the incumbent when its cost is already optimal.
    winner = min(range(len(rows)), key=lambda i: (rows[i]["modeled_cost_ns"], i))
    return {"schema": "hepta.hia.ndu.policy-generation-proposal.v1",
            "training_model_sha256": [digest(m) for m in models],
            "incumbent": incumbent, "proposed": rows[winner]["policy"],
            "candidates": rows, "transitions": used,
            "generation_budget": generation_budget,
            "training_wall_ns": time.perf_counter_ns() - started,
            "selection_data_used": False, "final_holdout_used": False,
            "authority": "DENY_ALL", "safety_certificate": False,
            "execution_authorized": False}
