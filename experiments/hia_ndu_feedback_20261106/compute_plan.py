"""Explicit compute-resource planner beside the immutable feedback v1 model.

The v1 coverage and whole-policy protocols commit to model.py's exact bytes.
This successor keeps those bytes and historical registrations intact. It reuses
v1's primitives and backend validator, with its resource-aware recurrence here;
it never patches model.plan, global functions, or the old protocol hashes.
"""
from __future__ import annotations

from dataclasses import asdict, replace
from fractions import Fraction
import time

from .compute_debit import PLAN_SCHEMA, SCHEMA, after_compute, validate_profile
from .model import (ACTIONS, ARMS, AUTHORITY, Q32, FeedbackError, Observation,
                    Scenario, SearchBudgetExhausted, _call_backend, action_cost,
                    action_name, action_number, certainty_equivalent, forecast,
                    immediate, mul_q32, preferences, q32, scalar_backend,
                    validate_observation)

BASE_MODEL_SHA256 = "56b335e5a7fc205e4ad955faf3eece2a63d43c097f71d5fb4af6d84ee1081b79"


def plan(scenario: Scenario, observation: Observation, arm: str, *, compute_profile,
         backend=None, max_transitions: int = 20000, fixed_action: int = 0):
    """Plan under an explicitly frozen compute-resource successor profile.

    This recurrence is separate from the byte-frozen v1 planner. Legal actions,
    costs, beliefs, observations, fixed-point operations and backend response
    validation still come from v1. Only this explicit entry point adds compute
    forecasts to resource transitions and utility, including future abstention.
    Forecast durations never establish hard physical timing guarantees.
    """
    validate_observation(scenario, observation)
    if arm not in ARMS and arm not in {"wrong-forecast", "no-adaptation"}:
        raise FeedbackError("unknown comparison arm")
    if type(max_transitions) is not int or not 1 <= max_transitions <= 1000000:
        raise FeedbackError("search budget bounds")
    if fixed_action not in ACTIONS or type(fixed_action) is not int:
        raise FeedbackError("fixed action must be a cache slot or empty")
    if arm in {"dynamic-ndu", "fixed-preference-ndu"} and backend is None:
        raise FeedbackError("native arm requires an explicit native backend")
    validate_profile(compute_profile, scenario)
    if arm == "exact-oracle":
        raise FeedbackError("the v1 independent oracle does not implement compute-resource debits")
    compute_objective = compute_profile.objective_digest(scenario)
    start = time.perf_counter_ns()
    counters = {"states": 0, "transitions": 0, "backups": 0, "backend_calls": 0}
    node_receipts = []
    memo = {}
    fixed = arm in {"fixed-preference-ndu", "no-adaptation"}
    depth = 1 if arm in {"fixed", "state-greedy"} else scenario.horizon - observation.step
    modeling = scenario
    planning_observation = observation
    if arm == "wrong-forecast":
        # An explicit model-error intervention: invert the current posterior.
        # No hidden label or future sample is used to make this wrong forecast.
        planning_observation = replace(observation, belief_num=observation.belief_den-observation.belief_num)
    elif arm == "no-adaptation":
        planning_observation = replace(observation, belief_num=scenario.prior0_num, belief_den=scenario.prior0_den)
    evaluator = backend if arm in {"dynamic-ndu", "fixed-preference-ndu"} else scalar_backend

    def with_compute_objective(candidates, **kwargs):
        # Keep v1's complete backend response validation while explicitly binding
        # this successor objective. No mutation of v1 globals or shared state.
        fn = evaluator.evaluate if hasattr(evaluator, "evaluate") else evaluator
        return fn(candidates, **{**kwargs, "objective_digest": compute_objective})

    def solve(state, remaining):
        key = (state, remaining)
        if key in memo:
            return memo[key]
        counters["states"] += 1
        pref = preferences(modeling, state, fixed=fixed)
        candidates = []
        if arm == "ordinary-mpc":
            pref = {"price_q32": Q32, "discount_q32": Q32, "risk_q32": 0, "scarcity_num": 0, "scarcity_den": 1}
        compute_ns = compute_profile.forecast(modeling, state)
        available = after_compute(modeling, state, compute_ns)
        # The price is fixed at the observed, pre-computation state for this
        # entire step, matching FeedbackEnvironment.step's actual-cost rule.
        # A deadline already reached by computation permits no new service,
        # including a declared zero-duration workload. Abstention remains legal.
        compute_exhausted = compute_ns >= min(state.budget, state.deadline)
        for action in ACTIONS:
            counters["transitions"] += 1
            if counters["transitions"] > max_transitions:
                raise SearchBudgetExhausted(f"search exceeded {max_transitions} action expansions", transitions=max_transitions, statistics=counters)
            cost = action_cost(modeling, state, action)["total"]
            total_cost = cost + compute_ns
            feasible = not compute_exhausted and cost <= min(available.budget, available.deadline)
            continuation = []
            if feasible and remaining > 1:
                for probability, request, signal, belief in forecast(modeling, state):
                    child = Observation(state.step + 1, request, signal, action, available.budget - cost,
                                        available.deadline - cost, belief.numerator, belief.denominator)
                    continuation.append((probability, solve(child, remaining - 1)[0]))
            value = certainty_equivalent(continuation, pref["risk_q32"])
            instant = -q32(Fraction(total_cost, modeling.cost_unit)) if arm == "ordinary-mpc" else immediate(modeling, total_cost, pref)
            candidates.append({"id": action_name(action), "instant_q32": instant,
                               "terminal_q32": value, "discount_q32": pref["discount_q32"],
                               "feasible": feasible, "resource_q32": q32(Fraction(total_cost, modeling.cost_unit)), "risk_q32": 0})
        # Upstream requires an explicit feasible abstention candidate. This
        # terminates delivery and incurs the registered remaining-request loss;
        # it is never an over-budget direct dispatch disguised as abstention.
        counters["transitions"] += 1
        if counters["transitions"] > max_transitions:
            raise SearchBudgetExhausted(f"search exceeded {max_transitions} action expansions", transitions=max_transitions, statistics=counters)
        candidates.append({"id": "abstain",
                           "instant_q32": -modeling.miss_penalty_q32 * (modeling.horizon-state.step)
                               - mul_q32(pref["price_q32"], q32(Fraction(compute_ns, modeling.cost_unit))),
                           "terminal_q32": 0, "discount_q32": Q32, "feasible": True,
                           "resource_q32": 0, "risk_q32": 0})
        counters["backups"] += 1
        counters["backend_calls"] += int(evaluator is not scalar_backend)
        response = _call_backend(with_compute_objective, candidates, modeling, state, pref)
        chosen = response["winners"][0]
        if arm == "fixed":
            desired = action_name(fixed_action)
            fallback = [c for c in candidates if c["feasible"] and c["id"] != "abstain"]
            chosen = desired if next(c for c in candidates if c["id"] == desired)["feasible"] else min(fallback, key=lambda c: (c["resource_q32"], c["id"]))["id"] if fallback else "abstain"
        values = response["values"]
        result = (values[chosen], action_number(chosen), values, candidates, pref)
        # A compact search proof trace contains every node and no hidden values.
        node_receipt = {"state_digest": state.state_digest, "preference": pref,
                        "candidate_ids": [c["id"] for c in candidates],
                        "eligible": [c["id"] for c in candidates if c["feasible"]],
                        "selected": chosen, "values_q32": values}
        node_receipt["compute_debit"] = {"forecast_ns": compute_ns,
            "budget_before": state.budget, "deadline_before": state.deadline,
            "budget_after": available.budget, "deadline_after": available.deadline,
            "service_deadline_exhausted": compute_exhausted}
        node_receipts.append(node_receipt)
        memo[key] = result
        return result

    try:
        value, selected, values, candidates, pref = solve(planning_observation, depth)
    except Exception as error:
        error.search_stats = {**counters, "transitions": min(counters["transitions"], max_transitions)}
        error.transitions = error.search_stats["transitions"]
        error.controller_wall_ns = time.perf_counter_ns()-start
        raise
    result = {"schema": PLAN_SCHEMA, "arm": arm, "action": selected,
            "selected_action": action_name(selected),
            "value_q32": value, "candidate_values_q32": values, "candidates": candidates,
            "preference": pref, "observation": asdict(observation), "state_digest": observation.state_digest,
            "forecast": [{"probability": [p.numerator, p.denominator], "request": r, "signal": s,
                          "belief": [b.numerator, b.denominator]} for p, r, s, b in forecast(modeling, planning_observation)],
            "planning_belief": [planning_observation.belief_num, planning_observation.belief_den],
            "forecast_intervention": "posterior-inversion" if arm == "wrong-forecast" else "reset-to-prior" if arm == "no-adaptation" else None,
            "search": counters, "search_complete": depth == scenario.horizon - observation.step,
            "depth": depth, "search_trace": node_receipts, "controller_wall_ns": time.perf_counter_ns() - start,
            "native_backend_used": evaluator is not scalar_backend,
            "scope": "finite compute-resource successor; ordinary MPC has a different additive objective",
            "authority": AUTHORITY, "production_activation": False}
    result["compute_debit"] = {"schema": SCHEMA, "profile_sha256": compute_profile.identity,
        "profile": asdict(compute_profile), "objective_digest": compute_objective,
        "forecast_is_physical_guarantee": False, "hard_realtime_guarantee": False,
        "cost_rule": "compute plus workload once at each modeled decision; measured total at dispatch"}
    return result
