"""A linear-work, forecast-priced planning gate for the finite research model.

The gate does one root greedy decision and scalar bounds, never a future-state
policy evaluation. Both ordinary and native planning receive the same bounds.
Forecast compute prices are caller-supplied training estimates, not guarantees
about realized elapsed time. The v1 model and its negative results are unchanged.
"""
from __future__ import annotations

from fractions import Fraction
import time

from .model import (ACTIONS, AUTHORITY, Q32, FeedbackError, SearchBudgetExhausted,
                    action_cost, digest, mul_q32, plan, q32, validate_observation)

PLANNER_ARMS = ("same-objective", "dynamic-ndu")
MAX_FORECAST_NS = 10**12


def _require(condition, reason):
    if not condition:
        raise FeedbackError("priced planning: " + reason)


def priced_plan(scenario, observation, planner_arm, *, backend=None,
                forecast_control_ns, greedy_forecast_ns, max_transitions=20000):
    """Return a complete ``plan`` decision with an explicit ``compute_gate``.

    ``forecast_control_ns`` measures this arm's full planner on separate training
    inputs; ``greedy_forecast_ns`` measures the common greedy controller there.
    Workload costs and observations must be expressed in nanoseconds, with
    ``scenario.cost_unit`` specifying nanoseconds per utility-cost unit.

    The optimistic planner has free future loading/retirement, hot execution,
    price one, no downside loss and no future computation bill. A lower bound
    on the greedy policy uses the maximum legal workload cost, price at most
    two, and CE >= min(child). Enough resources can certify continued feasibility
    and price one. Otherwise both abstention and later continued-work losses are
    retained: one immediate abstention penalty alone is not always a lower bound
    on a policy that can serve first and abstain later.

    Future greedy fees are conservatively included in a separate costed lower
    bound under the constant supplied greedy forecast. To cover a table of
    different future-depth forecasts, the caller must supply their training-only
    maximum. Neither choice is a bound on actual future elapsed time. The current
    greedy decision is already paid for, so that sunk fee is
    not credited against the additional planner's price. Zero task-value gap and
    horizon one always stop, regardless of forecast future fees. Returning a
    priced decision does not establish positive observed net benefit.

    Counting one scalar bound backup or root candidate bound as one budget unit,
    the gate consumes at most 3*horizon + 5 units, including the four greedy root
    expansions. An optional full planner receives only the remaining allowance.
    Any exception retains ``cost_receipt``, ``controller_wall_ns``,
    ``search_stats`` and ``transitions``; no partially searched answer is returned.
    """
    started = time.perf_counter_ns()
    phase = "validation"
    charged = bound_backups = root_checks = 0
    incumbent = None
    incumbent_wall = planner_wall = 0
    planner_started = gate_finished = None
    planner_attempted = False
    planner_stats = {}
    gate = None
    try:
        validate_observation(scenario, observation)
        _require(planner_arm in PLANNER_ARMS, "planner must be same-objective or dynamic-ndu")
        for name, value in (("forecast_control_ns", forecast_control_ns), ("greedy_forecast_ns", greedy_forecast_ns)):
            _require(type(value) is int and 0 <= value <= MAX_FORECAST_NS, name + " must be a bounded nonnegative integer")
        _require(type(max_transitions) is int and 1 <= max_transitions <= 1_000_000, "expansion budget")

        phase = "incumbent"
        incumbent_started = time.perf_counter_ns()
        incumbent = plan(scenario, observation, "state-greedy", max_transitions=max_transitions)
        incumbent_wall = time.perf_counter_ns() - incumbent_started
        charged = incumbent["search"]["transitions"]
        remaining = scenario.horizon - observation.step
        preference = incumbent["preference"]
        _require(Q32 <= preference["price_q32"] <= 2 * Q32 and 0 <= preference["risk_q32"] <= Q32,
                 "the declared price/risk envelope is required for these bounds")

        def charge():
            nonlocal charged
            if charged >= max_transitions:
                raise SearchBudgetExhausted("priced gate exhausted the shared expansion allowance", transitions=charged)
            charged += 1

        phase = "bounds"
        bounds_started = time.perf_counter_ns()
        control_fee = mul_q32(preference["price_q32"], q32(Fraction(forecast_control_ns, scenario.cost_unit)))
        current_greedy_fee = mul_q32(preference["price_q32"], q32(Fraction(greedy_forecast_ns, scenario.cost_unit)))
        maximum_cost = scenario.direct_cost + scenario.load_cost + scenario.retire_cost + scenario.holding_cost
        services = [c for c in incumbent["candidates"] if c["id"] != "abstain" and c["feasible"]]
        upper_actions = {}
        future_rows = []
        sufficient_resources = price_one = False
        future_slack = None
        future_price_upper = 2 * Q32 if scenario.dynamic_preferences else Q32
        future_greedy_fee = 0

        if remaining == 1 or not services:
            # The one-step greedy decision is already exact here. No native
            # call, future policy enumeration or extra bound expansion occurs.
            upper = gross_lower = costed_lower = incumbent["value_q32"]
            upper_actions = {c["id"]: c["instant_q32"] for c in incumbent["candidates"] if c["feasible"]}
            shortcut = "horizon_one" if remaining == 1 else "no_feasible_service"
        else:
            shortcut = None
            future_steps = remaining - 1
            if incumbent["action"] is not None:
                root_cost = action_cost(scenario, observation, incumbent["action"])["total"]
                future_slack = min(observation.budget, observation.deadline) - root_cost
                sufficient_resources = future_slack >= future_steps * maximum_cost
                # The model's scarcity target also has a cost_unit floor. A
                # zero or tiny workload cost alone cannot certify price one.
                price_one = (not scenario.dynamic_preferences or future_slack >=
                             max(future_steps * maximum_cost,
                                 (future_steps - 1) * maximum_cost + max(scenario.cost_unit, scenario.direct_cost)))
            else:
                price_one = not scenario.dynamic_preferences
            future_price_upper = Q32 if price_one else 2 * Q32
            reward_upper = scenario.completion_reward_q32 - q32(Fraction(scenario.hot_cost, scenario.cost_unit))
            reward_lower = scenario.completion_reward_q32 - mul_q32(future_price_upper, q32(Fraction(maximum_cost, scenario.cost_unit)))
            future_greedy_fee = mul_q32(future_price_upper, q32(Fraction(greedy_forecast_ns, scenario.cost_unit)))
            future_upper = future_lower = future_costed_lower = 0
            for k in range(1, remaining):
                abstain = -scenario.miss_penalty_q32 * k
                charge()
                bound_backups += 1
                future_upper = max(abstain, reward_upper + mul_q32(scenario.discount_q32, future_upper))
                forced_service = sufficient_resources and reward_lower > abstain
                # If service occurs, greedy's immediate value is at least both
                # its delivery lower bound and the explicit abstention value.
                service_floor = max(abstain, reward_lower)
                charge()
                bound_backups += 1
                delivery_lower = service_floor + mul_q32(scenario.discount_q32, future_lower)
                future_lower = delivery_lower if forced_service else min(abstain, delivery_lower)
                charge()
                bound_backups += 1
                costed_delivery_lower = service_floor - future_greedy_fee + mul_q32(scenario.discount_q32, future_costed_lower)
                future_costed_lower = (costed_delivery_lower if forced_service
                                       else min(abstain - future_greedy_fee, costed_delivery_lower))
                future_rows.append({"remaining": k, "upper_q32": future_upper,
                    "greedy_lower_q32": future_lower, "costed_greedy_lower_q32": future_costed_lower,
                    "abstain_q32": abstain, "delivery_reward_lower_q32": reward_lower,
                    "service_forced_by_bound": forced_service})
            for candidate in incumbent["candidates"]:
                charge()
                root_checks += 1
                if candidate["feasible"]:
                    upper_actions[candidate["id"]] = candidate["instant_q32"] + (
                        0 if candidate["id"] == "abstain" else mul_q32(candidate["discount_q32"], future_upper))
            upper = max(upper_actions.values())
            if incumbent["action"] is None:
                gross_lower = costed_lower = incumbent["value_q32"]
            else:
                gross_lower = incumbent["value_q32"] + mul_q32(preference["discount_q32"], future_lower)
                costed_lower = incumbent["value_q32"] + mul_q32(preference["discount_q32"], future_costed_lower)

        _require(costed_lower <= gross_lower <= upper, "a conservative bound contradicted its envelope")
        gross_gap, priced_gap = upper - gross_lower, upper - costed_lower
        invoke = shortcut is None and gross_gap > 0 and priced_gap > control_fee
        if shortcut:
            reason = shortcut
        elif gross_gap == 0:
            reason = "zero_task_gain_upper_bound"
        else:
            reason = "forecast_gain_upper_exceeds_compute_price" if invoke else "forecast_compute_price_covers_gain_upper"
        gate = {"schema": "hepta.hia.ndu.forecast-priced-gate.v1", "invoke": invoke, "reason": reason,
            "planner_arm": planner_arm, "incumbent": "state-greedy", "incumbent_action": incumbent["selected_action"],
            "incumbent_gross_lower_q32": gross_lower, "incumbent_costed_lower_q32": costed_lower,
            "optimal_upper_q32": upper, "gross_gain_upper_q32": gross_gap, "priced_gain_upper_q32": priced_gap,
            "forecast_compute_penalty_q32": control_fee, "compute_penalty_q32": control_fee,
            "forecast_control_ns": forecast_control_ns, "greedy_forecast_ns": greedy_forecast_ns,
            "current_greedy_forecast_fee_q32": current_greedy_fee, "current_greedy_fee_is_sunk": True,
            "future_greedy_fee_upper_q32": future_greedy_fee, "current_price_q32": preference["price_q32"],
            "future_price_upper_q32": future_price_upper, "cost_unit_ns": scenario.cost_unit,
            "forecast_identity": digest({"planner_arm": planner_arm, "forecast_control_ns": forecast_control_ns,
                                         "greedy_forecast_ns": greedy_forecast_ns, "cost_unit_ns": scenario.cost_unit}),
            "forecast_provenance": "caller-supplied; runner must freeze separate training evidence",
            "future_greedy_price_model": "constant supplied greedy_forecast_ns at every future greedy decision; not an observed-time bound",
            "unit_assumption": "raw workload/resource costs and forecast durations are nanoseconds",
            "cost_threshold_is_observed_guarantee": False, "positive_net_benefit_claim": False,
            "maximum_legal_delivery_cost_ns": maximum_cost, "future_slack_ns": future_slack,
            "future_resources_sufficient": sufficient_resources, "future_price_one_certified": price_one,
            "upper_by_root_action_q32": upper_actions, "future_bounds": future_rows,
            "certificate": "CE <= child maximum and CE >= child minimum; monotone signed ties-even Q32; bounded state prices",
            "future_state_enumerations": 0, "bound_backups": bound_backups, "root_bound_checks": root_checks,
            "gate_transitions": charged, "search_transitions": charged,
            "maximum_gate_transitions": 3 * remaining + 5,
            "incumbent_root_wall_ns": incumbent_wall,
            "bound_calculation_wall_ns": time.perf_counter_ns() - bounds_started,
            "authority": AUTHORITY, "scope": "registered finite model and forecast compute prices; actual total wall still required"}
        gate_finished = time.perf_counter_ns()
        gate["total_gate_wall_ns"] = gate_finished - started

        if invoke:
            allowance = max_transitions - charged
            if allowance < 1:
                raise SearchBudgetExhausted("no full-planner allowance remains after the priced gate", transitions=charged)
            phase = "planner"
            planner_attempted = True
            planner_started = time.perf_counter_ns()
            decision = plan(scenario, observation, planner_arm, backend=backend, max_transitions=allowance)
            planner_wall = time.perf_counter_ns() - planner_started
            planner_stats = dict(decision["search"])
            decision = dict(decision)
            decision["value_scope"] = "full finite-model planner value; forecast compute price used only for admission"
        else:
            decision = dict(incumbent)
            decision["native_backend_used"] = False
            decision["value_scope"] = "immediate greedy value; remaining-policy bounds are in compute_gate"
        decision["arm"] = planner_arm + "-priced"
        decision["compute_gate"] = gate
        decision["planner_search"] = planner_stats
        decision["search"] = {"states": incumbent["search"]["states"] + planner_stats.get("states", 0),
            "backups": incumbent["search"]["backups"] + planner_stats.get("backups", 0),
            "backend_calls": planner_stats.get("backend_calls", 0),
            "transitions": charged + planner_stats.get("transitions", 0),
            "gate_transitions": charged, "planner_transitions": planner_stats.get("transitions", 0),
            "bound_backups": bound_backups, "root_bound_checks": root_checks}
        gate["planner_wall_ns"] = planner_wall
        gate["planner_allowance"] = max_transitions - charged
        decision["controller_wall_ns"] = time.perf_counter_ns() - started
        return decision
    except BaseException as error:
        now = time.perf_counter_ns()
        previous = getattr(error, "search_stats", {})
        if phase == "incumbent":
            charged = previous.get("transitions", 0)
            incumbent_wall = now - incumbent_started
        elif phase == "planner":
            planner_stats = dict(previous)
            planner_wall = now - planner_started
        stats = {"gate_transitions": charged, "planner_transitions": planner_stats.get("transitions", 0),
                 "transitions": charged + planner_stats.get("transitions", 0),
                 "backend_calls": planner_stats.get("backend_calls", 0),
                 "bound_backups": bound_backups, "root_bound_checks": root_checks}
        error.search_stats = stats
        error.transitions = stats["transitions"]
        error.controller_wall_ns = now - started
        error.cost_receipt = {"schema": "hepta.hia.ndu.forecast-priced-failure.v1", "status": "failed",
            "phase": phase, "planner_arm": planner_arm if type(planner_arm) is str else "invalid planner type",
            "planner_attempted": planner_attempted,
            "forecast_control_ns": forecast_control_ns if type(forecast_control_ns) is int and 0 <= forecast_control_ns <= MAX_FORECAST_NS else "invalid forecast input",
            "greedy_forecast_ns": greedy_forecast_ns if type(greedy_forecast_ns) is int and 0 <= greedy_forecast_ns <= MAX_FORECAST_NS else "invalid forecast input",
            "controller_wall_ns": now - started, "incumbent_root_wall_ns": incumbent_wall,
            "total_gate_wall_ns": (gate_finished or now) - started, "planner_wall_ns": planner_wall,
            "search": stats, "compute_gate": gate, "error_type": type(error).__name__,
            "cost_threshold_is_observed_guarantee": False, "authority": AUTHORITY}
        raise
