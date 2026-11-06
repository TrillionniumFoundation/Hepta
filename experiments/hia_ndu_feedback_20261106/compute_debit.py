"""Opt-in forecast/observed time debits for the finite feedback experiment.

This profile reuses the existing planner and environment transitions. Forecasts
are model inputs, never bounds on physical execution. A dispatch guard does not
preempt a native call, undo a past effect, or qualify Linux/kernel hard deadlines.
The original price-only protocol and its historical results are not reinterpreted.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import time

from .model import (AUTHORITY, FeedbackError, Observation, action_cost, action_name,
                    digest, validate_observation)

SCHEMA = "hepta.hia.ndu.compute-resource-debit.v1"
PLAN_SCHEMA = "hepta.hia.ndu.compute-debit-plan.v1"
NANOSECOND_LABEL = "observed online controller plus workload nanoseconds"
MAX_NS = 10**12


def _require(condition, reason):
    if not condition:
        raise FeedbackError("compute debit: " + reason)


def _sha256(value):
    return (type(value) is str and len(value) == 64 and value != "0" * 64
            and set(value) <= set("0123456789abcdef"))


def _duration(value, name):
    _require(type(value) is int and 0 <= value <= MAX_NS,
             name + " must be a bounded nonnegative integer nanosecond duration")
    return value


@dataclass(frozen=True)
class ComputeDebitProfile:
    """One frozen forecast per remaining horizon, indexed by ``remaining - 1``.

    The calibration hash is an input binding, not certification of its contents
    or an observed-time guarantee. A formal campaign must independently freeze
    its training-only calibration before any held-out execution.
    """

    scenario_sha256: str
    calibration_sha256: str
    forecast_ns_by_remaining: tuple[int, ...]

    def __post_init__(self):
        _require(_sha256(self.scenario_sha256), "scenario identity must be SHA-256")
        _require(_sha256(self.calibration_sha256), "calibration identity must be SHA-256")
        _require(type(self.forecast_ns_by_remaining) is tuple
                 and 1 <= len(self.forecast_ns_by_remaining) <= 4,
                 "an immutable forecast for every remaining depth is required")
        for value in self.forecast_ns_by_remaining:
            _duration(value, "forecast")

    def validate(self, scenario):
        _require(digest(asdict(scenario)) == self.scenario_sha256,
                 "profile belongs to a different scenario")
        _require(len(self.forecast_ns_by_remaining) == scenario.horizon,
                 "forecast table does not cover the complete horizon")
        _require(scenario.cost_unit_label == NANOSECOND_LABEL,
                 "model resource units must explicitly be nanoseconds")
        return self

    @property
    def identity(self):
        return digest({"schema": SCHEMA, **asdict(self)})

    def forecast(self, scenario, observation):
        return self.forecast_ns_by_remaining[scenario.horizon - observation.step - 1]

    def objective_digest(self, scenario):
        return digest({"task_objective": scenario.objective_digest,
                       "compute_resource_profile": self.identity})


def validate_profile(profile, scenario):
    _require(type(profile) is ComputeDebitProfile, "an explicit immutable profile is required")
    return profile.validate(scenario)


def after_compute(scenario, observation, elapsed_ns):
    """Project remaining resources without mutating or charging the environment.

    The actual environment charges the measured *whole* step exactly once at
    completion/abstention. This projection is only for pre-dispatch feasibility.
    """
    validate_observation(scenario, observation)
    _duration(elapsed_ns, "compute time")
    return replace(observation, budget=max(0, observation.budget - elapsed_ns),
                   deadline=max(0, observation.deadline - elapsed_ns))


def dispatch_after_compute(env, decision, profile, *, step_started_ns, execute,
                           clock_ns=None):
    """Revalidate a profiled decision immediately before a workload callback.

    ``execute(post_compute_observation, action)`` may perform the selected work.
    It is never invoked when the measured controller wait exhausted either
    resource or leaves less than the registered workload forecast. Its output is
    retained separately from the environment's measured total-cost transition.

    The guard cannot guarantee callback duration or contain arbitrary effects.
    A failing callback remains an unknown physical outcome; it is not retried.
    The caller retains the failure receipt and its outer elapsed-cost ledger.
    """
    clock_ns = time.monotonic_ns if clock_ns is None else clock_ns
    scenario, observed = env.scenario, env.observe()
    validate_profile(profile, scenario)
    _require(type(step_started_ns) is int and step_started_ns >= 0, "invalid start clock")
    _require(type(decision) is dict and decision.get("schema") == PLAN_SCHEMA,
             "only an explicit compute-debit plan can use this dispatch route")
    _require(decision.get("state_digest") == observed.state_digest
             and decision.get("observation") == asdict(observed), "stale or rebound decision")
    _require(decision.get("compute_debit", {}).get("profile_sha256") == profile.identity,
             "decision/profile identity mismatch")
    action = decision.get("action")
    _require(decision.get("selected_action") == action_name(action), "inconsistent selected action")
    _require(callable(execute), "workload executor required")

    gate_clock = clock_ns()
    _require(type(gate_clock) is int and gate_clock >= step_started_ns, "nonmonotonic dispatch clock")
    elapsed = _duration(gate_clock - step_started_ns, "observed pre-dispatch time")
    remaining = after_compute(scenario, observed, elapsed)
    exhausted = elapsed >= min(observed.budget, observed.deadline)
    cost = 0 if action is None else action_cost(scenario, observed, action)["total"]
    admitted = action is not None and not exhausted and cost <= min(remaining.budget, remaining.deadline)
    reason = ("planner_abstained" if action is None else "controller_deadline_exceeded" if exhausted
              else "insufficient_resources_after_compute" if not admitted else "admitted_by_forecast")
    receipt = {"schema": SCHEMA, "profile_sha256": profile.identity,
               "observation": asdict(observed), "after_compute": asdict(remaining),
               "observed_pre_dispatch_ns": elapsed, "forecast_workload_ns": cost,
               "action_admitted": admitted, "reason": reason,
               "actual_charge_rule": "one measured whole-step debit; no additional forecast debit",
               "hard_realtime_guarantee": False, "authority": AUTHORITY,
               "production_activation": False}
    output = None
    try:
        if admitted:
            output = execute(remaining, action)
        end = clock_ns()
        _require(type(end) is int and end >= gate_clock, "nonmonotonic completion clock")
        total = _duration(end - step_started_ns, "observed whole-step time")
        _require(env.observe() == observed, "environment changed during guarded dispatch")
        outcome = env.step(action if admitted else None, actual_cost=total)
        if not admitted and action is not None:
            outcome["status"] = reason
        receipt.update(observed_total_ns=total, observed_after_gate_ns=total - elapsed,
                       actual_charged_ns=outcome["cost"], status="completed")
        return {"outcome": outcome, "native_execution": output,
                "compute_debit": receipt,
                "selected_action_was_not_executed": action is not None and not admitted}
    except BaseException as error:
        # Preserve an attempted effect and the irrecoverable elapsed work, even
        # if it is not possible to publish an environment transition for it.
        receipt.update(status="failed", effect_outcome="UNKNOWN" if admitted else "NOT_DISPATCHED")
        try:
            now = clock_ns()
            if type(now) is int and now >= gate_clock:
                receipt["observed_total_ns"] = now - step_started_ns
        except BaseException:
            pass
        error.compute_debit_receipt = receipt
        raise
