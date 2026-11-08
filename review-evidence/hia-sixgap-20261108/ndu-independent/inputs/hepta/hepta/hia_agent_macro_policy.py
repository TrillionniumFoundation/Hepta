"""Explicit Agent macro advice using the existing source-bound native NDU ABI.

This module is a caller-side controller. It never runs a compiler pass, invokes
an Agent, executes an artifact, or changes an adoption slot. Plans and forecasts
are supplied by the Agent; tool owners still admit every proposed operation.
The scalar cost profile is an experiment, not a claim of independent NDU value.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import re
import time

from .hia_bounded_wire import WireBudgetExceeded, checked_utf8_wire
from .hia_json_preflight import preflight_hia_json
from .hia_ndu_optimizer import OptimizationRejected, _native_rank, ns_to_ms_q32

STATE_SCHEMA = "hepta.hia.agent.macro-state.v1"
COMPARISON_SCHEMA = "hepta.hia.agent.macro-comparison.v1"
MAX_INPUT_BYTES = 1_048_576
MAX_NS = 1_000_000_000_000_000
MAX_TOKENS = 100_000_000
PHASES = frozenset({"setup", "discovery", "model", "search", "verification",
                    "emission", "evaluation", "adoption", "rollback", "future_use", "controller"})
ACTIONS = frozenset({"discover", "propose", "verify", "emit", "evaluate", "adopt", "use", "rollback", "keep_existing", "no_adopt", "stop"})
ARMS = frozenset({"fixed", "greedy", "ordinary", "ndu"})
ATTEMPT_STATUSES = frozenset({"completed", "failed", "rejected", "timed_out", "cancelled", "unknown"})
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,63}\Z")


class MacroPolicyRejected(ValueError):
    """Malformed or mismatched evidence cannot produce macro advice."""


def _fail(message):
    raise MacroPolicyRejected("E_HIA_MACRO: " + message)


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def digest(value):
    return sha256(wire(value)).hexdigest()


def _shape(value, fields, name):
    if type(value) is not dict or set(value) != set(fields):
        _fail(name + " has missing or unknown fields")


def _integer(value, name, maximum=MAX_NS, minimum=0):
    if type(value) is not int or not minimum <= value <= maximum:
        _fail(name + " requires a bounded exact integer")
    return value


def _sha(value, name):
    if type(value) is not str or not _HEX.fullmatch(value) or value == "0" * 64:
        _fail(name + " requires a nonzero lowercase SHA-256")
    return value


def _id(value, name):
    if type(value) is not str or not _ID.fullmatch(value):
        _fail(name + " requires a bounded identifier")
    return value


def _duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate JSON key")
        result[key] = value
    return result


def _decode(raw):
    if type(raw) not in (bytes, str):
        _fail("immutable JSON bytes or text required")
    try:
        if type(raw) is bytes:
            if len(raw) > MAX_INPUT_BYTES:
                _fail("input byte bound exceeded")
            text = raw.decode("utf-8")
        else:
            checked_utf8_wire(raw, MAX_INPUT_BYTES)
            text = raw
        preflight_hia_json(text, max_nodes=65536, max_depth=32)
        return json.loads(text, object_pairs_hook=_duplicates,
                          parse_constant=lambda _: _fail("nonfinite number"))
    except MacroPolicyRejected:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError, WireBudgetExceeded) as error:
        raise MacroPolicyRejected("E_HIA_MACRO: invalid bounded JSON") from error


def _budget(value):
    _shape(value, {"wall_ns", "model_tokens"}, "budget")
    _integer(value["wall_ns"], "wall budget", minimum=1)
    _integer(value["model_tokens"], "token budget", MAX_TOKENS)


def ledger_totals(entries):
    """Sum disjoint observed costs, retaining failed and rejected attempts.

    An entry is one complete attempt at one phase. Nested timings belong in its
    source receipt, not additional chargeable entries. Missing is never zero.
    Receipt hashes bind reported evidence; they do not authenticate its author.
    """
    if type(entries) is not list or len(entries) > 4096:
        _fail("ledger must contain at most 4096 entries")
    seen, receipts, unknown, phases = set(), set(), [], {}
    total_ns = total_tokens = failed_ns = 0
    for entry in entries:
        _shape(entry, {"id", "phase", "status", "wall_ns", "model_tokens", "receipt_sha256"}, "ledger entry")
        identity = _id(entry["id"], "entry id")
        if identity in seen:
            _fail("duplicate ledger entry")
        seen.add(identity)
        if (type(entry["phase"]) is not str or entry["phase"] not in PHASES
                or type(entry["status"]) is not str or entry["status"] not in ATTEMPT_STATUSES):
            _fail("invalid ledger phase or status")
        receipt = entry["receipt_sha256"]
        if receipt is None:
            unknown.append(identity + ":receipt")
        else:
            _sha(receipt, "receipt")
            if receipt in receipts:
                _fail("one receipt cannot be charged twice")
            receipts.add(receipt)
        phase = phases.setdefault(entry["phase"], {"wall_ns": 0, "model_tokens": 0, "attempts": 0})
        phase["attempts"] += 1
        for name, maximum in (("wall_ns", MAX_NS), ("model_tokens", MAX_TOKENS)):
            value = entry[name]
            if value is None:
                unknown.append(identity + ":" + name)
            else:
                _integer(value, name, maximum)
                phase[name] += value
        if entry["status"] == "unknown":
            unknown.append(identity + ":completion")
        total_ns += entry["wall_ns"] or 0
        total_tokens += entry["model_tokens"] or 0
        if entry["status"] in {"failed", "rejected", "timed_out", "cancelled"}:
            failed_ns += entry["wall_ns"] or 0
    _integer(total_ns, "total observed wall cost")
    _integer(total_tokens, "total model tokens", MAX_TOKENS)
    return {"observed_wall_ns": total_ns, "observed_model_tokens": total_tokens,
            "failed_attempt_wall_ns": failed_ns, "unknown": unknown,
            "complete": not unknown, "phases": phases, "attempts": len(entries)}


def _state(data):
    _shape(data, {"schema", "context_sha256", "objective_sha256", "agent_sha256", "installation",
                  "generation", "budget", "ledger", "stop_remaining_ns", "plans"}, "state")
    if data["schema"] != STATE_SCHEMA:
        _fail("unsupported macro state")
    for key in ("context_sha256", "objective_sha256", "agent_sha256"):
        _sha(data[key], key)
    _shape(data["installation"], {"worker_sha256", "backend_sha256", "catalog_sha256"}, "installation")
    for key, value in data["installation"].items():
        _sha(value, key)
    _integer(data["generation"], "generation", (1 << 32) - 1, 1)
    _budget(data["budget"])
    totals = ledger_totals(data["ledger"])
    _integer(data["stop_remaining_ns"], "stop continuation forecast")
    plans = data["plans"]
    if type(plans) is not list or not 0 <= len(plans) <= 16:
        _fail("zero to sixteen explicit macro plans required")
    seen = {"abstain"}
    for plan in plans:
        _shape(plan, {"id", "actions", "remaining_cost_ns", "uncertainty_ns", "model_tokens", "support_sha256"}, "plan")
        identity = _id(plan["id"], "plan id")
        if identity in seen:
            _fail("reserved or duplicate plan id")
        seen.add(identity)
        actions = plan["actions"]
        if (type(actions) is not list or not 1 <= len(actions) <= 16
                or any(type(action) is not str or action not in ACTIONS for action in actions)
                or actions[-1] != "stop" or "stop" in actions[:-1]):
            _fail("finite macro plan must end with exactly one stop")
        if (sum(action in {"keep_existing", "no_adopt"} for action in actions) > 1
                or any(action in {"keep_existing", "no_adopt"} for action in actions) and "adopt" in actions):
            _fail("retain/no-adopt plans cannot also adopt or select two terminal dispositions")
        for key in ("remaining_cost_ns", "uncertainty_ns"):
            _integer(plan[key], key)
        _integer(plan["model_tokens"], "planned model tokens", MAX_TOKENS)
        _sha(plan["support_sha256"], "plan support")
        _integer(plan["remaining_cost_ns"] + plan["uncertainty_ns"], "robust plan cost")
    return totals



def ordinary_plan_selection(data, *, elapsed_ns=0):
    """Exact ordinary control over every supplied finite continuation plan.

    This consumes the same frozen state, robust-cost objective and original
    allowances as native advice. It is a strong baseline for this finite scalar
    profile, not an oracle for undisclosed plans or stochastic task dynamics.
    Ties retain the incumbent. Unknown costs never receive an invented zero.
    """
    totals = _state(data)
    _integer(elapsed_ns, "controller elapsed time")
    remaining_wall = data["budget"]["wall_ns"] - totals["observed_wall_ns"] - elapsed_ns
    remaining_tokens = data["budget"]["model_tokens"] - totals["observed_model_tokens"]
    result = {"selected_id": "abstain", "next_action": "stop", "disposition": "keep_existing",
              "status": "ADVISORY", "reason": "incumbent_minimum_or_tie",
              "remaining_wall_ns": remaining_wall, "remaining_model_tokens": remaining_tokens,
              "considered_plans": [], "forecast_is_observed_benefit": False}
    if not totals["complete"]:
        result.update(status="BLOCKED", reason="unknown_observed_costs")
        return result
    if remaining_wall <= 0 or remaining_tokens < 0:
        result.update(status="BLOCKED", reason="lifecycle_budget_exhausted")
        return result
    # Incumbent wins ties; stable plan ID ordering avoids source-order bias.
    best = (data["stop_remaining_ns"], 0, "abstain")
    for plan in sorted(data["plans"], key=lambda row: row["id"]):
        robust_cost = plan["remaining_cost_ns"] + plan["uncertainty_ns"]
        feasible = robust_cost <= remaining_wall and plan["model_tokens"] <= remaining_tokens
        result["considered_plans"].append({"id": plan["id"], "robust_cost_ns": robust_cost,
            "model_tokens": plan["model_tokens"], "budget_feasible": feasible})
        if feasible and (robust_cost, 1, plan["id"]) < best:
            best = (robust_cost, 1, plan["id"])
    if best[2] != "abstain":
        plan = next(plan for plan in data["plans"] if plan["id"] == best[2])
        disposition = ("no_adopt" if "no_adopt" in plan["actions"] else
                       "keep_existing" if "keep_existing" in plan["actions"] else
                       "stop" if plan["actions"] == ["stop"] else "continue")
        result.update(selected_id=plan["id"], next_action=plan["actions"][0],
                      disposition=disposition, reason="ordinary_full_budget_minimum")
    return result


def advise_ordinary(raw):
    """Costed deterministic baseline; no native/provider call or side effect."""
    started = time.perf_counter_ns()
    data = _decode(raw)
    _state(data)
    next_entry_id = "controller." + str(len(data["ledger"]))
    if next_entry_id in {row["id"] for row in data["ledger"]}:
        _fail("controller ledger id collision")
    if len(data["ledger"]) >= 4096:
        _fail("controller ledger capacity exhausted")
    # The budget observation has an explicit instant. Selection and hashing
    # remain charged after that instant; operation owners recheck on dispatch.
    decision_elapsed = time.perf_counter_ns() - started
    selected = ordinary_plan_selection(data, elapsed_ns=decision_elapsed)
    result = {"schema": "hepta.hia.agent.ordinary-advice.v1", "state_sha256": digest(data),
              "context_sha256": data["context_sha256"], "installation": data["installation"],
              "policy": "full_budget_argmin", "decision_elapsed_ns": decision_elapsed,
              "authority": "DENY_ALL", "execution_authorized": False,
              "native_ndu_evaluated": False, "net_benefit_established": False, **selected}
    elapsed = time.perf_counter_ns() - started
    result["controller_wall_ns"] = elapsed
    entry = {"id": next_entry_id, "phase": "controller",
             "status": "completed" if result["status"] == "ADVISORY" else "rejected",
             "wall_ns": elapsed, "model_tokens": 0, "receipt_sha256": digest(result)}
    updated = deepcopy(data)
    updated["ledger"].append(entry)
    result.update(ledger_entry=entry, next_state=updated,
                  observed_costs=ledger_totals(updated["ledger"]))
    return result


def advise_macro(raw, *, bridge=None, timeout_ns=1_000_000_000):
    """Rank explicit macro plans through the original native value interface.

    Forecast costs include the complete remaining sequence, including model
    calls and unsuccessful search. All observed sunk costs and this invocation
    remain charged. No native image means BLOCKED, never a Python substitute.
    The response only recommends the first action; actual tools recheck state.
    """
    started = time.perf_counter_ns()
    data = _decode(raw)
    totals = _state(data)
    _integer(timeout_ns, "native timeout", minimum=1)
    # Reserve the deterministic receipt identity/capacity before any native
    # work. A full or colliding journal must not discard an executed attempt.
    next_entry_id = "controller." + str(len(data["ledger"]))
    if next_entry_id in {row["id"] for row in data["ledger"]}:
        _fail("controller ledger id collision")
    if len(data["ledger"]) >= 4096:
        _fail("controller ledger capacity exhausted")
    state_sha = digest(data)
    result = {"schema": "hepta.hia.agent.macro-advice.v1", "state_sha256": state_sha,
              "context_sha256": data["context_sha256"], "installation": data["installation"],
              "selected_id": "abstain", "next_action": "stop", "status": "BLOCKED",
              "reason": "native_bridge_unavailable", "native_request": None,
              "native_response": None, "native_identity": None, "native_ndu_evaluated": False,
              "native_profile": "hia-ndu-bridge scalar supplied-cost ranking",
              "recursive_utility_evaluated": False, "learned_macro_dynamics": False,
              "authority": "DENY_ALL", "execution_authorized": False, "safety_certificate": False,
              "net_benefit_established": False, "forecast_is_observed_benefit": False}
    remaining = data["budget"]["wall_ns"] - totals["observed_wall_ns"]
    tokens = data["budget"]["model_tokens"] - totals["observed_model_tokens"]
    if not totals["complete"]:
        result["reason"] = "unknown_observed_costs"
    elif remaining <= 0 or tokens < 0:
        result["reason"] = "lifecycle_budget_exhausted"
    elif bridge is not None:
        elapsed = time.perf_counter_ns() - started
        remaining -= elapsed
        plans = {plan["id"]: plan for plan in data["plans"]}
        rows = [{"id": "abstain", "cost_q32": ns_to_ms_q32(data["stop_remaining_ns"]),
                 "uncertainty_q32": 0, "resource_q32": 0, "hard_violation": False,
                 "support_sha256": state_sha}]
        for plan in data["plans"]:
            cost = plan["remaining_cost_ns"] + plan["uncertainty_ns"]
            rows.append({"id": plan["id"], "cost_q32": ns_to_ms_q32(cost),
                         "uncertainty_q32": ns_to_ms_q32(plan["uncertainty_ns"]),
                         "resource_q32": ns_to_ms_q32(cost),
                         "hard_violation": cost > remaining or plan["model_tokens"] > tokens,
                         "support_sha256": digest({"state": state_sha, "plan": plan})})
        request = {"schema": "hepta.hia.ndu-request.v1",
                   "objective_sha256": digest({"objective": data["objective_sha256"], "state": state_sha}),
                   "generation": data["generation"], "resource_cap_q32": ns_to_ms_q32(max(remaining, 0)),
                   "candidates": rows}
        result["native_request"] = request
        if remaining <= 0:
            result["reason"] = "budget_exhausted_before_native"
        else:
            try:
                response, identity = _native_rank(bridge, request,
                    timeout_s=min(timeout_ns, remaining) / 1_000_000_000)
                result.update(native_response=response, native_identity=identity,
                              native_ndu_evaluated=True, status="ADVISORY", reason="native_evaluator_abstained")
                selected = response.get("advisory_recommendation") or "abstain"
                if selected != "abstain":
                    plan = plans[selected]
                    final_remaining = data["budget"]["wall_ns"] - totals["observed_wall_ns"] - (time.perf_counter_ns() - started)
                    if plan["remaining_cost_ns"] + plan["uncertainty_ns"] <= final_remaining:
                        result.update(selected_id=selected, next_action=plan["actions"][0], reason="native_macro_advice")
                    else:
                        result["reason"] = "budget_exhausted_after_native"
            except (OptimizationRejected, ValueError, TypeError, KeyError, OSError, OverflowError) as error:
                # Preserve failed calls in the next state; never refund work.
                result.update(reason="native_evaluator_rejected", native_error=str(error))
    elapsed = time.perf_counter_ns() - started
    evidence = {key: value for key, value in result.items() if key not in {"next_state", "ledger_entry"}}
    entry = {"id": next_entry_id, "phase": "controller",
             "status": "completed" if result["status"] == "ADVISORY" else "rejected",
             "wall_ns": elapsed, "model_tokens": 0, "receipt_sha256": digest(evidence)}
    updated = deepcopy(data)
    updated["ledger"].append(entry)
    result.update(ledger_entry=entry, next_state=updated,
                  observed_costs=ledger_totals(updated["ledger"]), controller_wall_ns=elapsed)
    return result


def assess_macro_comparison(raw):
    """Compare all registered real tasks with the same Agent and budgets.

    This is a strict assessor of supplied evidence, not an attestation service.
    Synthetic receipts can exercise the logic but can never close P1. Forecast
    amortization is excluded: only actual future-use events enter the ledger.
    """
    data = _decode(raw)
    _shape(data, {"schema", "registration_sha256", "agent_sha256", "objective_sha256", "budget",
                  "task_inventory", "minimum_gain_ns", "arms"}, "comparison")
    if data["schema"] != COMPARISON_SCHEMA:
        _fail("unsupported macro comparison")
    for key in ("registration_sha256", "agent_sha256", "objective_sha256"):
        _sha(data[key], key)
    _budget(data["budget"])
    _integer(data["minimum_gain_ns"], "minimum gain", minimum=1)
    tasks = data["task_inventory"]
    if type(tasks) is not list or not 8 <= len(tasks) <= 128:
        _fail("eight to 128 preregistered tasks required")
    inventory, reasons = {}, []
    for task in tasks:
        _shape(task, {"id", "input_sha256", "qualification", "qualification_receipt_sha256"}, "task")
        tid = _id(task["id"], "task id")
        if tid in inventory:
            _fail("duplicate registered task")
        _sha(task["input_sha256"], "task input")
        _sha(task["qualification_receipt_sha256"], "task qualification")
        if type(task["qualification"]) is not str or task["qualification"] not in {"real_agent_task", "synthetic_fixture"}:
            _fail("unknown task qualification")
        if task["qualification"] != "real_agent_task":
            reasons.append("synthetic_task:" + tid)
        inventory[tid] = task
    if list(inventory) != sorted(inventory):
        _fail("task inventory must have canonical order")
    registration = {key: data[key] for key in ("agent_sha256", "objective_sha256", "budget",
                                              "task_inventory", "minimum_gain_ns")}
    if digest(registration) != data["registration_sha256"]:
        _fail("canonical task registration digest differs")
    if type(data["arms"]) is not list or len(data["arms"]) != len(ARMS):
        _fail("fixed, greedy, ordinary and NDU arms required")
    totals, all_costs, arm_eligibility = {}, {}, {}
    for arm in data["arms"]:
        _shape(arm, {"strategy", "agent_sha256", "registration_sha256", "budget", "observations"}, "arm")
        name = arm["strategy"]
        if type(name) is not str or name not in ARMS or name in totals:
            _fail("duplicate or unavailable comparison arm")
        for key in ("agent_sha256", "registration_sha256", "budget"):
            if arm[key] != data[key]:
                _fail("different Agent, registered tasks or budget")
        observations = arm["observations"]
        if type(observations) is not list or len(observations) != len(inventory):
            _fail("missing or extra planned task observations")
        seen, complete_costs = set(), []
        arm_reason_start = len(reasons)
        for row in observations:
            _shape(row, {"task_id", "input_sha256", "qualification_receipt_sha256", "status", "result_receipt_sha256",
                         "correct", "ledger", "phase_inventory", "native_ndu_receipts"}, "task observation")
            tid = _id(row["task_id"], "observed task id")
            if tid not in inventory or tid in seen:
                _fail("unregistered or repeated task observation")
            seen.add(tid)
            task = inventory[tid]
            if (row["input_sha256"] != task["input_sha256"]
                    or row["qualification_receipt_sha256"] != task["qualification_receipt_sha256"]):
                _fail("task or qualification identity drift")
            if (type(row["status"]) is not str or row["status"] not in ATTEMPT_STATUSES
                    or type(row["correct"]) is not bool):
                _fail("invalid task completion")
            if row["status"] != "completed" or row["correct"] is not True:
                reasons.append(name + ":undelivered_task:" + tid)
            if row["result_receipt_sha256"] is None:
                reasons.append(name + ":missing_result_evidence:" + tid)
            else:
                _sha(row["result_receipt_sha256"], "result receipt")
            costs = ledger_totals(row["ledger"])
            # Every cost category must be explicitly inventoried as observed or
            # not performed with a receipt. Omitted categories cannot be zero.
            _shape(row["phase_inventory"], PHASES, "phase inventory")
            for phase, declaration in row["phase_inventory"].items():
                _shape(declaration, {"performed", "receipt_sha256"}, "phase declaration")
                if type(declaration["performed"]) is not bool:
                    _fail("phase performed must be boolean")
                _sha(declaration["receipt_sha256"], "phase inventory receipt")
                if declaration["performed"] != (phase in costs["phases"]):
                    _fail("phase inventory differs from charged ledger")
            if not costs["complete"]:
                reasons.append(name + ":unknown_costs:" + tid)
            if costs["phases"].get("model", {}).get("model_tokens", 0) <= 0:
                reasons.append(name + ":no_observed_agent_call:" + tid)
            if costs["phases"].get("future_use", {}).get("wall_ns", 0) <= 0:
                reasons.append(name + ":no_observed_downstream_use:" + tid)
            if (costs["observed_wall_ns"] > data["budget"]["wall_ns"]
                    or costs["observed_model_tokens"] > data["budget"]["model_tokens"]):
                reasons.append(name + ":budget_exceeded:" + tid)
            receipts = row["native_ndu_receipts"]
            if (type(receipts) is not list or len(receipts) > 64
                    or any(type(value) is not str for value in receipts) or len(set(receipts)) != len(receipts)):
                _fail("native NDU receipts must be a bounded unique list")
            for receipt in receipts:
                _sha(receipt, "native NDU receipt")
            if name == "ndu" and not receipts:
                reasons.append("ndu:no_native_value_evaluation:" + tid)
            complete_costs.append({"task_id": tid, **costs})
        totals[name] = sum(cost["observed_wall_ns"] for cost in complete_costs)
        all_costs[name] = complete_costs
        arm_reasons = reasons[arm_reason_start:]
        arm_eligibility[name] = {"eligible": not arm_reasons, "reasons": arm_reasons}
    if set(totals) != ARMS:
        _fail("all four comparison arms are required")
    best = min((totals[name], name) for name in ARMS - {"ndu"})
    saving = best[0] - totals["ndu"]
    # Historical v1 fields are raw arithmetic over every attempted arm. A cheap
    # arm can be cheap because it failed early, and must never become a completed
    # control or make the headline NDU saving positive. Keep its original cost;
    # qualify a separate comparison only when every registered arm delivered
    # every task, retained complete observed costs, and stayed within budget.
    complete_controls = sorted(name for name in ARMS - {"ndu"}
                               if arm_eligibility[name]["eligible"])
    complete_best = (min((totals[name], name) for name in complete_controls)
                     if complete_controls else None)
    all_arms_eligible = all(row["eligible"] for row in arm_eligibility.values())
    completed_comparison = {
        "eligible": all_arms_eligible,
        "arm_eligibility": arm_eligibility,
        "complete_controls": complete_controls,
        "best_complete_control": complete_best[1] if complete_best else None,
        "ndu_saving_ns": complete_best[0] - totals["ndu"] if all_arms_eligible else None,
        "scope": "complete supplied same-budget task observations; not task/provider provenance or economic attestation",
    }
    if saving < data["minimum_gain_ns"]:
        reasons.append("no_full_cost_advantage_over_best_control")
    # These supplied hashes cannot authenticate a provider/model measurement,
    # a real task, or actual native execution. Keep the arithmetic useful, but
    # never turn a relabelled fixture or self-reported estimate into P1 closure.
    arithmetic_reasons = list(reasons)
    reasons.append("original_receipts_not_independently_authenticated")
    return {"schema": "hepta.hia.agent.macro-comparison-verdict.v1", "input_sha256": digest(data),
            "registered_tasks": len(inventory), "arm_wall_ns": totals, "arm_costs": all_costs,
            "best_control": best[1], "ndu_saving_ns": saving, "reasons": reasons,
            "legacy_cost_fields_scope": "raw arithmetic including failed/incomplete arms; not completed-control gains",
            "raw_lowest_cost_control": best[1], "raw_ndu_wall_difference_ns": saving,
            "completed_comparison": completed_comparison,
            "reported_arithmetic_positive": not arithmetic_reasons,
            "reported_arithmetic_reasons": arithmetic_reasons,
            "observed_scope_positive": False, "p1_acceptance": "HOLD",
            "economic_benefit_established": False, "authority": "DENY_ALL",
            "execution_authorized": False, "input_receipts_authenticated": False,
            "statistical_generalization_proved": False, "forecast_future_savings_counted": False,
            "scope": "supplied same-Agent same-budget registered real-task observations; independent source review required"}
