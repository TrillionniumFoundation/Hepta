"""Strict six-task v2 comparison, separate from the unchanged v1 contract.

Only the immutable bounded wire/ledger validation primitives are shared with
v1. No task padding, rescaling, omitted failure, invented usage or mutation of
historical receipts is performed here.
"""
from hepta.hia_agent_macro_policy import (
    ARMS, ATTEMPT_STATUSES, COMPARISON_SCHEMA, PHASES, _budget, _decode,
    _fail, _id, _integer, _sha, _shape, digest, ledger_totals,
)


def assess_multistep_comparison(raw, task_purposes):
    """Assess exactly two calibration plus four heldout synthetic tasks.

    This is a separate v2 entry point. The public v1 assessor retains its
    eight-to-128 task contract. Supplied identities never authenticate provider
    execution or establish economic value; the original-byte verifier supplies
    the external causal/artifact checks.
    """
    data = _decode(raw)
    _shape(data, {"schema", "registration_sha256", "agent_sha256", "objective_sha256", "budget",
                  "task_inventory", "minimum_gain_ns", "arms"}, "comparison")
    if data["schema"] != COMPARISON_SCHEMA:
        _fail("unsupported macro comparison")
    for key in ("registration_sha256", "agent_sha256", "objective_sha256"):
        _sha(data[key], key)
    _budget(data["budget"])
    if data["budget"] != {"wall_ns": 180_000_000_000, "model_tokens": 32768}:
        _fail("v2 original 180-second/32768-token cell allowance required")
    _integer(data["minimum_gain_ns"], "minimum gain", minimum=1)
    tasks = data["task_inventory"]
    if type(tasks) is not list or len(tasks) != 6:
        _fail("v2 requires exactly six preregistered tasks")
    if (type(task_purposes) is not dict or len(task_purposes) != 6
            or list(task_purposes.values()).count("calibration") != 2
            or list(task_purposes.values()).count("heldout") != 4):
        _fail("v2 requires exactly two calibration and four heldout task purposes")
    inventory, reasons = {}, []
    for task in tasks:
        _shape(task, {"id", "input_sha256", "qualification", "qualification_receipt_sha256"}, "task")
        tid = _id(task["id"], "task id")
        if tid in inventory:
            _fail("duplicate registered task")
        _sha(task["input_sha256"], "task input")
        _sha(task["qualification_receipt_sha256"], "task qualification")
        if task["qualification"] != "synthetic_fixture":
            _fail("v2 private synthetic tasks cannot be relabelled as real user tasks")
        if task["qualification"] != "real_agent_task":
            reasons.append("synthetic_task:" + tid)
        inventory[tid] = task
    if set(task_purposes) != set(inventory):
        _fail("v2 purpose inventory differs from registered task identities")
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
            if costs["phases"].get("model", {}).get("attempts", 0) > 3:
                _fail("v2 scheduled model round bound exceeded")
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
            if (type(receipts) is not list or len(receipts) > 1
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
    return {"schema": "hepta.hia.agent.macro-multistep-comparison-verdict.v2", "input_sha256": digest(data),
            "registered_tasks": len(inventory), "task_purposes": dict(task_purposes), "arm_wall_ns": totals, "arm_costs": all_costs,
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
            "scope": "exact six-task synthetic v2 study; supplied same-Agent same-budget costs and completion, not formal first-use or economic authentication"}
