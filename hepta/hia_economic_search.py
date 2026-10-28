"""Finite, advisory measurement/stop plans evaluated by the original NDU.

The host supplies measured cost estimates; no learning or value-of-information
oracle is hidden in this module. The pinned recursive NDU computes the actual
continuation recursion and feasibility/Pareto result. A model-matched integer
control is included deliberately: scalar deterministic NDU is not expected to
outperform that arithmetic by discovering information absent from its inputs.

Actions describe bounded attempts to prepare and measure a candidate. They do
not authorize running it. An executor must freshly verify resources, all-input
equivalence and totality before native build/execution, and again at publication.
"""
from __future__ import annotations

from hashlib import sha256
import json
import re
import time

from .hia_ndu import NduBridge, Q32, REQUEST_SCHEMA, candidate, event

SCHEMA = "hepta.hia.economic-search.v1"
RECURSIVE_PIN = "2590c0c94c5bf9a9004caeeb7b75edd6faf3eb8b"
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[a-zA-Z][a-zA-Z0-9_-]{0,47}\Z")
_LIMIT_NS = 1_000_000_000_000


class EconomicSearchRejected(ValueError):
    pass


def _reject(message):
    raise EconomicSearchRejected("E_HIA_ECONOMIC_SEARCH: " + message)


def _wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _digest(value):
    return sha256(_wire(value)).hexdigest()


def _integer(value, label, *, minimum=0, maximum=_LIMIT_NS):
    if type(value) is not int or not minimum <= value <= maximum:
        _reject(label + " must be an exact bounded integer")
    return value


def _hash(value, label):
    if type(value) is not str or not _HEX.fullmatch(value) or value == "0" * 64:
        _reject(label + " must be a nonzero SHA-256 digest")


def _q32(value, divisor):
    """Signed ns to fixed-point units, nearest/ties-even, with no clipping."""
    quotient, remainder = divmod(abs(value) * Q32, divisor)
    quotient += remainder * 2 > divisor or remainder * 2 == divisor and quotient % 2 == 1
    result = quotient if value >= 0 else -quotient
    if not -(1 << 63) <= result < 1 << 63:
        _reject("fixed-point cost overflow")
    return result


def measurement_request(snapshot):
    """Build bounded continuation paths from one exact host observation state.

    A candidate needs ``sample_quorum`` successful samples before it can be the
    suggested stopping incumbent. A measurement action buys the remaining
    quorum, including preparation if no artifact is prepared, then publication.
    Only the first measurement is executed before replanning on actual feedback.
    Already paid costs are bound to the snapshot, not charged again to future
    decisions. They must remain in the executor's final net-gain gate and ledger.

    ``runtime_upper_ps`` is an empirical estimate, not a physical upper-bound
    theorem. Using picoseconds avoids rounding a sub-ns gain to zero; all cost
    arithmetic is integer, and terminal saving is rounded down to ns.
    """
    keys = {"baseline_sha256", "baseline_lower_ps", "expected_calls", "spent_search_ns",
            "remaining_budget_ns", "remaining_measurements", "sample_quorum",
            "publication_estimate_ns", "objective_sha256", "generation", "candidates"}
    if type(snapshot) is not dict or set(snapshot) != keys:
        _reject("unexpected snapshot shape")
    for field in ("baseline_sha256", "objective_sha256"):
        _hash(snapshot[field], field)
    for field in ("baseline_lower_ps", "expected_calls", "spent_search_ns",
                  "remaining_budget_ns", "publication_estimate_ns"):
        _integer(snapshot[field], field)
    _integer(snapshot["generation"], "generation", minimum=1, maximum=(1 << 64) - 1)
    quorum = _integer(snapshot["sample_quorum"], "sample_quorum", minimum=2, maximum=8)
    remaining = _integer(snapshot["remaining_measurements"], "remaining_measurements", maximum=256)
    rows = snapshot["candidates"]
    if type(rows) is not list or not 1 <= len(rows) <= 32:
        _reject("one to thirty-two candidates required")
    seen = set()
    row_keys = {"id", "program_sha256", "support_sha256", "runtime_upper_ps",
                "prepare_estimate_ns", "sample_estimate_ns", "successful_samples",
                "prepared", "blocked"}
    for row in rows:
        if type(row) is not dict or set(row) != row_keys:
            _reject("unexpected candidate observation shape")
        cid = row["id"]
        if type(cid) is not str or not _ID.fullmatch(cid) or cid in seen or cid == "abstain":
            _reject("candidate id is invalid, duplicated or reserved")
        seen.add(cid)
        for field in ("program_sha256", "support_sha256"):
            _hash(row[field], field)
        for field in ("runtime_upper_ps", "prepare_estimate_ns", "sample_estimate_ns"):
            _integer(row[field], field)
        count = _integer(row["successful_samples"], "successful_samples", maximum=quorum)
        if type(row["prepared"]) is not bool or type(row["blocked"]) is not bool:
            _reject("prepared/blocked must be exact booleans")
        if count and not row["prepared"]:
            _reject("successful native samples require a prepared artifact")
    if len(_wire(snapshot)) > 256 * 1024:
        _reject("snapshot byte budget exceeded")
    # Detach from caller mutations; neither model branch acquires mutable state.
    snapshot = json.loads(_wire(snapshot))
    rows = snapshot["candidates"]
    support = _digest(snapshot)
    objective = snapshot["objective_sha256"]
    publication_ns = snapshot["publication_estimate_ns"]
    budget_ns = snapshot["remaining_budget_ns"]
    baseline_ps = snapshot["baseline_lower_ps"]
    calls = snapshot["expected_calls"]

    def saving(row):
        value = max(0, (baseline_ps - row["runtime_upper_ps"]) * calls // 1000)
        return _integer(value, "modeled terminal saving")

    ready = [row for row in rows if row["successful_samples"] >= quorum and not row["blocked"]]
    best = min(ready, key=lambda row: (row["runtime_upper_ps"], row["id"]), default=None)
    stop_id = best["id"] if (best is not None and saving(best) > publication_ns
                              and publication_ns <= budget_ns) else "abstain"
    plans, descriptions = [], {}

    def add(action_id, costs, terminal, *, permitted, selected_id, kind):
        cost_sum = sum(costs)
        _integer(cost_sum, "modeled continuation cost")
        description = {"kind": kind, "candidate_id": selected_id,
                       "future_stage_costs_ns": costs, "future_cost_ns": cost_sum,
                       "modeled_terminal_saving_ns": terminal,
                       "modeled_net_saving_ns": terminal - cost_sum,
                       "permitted": permitted,
                       "verification_scope": "bounded_advisory_action_only_no_HIA_execution_permission"}
        descriptions[action_id] = description
        plans.append(candidate(candidate_id=action_id, verified=permitted,
            verification_digest=_digest(description), support_digest=support,
            events=[event(identity=f"{support}:{action_id}:{index}",
                          instant_q32=-_q32(cost, 1_000_000), preference_digest=objective)
                    for index, cost in enumerate(costs)],
            terminal_q32=_q32(terminal, 1_000_000),
            resource_cost_q32=_q32(cost_sum, 1000)))

    add("abstain", [0], 0, permitted=True, selected_id="abstain", kind="stop")
    if stop_id != "abstain":
        add("stop", [publication_ns], saving(best), permitted=True,
            selected_id=stop_id, kind="stop")
    for row in rows:
        needed = quorum - row["successful_samples"]
        if needed == 0:
            continue
        costs = ([row["prepare_estimate_ns"]] if not row["prepared"] else [])
        costs += [row["sample_estimate_ns"]] * needed + [publication_ns]
        add("measure_" + row["id"], costs, saving(row),
            permitted=not row["blocked"] and needed <= remaining,
            selected_id=row["id"], kind="measure")
    request = {"schema": REQUEST_SCHEMA, "objective_digest": objective,
        "snapshot_digest": support, "generation": snapshot["generation"],
        "utility_unit": "forecast-net-wall-milliseconds", "resource_unit": "microseconds",
        "risk_unit": "probability", "risk_ceiling_q32": 0,
        "resource_budget_q32": _q32(budget_ns, 1000), "candidates": plans}
    return {"request": request, "actions": descriptions, "snapshot": snapshot,
            "stopping_candidate_id": stop_id}


def _arithmetic_choice(request):
    """Independent exact control for this no-discount, one-axis request profile."""
    values = []
    for row in request["candidates"]:
        if not row["verified"] or row["resource_cost_q32"] > request["resource_budget_q32"]:
            continue
        value = row["terminal_q32"]
        for step in reversed(row["events"]):
            if step["discount_q32"] != Q32:
                _reject("arithmetic control supports only the declared unit discount")
            value = step["instant_q32"] + value
        values.append((value, row["id"]))
    maximum = max(value for value, _ in values)
    tied = [name for value, name in values if value == maximum]
    return tied[0] if len(tied) == 1 else None


def choose_measurement(snapshot, *, backend, bridge=None):
    """Choose one next measurement or stop; no candidate code runs here."""
    started = time.perf_counter_ns()
    if backend not in {"ndu", "arithmetic"}:
        _reject("backend must be ndu or arithmetic")
    prepared = measurement_request(snapshot)
    request = prepared["request"]
    response, transport = None, None
    if backend == "ndu":
        if not isinstance(bridge, NduBridge):
            _reject("NDU requires the identity-bound recursive bridge")
        if bridge.manifest["identity"].get("source_commit") != RECURSIVE_PIN:
            _reject("recursive bridge source pin mismatch")
        transport = {"argv": [str(bridge.executable)], "identity_manifest": str(bridge.identity_manifest),
                     "binary_sha256": bridge.manifest["binary_sha256"], "timeout_s": bridge.timeout}
        response = bridge.evaluate(request)
        selected = response["advisory_candidate_id"]
    else:
        if bridge is not None:
            _reject("arithmetic control does not use a native bridge")
        selected = _arithmetic_choice(request)
    if selected is None:
        action = {"kind": "stop", "candidate_id": prepared["stopping_candidate_id"]}
        reason = "tie_or_no_unique_advisory_recommendation"
    else:
        if selected not in prepared["actions"]:
            _reject("evaluator named an unknown action")
        row = prepared["actions"][selected]
        if not row["permitted"] or row["future_cost_ns"] > prepared["snapshot"]["remaining_budget_ns"]:
            _reject("evaluator selected an unavailable or over-budget action")
        action = {"kind": row["kind"], "candidate_id": row["candidate_id"]}
        reason = "advisory_future_cost_comparison"
    return {"schema": SCHEMA, "backend": backend, "action": action, "reason": reason,
        **prepared, "native_response": response, "native_transport": transport,
        "control_wall_ns": time.perf_counter_ns() - started,
        "authority": "DENY_ALL", "claims": {
            "native_recursive_utility_invoked": backend == "ndu", "online_learning": False,
            "forecast_is_measured_future": False, "HIA_safety_proved": False,
            "global_optimality": False, "incremental_ndu_advantage": False,
        }}
