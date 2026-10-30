"""Stateful preparation/holding workloads for the original finite NDU profile.

Preparing a variant pays its cost once and leaves an explicitly charged resident
state.  A later refusal creates a new snapshot and consumes actual reported
budget; it cannot reuse the rejected proposal's projected benefit.  This module
constructs a bounded planning model.  It neither verifies machine code nor turns
model costs into application measurements or native NDU evaluation receipts.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from itertools import combinations
import json
import re

SCHEMA = "hepta.hia.ndu.stateful-preparation.v1"
_MAX_NS = 1_000_000_000_000
_ID = re.compile(r"[a-zA-Z][a-zA-Z0-9_-]{0,31}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_STATUSES = {"verified", "rejected", "unknown", "timeout"}
_FIELDS = {"schema", "name", "objective_digest", "generation", "baseline",
           "variants", "initial_ready", "memory_budget_bytes", "budget_ns",
           "completion_value_ns", "sunk_cost_ns", "observations", "cost_basis"}
_VARIANT_FIELDS = {"id", "source_sha256", "verification_sha256", "support_sha256",
                   "status", "preparation_ns", "holding_ns", "resident_bytes", "latency_ns"}
_BASE_FIELDS = {"source_sha256", "verification_sha256", "latency_ns"}


class StatefulPlanningError(ValueError):
    """An incomplete or inconsistent model cannot authorize planning."""


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return sha256(wire(value)).hexdigest()


def _require(condition, message):
    if not condition:
        raise StatefulPlanningError("E_HIA_NDU_STATEFUL: " + message)


def _int(value, name, maximum=_MAX_NS):
    _require(type(value) is int and 0 <= value <= maximum,
             name + " requires a bounded nonnegative integer")
    return value


def _hex(value, name):
    _require(type(value) is str and _HEX.fullmatch(value) is not None
             and value != "0" * 64, name + " requires a nonzero SHA-256")


def validate_model(value):
    """Validate one bounded detached JSON snapshot; never reread caller state.

    This remains an offline advisory model, not native execution authority.
    Existing HIA intake rejects subclasses, cycles and oversized containers
    before materializing JSON. All semantic checks below use the decoded bytes.
    """
    from .hia_json_preflight import preflight_hia_json
    from .hia_program_tools import HIAEditRejected, bounded_json_wire, decode_json
    try:
        _require(type(value) is dict, "model must be an ordinary JSON object")
        encoded = bounded_json_wire(value, 500_000)
        preflight_hia_json(encoded.decode("ascii"), max_nodes=32768, max_depth=32)
        value = decode_json(encoded)
    except (HIAEditRejected, ValueError, TypeError, RuntimeError, UnicodeError,
            RecursionError, OverflowError) as error:
        raise StatefulPlanningError("E_HIA_NDU_STATEFUL: bounded model snapshot rejected") from error
    _require(type(value) is dict and set(value) == _FIELDS, "unknown or missing model fields")
    _require(value["schema"] == SCHEMA, "unsupported schema")
    _require(type(value["name"]) is str and _ID.fullmatch(value["name"]) is not None,
             "invalid model name")
    _hex(value["objective_digest"], "objective")
    _int(value["generation"], "generation", (1 << 32) - 1)
    _require(value["generation"] > 0, "generation must be nonzero")
    for field in ("memory_budget_bytes", "budget_ns", "completion_value_ns", "sunk_cost_ns"):
        _int(value[field], field)
    _require(type(value["cost_basis"]) is str
             and value["cost_basis"] in {"declared-model-only", "caller-measurement-estimates"},
             "cost basis must be explicit")
    base = value["baseline"]
    _require(type(base) is dict and set(base) == _BASE_FIELDS, "invalid baseline fields")
    _hex(base["source_sha256"], "baseline source")
    _hex(base["verification_sha256"], "baseline verification")
    horizon = len(base["latency_ns"]) if type(base["latency_ns"]) is list else 0
    _require(1 <= horizon <= 4, "one to four remaining batches required")
    for latency in base["latency_ns"]:
        _int(latency, "baseline latency")
    variants = value["variants"]
    _require(type(variants) is list and 1 <= len(variants) <= 3, "one to three variants required")
    names = set()
    for variant in variants:
        _require(type(variant) is dict and set(variant) == _VARIANT_FIELDS,
                 "unknown or missing variant fields")
        name = variant["id"]
        _require(type(name) is str and _ID.fullmatch(name) is not None and name not in names,
                 "invalid or duplicate variant identity")
        names.add(name)
        for key in ("source_sha256", "verification_sha256", "support_sha256"):
            _hex(variant[key], key)
        _require(type(variant["status"]) is str and variant["status"] in _STATUSES,
                 "invalid verification status")
        for key in ("preparation_ns", "resident_bytes"):
            _int(variant[key], key)
        for key in ("holding_ns", "latency_ns"):
            _require(type(variant[key]) is list and len(variant[key]) == horizon,
                     "variant costs must cover every remaining batch")
            for cost in variant[key]:
                _int(cost, key)
    ready = value["initial_ready"]
    _require(type(ready) is list and all(type(name) is str for name in ready)
             and len(set(ready)) == len(ready) and set(ready) <= names,
             "invalid initial prepared set")
    by_id = {v["id"]: v for v in variants}
    _require(all(by_id[name]["status"] == "verified" for name in ready),
             "an incumbent prepared variant must be verified")
    _require(sum(by_id[name]["resident_bytes"] for name in ready) <= value["memory_budget_bytes"],
             "incumbent exceeds the resident-memory model quota")
    observations = value["observations"]
    _require(type(observations) is list and len(observations) <= 120
             and all(type(row) is dict for row in observations), "invalid past observations")
    # Bound even losing complete paths before they reach the native utility
    # profile. Unknown/unaffordable costs are not replaced with zero.
    upper = (sum(v["preparation_ns"] for v in variants)
             + sum(base["latency_ns"])
             + sum(sum(v["holding_ns"]) for v in variants))
    _require(upper <= _MAX_NS, "complete cost envelope exceeds the finite profile")
    result = value
    result["variants"].sort(key=lambda v: v["id"])
    result["initial_ready"].sort()
    return result


def _subsets(names):
    for length in range(len(names) + 1):
        yield from combinations(names, length)


def _state_id(ready):
    # At most eight states. Opaque IDs avoid concatenated-ID length collisions.
    return "ready-" + digest(list(ready))[:16]


def _state_cost(model, ready, batch):
    by_id = {v["id"]: v for v in model["variants"]}
    alternatives = [(model["baseline"]["latency_ns"][batch], "baseline")]
    alternatives.extend((by_id[name]["latency_ns"][batch], name) for name in ready)
    latency, dispatch = min(alternatives)
    holding = sum(by_id[name]["holding_ns"][batch] for name in ready)
    return {"dispatch": dispatch, "execution_ns": latency, "holding_ns": holding,
            "total_ns": latency + holding,
            "resident_bytes": sum(by_id[name]["resident_bytes"] for name in ready)}


def graph_fields(raw):
    """Expand prepared sets, pay-once acquisitions and resident holding costs.

    Every transition adds at least one previously absent variant. An acquired
    variant cannot be acquired again. A transition may prepare several variants
    together, so fixed configurations and adaptive plans share the same bank.
    All dispatch/holding estimates and refusal facts are disclosed to controls.
    """
    model = validate_model(raw)
    variants = {v["id"]: v for v in model["variants"]}
    initial = set(model["initial_ready"])
    names = sorted(variants)
    ready_sets = [tuple(sorted(initial | set(extra))) for extra in _subsets(sorted(set(names) - initial))]
    states, costs, details = {}, {}, {}
    for ready in ready_sets:
        identity = _state_id(ready)
        row = [_state_cost(model, ready, batch) for batch in range(len(model["baseline"]["latency_ns"]))]
        statuses = [variants[name]["status"] for name in ready]
        if any(item["resident_bytes"] > model["memory_budget_bytes"] for item in row):
            status = "rejected"
        else:
            status = next((s for s in ("rejected", "timeout", "unknown") if s in statuses), "verified")
        source = {"baseline": model["baseline"]["source_sha256"],
                  "ready": {name: variants[name]["source_sha256"] for name in ready}}
        verification = {"baseline": model["baseline"]["verification_sha256"],
                        "ready": {name: variants[name]["verification_sha256"] for name in ready},
                        "memory_budget_bytes": model["memory_budget_bytes"], "status": status}
        states[identity] = {"source_sha256": digest(source),
                            "verification_sha256": digest(verification), "status": status}
        costs[identity] = [item["total_ns"] for item in row]
        details[identity] = {"ready": list(ready), "batches": row}
    transitions = []
    for ready in ready_sets:
        for target in ready_sets:
            if not set(ready) < set(target):
                continue
            acquired = sorted(set(target) - set(ready))
            source_id, target_id = _state_id(ready), _state_id(target)
            transitions.append({"id": "prepare-" + digest([ready, target])[:20],
                "source": source_id, "target": target_id,
                "setup_ns": sum(variants[name]["preparation_ns"] for name in acquired),
                "status": states[target_id]["status"],
                "verification_sha256": digest({"acquired": [variants[name]["verification_sha256"] for name in acquired],
                                                "state": states[target_id]["verification_sha256"]}),
                "support_sha256": digest({name: variants[name]["support_sha256"] for name in acquired})})
    binding = {"schema": SCHEMA, "model_sha256": digest(model), "states": details,
        "preparation_charged": "once per acquisition; already prepared variants have no new setup cost",
        "holding_charged": "each resident variant for every remaining batch, including stop paths",
        "dispatch_rule": "lowest supplied current-batch execution cost; exact ties use stable variant identity",
        "sunk_cost_ns": model["sunk_cost_ns"], "cost_basis": model["cost_basis"],
        "verification_inputs_are_external_assertions": True,
        "native_application_executed": False, "safety_certificate": False}
    fields = {"objective_digest": model["objective_digest"], "snapshot_digest": digest(binding),
        "generation": model["generation"], "initial_state": _state_id(tuple(model["initial_ready"])),
        "states": states, "transitions": transitions, "batch_costs_ns": costs,
        "remaining_budget_ns": model["budget_ns"], "completion_value_ns": model["completion_value_ns"],
        "decision_cost_ns": 0, "observations": [*model["observations"], binding]}
    return fields, binding


def build_request(raw, *, search="dynamic-frontier"):
    """Use the real existing finite planner, without producing a native receipt."""
    from .hia_ndu import finite_plan_request
    fields, binding = graph_fields(raw)
    result = finite_plan_request(**fields, search=search)
    result["stateful_binding"] = binding
    return result


def observe_refusal(raw, *, variant_id, actual_attempt_ns, observation_digest):
    """Create a successor snapshot after an observed failed preparation attempt.

    The caller reports elapsed cost; no measurement is invented here. This does
    not advance the workload's batch, create prepared code or erase past costs.
    Exhausted budget remains zero with an explicit overrun; remaining work can
    still be infeasible. Callers must retain the complete observation ledger.
    """
    model = validate_model(raw)
    _int(actual_attempt_ns, "actual attempt cost")
    _hex(observation_digest, "refusal observation")
    variants = {v["id"]: v for v in model["variants"]}
    _require(type(variant_id) is str and variant_id in variants
             and variant_id not in model["initial_ready"],
             "refusal must name an unprepared variant")
    _require(not any(row.get("observation_digest") == observation_digest
                     for row in model["observations"]), "refusal observation was already consumed")
    _require(model["generation"] < (1 << 32) - 1, "generation exhausted")
    _require(model["sunk_cost_ns"] + actual_attempt_ns <= _MAX_NS, "sunk-cost ledger overflow")
    before = model["budget_ns"]
    variants[variant_id]["status"] = "rejected"
    variants[variant_id]["verification_sha256"] = observation_digest
    model["budget_ns"] = max(0, before - actual_attempt_ns)
    model["sunk_cost_ns"] += actual_attempt_ns
    model["generation"] += 1
    model["observations"].append({"kind": "preparation-refused", "variant_id": variant_id,
        "actual_attempt_ns": actual_attempt_ns, "budget_before_ns": before,
        "budget_after_ns": model["budget_ns"], "budget_overrun_ns": max(0, actual_attempt_ns - before),
        "observation_digest": observation_digest, "generation": model["generation"]})
    return validate_model(model)


def separability_diagnostic(raw):
    """Recognize the old profile in which a full DP adds no planning opportunity.

    This is an exact sufficient condition on the declared finite model, not an
    empirical claim about compiler policies. False means this particular
    reduction is unavailable; it does not prove a useful continuation benefit.
    """
    model = validate_model(raw)
    available = [v for v in model["variants"] if v["status"] == "verified"]
    all_ready = set(v["id"] for v in available) <= set(model["initial_ready"])
    zero_holding = all(not any(v["holding_ns"]) for v in available)
    fits = sum(v["resident_bytes"] for v in available) <= model["memory_budget_bytes"]
    reducible = all_ready and zero_holding and fits
    minimum = sum(min([value, *(v["latency_ns"][batch] for v in available)])
                  for batch, value in enumerate(model["baseline"]["latency_ns"])) if reducible else None
    return {"schema": "hepta.hia.ndu.separability-diagnostic.v1", "profile_sha256": digest(model),
            "stepwise_minimum_is_finite_global_minimum": reducible,
            "reason": ("all legal variants are already prepared; no holding or action-dependent future cost"
                       if reducible else "preparation, residency or unavailable state prevents this sufficient reduction"),
            "minimum_execution_ns": minimum,
            "completion_fits_budget": minimum <= model["budget_ns"] if reducible else None,
            "continuation_advantage_established": False,
            "scope": "supplied finite deterministic model only", "authority": "DENY_ALL"}
