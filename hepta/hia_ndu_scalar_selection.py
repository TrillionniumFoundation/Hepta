"""Explicit caller selection after the admitted, fixed scalar NDU response.

The native bridge has one minimized supplied-cost axis and zero Pareto
tolerance. It deliberately emits no recommendation for an ambiguous frontier.
A null recommendation therefore is not an explicit abstain. This module checks
the response's relation to that bounded scalar request and records a separate
caller tie decision. It never calls an evaluator, verifies its executable, or
substitutes for native evaluation. Call it only after native identity admission.
It does not prove program safety, forecast accuracy or incremental NDU value.
"""
from __future__ import annotations

from hashlib import sha256
import json
import re

SELECTION_SCHEMA = "hepta.hia.ndu-scalar-selection.v1"
SELECTION_PROFILE = "hia-total-cost-ms-v1"
TIE_POLICY = "incumbent-if-on-frontier-else-lexicographic-id.v1"
_ID = re.compile(r"[a-zA-Z][a-zA-Z0-9_.:-]{0,63}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_MAX = (1 << 63) - 1


class ScalarSelectionRejected(ValueError):
    """The reply is inconsistent with the supported fixed scalar profile."""


def _require(ok, message):
    if not ok:
        raise ScalarSelectionRejected("E_HIA_NDU_SELECTION: " + message)


def _digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=False, allow_nan=False).encode("utf-8")).hexdigest()


def _id(value):
    return type(value) is str and _ID.fullmatch(value) is not None


def _integer(value, maximum=_MAX):
    return type(value) is int and 0 <= value <= maximum


def resolve_scalar_selection(request, response):
    """Return a distinct, request-bound selection receipt; mutate neither input.

    The unchanged native evaluator must already have run successfully, with its
    source/image identity checked by the caller. The only caller policy here is
    to retain an incumbent on the minimum-cost frontier, otherwise use its first
    lexicographic ID. The raw native null recommendation remains null. This is
    the same tie policy as the strong ordinary enumerator, not extra NDU value.
    All work remains inside the caller's original measured budget interval.
    """
    _require(type(request) is dict and set(request) == {
        "schema", "objective_sha256", "generation", "resource_cap_q32", "candidates"},
        "closed scalar request required")
    _require(request["schema"] == "hepta.hia.ndu-request.v1", "unsupported request schema")
    objective = request["objective_sha256"]
    _require(type(objective) is str and _HEX.fullmatch(objective), "invalid objective digest")
    _require(_integer(request["generation"], (1 << 64) - 1) and request["generation"] > 0,
             "invalid generation")
    cap = request["resource_cap_q32"]
    _require(_integer(cap), "invalid resource cap")
    candidates = request["candidates"]
    _require(type(candidates) is list and 1 <= len(candidates) <= 128, "candidate bound")
    rows = {}
    for row in candidates:
        _require(type(row) is dict and set(row) == {"id", "cost_q32", "uncertainty_q32",
            "resource_q32", "hard_violation", "support_sha256"}, "closed scalar row required")
        cid = row["id"]
        _require(_id(cid) and cid not in rows, "invalid or duplicate candidate ID")
        _require(all(_integer(row[name]) for name in ("cost_q32", "uncertainty_q32", "resource_q32"))
                 and type(row["hard_violation"]) is bool, "invalid scalar row values")
        support = row["support_sha256"]
        _require(type(support) is str and _HEX.fullmatch(support), "invalid support digest")
        rows[cid] = row
    feasible = {cid: row for cid, row in rows.items()
                if not row["hard_violation"] and row["resource_q32"] <= cap}
    _require("abstain" in feasible, "a feasible native incumbent is required")
    minimum = min(row["cost_q32"] for row in feasible.values())
    frontier = sorted(cid for cid, row in feasible.items() if row["cost_q32"] == minimum)

    _require(type(response) is dict, "native response must be an object")
    _require(response.get("request_sha256") == _digest(request)
             and response.get("objective_sha256") == objective
             and type(response.get("generation")) is int
             and response["generation"] == request["generation"], "response/request binding")
    _require("advisory_recommendation" in response, "missing native recommendation field")
    recommendation = response["advisory_recommendation"]
    _require(recommendation is None or _id(recommendation), "invalid native recommendation")
    actual_frontier = response.get("pareto_frontier")
    _require(type(actual_frontier) is list and actual_frontier == frontier,
             "native frontier differs from the fixed scalar profile")
    rejected = response.get("rejected")
    _require(type(rejected) is list and len(rejected) <= 128, "invalid native rejected rows")
    rejected_ids = []
    for row in rejected:
        _require(type(row) is dict and set(row) == {"id", "reasons"}
                 and _id(row["id"]) and type(row["reasons"]) is str and row["reasons"],
                 "invalid native rejected row")
        rejected_ids.append(row["id"])
    _require(rejected_ids == sorted(set(rows) - set(feasible)), "native feasibility partition differs")

    disposition = response.get("disposition")
    if len(feasible) == 1:
        _require(disposition == "InfeasibleExplicitAbstain" and recommendation == "abstain",
                 "native explicit-abstain disposition differs")
        selected, source = "abstain", "native_explicit_abstain"
    elif len(frontier) == 1:
        _require(disposition == "UniqueParetoRecommendation" and recommendation == frontier[0],
                 "native unique recommendation differs")
        selected, source = frontier[0], "native_unique_pareto"
    else:
        _require(disposition == "ParetoSetRequiresSlowPath" and recommendation is None,
                 "native ambiguous-frontier disposition differs")
        selected = "abstain" if "abstain" in frontier else frontier[0]
        source = "caller_pareto_tie_policy"
    return {"schema": SELECTION_SCHEMA, "profile": SELECTION_PROFILE,
        "request_sha256": _digest(request), "native_response_sha256": _digest(response),
        "native_disposition": disposition, "native_recommendation": recommendation,
        "validated_pareto_frontier": frontier, "selected_id": selected,
        "selection_source": source, "caller_tie_policy": TIE_POLICY,
        "caller_tie_policy_applied": source == "caller_pareto_tie_policy",
        "scope": "fixed scalar supplied-cost profile and caller tie policy only",
        "assumptions": ["caller already admitted the unchanged native bridge source and executable",
            "request uses hia-total-cost-ms-v1 with zero Pareto tolerance and no scalarization"],
        "native_identity_validated_here": False, "authority": "ADVISORY_ONLY",
        "proves_program_safety": False, "forecast_is_observed_benefit": False,
        "incremental_ndu_advantage_established": False}
