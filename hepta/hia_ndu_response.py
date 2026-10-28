"""Pure response checks for the original bounded supplied-path NDU profile.

The recursive, finite-graph and stream bridges use this same response contract:
linear Q32 path receipts, zero projections and advisory-only authority. Their
source/compiler admission remains separate. This module has no transport,
cache, native runtime or compiler dependencies and confers no proof authority.
"""
from hashlib import sha256
import json
import re


RESPONSE_PROFILE = "hepta.hia.ndu.response-profile.linear-q32.v1"
_RESPONSE_KEYS = frozenset({"schema", "status", "request_digest", "objective_digest", "snapshot_digest",
    "generation", "identity", "authority", "safety_certificate", "optimality_scope", "disposition",
    "advisory_candidate_id", "evaluated_candidate_ids", "pareto_candidate_ids", "rejected",
    "evaluation_digest", "evaluation_policy_digest", "utility_profile_digest", "paths"})
_PATH_KEYS = frozenset({"id", "verification_digest", "support_digest", "values_q32",
    "recursive_evidence_digest", "resource_cost_q32", "risk_q32", "projection_count"})


class NduResponseError(ValueError):
    """The supplied response does not satisfy its declared wire profile."""


def _identity_wire(value):
    if type(value) is not dict:
        raise NduResponseError("native response: malformed build identity")
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as error:
        raise NduResponseError("native response: malformed build identity") from error


def validate_response(response, request, payload, manifest, *, profile):
    """Check an advisory reply against the exact frozen request sent on the wire.

This validates structure, bindings and receipt consistency. It does not prove
the reported utility values, authenticate input proof digests, re-evaluate the
NDU algorithm or authorize candidate execution/publication. Unknown profiles
and fields refuse instead of silently inheriting this profile's constraints.
"""
    if type(profile) is not str or profile != RESPONSE_PROFILE:
        raise NduResponseError("native response: unsupported validation profile")
    if (type(response) is not dict or set(response) != _RESPONSE_KEYS
            or response.get("schema") != "hepta.hia.ndu.response.v1"
            or response.get("status") != "advisory"
            or response.get("authority") != "DENY_ALL"
            or response.get("safety_certificate") is not False
            or response.get("optimality_scope") != "bounded-supplied-candidate-paths-only"
            or type(response.get("generation")) is not int
            or type(response.get("disposition")) is not str):
        raise NduResponseError("native response: schema or authority changed")
    try:
        if type(request) is not dict or type(payload) is not bytes or type(manifest) is not dict:
            raise NduResponseError("native response: malformed frozen request or identity")
        expected = {"objective_digest": request.get("objective_digest"),
                    "snapshot_digest": request.get("snapshot_digest"),
                    "generation": request.get("generation"),
                    "request_digest": sha256(payload).hexdigest()}
        if any(response.get(name) != value for name, value in expected.items()):
            raise NduResponseError("native response: stale or foreign bindings")
        # JSON identity is typed: Python's False == 0 must not alias two
        # different native build-identity representations.
        if _identity_wire(response["identity"]) != _identity_wire(manifest["identity"]):
            raise NduResponseError("native response: stale or foreign build identity")
        rows = request["candidates"]
        if (type(rows) is not list or not rows or any(type(row) is not dict
                or type(row.get("id")) is not str for row in rows)):
            raise NduResponseError("native response: malformed frozen candidate inventory")
        inputs = {row["id"]: row for row in rows}
        if len(inputs) != len(rows):
            raise NduResponseError("native response: duplicate frozen candidate")
        candidates = set(inputs)
        chosen = response["advisory_candidate_id"]
        if chosen is not None and (type(chosen) is not str or chosen not in candidates):
            raise NduResponseError("native response: unknown selected candidate")
        for name in ("evaluation_digest", "evaluation_policy_digest", "utility_profile_digest"):
            value = response[name]
            if type(value) is not str or not re.fullmatch("[0-9a-f]{64}", value) or value == "0" * 64:
                raise NduResponseError("native response: malformed evaluation digest")
        sets = {}
        for name in ("evaluated_candidate_ids", "pareto_candidate_ids"):
            values = response[name]
            if (type(values) is not list or any(type(x) is not str for x in values)
                    or len(values) != len(set(values)) or not set(values) <= candidates):
                raise NduResponseError("native response: malformed candidate frontier")
            sets[name] = set(values)
        if not sets["pareto_candidate_ids"] <= sets["evaluated_candidate_ids"]:
            raise NduResponseError("native response: foreign Pareto candidate")
        if chosen is not None and chosen not in sets["pareto_candidate_ids"]:
            raise NduResponseError("native response: selected candidate outside admitted frontier")
        evaluated, frontier = sets["evaluated_candidate_ids"], sets["pareto_candidate_ids"]
        disposition = response["disposition"]
        consistent = {
            "InfeasibleExplicitAbstain": evaluated == frontier == {"abstain"} and chosen == "abstain",
            "UniqueParetoRecommendation": (len(frontier) == 1 and chosen in frontier
                                            and evaluated != {"abstain"}),
            "ParetoSetRequiresSlowPath": len(frontier) > 1 and chosen is None,
        }
        if not consistent.get(disposition, False):
            raise NduResponseError("native response: disposition disagrees with selected frontier")
        rejected = response["rejected"]
        if type(rejected) is not list:
            raise NduResponseError("native response: malformed rejection list")
        denied = set()
        for row in rejected:
            if (type(row) is not dict or set(row) != {"id", "reasons"}
                    or type(row["id"]) is not str or row["id"] not in candidates or row["id"] in denied
                    or type(row["reasons"]) is not list or not row["reasons"]
                    or any(type(x) is not str or not x for x in row["reasons"])):
                raise NduResponseError("native response: malformed rejection entry")
            denied.add(row["id"])
        if denied & evaluated or denied | evaluated != candidates:
            raise NduResponseError("native response: incomplete evaluation partition")
        paths = response["paths"]
        if type(paths) is not list or len(paths) != len(candidates):
            raise NduResponseError("native response: malformed path inventory")
        seen = set()
        for row in paths:
            if (type(row) is not dict or set(row) != _PATH_KEYS or type(row["id"]) is not str
                    or row["id"] not in candidates or row["id"] in seen):
                raise NduResponseError("native response: malformed path entry")
            seen.add(row["id"])
            original = inputs[row["id"]]
            if (type(row["resource_cost_q32"]) is not int or not 0 <= row["resource_cost_q32"] < (1 << 63)
                    or type(row["risk_q32"]) is not int or not 0 <= row["risk_q32"] <= (1 << 32)):
                raise NduResponseError("native response: path costs and risk must be exact bounded integers")
            if any(row[name] != original[name] for name in ("verification_digest", "support_digest",
                                                            "resource_cost_q32", "risk_q32")):
                raise NduResponseError("native response: stale path bindings")
            values, proof = row["values_q32"], row["recursive_evidence_digest"]
            if (type(values) is not list or len(values) != len(original["events"]) + 1
                    or any(type(v) is not int or not -(1 << 63) <= v < (1 << 63) for v in values)
                    or type(row["projection_count"]) is not int or row["projection_count"] != 0
                    or type(proof) is not str or not re.fullmatch("[0-9a-f]{64}", proof)
                    or proof == "0" * 64):
                raise NduResponseError("native response: malformed recursive path")
    except (KeyError, TypeError) as error:
        raise NduResponseError("native response: malformed request or response") from error
