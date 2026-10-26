"""Deterministic, fail-closed *advisory* call-graph impact for HIA Agent patches.

Only the existing verified program and apply_program_patch implement language
and mutation semantics. This read-only observer cannot authorize a patch,
claim behavioral equivalence, publish a file, or validate external callers.
"""
from __future__ import annotations

from collections import deque
from hashlib import sha256
import json

from .hia_program import verify_program
from .hia_program_tools import apply_program_patch

SCHEMA = "hepta.hia.patch-impact.v1"
MAX_FUNCTIONS = 1024
_RECEIPT_FIELDS = {
    "hepta.hia.patch-result.v1": frozenset({
        "schema", "ok", "status", "before_sha256", "after_sha256",
        "edits", "interface_changes", "claims"}),
    "hepta.hia.patch-result.v2": frozenset({
        "schema", "ok", "status", "before_sha256", "after_sha256",
        "edits", "interface_changes", "interface_policy", "claims"}),
}
_RECEIPT_CLAIMS = {
    "hepta.hia.patch-result.v1": {
        "whole_module_rechecked": True,
        "behavior_equivalence_proved": False,
        "native_executed": False,
    },
    "hepta.hia.patch-result.v2": {
        "whole_module_rechecked": True,
        "behavior_equivalence_proved": False,
        "native_executed": False,
        "interface_preserved": None,  # checked against exact ABI comparison
        "external_callers_revalidated": False,
    },
}


class HIAImpactRejected(ValueError):
    pass


def _reject(reason):
    raise HIAImpactRejected("E_HIA_IMPACT: " + reason)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      allow_nan=False, ensure_ascii=False)


def _functions(verified):
    data = verified.as_dict()
    functions = data.get("functions")
    if type(functions) is not list or not 1 <= len(functions) <= MAX_FUNCTIONS:
        _reject("invalid function inventory")
    by_name = {}
    for fn in functions:
        if type(fn) is not dict or type(fn.get("name")) is not str or fn["name"] in by_name:
            _reject("unreviewed function identity")
        by_name[fn["name"]] = fn
    return by_name


def _incoming(functions):
    """Return edges callee -> callers from *verified* closed call operations."""
    incoming = {name: set() for name in functions}
    for caller, function in functions.items():
        for block in function["blocks"]:
            for operation in block["ops"]:
                if operation["op"] != "call":
                    continue
                callee = operation["attrs"]["function"]
                if callee not in incoming:
                    _reject("verified program has unlisted callee")
                incoming[callee].add(caller)
    return incoming


def _interface(functions):
    return {name: _canonical([fn["params"], fn["returns"], fn["effects"]])
            for name, fn in functions.items()}


def analyze_patch_impact(document, request):
    """Run the existing Agent patch verifier and report conservative impact.

    This is a *finite static call-graph reachability* hint for selecting tests,
    not behavior equivalence or a resource-proven semantic diff. Both old/new
    graphs are considered so removed call edges never erase impacted callers.
    Returns the existing candidate and unmodified patch receipt separately.
    """
    original = verify_program(document)
    candidate, patch_receipt = apply_program_patch(original, request)
    checked = verify_program(candidate)
    if checked.canonical_bytes != candidate.canonical_bytes:
        _reject("patch output changed after validation")
    schema = patch_receipt.get("schema") if type(patch_receipt) is dict else None
    claims = patch_receipt.get("claims") if schema in _RECEIPT_FIELDS else None
    if (schema not in _RECEIPT_FIELDS
            or set(patch_receipt) != _RECEIPT_FIELDS[schema]
            or type(claims) is not dict
            or set(claims) != set(_RECEIPT_CLAIMS[schema])
            or any(claims[k] is not expected for k, expected in
                   _RECEIPT_CLAIMS[schema].items() if expected is not None)
            or patch_receipt.get("status") != "verified_unpublished"
            or patch_receipt.get("ok") is not True
            or patch_receipt.get("before_sha256") != original.sha256
            or patch_receipt.get("after_sha256") != checked.sha256
            or type(patch_receipt.get("edits")) is not int
            or patch_receipt["edits"] < 1):
        _reject("unqualified or fabricated Agent patch receipt")

    before, after = _functions(original), _functions(checked)
    if set(before) - set(after):
        # Current mutation grammar never deletes entire declarations.
        _reject("patch unexpectedly removed a function")
    changes = sorted(name for name in set(before) | set(after)
                     if name not in before or name not in after
                     or _canonical(before[name]) != _canonical(after[name]))
    old_abi, new_abi = _interface(before), _interface(after)
    interface_changes = sorted(name for name in set(old_abi) | set(new_abi)
                               if old_abi.get(name) != new_abi.get(name))
    if (type(patch_receipt.get("interface_changes")) is not list
            or patch_receipt["interface_changes"] != interface_changes):
        _reject("Agent interface change receipt contradicts actual programs")
    if patch_receipt["schema"] == "hepta.hia.patch-result.v2":
        policy = patch_receipt.get("interface_policy")
        if (type(policy) is not str or policy not in {"preserve", "migrate"}
                or patch_receipt["claims"].get("interface_preserved") is not (not interface_changes)
                or patch_receipt["claims"].get("external_callers_revalidated") is not False):
            _reject("Agent migration-policy receipt contradicts verified program")
    elif interface_changes:
        _reject("legacy patch may not claim changed interface")

    old_edges, new_edges = _incoming(before), _incoming(after)
    reverse = {name: set() for name in set(before) | set(after)}
    for graph in (old_edges, new_edges):
        for callee, callers in graph.items():
            reverse[callee].update(callers)
    pending = deque(changes)
    affected = set(changes)
    while pending:
        current = pending.popleft()
        for caller in sorted(reverse.get(current, ())):
            if caller not in affected:
                affected.add(caller)
                pending.append(caller)
    impacted_existing = sorted(affected & set(after))
    unchanged_candidates = sorted(set(after) - affected)
    report = {
        "schema": SCHEMA,
        "status": "verified_static_callgraph_impact_not_equivalence",
        "before_sha256": original.sha256,
        "after_sha256": checked.sha256,
        "patch_result_schema": patch_receipt["schema"],
        "direct_changed_functions": changes,
        "interface_changed_functions": interface_changes,
        "potentially_affected_functions": impacted_existing,
        "unaffected_by_static_callgraph": unchanged_candidates,
        "old_call_edges": sorted([{"caller": caller, "callee": callee}
                                  for callee, callers in old_edges.items()
                                  for caller in callers], key=lambda e: (e["caller"], e["callee"])),
        "new_call_edges": sorted([{"caller": caller, "callee": callee}
                                  for callee, callers in new_edges.items()
                                  for caller in callers], key=lambda e: (e["caller"], e["callee"])),
        "claims": {
            "source_and_candidate_reverified": True,
            "both_verified_call_graphs_scanned": True,
            "direct_and_transitive_callers_included": True,
            "functional_equivalence_proved": False,
            "dynamic_reachability_proved": False,
            "external_callers_revalidated": False,
            "native_execution_qualified": False,
            "physical_device_qualified": False,
        },
    }
    report["sha256"] = sha256(_canonical(report).encode("utf-8")).hexdigest()
    return checked, patch_receipt, report
