"""Close the finite resource contract around a rechecked leaf-call expansion.

An operation-preserving optimization can still change evaluator quota failures:
inlining removes call-entry/return ticks and synchronous frames.  This module
never imports an old resource receipt.  It verifies the actual transformation,
recomputes both actual Core budgets, and admits the candidate under an explicit
policy.  The stricter policy also requires the source to fit those same quotas.

The contract is deliberately finite and opt-in.  It does not establish native
RSS, stack bytes, CPU time, host-failure cleanup, asynchronous cancellation, or
backend refinement.  Serialized reports carry evidence, never authority.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

from .hia_program import _decode, scalar_value_valid, verify_program
from .hia_static_budget import analyze_static_budget


SCHEMA = "hepta.hia.expansion-resource-contract.v1"
POLICY_SCHEMA = "hepta.hia.expansion-resource-policy.v1"
MODES = frozenset({"candidate_requalified", "both_fit_same_quotas"})
LIMITS = ("max_allocator_interactions", "max_vm_ticks", "max_call_depth",
          "max_live_heap_bytes")
SOURCE_FILES = (
    "hia_optimization_contract.py", "hia_call_expansion.py", "hia_optimization.py",
    "hia_program.py", "hia_program_composite.py", "hia_schema.py", "hia_opcodes.py", "hia_semantic_kernel.py",
    "hia_json_preflight.py", "hia_static_budget.py", "hia_heap_bound.py",
    "hia_program_runtime.py", "hia_bounded_memory.py",
)

# Statements about the selected semantic relation, not an extension of it.
BEHAVIOR = {
    "normal_return": "same typed result and ordered resource operations",
    "error_as_value": "ordinary return; explicit owner/loan cleanup remains mandatory",
    "allocator_failure": "same allocation order and fallible-result handling for the same failure schedule",
    "trap": "same first program trap and preceding resource operations; no automatic unwind claim",
    "budget_stop": "VM ticks, call depth and payload quotas are freshly checked; exact stop locations are not preserved",
    "cooperative_cancel": "explicit ordinary cleanup branches can be compared; no general cancellation theorem",
    "host_interruption": "no cleanup, rollback, retry or exactly-once claim",
    "module_composition": "closed actual module and every call interface reverified; no open-world import assumptions",
}
RECOMPUTED = ["max_allocator_interactions", "max_vm_ticks", "max_call_depth",
              "max_live_heap_bytes"]
UNQUALIFIED = ["native_stack_bytes", "native_cpu_time", "process_rss",
               "allocator_metadata", "foreign_allocators", "asynchronous_cancellation",
               "host_recursion_limit", "diagnostic_locations", "backend_refinement"]


class HIAOptimizationContractRejected(ValueError):
    pass


def _reject(message):
    raise HIAOptimizationContractRejected("E_HIA_OPT_RESOURCE_CONTRACT: " + message)


def _wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _snapshot(value):
    # Reuse the bounded, exact-built-in JSON snapshot used by the Core checker.
    # This is only an input gate: actual Core verification still follows.
    return _decode(value)[0]


def contract_checker_identity():
    digest = sha256()
    for name in SOURCE_FILES:
        digest.update(name.encode() + b"\0" + Path(__file__).with_name(name).read_bytes() + b"\0")
    return digest.hexdigest()


def _policy(value):
    policy = _snapshot(value)
    if (type(policy) is not dict
            or set(policy) != {"schema", "budget_mode", *LIMITS}
            or policy["schema"] != POLICY_SCHEMA
            or type(policy["budget_mode"]) is not str
            or policy["budget_mode"] not in MODES):
        _reject("exact versioned policy fields and a reviewed budget mode are required")
    maxima = {"max_allocator_interactions": 10_000_000, "max_vm_ticks": 10_000_000,
              "max_call_depth": 256, "max_live_heap_bytes": 1024 * 1024 * 1024}
    for key in LIMITS:
        minimum = 1 if key in {"max_vm_ticks", "max_call_depth"} else 0
        if type(policy[key]) is not int or not minimum <= policy[key] <= maxima[key]:
            _reject("invalid explicit " + key)
    return policy


def _invocation(checked, function, arguments):
    if type(function) is not str or type(arguments) not in {list, tuple}:
        _reject("an exact scalar function and argument list are required")
    frozen = _snapshot(list(arguments))
    functions = {fn["name"]: fn for fn in checked.as_dict()["functions"]}
    if (function not in checked.scalar_entrypoints or function not in functions
            or len(frozen) != len(functions[function]["params"])
            or any(not scalar_value_valid(value, parameter["type"])
                   for value, parameter in zip(frozen, functions[function]["params"]))):
        _reject("invocation arguments differ from the actual public scalar interface")
    return {"function": function, "arguments": frozen}


def _bounds(checked, invocation):
    from .hia_heap_bound import (qualify_finite_entry_live_heap_budget,
        qualify_finite_entry_live_heap_budget_v8_with_borrowed_extents, qualify_live_heap_budget)

    # Every function's acyclic event profile is checked. The payload policy is
    # for this one exact public invocation; owned returns must not silently
    # inherit the different all-function heap-summary meaning.
    static = analyze_static_budget(checked)
    function, arguments = invocation["function"], invocation["arguments"]
    schema = checked.as_dict()["schema"]
    if schema == "hepta.hia.program.v7":
        heap = qualify_finite_entry_live_heap_budget(checked, function, arguments,
                                                   max_live_heap_bytes=1024 * 1024 * 1024)
        peak = heap["peak_bound_bytes"]
    elif schema == "hepta.hia.program.v8":
        heap = qualify_finite_entry_live_heap_budget_v8_with_borrowed_extents(
            checked, function, arguments, max_live_heap_bytes=1024 * 1024 * 1024)
        peak = heap["peak_bound_bytes"]
    else:
        # Legacy schemas retain their original stricter all-function meaning.
        # Unsupported owned boundaries fail; they are never relabeled v7/v8.
        heap = qualify_live_heap_budget(checked, max_live_heap_bytes=1024 * 1024 * 1024)
        peak = heap["peak_bounds"][function]
    row = dict(next(row for row in static["functions"] if row["function"] == function))
    row["max_live_heap_bytes"] = peak
    return {"schema": "hepta.hia.expansion-invocation-budget.v1",
            "core_sha256": checked.sha256, "invocation": invocation,
            "functions": [row], "static_budget": static, "heap_admission": heap}


def _fits(budget, policy):
    return all(row[key] <= policy[key] for row in budget["functions"] for key in LIMITS)


def _check(base, proposal, policy, function, arguments):
    from .hia_call_expansion import verify_leaf_call_expansion

    identity = contract_checker_identity()
    policy = _policy(policy)
    original = verify_program(base)
    invocation = _invocation(original, function, arguments)
    frozen = _snapshot(proposal)
    proof = verify_leaf_call_expansion(original, frozen)
    if proof.get("status") != "verified":
        _reject("actual leaf-call transformation rejected: " + proof.get("reason", "missing reason"))
    candidate = verify_program(frozen["candidate_core"])
    if (proof.get("base_sha256") != original.sha256
            or proof.get("candidate_sha256") != candidate.sha256):
        _reject("semantic proof differs from the actual before/after Core")
    _invocation(candidate, function, invocation["arguments"])
    before, after = _bounds(original, invocation), _bounds(candidate, invocation)
    source_fits, candidate_fits = _fits(before, policy), _fits(after, policy)
    if not candidate_fits:
        _reject("candidate exceeds an explicit freshly computed resource limit")
    if policy["budget_mode"] == "both_fit_same_quotas" and not source_fits:
        _reject("source does not fit the same quotas; budget-failure behavior cannot be inherited")
    left = {row["function"]: row for row in before["functions"]}
    right = {row["function"]: row for row in after["functions"]}
    if left.keys() != right.keys():
        _reject("resource summaries have different module interfaces")
    # Timing is an observation, never part of reproducible admission identity.
    semantic = {key: value for key, value in proof.items() if key != "verification_wall_ns"}
    report = {
        "schema": SCHEMA, "status": "qualified_finite_expansion_resource_contract",
        "checker_sha256": identity, "base_sha256": original.sha256,
        "candidate_sha256": candidate.sha256,
        "proposal_sha256": sha256(_wire(frozen)).hexdigest(), "policy": policy,
        "scope": "exact_public_scalar_invocation", "invocation": invocation,
        "semantic_verification": semantic, "before": before, "after": after,
        "source_fits_same_quotas": source_fits, "candidate_fits_same_quotas": candidate_fits,
        "deltas": [{"function": name, **{key: right[name][key] - left[name][key]
                                         for key in LIMITS}} for name in sorted(left)],
        "required_behavior": dict(BEHAVIOR), "recomputed_budgets": list(RECOMPUTED),
        "not_qualified": list(UNQUALIFIED),
        "claims": {
            "actual_before_after_core_reverified": True,
            "ordered_leaf_expansion_relation_rechecked": True,
            "actual_candidate_resource_limits_recomputed": True,
            "resource_bounds_for_all_input_values": False,
            "both_fit_declared_vm_event_quotas": source_fits,
            "exact_budget_stop_behavior_preserved": False,
            "source_cancellation_or_host_cleanup_proved": False,
            "backend_refinement_or_native_resource_bounds_proved": False,
            "whole_language_soundness_proved": False,
        },
    }
    if contract_checker_identity() != identity:
        _reject("checker changed during contract qualification")
    report["sha256"] = sha256(_wire(report)).hexdigest()
    return report, candidate


def qualify_expansion_contract(base, proposal, *, function, arguments, policy):
    """Recheck actual semantics and resources; never accept a producer receipt."""
    return _check(base, proposal, policy, function, arguments)[0]


def validate_expansion_contract(base, proposal, receipt, *, function, arguments, policy):
    """Fresh replay against caller-supplied policy, including every bound/claim."""
    expected, _ = _check(base, proposal, policy, function, arguments)
    if _wire(_snapshot(receipt)) != _wire(expected):
        _reject("retained contract differs from independent actual-Core replay")
    return expected


def execute_contracted_expansion(base, proposal, function, arguments, *, policy,
                                 receipt=None, allocation_fail_at=None):
    """Execute only the freshly admitted candidate with the explicit VM quotas.

    Program traps and any actual evaluator/host-recursion stops retain their
    stopped resource ledgers. They are not renamed cancellation or cleanup.
    Native publication must use its own native artifact and resource contract.
    """
    from .hia_program_runtime import (HIAProgramBudgetExceeded, HIAProgramTrap,
                                     execute_program)

    contract, candidate = _check(base, proposal, policy, function, arguments)
    if receipt is not None and _wire(_snapshot(receipt)) != _wire(contract):
        _reject("retained contract differs before execution")
    limits = contract["policy"]
    try:
        observed = execute_program(candidate, contract["invocation"]["function"],
            contract["invocation"]["arguments"],
            max_steps=limits["max_vm_ticks"], max_call_depth=limits["max_call_depth"],
            max_heap_bytes=limits["max_live_heap_bytes"], allocation_fail_at=allocation_fail_at)
    except (HIAProgramTrap, HIAProgramBudgetExceeded) as error:
        observed = error.report
    return {"contract": contract, "execution": observed,
            "automatic_cleanup_or_retry_claimed": False}
