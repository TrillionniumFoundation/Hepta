"""Finite boolean-input control-flow execution over independently verified Resource IR.

This adapter DOES NOT infer source-level scalar semantics or replace the sole
resource checker. It executes only branch edges whose condition is a boolean
value parameter of a *source-derived*, already verified Resource IR function.
It reuses hia_resource_trace to execute the exact owner/loan/drop transitions.

No source authenticity, pointer/memory semantics or native refinement follows.
"""
from __future__ import annotations

from hashlib import sha256
import json

from .hia_resource_trace import HIAResourceTraceRejected, replay_resource_path


class HIABooleanTraceRejected(ValueError):
    """A graph or boolean input cannot be executed within the finite profile."""


def _reject(message: str) -> None:
    raise HIABooleanTraceRejected("E_HIA_BOOL_TRACE: " + message)


_CLAIMS = {
    "general_numeric_execution_proved": False,
    "source_boolean_equivalence_proved": False,
    "full_memory_ssa_proved": False,
    "pointer_provenance_proved": False,
    "source_to_ir_refinement_proved": False,
    "native_backend_refinement_proved": False,
    "whole_language_soundness_proved": False,
}


def replay_boolean_resource_path(graph: dict, verified: dict, function_name: str, *,
                                 inputs: dict[str, bool], fuel: int = 4096) -> dict:
    """Select every branch from an actual input bool, then replay resource ops.

    This finite profile requires all parameters to be immutable, by-value bools
    and *all* branch conditions to refer to those same parameter slots. Copies,
    computed conditions, side-effectful branch operands, loop induction and
    opaque scalar assignments have no modeled value semantics and reject.

    The resource graph is still merely a checked-source abstraction; only the
    bool-input to branch-edge selection, not Hepta language semantics, executes.
    """
    if (type(graph) is not dict or type(verified) is not dict
            or type(function_name) is not str or not function_name
            or type(inputs) is not dict or len(inputs) > 16
            or type(fuel) is not int or not 1 <= fuel <= 10000):
        _reject("invalid bounded source, inputs or fuel")
    functions = graph.get("functions")
    if type(functions) is not list:
        _reject("missing Resource IR function inventory")
    matches = [fn for fn in functions if type(fn) is dict and fn.get("name") == function_name]
    if len(matches) != 1:
        _reject("function missing or ambiguous")
    function = matches[0]
    parameters = function.get("params")
    if (type(parameters) is not list or len(parameters) > 16 or
            any(type(p) is not dict or type(p.get("id")) is not str or not p["id"]
                or p.get("type") != "bool" or p.get("mode") != "value"
                for p in parameters)):
        _reject("only immutable by-value bool parameters are executable")
    names = [p["id"] for p in parameters]
    if (len(set(names)) != len(names) or set(inputs) != set(names)
            or any(type(value) is not bool for value in inputs.values())):
        _reject("every bool parameter requires an exact bool input")
    blocks = function.get("blocks")
    if (type(blocks) is not list or len(blocks) > 4096 or
            any(type(block) is not dict or type(block.get("id")) is not str
                for block in blocks)):
        _reject("invalid block identity")
    by_id = {block["id"]: block for block in blocks}
    if len(by_id) != len(blocks):
        _reject("duplicate CFG block")
    entry = function.get("entry")
    if type(entry) is not str or entry not in by_id:
        _reject("missing entry block")
    # Prevent the abstract Resource IR's `use` from changing a branch input.
    # Even if the reference verifier accepts some writable caller-local, this
    # executable value profile does not model such a write.
    for block in blocks:
        ops = block.get("ops")
        if type(ops) is not list:
            _reject("malformed operation block")
        for operation in ops:
            if type(operation) is not dict or type(operation.get("op")) is not str:
                _reject("malformed resource operation")
            place = operation.get("place")
            if type(place) is dict:
                root, mode = place.get("root"), operation.get("mode")
                if type(root) is not str:
                    _reject("malformed resource place root")
                if mode is not None and type(mode) is not str:
                    _reject("malformed resource access mode")
                if root in inputs and mode in {"write", "mut"}:
                    _reject("value parameter may be mutated before a branch")
    visited = []
    choices = []
    edge_decisions = []
    current = entry
    while len(visited) < fuel:
        if current not in by_id:
            _reject("missing CFG successor")
        visited.append(current)
        term = by_id[current].get("term")
        if type(term) is not dict:
            _reject("missing CFG terminator")
        kind = term.get("op")
        if kind == "return":
            break
        if kind == "jump":
            target = term.get("target")
        elif kind == "branch":
            condition = term.get("condition")
            if type(condition) is not str or condition not in inputs:
                _reject("computed/unknown branch condition has no value interpreter")
            condition_value = inputs[condition]
            index = 0 if condition_value else 1
            choices.append(index)
            edge_decisions.append({"block": current, "param": condition,
                                   "value": condition_value, "edge": "then" if index == 0 else "else"})
            target = term.get("then" if index == 0 else "else")
        else:
            _reject("switch, trap and exceptional branches require another profile")
        if type(target) is not str:
            _reject("invalid branch target")
        current = target
    else:
        _reject("finite execution fuel exhausted")
    try:
        replay = replay_resource_path(graph, verified, function_name,
                                      choices=tuple(choices), fuel=fuel)
    except HIAResourceTraceRejected as exc:
        raise HIABooleanTraceRejected("E_HIA_BOOL_TRACE: " + str(exc)) from exc
    if (replay.get("blocks_visited") != visited or
            replay.get("choices_consumed") != len(choices) or
            replay.get("status") != "finite_resource_path_replayed_values_abstract" or
            replay.get("branch_choices_supplied_by_caller") is not True):
        _reject("value-selected and independently replayed CFG paths disagree")
    payload = {
        "schema": "hepta.hia-boolean-resource-trace.v1",
        "status": "finite_boolean_parameter_branches_resource_path_replayed",
        "resource_ir_sha256": replay["resource_ir_sha256"],
        "source_sha256": replay["source_sha256"],
        "project_sha256": replay["project_sha256"],
        "function": function_name,
        "inputs": {name: inputs[name] for name in names},
        "blocks_visited": visited,
        "edge_decisions": edge_decisions,
        "resource_witness_sha256": replay["witness_sha256"],
        "resource_operation_counts": replay["counts"],
        "resource_events": replay["events"],
        "claims": dict(_CLAIMS),
    }
    data = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if len(data.encode("utf-8")) > 8 * 1024 * 1024:
        _reject("trace output exceeds bounded budget")
    payload["trace_sha256"] = sha256(data.encode("utf-8")).hexdigest()
    return payload
