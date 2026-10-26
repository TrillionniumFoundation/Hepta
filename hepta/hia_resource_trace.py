"""Bounded path replay of the EXISTING independently checked Resource IR.

This is a test-only operational *resource-state* witness, not a second source
checker, numeric interpreter, LLVM emitter, or proof of source/refinement.
Branches are supplied by a caller; the original IR abstracts scalar values.
The sole ownership transition implementation is resource_ir._Verifier.
"""
from __future__ import annotations

from hashlib import sha256
import json

from .resource_ir import ResourceIRError, _CLAIMS, _State, _Verifier, verify_resource_ir


class HIAResourceTraceRejected(ValueError):
    """Cannot replay a complete finite resource path with this profile."""


def _reject(message: str) -> None:
    raise HIAResourceTraceRejected("E_HIA_RESOURCE_TRACE: " + message)


_SUPPORTED = frozenset({
    "acquire", "move", "drop", "borrow", "end_borrow", "use",
})
_PROOF_CLAIMS = {
    "numeric_value_execution_proved": False,
    "memory_byte_semantics_proved": False,
    "source_to_ir_refinement_proved": False,
    "native_backend_refinement_proved": False,
    "pointer_provenance_proved": False,
    "independent_source_binding_proved": False,
    "whole_language_soundness_proved": False,
}


def replay_resource_path(graph: dict, verified: dict, function_name: str,
                         *, choices: tuple[int, ...] = (), fuel: int = 4096) -> dict:
    """Replay one bounded CFG path with the existing typed ownership checker.

    choices holds a 0-based successor index for every dynamic branch/switch
    occurrence, including repeated loop headers. Because copied scalar values
    are abstract, these choices are NOT inferred from Hepta source execution.
    Neither the supplied receipt nor a digest authenticates the original source.
    """
    if (type(graph) is not dict or type(verified) is not dict
            or type(function_name) is not str or not function_name
            or type(fuel) is not int or not 1 <= fuel <= 10000
            or type(choices) is not tuple or len(choices) > fuel
            or any(type(choice) is not int or choice < 0 for choice in choices)):
        _reject("invalid bounded graph, function or branch witness")
    try:
        encoded = json.dumps(graph, sort_keys=True, separators=(",", ":"),
                             allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, RecursionError, OverflowError) as exc:
        raise HIAResourceTraceRejected("E_HIA_RESOURCE_TRACE: graph cannot be encoded") from exc
    if len(encoded) > 8 * 1024 * 1024:
        _reject("graph exceeds 8 MiB witness limit")
    receipt = verify_resource_ir(graph)
    if (receipt.get("ok") is not True or receipt.get("status") != "resource_cfg_verified"
            or receipt.get("ir_sha256") != sha256(encoded).hexdigest()
            or verified.get("ok") is not True
            or verified.get("status") != receipt["status"]
            or verified.get("ir_sha256") != receipt["ir_sha256"]
            or verified.get("functions") != receipt.get("functions")
            or verified.get("external_obligations") != {}
            or graph.get("obligations") != {}
            or type(verified.get("claims")) is not dict
            or set(verified["claims"]) != set(_CLAIMS)
            or any(verified["claims"][key] is not expected
                   for key, expected in _CLAIMS.items())):
        _reject("resource graph and exact independent verification disagree")
    if graph.get("schema") not in {"hepta.resource-ir.v3", "hepta.resource-ir.v4", "hepta.resource-ir.v5"}:
        _reject("unsupported resource schema")
    functions = [fn for fn in graph["functions"] if fn["name"] == function_name]
    if len(functions) != 1 or functions[0]["external"] or functions[0].get("type_params"):
        _reject("requires a single non-generic source-derived function")
    fn = functions[0]
    if (any(parameter["mode"] not in {"value", "read", "mut"} for parameter in fn["params"])
            or fn["returns"] != {"type": "Unit", "mode": "value", "origin": None}):
        _reject("only a Unit-returning local function without owned inputs is replayable")
    blocks = {block["id"]: block for block in fn["blocks"]}
    if len(blocks) != len(fn["blocks"]):
        _reject("duplicate source resource block")
    if any(op["op"] not in _SUPPORTED for block in blocks.values() for op in block["ops"]):
        _reject("unknown/external/aggregate/view instruction has no finite replay semantics")
    if any(op["op"] == "acquire" and op.get("kind") != "buffer"
           for block in blocks.values() for op in block["ops"]):
        _reject("fallible allocation outcome cannot be inferred from abstract values")
    if any(block["term"]["op"] not in {"jump", "branch", "return"} for block in blocks.values()):
        _reject("switch/exceptional control flow is not in finite replay profile")
    if any(graph["types"][local["type"]]["kind"] == "view" for local in fn["locals"]):
        _reject("stored views require a separate executable region model")

    # Static verification has already required every CFG block, edge, loan and
    # exit to be valid. Replay reuses exactly its transfer semantics; no second
    # ownership policy may disagree with the native Resource IR authority.
    checker = _Verifier(graph)
    try:
        checker.validate_types()
        checker.validate_signatures()
        checker.body(fn)
        state = _State(set())
        current = fn["entry"]
        index = 0
        events = []
        path = []
        counts = {name: 0 for name in sorted(_SUPPORTED)}
        while len(path) < fuel:
            block = blocks[current]
            checker.block = current
            path.append(current)
            for op in block["ops"]:
                checker.operation(op, state)
                counts[op["op"]] += 1
                if len(events) >= 10000:
                    _reject("operation trace exceeds finite budget")
                events.append({"block": current, "op": op["op"],
                               "live_owned_roots": sorted({root for root, _ in checker.outstanding(state)}),
                               "live_loans": sorted(state.loans)})
            edges = checker.terminator(block["term"], state, fn)
            if not edges:
                if index != len(choices):
                    _reject("unconsumed branch witness choices")
                if checker.outstanding(state) or state.loans or state.views:
                    _reject("normal return leaks a resource")
                result = {
                    "schema": "hepta.hia-resource-path.v0",
                    "status": "finite_resource_path_replayed_values_abstract",
                    "resource_ir_sha256": receipt["ir_sha256"],
                    "source_sha256": graph["source_sha256"],
                    "project_sha256": graph["project_sha256"],
                    "function": function_name,
                    "blocks_visited": path,
                    "choices_consumed": index,
                    "branch_choices_supplied_by_caller": True,
                    "counts": counts,
                    "events": events,
                    "claims": dict(_PROOF_CLAIMS),
                }
                witness = json.dumps(result, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode("utf-8")
                result["witness_sha256"] = sha256(witness).hexdigest()
                return result
            if len(edges) == 1:
                current, state = edges[0]
            else:
                if index >= len(choices) or choices[index] >= len(edges):
                    _reject("missing/out-of-range abstract branch choice")
                current, state = edges[choices[index]]
                index += 1
        _reject("finite path fuel exhausted; not evidence of nontermination")
    except ResourceIRError as exc:
        raise HIAResourceTraceRejected("E_HIA_RESOURCE_TRACE: " + str(exc)) from exc
