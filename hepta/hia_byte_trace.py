"""Finite byte memory execution over a verified boolean-selected Resource IR path.

This is a *test oracle* for HIA v1 research, NOT a second ownership checker,
source-level value interpreter, native LLVM backend or general Memory SSA.
Allocation extents and load/store indices/values are external *test inputs*,
not inferred from checked source. Every Resource IR transition is first
replayed with the existing independent verifier. All proof claims remain false.
"""
from __future__ import annotations

from hashlib import sha256
import json

from .hia_boolean_trace import HIABooleanTraceRejected, replay_boolean_resource_path


class HIAByteTraceRejected(ValueError):
    """Closed synthetic byte-memory profile rejected the supplied inputs."""


def _reject(message: str) -> None:
    raise HIAByteTraceRejected("E_HIA_BYTE_TRACE: " + message)


_CLAIMS = {
    "memory_bytes_match_original_source_proved": False,
    "full_memory_ssa_proved": False,
    "interprocedural_aliasing_proved": False,
    "pointer_provenance_proved": False,
    "allocator_failure_semantics_proved": False,
    "native_llvm_backend_refinement_proved": False,
    "whole_language_soundness_proved": False,
}


def replay_byte_memory_path(graph: dict, verified: dict, function_name: str, *,
                            inputs: dict[str, bool], actions: tuple[dict, ...],
                            fuel: int = 4096) -> dict:
    """Execute a bounded external byte action stream against owner/loan path.

    Supported Resource ops: acquire(buffer), move, borrow(shared/unique),
    use(read/write), end_borrow, drop. A scalar param use is permitted only
    as an immutable read. The external action stream contains exactly one
    {kind:alloc,bytes:n} for each dynamic buffer acquire and one
    {kind:read,index:i}/{kind:write,index:i,value:u8} for each dynamic
    buffer use. The memory token is incremented on alloc, write and free.

    This models a finite synthetic memory program, not source byte semantics.
    """
    if (type(actions) is not tuple or len(actions) > 10000 or
            any(type(item) is not dict for item in actions)):
        _reject("invalid bounded external byte action script")
    try:
        control = replay_boolean_resource_path(
            graph, verified, function_name, inputs=inputs, fuel=fuel)
    except HIABooleanTraceRejected as exc:
        raise HIAByteTraceRejected("E_HIA_BYTE_TRACE: " + str(exc)) from exc
    functions = [fn for fn in graph["functions"] if fn["name"] == function_name]
    if len(functions) != 1:
        _reject("missing source Resource function")
    fn = functions[0]
    blocks = {block["id"]: block for block in fn["blocks"]}
    owners: dict[str, int] = {}
    buffers: dict[int, bytearray] = {}
    loans: dict[str, tuple[int, str]] = {}
    allocated = 0
    freed = 0
    token = 0
    action_index = 0
    total_requested = 0
    peak_live_bytes = 0
    observations: list[dict] = []
    op_order = []
    scalar_params = set(inputs)

    def next_action(kind: str) -> dict:
        nonlocal action_index
        if action_index >= len(actions):
            _reject("missing external byte action")
        item = actions[action_index]
        action_index += 1
        expected = {"kind", "bytes"} if kind == "alloc" else (
            {"kind", "index", "value"} if kind == "write" else {"kind", "index"})
        if set(item) != expected or item.get("kind") != kind:
            _reject("byte action kind or exact schema mismatch")
        return item

    for block_id in control["blocks_visited"]:
        block = blocks[block_id]
        for operation in block["ops"]:
            op = operation["op"]
            op_order.append(op)
            if op == "acquire":
                if operation["kind"] != "buffer":
                    _reject("fallible/foreign allocator outside finite profile")
                dest = operation["dest"]
                if type(dest) is not str or dest in owners:
                    _reject("invalid or overlapping new owner")
                req = next_action("alloc")
                size = req["bytes"]
                if (type(size) is not int or not 0 <= size <= 4096
                        or total_requested + size > 1024 * 1024):
                    _reject("unbounded or untyped allocation length")
                total_requested += size
                allocated += 1
                buffers[allocated] = bytearray(size)
                owners[dest] = allocated
                peak_live_bytes = max(peak_live_bytes, sum(map(len, buffers.values())))
                token += 1
                observations.append({"block": block_id, "kind": "alloc", "slot": dest,
                                     "allocation": allocated, "bytes": size, "memory_token": token})
            elif op == "move":
                src, dest = operation["src"], operation["dest"]
                if (type(src) is not str or type(dest) is not str or
                        src not in owners or dest in owners or
                        any(allocation == owners[src] for allocation, _ in loans.values())):
                    _reject("invalid owner transfer or outstanding loan")
                owners[dest] = owners.pop(src)
                observations.append({"block": block_id, "kind": "move",
                                     "src": src, "dest": dest, "memory_token": token})
            elif op == "borrow":
                identifier, place, mode = operation["id"], operation["place"], operation["mode"]
                root = place.get("root") if type(place) is dict else None
                if (type(identifier) is not str or identifier in loans or
                        type(root) is not str or place.get("path") != [] or
                        root not in owners or type(mode) is not str or
                        mode not in {"read", "mut"}):
                    _reject("borrow must refer to a live whole owned buffer")
                allocation = owners[root]
                if (mode == "mut" and any(key == allocation for key, _ in loans.values()) or
                        mode == "read" and any(key == allocation and own_mode == "mut"
                                               for key, own_mode in loans.values())):
                    _reject("conflicting alias to the same allocation")
                loans[identifier] = (allocation, mode)
                observations.append({"block": block_id, "kind": "borrow", "loan": identifier,
                                     "allocation": allocation, "mode": mode, "memory_token": token})
            elif op == "end_borrow":
                identifier = operation["id"]
                if type(identifier) is not str or identifier not in loans:
                    _reject("ending missing byte loan")
                loans.pop(identifier)
                observations.append({"block": block_id, "kind": "end_borrow",
                                     "loan": identifier, "memory_token": token})
            elif op == "use":
                mode = operation["mode"]
                place = operation.get("place")
                if type(mode) is not str:
                    _reject("byte access mode must be a string")
                if type(place) is dict:
                    root = place.get("root")
                    if type(root) is not str:
                        _reject("byte access place must have a string root")
                    if root in scalar_params:
                        if mode != "read" or place.get("path") != []:
                            _reject("boolean branch param must remain immutable")
                        continue
                if mode not in {"read", "write"}:
                    _reject("unsupported byte memory operation mode")
                if "loan" in operation:
                    loan_id = operation["loan"]
                    if type(loan_id) is not str or loan_id not in loans:
                        _reject("unknown byte loan")
                    allocation, permission = loans[loan_id]
                    if mode == "write" and permission != "mut":
                        _reject("shared loan cannot write")
                else:
                    # The verified Resource IR uses a single '*' projection
                    # for a Buffer<u8> element access. This byte oracle binds
                    # its concrete index to an EXTERNAL action, NOT to the
                    # checked source's scalar SSA. Nested projections reject.
                    if (type(place) is not dict or
                            place.get("path") not in ([], ["*"])):
                        _reject("only whole Buffer<u8> or one checked indexed element is modeled")
                    root = place.get("root")
                    if type(root) is not str or root not in owners:
                        _reject("memory access through missing owner")
                    allocation = owners[root]
                    if any(a == allocation for a, _ in loans.values()):
                        _reject("direct owner access conflicts with a live loan")
                access = next_action("write" if mode == "write" else "read")
                idx = access["index"]
                if type(idx) is not int or not 0 <= idx < len(buffers[allocation]):
                    _reject("untyped or out-of-bounds byte index")
                if mode == "write":
                    value = access["value"]
                    if type(value) is not int or not 0 <= value <= 255:
                        _reject("byte value must be an exact u8")
                    buffers[allocation][idx] = value
                    token += 1
                else:
                    value = buffers[allocation][idx]
                observations.append({"block": block_id, "kind": mode, "allocation": allocation,
                                     "index": idx, "value": value, "memory_token": token})
            elif op == "drop":
                src = operation["src"]
                if type(src) is not str or src not in owners:
                    _reject("drop of absent owner")
                allocation = owners.pop(src)
                if any(key == allocation for key, _ in loans.values()):
                    _reject("drop while loan remains")
                buffers.pop(allocation)
                freed += 1
                token += 1
                observations.append({"block": block_id, "kind": "drop", "slot": src,
                                     "allocation": allocation, "memory_token": token})
            else:
                _reject("unsupported Resource IR opcode in byte-value profile")
        live_bytes = sum(map(len, buffers.values()))
        peak_live_bytes = max(peak_live_bytes, live_bytes)
    if (action_index != len(actions) or owners or loans or buffers or
            allocated != freed or len(op_order) != len(control["resource_events"]) or
            any(a != b["op"] for a, b in zip(op_order, control["resource_events"]))):
        _reject("memory model and independently executed Resource IR disagree")
    payload = {
        "schema": "hepta.hia-byte-memory-trace.v0",
        "status": "finite_external_byte_actions_over_verified_resource_path",
        "resource_ir_sha256": control["resource_ir_sha256"],
        "boolean_trace_sha256": control["trace_sha256"],
        "function": function_name,
        "external_allocation_extents_and_memory_actions": True,
        "memory_token_final": token,
        "allocation_count": allocated,
        "free_count": freed,
        "peak_live_bytes": peak_live_bytes,
        "total_requested_bytes": total_requested,
        "memory_observations": observations,
        "claims": dict(_CLAIMS),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if len(encoded.encode("utf-8")) > 8 * 1024 * 1024:
        _reject("memory witness output exceeds budget")
    payload["trace_sha256"] = sha256(encoded.encode("utf-8")).hexdigest()
    return payload
