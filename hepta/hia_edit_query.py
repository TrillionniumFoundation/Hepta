"""Small, snapshot-bound edit queries over the independently verified Core.

The query is an editing view, never another semantic authority.  A client may
omit immutable identifiers from a model prompt, but the host must retain the
complete query.  Applying a response reconstructs that exact query and uses the
ordinary whole-program patch verifier.  Neither context slicing nor a hash is
a proof of functional equivalence.
"""
from __future__ import annotations

import copy
from collections import deque
from hashlib import sha256
import json

from .hia_program import verify_program
from .hia_program_tools import (HIAEditRejected, PATCH_SCHEMA, apply_program_patch,
                                  bounded_json_wire, decode_json)

QUERY_SCHEMA = "hepta.hia.edit-query.v1"
FIELDS = frozenset({"op", "args", "attrs"})
MAX_RESPONSE_BYTES = 16 * 1024
MAX_QUERY_BYTES = 1024 * 1024
# Bound context shown to an Agent. Never silently truncate SSA descendants:
# an incomplete downstream slice is not safe to present as complete.
MAX_VISIBLE_OPERATIONS = 256


def _reject(message):
    raise HIAEditRejected("E_HIA_QUERY: " + message)


def _wire(value):
    return bounded_json_wire(value, MAX_QUERY_BYTES)


def _cfg_edges(term):
    """Real verified HIA terminators, not guessed textual jump targets."""
    if term["op"] == "jump":
        return (term,)
    if term["op"] == "branch":
        return (term["then"], term["else"])
    return ()


def _cfg_downstream_slice(fn, source_block, affected, shown_count):
    """Bounded transitive *explicit SSA value* uses across CFG block arguments.

    Canonical verify_program already admitted the complete function. This is
    presentation-only: the graph contains no inferred alias/hidden-effect or
    control-dependence proof. An affected backedge returning to the selected
    block refuses the compact view rather than implying loop closure.
    """
    blocks = {block["id"]: block for block in fn["blocks"]}
    incoming = {}
    pending = deque()
    queued = set()

    def propagate(origin, flowing):
        for edge in _cfg_edges(origin["term"]):
            destination = blocks[edge["target"]]
            forwarded = {formal["name"] for formal, actual
                         in zip(destination["params"], edge["args"])
                         if actual in flowing}
            if not forwarded:
                continue
            if destination["id"] == source_block["id"]:
                _reject("cross-block SSA cycle reaches selected block; use full-module view")
            observed = incoming.setdefault(destination["id"], set())
            fresh = forwarded - observed
            if fresh:
                observed.update(fresh)
                if destination["id"] not in queued:
                    pending.append(destination["id"])
                    queued.add(destination["id"])

    propagate(source_block, affected)
    while pending:
        ident = pending.popleft()
        queued.remove(ident)
        block = blocks[ident]
        flowing = set(incoming[ident])
        for ins in block["ops"]:
            if flowing.intersection(ins["args"]):
                flowing.update(out["name"] for out in ins["out"])
        propagate(block, flowing)

    result = []
    # The immutable program's declaration order, not a hash/set order,
    # determines visible block and instruction ordering.
    for block in fn["blocks"]:
        ident = block["id"]
        if ident not in incoming:
            continue
        flowing = set(incoming[ident])
        consumer_indices = set()
        for index, ins in enumerate(block["ops"]):
            if flowing.intersection(ins["args"]):
                consumer_indices.add(index)
                flowing.update(out["name"] for out in ins["out"])

        producers = {out["name"]: index
                     for index, ins in enumerate(block["ops"]) for out in ins["out"]}
        needed = set()
        pending_inputs = [arg for i in consumer_indices for arg in block["ops"][i]["args"]]
        while pending_inputs:
            value = pending_inputs.pop()
            producer = producers.get(value)
            if producer is not None and producer not in consumer_indices and producer not in needed:
                needed.add(producer)
                pending_inputs.extend(block["ops"][producer]["args"])
        shown_count += len(consumer_indices) + len(needed)
        if shown_count > MAX_VISIBLE_OPERATIONS:
            _reject("transitive SSA view exceeds bounded operation budget")
        result.append({
            "id": ident,
            "params": block["params"],
            "affected_params": sorted(incoming[ident]),
            "dependencies": [{"index": i, "operation": block["ops"][i]}
                             for i in sorted(needed)],
            "consumers": [{"index": i, "operation": block["ops"][i]}
                          for i in sorted(consumer_indices)],
            "terminator": block["term"],
            "branch_condition_affected": (block["term"]["op"] == "branch"
                                           and block["term"]["cond"] in flowing),
        })
    return result


def prepare_edit(document, *, function, block, output, fields):
    """Select a value-producing instruction by its SSA output, not text offsets."""
    original = verify_program(document)
    if (type(fields) not in (list, tuple) or not fields or len(fields) > len(FIELDS)
            or any(type(x) is not str or x not in FIELDS for x in fields)
            or len(set(fields)) != len(fields)):
        _reject("fields must be a unique nonempty subset of op, args, attrs")
    if any(type(x) is not str for x in (function, block, output)):
        _reject("function, block and output identities must be strings")
    data = original.as_dict()
    matches = [fn for fn in data["functions"] if fn["name"] == function]
    if len(matches) != 1:
        _reject("function not found")
    fn = matches[0]
    matches = [b for b in fn["blocks"] if b["id"] == block]
    if len(matches) != 1:
        _reject("block not found")
    node = matches[0]
    sites = [(index, op) for index, op in enumerate(node["ops"])
             if any(value["name"] == output for value in op["out"])]
    if len(sites) != 1:
        _reject("SSA output does not identify one instruction")
    index, operation = sites[0]
    outputs = {value["name"] for value in operation["out"]}
    # Capture the transitive *same-block* SSA dataflow use chain. A direct
    # consumer may feed a second, third, or later instruction that actually
    # determines the return value. The previous one-hop view exposed the
    # final terminator but omitted intermediate producers of its inputs.
    # All named SSA values are already checked and closed by verify_program.
    affected = set(outputs)
    consumers = []
    for i, op in enumerate(node["ops"][index + 1:], index + 1):
        if affected.intersection(op["args"]):
            consumers.append({"index": i, "operation": op})
            affected.update(value["name"] for value in op["out"])
    shown = {index, *(item["index"] for item in consumers)}
    producers = {value["name"]: i for i, op in enumerate(node["ops"])
                 for value in op["out"]}
    # Close every displayed instruction's inputs, including the consumer's
    # other operands. Their definitions may follow the selected instruction.
    needed = set()
    pending = [arg for i in shown for arg in node["ops"][i]["args"]]
    while pending:
        value = pending.pop()
        producer = producers.get(value)
        if producer is not None and producer not in shown and producer not in needed:
            needed.add(producer)
            pending.extend(node["ops"][producer]["args"])
    # Showing only the first N would misrepresent the real downstream graph.
    # Prefer explicit refusal so an Agent can switch to a full-module view.
    if len(shown) + len(needed) > MAX_VISIBLE_OPERATIONS:
        _reject("transitive SSA view exceeds bounded operation budget")
    downstream = _cfg_downstream_slice(fn, node, affected, len(shown) + len(needed))
    visible_ops = [operation, *(node["ops"][i] for i in needed),
                   *(item["operation"] for item in consumers)]
    for downstream_block in downstream:
        visible_ops.extend(item["operation"] for item in
                           [*downstream_block["dependencies"],
                            *downstream_block["consumers"]])
    calls = {op["attrs"]["function"] for op in visible_ops if op["op"] == "call"}
    query = {
        "schema": QUERY_SCHEMA,
        "base_sha256": original.sha256,
        "input_sha256": getattr(original, "input_sha256", original.sha256),
        "selector": {"function": function, "block": block, "output": output},
        "fields": sorted(fields),
        "operation_sha256": sha256(_wire(operation)).hexdigest(),
        "context": {
            "function": {key: fn[key] for key in ("name", "params", "returns", "effects")},
            "block_params": node["params"],
            "dependencies": [{"index": i, "operation": node["ops"][i]} for i in sorted(needed)],
            "operation_index": index,
            "operation": operation,
            "consumers": consumers,
            "downstream": downstream,
            "terminator": node["term"],
            "callees": [{key: other[key] for key in ("name", "params", "returns", "effects")}
                        for other in data["functions"] if other["name"] in calls],
        },
        "scope": ("single-instruction explicit SSA value slice (including CFG edges); "
                  "control-dependence, aliases and omitted code are NOT proved; "
                  "whole module is reverified"),
    }
    _wire(query)  # Prepare never emits a query that the apply/render gate cannot read.
    return copy.deepcopy(query)


def apply_edit(document, query, response):
    """Apply only selected fields, retaining immutable outputs and all context."""
    original = verify_program(document)
    if type(query) is not dict:
        _reject("query must be an exact prepare_edit result")
    selector = query.get("selector")
    if type(selector) is not dict or set(selector) != {"function", "block", "output"}:
        _reject("invalid query selector")
    reconstructed = prepare_edit(original, **selector, fields=query.get("fields"))
    try:
        exact = _wire(query) == _wire(reconstructed)
    except (TypeError, ValueError, RecursionError) as exc:
        raise HIAEditRejected("E_HIA_QUERY: query is not canonical JSON") from exc
    # Python container equality equates True with 1 and 1.0 with 1. The wire
    # snapshot must preserve those distinctions even for in-process callers.
    if not exact:
        _reject("stale or modified edit query")
    if type(response) in (str, bytes):
        raw = response.encode() if type(response) is str else response
        if len(raw) > MAX_RESPONSE_BYTES:
            _reject("response exceeds edit budget")
        response = decode_json(raw)
    else:
        raw = bounded_json_wire(response, MAX_RESPONSE_BYTES)
        response = decode_json(raw)
    if (type(response) is not dict or not response
            or not set(response).issubset(reconstructed["fields"])):
        _reject("response may replace only the selected instruction fields")
    candidate = copy.deepcopy(reconstructed["context"]["operation"])
    candidate.update(response)
    fn = next(fn for fn in original.as_dict()["functions"] if fn["name"] == selector["function"])
    block = next(b for b in fn["blocks"] if b["id"] == selector["block"])
    index = next(i for i, op in enumerate(block["ops"])
                 if any(value["name"] == selector["output"] for value in op["out"]))
    verified, receipt = apply_program_patch(original, {
        "schema": PATCH_SCHEMA, "expected_sha256": original.sha256,
        "edits": [{"action": "replace_operation", "function": selector["function"],
                   "block": selector["block"], "index": index, "operation": candidate}],
    })
    receipt["edit_query"] = {"schema": QUERY_SCHEMA, "selector": selector,
                             "query_sha256": sha256(_wire(reconstructed)).hexdigest(),
                             "response_bytes": len(raw), "response_sha256": sha256(raw).hexdigest(),
                             "context_reconstructed": True, "entire_module_reverified": True}
    return verified, receipt


def render_edit_context(query):
    """Fail closed on malformed, untrusted in-memory Agent presentation data."""
    try:
        return _render_edit_context_checked(query)
    except HIAEditRejected:
        raise
    except (KeyError, IndexError, TypeError, AttributeError, ValueError,
            UnicodeError, RecursionError) as exc:
        raise HIAEditRejected("E_HIA_QUERY: malformed edit presentation") from exc


def _render_edit_context_checked(query):
    """Deterministic display only; never a substitute for apply-time replay."""
    expected = {"schema", "base_sha256", "input_sha256", "selector", "fields",
                "operation_sha256", "context", "scope"}
    if type(query) is not dict or set(query) != expected or query.get("schema") != QUERY_SCHEMA:
        _reject("expected exact prepared edit query fields")
    _wire(query)  # Refuse unbounded forged display data before rendering.
    if type(query["context"]) is not dict or type(query["selector"]) is not dict:
        _reject("malformed edit context/selector")
    context = query["context"]
    fn = context["function"]
    params = ", ".join(v["name"] + ":" + v["type"] for v in fn["params"])
    lines = ["function " + fn["name"] + "(" + params + ") -> " + ",".join(fn["returns"])
             + " effects{" + ",".join(fn["effects"]) + "}",
             "block " + query["selector"]["block"] + "(" +
             ", ".join(v["name"] + ":" + v["type"] for v in context["block_params"]) + ")"]

    def line(op):
        out = ",".join("%" + value["name"] + ":" + value["type"] for value in op["out"])
        args = ",".join("%" + name for name in op["args"])
        attrs = " " + _wire(op["attrs"]).decode() if op["attrs"] else ""
        return (out + " = " if out else "") + op["op"] + "(" + args + ")" + attrs

    selected = context["operation_index"]
    instructions = [*context["dependencies"], *context["consumers"],
                    {"index": selected, "operation": context["operation"]}]
    lines.extend(("EDIT " if item["index"] == selected else "") + line(item["operation"])
                 for item in sorted(instructions, key=lambda item: item["index"]))
    lines.append(_wire(context["terminator"]).decode())
    for successor in context["downstream"]:
        lines.append("downstream block " + successor["id"] + "(" +
                     ", ".join(p["name"] + ":" + p["type"] for p in successor["params"]) +
                     ") affected{" + ",".join(successor["affected_params"]) + "}")
        if successor["branch_condition_affected"]:
            lines.append("affected branch condition (control dependence unproved)")
        entries = [*successor["dependencies"], *successor["consumers"]]
        lines.extend(line(item["operation"]) for item in
                     sorted(entries, key=lambda item: item["index"]))
        lines.append(_wire(successor["terminator"]).decode())
    for callee in context["callees"]:
        lines.append("callee " + _wire(callee).decode())
    return "\n".join(lines)
