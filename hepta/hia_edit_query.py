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

from .hia_program import _ident, verify_program
from .hia_program_tools import (HIAEditRejected, PATCH_SCHEMA, apply_program_patch,
                                  bounded_json_wire, decode_json)

QUERY_SCHEMA = "hepta.hia.edit-query.v2"
FIELDS = frozenset({"op", "args", "attrs"})
MAX_RESPONSE_BYTES = 16 * 1024
MAX_QUERY_BYTES = 1024 * 1024
# Bound context shown to an Agent. Never silently truncate SSA descendants:
# an incomplete downstream slice is not safe to present as complete.
MAX_VISIBLE_OPERATIONS = 256
MAX_VISIBLE_BLOCKS = 64


def _reject(message):
    raise HIAEditRejected("E_HIA_QUERY: " + message)


def _wire(value):
    return bounded_json_wire(value, MAX_QUERY_BYTES)

def _display_atom(value, *, dotted=False):
    """Reuse canonical Core lexical identity for one Agent display atom."""
    if type(value) is not str or not value or len(value) > 128:
        _reject("invalid Agent display identity")
    for part in value.split(".") if dotted else (value,):
        _ident(part, "Agent display name")
    return value


def _cfg_edges(term):
    """Real verified HIA terminators, not guessed textual jump targets."""
    if term["op"] == "jump":
        return (term,)
    if term["op"] == "branch":
        return (term["then"], term["else"])
    return ()


def _terminator_inputs(term):
    """Every value named by a displayed terminator must have a definition."""
    if term["op"] == "ret":
        return list(term["values"])
    values = [term["cond"]] if term["op"] == "branch" else []
    return values + [arg for edge in _cfg_edges(term) for arg in edge["args"]]


def _cfg_downstream_slice(fn, source_block, affected, shown_count):
    """Bounded SSA uses and successors of value-affected branch conditions.

    A changed condition can select a different constant return or side effect
    without forwarding the condition as a block argument. Include every
    operation in both successor regions, even after reconvergence. This is a
    conservative reachability view, not a postdominator/control-dependence or
    memory-alias proof. Backedges to the selected block still require the
    full-module view. Downstream cycles reach a bounded monotone fixed point.
    """
    blocks = {block["id"]: block for block in fn["blocks"]}
    incoming = {}
    control_reachable = set()
    pending = deque()
    queued = set()

    def propagate(origin, flowing):
        controls = (origin["id"] in control_reachable or
                    origin["term"]["op"] == "branch" and
                    origin["term"]["cond"] in flowing)
        for edge in _cfg_edges(origin["term"]):
            destination = blocks[edge["target"]]
            forwarded = {formal["name"] for formal, actual
                         in zip(destination["params"], edge["args"])
                         if actual in flowing}
            if not forwarded and not controls:
                continue
            if destination["id"] == source_block["id"]:
                _reject("cross-block SSA cycle reaches selected block; use full-module view")
            observed = incoming.setdefault(destination["id"], set())
            if 1 + len(incoming) > MAX_VISIBLE_BLOCKS:
                _reject("transitive CFG view exceeds bounded block budget")
            fresh = forwarded - observed
            new_control = controls and destination["id"] not in control_reachable
            if fresh or new_control:
                observed.update(fresh)
                if controls:
                    control_reachable.add(destination["id"])
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
        # A control-reachable block can change behavior through operations
        # unrelated to the selected value, including no-result stores/drops.
        needed = (set(range(len(block["ops"]))) - consumer_indices
                  if ident in control_reachable else set())
        pending_inputs = (_terminator_inputs(block["term"]) +
                          [arg for i in consumer_indices | needed
                           for arg in block["ops"][i]["args"]])
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
            "control_reachable": ident in control_reachable,
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
    pending = (_terminator_inputs(node["term"]) +
               [arg for i in shown for arg in node["ops"][i]["args"]])
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
        "scope": ("explicit SSA slice with complete displayed terminator inputs and "
                  "full reachable regions of value-affected branches; precise "
                  "control-dependence, aliases and behavioral equivalence are NOT proved; "
                  "whole module is reverified"),
    }
    _wire(query)  # Prepared query must fit the same limit as render/apply.
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
    selector = query["selector"]
    if type(selector) is not dict or set(selector) != {"function", "block", "output"}:
        _reject("invalid rendered selector fields")
    if (type(query["fields"]) is not list or not query["fields"]
            or len(query["fields"]) > len(FIELDS)
            or any(type(x) is not str or x not in FIELDS for x in query["fields"])
            or len(set(query["fields"])) != len(query["fields"])):
        _reject("invalid rendered field selection")
    fn = context["function"]
    if _display_atom(selector["function"]) != _display_atom(fn["name"]):
        _reject("rendered function disagrees with selector")
    selected_name = _display_atom(selector["output"])
    if selected_name not in [_display_atom(v["name"]) for v in context["operation"]["out"]]:
        _reject("rendered SSA output disagrees with selector")
    params = ", ".join(_display_atom(v["name"]) + ":" + _display_atom(v["type"])
                       for v in fn["params"])
    lines = ["function " + _display_atom(fn["name"]) + "(" + params + ") -> "
             + ",".join(_display_atom(t) for t in fn["returns"])
             + " effects{" + ",".join(_display_atom(t) for t in fn["effects"]) + "}",
             "block " + _display_atom(selector["block"]) + "(" +
             ", ".join(_display_atom(v["name"]) + ":" + _display_atom(v["type"])
                       for v in context["block_params"]) + ")"]

    def line(op):
        out = ",".join("%" + _display_atom(value["name"]) + ":" +
                       _display_atom(value["type"]) for value in op["out"])
        args = ",".join("%" + _display_atom(name) for name in op["args"])
        attrs = " " + _wire(op["attrs"]).decode() if op["attrs"] else ""
        return (out + " = " if out else "") + _display_atom(op["op"], dotted=True) + "(" + args + ")" + attrs

    selected = context["operation_index"]
    if type(selected) is not int or selected < 0:
        _reject("rendered operation index must be a nonnegative integer")
    if type(context["dependencies"]) is not list or type(context["consumers"]) is not list:
        _reject("rendered SSA context lists are malformed")
    instructions = [*context["dependencies"], *context["consumers"],
                    {"index": selected, "operation": context["operation"]}]
    if len(instructions) > MAX_VISIBLE_OPERATIONS:
        _reject("rendered SSA operation budget exceeded")
    indices = [item["index"] for item in instructions]
    if (any(type(i) is not int or i < 0 for i in indices)
            or len(set(indices)) != len(indices)):
        _reject("duplicate or noninteger rendered SSA indexes")
    lines.extend(("EDIT " if item["index"] == selected else "") + line(item["operation"])
                 for item in sorted(instructions, key=lambda item: item["index"]))
    lines.append(_wire(context["terminator"]).decode())

    downstream = context.get("downstream")
    if type(downstream) is not list:
        _reject("missing verified CFG downstream presentation")
    if 1 + len(downstream) > MAX_VISIBLE_BLOCKS:
        _reject("rendered CFG context exceeds block budget")
    seen_blocks = set()
    visible_count = len(instructions)
    for successor in downstream:
        expected_fields = {"id", "params", "affected_params", "dependencies",
                           "consumers", "terminator", "branch_condition_affected",
                           "control_reachable"}
        if type(successor) is not dict or set(successor) != expected_fields:
            _reject("malformed downstream CFG block presentation")
        ident = _display_atom(successor["id"])
        if ident == selector["block"] or ident in seen_blocks:
            _reject("duplicate/selected downstream CFG block")
        seen_blocks.add(ident)
        if type(successor["params"]) is not list or type(successor["affected_params"]) is not list:
            _reject("invalid downstream SSA block parameters")
        params = successor["params"]
        if any(type(p) is not dict or set(p) != {"name", "type"} for p in params):
            _reject("invalid downstream typed SSA parameter")
        param_names = [_display_atom(p["name"]) for p in params]
        if len(set(param_names)) != len(param_names):
            _reject("duplicate downstream block parameter")
        param_text = ", ".join(_display_atom(p["name"]) + ":" + _display_atom(p["type"])
                               for p in params)
        affected = [_display_atom(p) for p in successor["affected_params"]]
        if type(successor["control_reachable"]) is not bool:
            _reject("invalid control-reachable CFG flag")
        if ((not affected and not successor["control_reachable"])
                or len(set(affected)) != len(affected)
                or any(name not in param_names for name in affected)):
            _reject("unbound downstream affected SSA parameter")
        deps, consumers = successor["dependencies"], successor["consumers"]
        if type(deps) is not list or type(consumers) is not list:
            _reject("invalid downstream SSA operation collections")
        entries = [*deps, *consumers]
        visible_count += len(entries)
        if visible_count > MAX_VISIBLE_OPERATIONS:
            _reject("rendered CFG context exceeds SSA operation budget")
        if any(type(item) is not dict or set(item) != {"index", "operation"}
               for item in entries):
            _reject("invalid downstream SSA operation record")
        positions = [item["index"] for item in entries]
        if (any(type(index) is not int or index < 0 for index in positions)
                or len(set(positions)) != len(positions)):
            _reject("duplicate or invalid downstream SSA operation index")
        if type(successor["branch_condition_affected"]) is not bool:
            _reject("invalid downstream branch-affect flag")
        if type(successor["terminator"]) is not dict:
            _reject("invalid downstream terminator")
        lines.append("downstream block " + ident + "(" + param_text + ") affected{" +
                     ",".join(affected) + "}")
        if successor["control_reachable"]:
            lines.append("affected-branch reachable region (all operations shown)")
        if successor["branch_condition_affected"]:
            if successor["terminator"].get("op") != "branch":
                _reject("non-branch CFG flagged as affected condition")
            lines.append("affected branch condition (control dependence unproved)")
        lines.extend(line(item["operation"])
                     for item in sorted(entries, key=lambda item: item["index"]))
        lines.append(_wire(successor["terminator"]).decode())
    for callee in context["callees"]:
        lines.append("callee " + _wire(callee).decode())
    return "\n".join(lines)
