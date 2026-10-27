"""Small, snapshot-bound edit queries over the independently verified Core.

The query is an editing view, never another semantic authority.  A client may
omit immutable identifiers from a model prompt, but the host must retain the
complete query.  Applying a response reconstructs that exact query and uses the
ordinary whole-program patch verifier.  Neither context slicing nor a hash is
a proof of functional equivalence.
"""
from __future__ import annotations

import copy
from hashlib import sha256
import json

from .hia_program import verify_program
from .hia_program_tools import HIAEditRejected, PATCH_SCHEMA, apply_program_patch, decode_json

QUERY_SCHEMA = "hepta.hia.edit-query.v1"
FIELDS = frozenset({"op", "args", "attrs"})
MAX_RESPONSE_BYTES = 16 * 1024


def _reject(message):
    raise HIAEditRejected("E_HIA_QUERY: " + message)


def _wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


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
    consumers = [{"index": i, "operation": op}
                 for i, op in enumerate(node["ops"][index + 1:], index + 1)
                 if outputs.intersection(op["args"])]
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
    calls = {op["attrs"]["function"] for op in [operation, *(node["ops"][i] for i in needed),
                                               *(item["operation"] for item in consumers)]
             if op["op"] == "call"}
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
            "terminator": node["term"],
            "callees": [{key: other[key] for key in ("name", "params", "returns", "effects")}
                        for other in data["functions"] if other["name"] in calls],
        },
        "scope": "single-instruction view; omitted code is still reverified before admission",
    }
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
        try:
            raw = _wire(response)
        except (TypeError, ValueError, RecursionError) as exc:
            raise HIAEditRejected("E_HIA_QUERY: response is not bounded JSON") from exc
        if len(raw) > MAX_RESPONSE_BYTES:
            _reject("response exceeds edit budget")
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
    """Deterministic compact editing view; it does not define executable syntax."""
    if type(query) is not dict or query.get("schema") != QUERY_SCHEMA:
        _reject("expected a prepared edit query")
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
    for callee in context["callees"]:
        lines.append("callee " + _wire(callee).decode())
    return "\n".join(lines)
