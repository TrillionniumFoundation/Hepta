"""Snapshot-bound simultaneous editing of several HIA instructions.

An atomic batch can repair mutually dependent resource uses without admitting
an invalid intermediate program.  Sites grant only field-level edits; the
ordinary patch verifier checks the whole result once.  Contexts and digests
are editing aids, never proofs of behavior or authority to skip verification.
"""
from __future__ import annotations

import copy
import json
from hashlib import sha256

from .hia_edit_query import prepare_edit
from .hia_program import verify_program
from .hia_program_tools import (HIAEditRejected, PATCH_SCHEMA, apply_program_patch,
                                  bounded_json_wire, decode_json)

QUERY_SCHEMA = "hepta.hia.edit-batch-query.v1"
MAX_SITES = 16
MAX_QUERY_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 64 * 1024


def _reject(message):
    raise HIAEditRejected("E_HIA_EDIT_BATCH: " + message)


def _wire(value):
    return bounded_json_wire(value, MAX_QUERY_BYTES)


def _bounded(value, maximum, label):
    try:
        raw = (value.encode() if type(value) is str else value
               if type(value) is bytes else bounded_json_wire(value, maximum))
    except (TypeError, ValueError, RecursionError) as exc:
        raise HIAEditRejected("E_HIA_EDIT_BATCH: invalid " + label) from exc
    if len(raw) > maximum:
        _reject(label + " exceeds byte budget")
    return decode_json(raw), raw


def prepare_batch(document, selections):
    """Bind ordered, nonoverlapping SSA sites to one immutable input snapshot."""
    original = verify_program(document)
    if type(selections) is not list or not 1 <= len(selections) <= MAX_SITES:
        _reject("a batch requires 1..16 selections")
    sites, seen = [], set()
    for selection in selections:
        if type(selection) is not dict or set(selection) != {"function", "block", "output", "fields"}:
            _reject("a selection requires exactly function, block, output, fields")
        query = prepare_edit(original, **selection)
        # Two outputs of one multi-result instruction are still one site.
        key = (selection["function"], selection["block"], query["context"]["operation_index"])
        if key in seen:
            _reject("selections overlap one instruction")
        seen.add(key)
        sites.append({"site": len(sites), "query": query})
    result = {"schema": QUERY_SCHEMA, "base_sha256": original.sha256,
              "input_sha256": getattr(original, "input_sha256", original.sha256),
              "sites": sites, "application": "simultaneous_preserving_interfaces",
              "scope": "selected fields only; whole module reverified after all replacements"}
    if len(_wire(result)) > MAX_QUERY_BYTES:
        _reject("combined query exceeds byte budget")
    return copy.deepcopy(result)


def apply_batch(document, query, response):
    """Apply every selected site or reject the entire batch without publication."""
    original = verify_program(document)
    query, query_bytes = _bounded(query, MAX_QUERY_BYTES, "query")
    if type(query) is not dict or query.get("schema") != QUERY_SCHEMA:
        _reject("expected an exact prepared batch query")
    sites = query.get("sites")
    if type(sites) is not list or not 1 <= len(sites) <= MAX_SITES:
        _reject("invalid query sites")
    selections = []
    for index, item in enumerate(sites):
        if (type(item) is not dict or set(item) != {"site", "query"}
                or type(item["site"]) is not int or item["site"] != index
                or type(item["query"]) is not dict):
            _reject("query sites must retain their exact ordered identities")
        nested = item["query"]
        selector = nested.get("selector")
        if type(selector) is not dict or set(selector) != {"function", "block", "output"}:
            _reject("invalid nested selection")
        selections.append({**selector, "fields": nested.get("fields")})
    # Every later phase must use the same captured immutable input. Reading
    # the caller's mutable dict again could bind query B but apply to snapshot A.
    reconstructed = prepare_batch(original, selections)
    if _wire(query) != _wire(reconstructed):
        _reject("stale or altered batch query")
    response, response_bytes = _bounded(response, MAX_RESPONSE_BYTES, "response")
    if type(response) is not dict or set(response) != {"edits"}:
        _reject("response requires exactly edits")
    edits = response["edits"]
    if type(edits) is not list or len(edits) != len(sites):
        _reject("every selected site must occur exactly once")
    replacements, seen = [], set()
    for item in edits:
        if type(item) is not dict or set(item) != {"site", "changes"}:
            _reject("an edit requires exactly site and changes")
        index, changes = item["site"], item["changes"]
        if type(index) is not int or not 0 <= index < len(sites) or index in seen:
            _reject("duplicate or invalid site")
        seen.add(index)
        nested = reconstructed["sites"][index]["query"]
        if type(changes) is not dict or not changes or not set(changes).issubset(nested["fields"]):
            _reject("changes exceed selected fields")
        operation = copy.deepcopy(nested["context"]["operation"])
        operation.update(changes)
        selector = nested["selector"]
        replacements.append({"action": "replace_operation", "function": selector["function"],
                             "block": selector["block"], "index": nested["context"]["operation_index"],
                             "operation": operation})
    verified, receipt = apply_program_patch(original, {
        "schema": PATCH_SCHEMA, "expected_sha256": original.sha256, "edits": replacements})
    receipt["edit_batch"] = {"schema": QUERY_SCHEMA, "sites": len(sites),
                             "query_sha256": sha256(_wire(reconstructed)).hexdigest(),
                             "response_sha256": sha256(response_bytes).hexdigest(),
                             "response_bytes": len(response_bytes),
                             "intermediate_candidates_admitted": False,
                             "entire_module_reverified": True}
    return verified, receipt


def render_batch_context(query):
    """Fail closed on malformed, untrusted batch presentation data."""
    try:
        return _render_batch_context_checked(query)
    except HIAEditRejected:
        raise
    except (KeyError, IndexError, TypeError, AttributeError, ValueError,
            UnicodeError, RecursionError) as exc:
        raise HIAEditRejected("E_HIA_EDIT_BATCH: malformed batch presentation") from exc


def _render_batch_context_checked(query):
    """Deduplicate dependency views while retaining original SSA order."""
    query, _ = _bounded(query, MAX_QUERY_BYTES, "query")
    expected = {"schema", "base_sha256", "input_sha256", "sites", "application", "scope"}
    if type(query) is not dict or set(query) != expected or query.get("schema") != QUERY_SCHEMA:
        _reject("expected exact prepared batch query fields")
    functions, blocks = {}, {}
    sites = query["sites"]
    if type(sites) is not list or not 1 <= len(sites) <= MAX_SITES:
        _reject("invalid query sites")
    nested_fields = {"schema", "base_sha256", "input_sha256", "selector", "fields",
                     "operation_sha256", "context", "scope"}
    for index, item in enumerate(sites):
        if (type(item) is not dict or set(item) != {"site", "query"}
                or type(item["site"]) is not int or item["site"] != index):
            _reject("batch display sites must retain unique ordered integer identities")
        nested = item["query"]
        if (type(nested) is not dict or set(nested) != nested_fields
                or nested.get("schema") != "hepta.hia.edit-query.v1"):
            _reject("invalid nested edit query presentation")
        if type(nested["context"]) is not dict or type(nested["selector"]) is not dict:
            _reject("invalid nested edit context/selector")
        context, selector = nested["context"], nested["selector"]
        functions[selector["function"]] = context["function"]
        key = (selector["function"], selector["block"])
        block = blocks.setdefault(key, {"params": context["block_params"], "ops": {}, "edits": {},
                                        "term": context["terminator"], "callees": {}})
        operations = [*context["dependencies"], *context["consumers"],
                      {"index": context["operation_index"], "operation": context["operation"]}]
        for entry in operations:
            previous = block["ops"].get(entry["index"])
            if previous is not None and _wire(previous) != _wire(entry["operation"]):
                _reject("conflicting displayed operations")
            block["ops"][entry["index"]] = entry["operation"]
        block["edits"][context["operation_index"]] = (item["site"], nested["fields"])
        block["callees"].update({fn["name"]: fn for fn in context["callees"]})
        # Downstream explicit SSA uses may be displayed by several edit
        # selections. Deduplicate by immutable function/block/op identities,
        # just as same-block producers/consumers are deduplicated above.
        for successor in context["downstream"]:
            successor_key = (selector["function"], successor["id"])
            successor_block = blocks.setdefault(successor_key, {
                "params": successor["params"], "ops": {}, "edits": {},
                "term": successor["terminator"], "callees": {},
                "affected_params": set(),
            })
            if (_wire(successor_block["params"]) != _wire(successor["params"])
                    or _wire(successor_block["term"]) != _wire(successor["terminator"])):
                _reject("conflicting downstream CFG presentation")
            successor_block.setdefault("affected_params", set()).update(
                successor["affected_params"])
            for occurrence in [*successor["dependencies"], *successor["consumers"]]:
                old = successor_block["ops"].get(occurrence["index"])
                if old is not None and _wire(old) != _wire(occurrence["operation"]):
                    _reject("conflicting downstream SSA operation")
                successor_block["ops"][occurrence["index"]] = occurrence["operation"]
    lines = []
    for name, fn in functions.items():
        params = ",".join(v["name"] + ":" + v["type"] for v in fn["params"])
        lines.append("fn " + name + "(" + params + ")->" + ",".join(fn["returns"])
                     + " effects{" + ",".join(fn["effects"]) + "}")
        for (function, label), block in blocks.items():
            if function != name:
                continue
            lines.append("block " + label + "(" + ",".join(v["name"] + ":" + v["type"]
                                                           for v in block["params"]) + ")")
            if block.get("affected_params"):
                lines.append("affected CFG inputs{" +
                             ",".join(sorted(block["affected_params"])) + "}")
            for index, op in sorted(block["ops"].items()):
                prefix = ""
                if index in block["edits"]:
                    ident, fields = block["edits"][index]
                    prefix = "@" + str(ident) + "{" + ",".join(fields) + "} "
                outputs = ",".join("%" + v["name"] + ":" + v["type"] for v in op["out"])
                args = ",".join("%" + v for v in op["args"])
                attrs = " " + _wire(op["attrs"]).decode() if op["attrs"] else ""
                lines.append(prefix + (outputs + "=" if outputs else "") + op["op"] + "(" + args + ")" + attrs)
            lines.append(_wire(block["term"]).decode())
            lines.extend("callee " + _wire(fn).decode() for fn in block["callees"].values())
    return "\n".join(lines)
