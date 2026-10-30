"""Revision-bound node edits with no model-supplied files, paths or functions.

HIA admission delegates to the production whole-Core verifier. Rust proposals
are syntax-only until the trusted caller validates the whole candidate through
the finite source admission and real rustc. Neither query digests nor parsers
are proof of functional correctness.
"""
from __future__ import annotations

import copy
from hashlib import sha256
import re

from hepta.hia_edit_batch import prepare_batch, apply_batch
from hepta.hia_program import verify_program
from hepta.hia_program_tools import apply_program_patch, bounded_json_wire, decode_json, function_signature
from experiments.hia_agent_structured_v7_20261029.rust_syntax import parse_function, parsed_signature, validate_fragment

SCHEMA = "hepta.agent.structured-query.v1"
RESPONSE_SCHEMA = "hepta.agent.structured-response.v1"
PROFILE = "finite-node-editing.v1"
MAX_RESPONSE_BYTES = 65536
MAX_QUERY_BYTES = 1024 * 1024
MAX_EDITS = 16
MAX_NODES = 1024
MAX_INSERTED_OPERATIONS = 16


class EditRejected(ValueError):
    pass


def reject(message):
    raise EditRejected("E_STRUCTURED_EDIT: " + message)


def wire(value, maximum=MAX_QUERY_BYTES):
    return bounded_json_wire(value, maximum, ensure_ascii=True, sort_keys=True)


def digest(value):
    return sha256(wire(value)).hexdigest()


def response_digest(value):
    raw = value.encode() if type(value) is str else value if type(value) is bytes else wire(value, MAX_RESPONSE_BYTES)
    return sha256(raw).hexdigest()


def snapshot_files(files):
    if type(files) is not dict or not 1 <= len(files) <= 16:
        reject("bounded file map required")
    snapshot = dict(files)
    for name, text in snapshot.items():
        if (type(name) is not str or re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*\.rs", name) is None
                or type(text) is not str or not text.isascii() or len(text) > 16384):
            reject("ordinary named ASCII Rust source files required")
    return snapshot


def seal(query):
    if len(query["nodes"]) > MAX_NODES:
        reject("query node budget")
    query["query_sha256"] = digest(query)
    wire(query)
    return copy.deepcopy(query)


def response_for(query, edits):
    """For a caller/model transport to attach only immutable query identities."""
    return {"schema": RESPONSE_SCHEMA, "base_sha256": query["base_sha256"],
            "query_sha256": query["query_sha256"], "edits": copy.deepcopy(edits)}


def checked_edits(expected, supplied_query, response):
    # Reconstruct from the actual captured source and trusted host edit scope.
    # A model cannot grant itself authority by altering a supplied query/hash.
    if wire(expected) != wire(supplied_query):
        reject("stale or altered complete query")
    if type(response) in (str, bytes):
        raw = response.encode() if type(response) is str else response
        if len(raw) > MAX_RESPONSE_BYTES:
            reject("response byte budget")
        response = decode_json(raw)
    else:
        response = decode_json(wire(response, MAX_RESPONSE_BYTES))
    if type(response) is not dict or set(response) != {"schema", "base_sha256", "query_sha256", "edits"}:
        reject("exact revision-bound response envelope required")
    if response["schema"] != RESPONSE_SCHEMA or any(response[key] != expected[key] for key in ("base_sha256", "query_sha256")):
        reject("stale response revision or query digest")
    edits = response["edits"]
    if type(edits) is not list or not 1 <= len(edits) <= MAX_EDITS:
        reject("one to sixteen edits required")
    catalogue = {item["id"]: item for item in expected["nodes"]}
    used = set()
    result = []
    for edit in edits:
        if type(edit) is not dict or set(edit) != {"node", "changes"}:
            reject("node edits require exactly node and changes")
        ident, changes = edit["node"], edit["changes"]
        if type(ident) is not str or ident not in catalogue:
            reject("unknown or unauthorized node; select an ID from the captured public catalogue")
        if ident in used:
            reject("duplicate node " + repr(ident) + "; supply its changes once in the complete transaction")
        node = catalogue[ident]
        if type(changes) is not dict or not changes or not set(changes).issubset(node["fields"]):
            received = sorted(changes) if type(changes) is dict else type(changes).__name__
            reject("changes exceed the selected node fields: node=" + repr(ident)
                   + "; received=" + repr(received) + "; allowed=" + repr(node["fields"])
                   + ("; this node is read-only" if not node["fields"]
                      else "; changes must be a nonempty object containing only these fields"))
        used.add(ident)
        result.append((copy.deepcopy(node), copy.deepcopy(changes)))
    return result


def prepare_rust(files, editable_symbols, *, interface_policy="preserve"):
    source = snapshot_files(files)
    if type(interface_policy) is not str or interface_policy not in {"preserve", "migrate"}:
        reject("trusted explicit interface policy required")
    if type(editable_symbols) is not dict or not editable_symbols or not set(editable_symbols).issubset(source):
        reject("trusted editable symbol map required")
    nodes = []
    for name in sorted(editable_symbols):
        symbol, parsed = parse_function(source[name])
        if type(editable_symbols[name]) is not str or symbol != editable_symbols[name]:
            reject("editable symbol differs from parsed source")
        for index, node in enumerate(parsed):
            fields = [] if interface_policy == "preserve" and node.get("role") in {"parameter_type", "return_type"} else ["text"]
            nodes.append({"id": name + "/" + symbol + "/n" + str(index), "file": name, "symbol": symbol,
                          **node, "fields": fields, "text": source[name][node["start"]:node["end"]]})
    return seal({"schema": SCHEMA, "language": "rust", "profile": PROFILE,
                 "base_sha256": digest(source), "files": {name: sha256(text.encode()).hexdigest() for name,text in sorted(source.items())},
                 "editable_symbols": dict(sorted(editable_symbols.items())), "nodes": nodes, "interface_policy": interface_policy,
                 "scope": "expression/type fragments only; unchanged bytes outside selected spans retained; whole-candidate admission and real rustc required"})


def propose_rust(files, query, response, *, editable_symbols, interface_policy="preserve"):
    source = snapshot_files(files)
    expected = prepare_rust(source, editable_symbols, interface_policy=interface_policy)
    edits = checked_edits(expected, query, response)
    replacements = {}
    for node, changes in edits:
        if set(changes) != {"text"} or type(changes["text"]) is not str:
            reject("a Rust node requires one replacement text fragment")
        validate_fragment(changes["text"], node["category"])
        replacements.setdefault(node["file"], []).append((node["start"], node["end"], changes["text"]))
    for name, spans in replacements.items():
        spans.sort()
        if any(left[1] > right[0] for left,right in zip(spans, spans[1:])):
            reject("overlapping ancestor/descendant Rust nodes")
    candidate = dict(source)
    for name, spans in replacements.items():
        for start,end,text in reversed(spans):
            candidate[name] = candidate[name][:start] + text + candidate[name][end:]
        symbol, new_nodes = parse_function(candidate[name])
        if symbol != editable_symbols[name]:
            reject("whole-candidate parsed symbol changed")
        if interface_policy == "preserve" and parsed_signature(candidate[name]) != parsed_signature(source[name]):
            reject("whole-candidate interface changed without migration authority")
        _, old_nodes = parse_function(source[name])
        def moved(position):
            return position + sum(len(text) - (end-start) for start,end,text in spans if end <= position)
        actual = {(n["start"], n["end"], n["category"], n["shape"], n["anchor"]) for n in new_nodes}
        for old in old_nodes:
            if any(start <= old["start"] and old["end"] <= end for start,end,_ in spans):
                continue  # Only selected AST subtrees may change structure.
            retained = (moved(old["start"]), moved(old["end"]), old["category"], old["shape"], moved(old["anchor"]))
            if retained not in actual:
                reject("replacement changes enclosing or unselected Rust syntax; use explicit grouping")
    receipt = {"schema": "hepta.agent.structured-edit-result.v1", "language": "rust",
               "before_sha256": expected["base_sha256"], "after_sha256": digest(candidate),
               "query_sha256": expected["query_sha256"], "response_sha256": response_digest(response),
               "node_edits": len(edits), "whole_functions_supplied_by_model": 0,
               "changed_files": sorted(replacements), "source_published": False,
               "status": "syntax_proposal_unadmitted", "type_or_ownership_admitted": False,
               "unselected_ast_context_preserved": True,
               "functional_correctness_proved": False}
    return candidate, receipt


def prepare_hia(document, editable_functions, *, interface_policy="preserve"):
    original = verify_program(document)
    data = original.as_dict()
    if (type(editable_functions) not in (list, tuple) or not editable_functions
            or any(type(n) is not str for n in editable_functions)
            or len(set(editable_functions)) != len(editable_functions)
            or interface_policy not in {"preserve", "migrate"}):
        reject("trusted editable function scope and interface policy required")
    present = {f["name"] for f in data["functions"]}
    if not set(editable_functions).issubset(present):
        reject("unknown editable function")
    nodes = []
    for function in data["functions"]:
        name = function["name"]
        if name not in editable_functions:
            continue
        nodes.append({"id": name + "/signature", "kind": "signature", "function": name,
                      "fields": ["params", "returns"] if interface_policy == "migrate" else [],
                      "params": function["params"], "returns": function["returns"]})
        for block in function["blocks"]:
            prefix = name + "/" + block["id"] + "/"
            common = {"function": name, "block": block["id"]}
            nodes.append({"id": prefix + "parameters", "kind": "block_parameters", **common,
                          "fields": ["params"], "params": block["params"]})
            for index, operation in enumerate(block["ops"]):
                nodes.append({"id": prefix + "instruction" + str(index), "kind": "operation", **common,
                              "index": index, "fields": ["op", "args", "out", "attrs", "delete"], "operation": operation})
            for index in range(len(block["ops"]) + 1):
                nodes.append({"id": prefix + "insert" + str(index), "kind": "insert", **common,
                              "index": index, "fields": ["operations"]})
            nodes.append({"id": prefix + "terminator", "kind": "terminator", **common,
                          "fields": ["term"], "term": block["term"]})
    return seal({"schema": SCHEMA, "language": "hia", "profile": PROFILE,
                 "base_sha256": original.sha256, "input_sha256": getattr(original, "input_sha256", original.sha256),
                 "editable_functions": sorted(editable_functions), "interface_policy": interface_policy,
                 "signatures": [function_signature(f, include_return_loans=True) for f in data["functions"]],
                 "nodes": nodes,
                 "scope": "selected instruction/terminator/signature fields only; production verifier checks the whole module atomically"})


def _same_parameter_identity(before, after):
    if (type(after) is not list or len(after) != len(before)
            or any(type(p) is not dict or set(p) != {"name", "type"} or type(p["type"]) is not str for p in after)
            or [p["name"] for p in before] != [p["name"] for p in after]):
        reject("parameter edits may change types, not identity or arity")


def apply_hia(document, query, response, *, editable_functions, interface_policy="preserve"):
    original = verify_program(document)
    expected = prepare_hia(original, editable_functions, interface_policy=interface_policy)
    edits = checked_edits(expected, query, response)
    original_data = original.as_dict()
    candidate = copy.deepcopy(original_data)
    by_function = {f["name"]: f for f in candidate["functions"]}
    rebuilt = set()
    instructions, insertions, deletions = {}, {}, set()
    local_patch = []
    fast_selections, fast_edits = [], []
    inserted = 0
    fast = True
    for node, changes in edits:
        name = node["function"]
        fn = by_function[name]
        if node["kind"] == "signature":
            if interface_policy != "migrate":
                reject("signature edits require trusted explicit migration policy")
            if "params" in changes:
                _same_parameter_identity(fn["params"], changes["params"])
            if "returns" in changes and (type(changes["returns"]) is not list or len(changes["returns"]) != len(fn["returns"])):
                reject("return type edits must retain arity")
            fn.update(changes); rebuilt.add(name); fast = False
            continue
        block = next(b for b in fn["blocks"] if b["id"] == node["block"])
        if node["kind"] == "block_parameters":
            _same_parameter_identity(block["params"], changes["params"])
            block["params"] = changes["params"]; rebuilt.add(name); fast = False
        elif node["kind"] == "insert":
            operations = changes.get("operations")
            if type(operations) is not list or not operations:
                reject("insert requires a nonempty instruction list")
            inserted += len(operations)
            if inserted > MAX_INSERTED_OPERATIONS:
                reject("inserted instruction budget")
            insertions[(name, node["block"], node["index"])] = operations
            rebuilt.add(name); fast = False
        elif node["kind"] == "terminator":
            block["term"] = changes["term"]
            local_patch.append({"action": "replace_terminator", "function": name, "block": node["block"], "term": changes["term"]})
            fast = False
        elif node["kind"] == "operation":
            key = (name, node["block"], node["index"])
            if "delete" in changes:
                if changes != {"delete": True}:
                    reject("delete cannot be mixed with instruction replacements")
                deletions.add(key); rebuilt.add(name); fast = False
                continue
            operation = copy.deepcopy(node["operation"]); operation.update(changes)
            instructions[key] = operation
            local_patch.append({"action": "replace_operation", "function": name, "block": node["block"], "index": node["index"], "operation": operation})
            if set(changes).issubset({"op", "args", "attrs"}) and node["operation"]["out"]:
                fast_selections.append({"function": name, "block": node["block"], "output": node["operation"]["out"][0]["name"], "fields": sorted(changes)})
                fast_edits.append({"site": len(fast_edits), "changes": changes})
            else:
                fast = False
    for fn in candidate["functions"]:
        for block in fn["blocks"]:
            rebuilt_ops = []
            for index, operation in enumerate(block["ops"]):
                key = (fn["name"], block["id"], index)
                rebuilt_ops.extend(insertions.get(key, []))
                if key not in deletions:
                    rebuilt_ops.append(instructions.get(key, operation))
            rebuilt_ops.extend(insertions.get((fn["name"], block["id"], len(block["ops"])), []))
            block["ops"] = rebuilt_ops
    if fast:
        production_query = prepare_batch(original, fast_selections)
        verified, receipt = apply_batch(original, production_query, {"edits": fast_edits})
        backend = "production_apply_batch"
    else:
        patch = [p for p in local_patch if p["function"] not in rebuilt]
        patch.extend({"action": "replace_function", "function": name, "definition": by_function[name]} for name in sorted(rebuilt))
        verified, receipt = apply_program_patch(original, {"schema": "hepta.hia.patch.v2", "expected_sha256": original.sha256,
                                                         "interface_policy": interface_policy, "edits": patch})
        backend = "production_apply_program_patch"
    receipt["structured_editor"] = {"profile": PROFILE, "query_sha256": expected["query_sha256"],
                                   "response_sha256": response_digest(response), "node_edits": len(edits),
                                   "whole_functions_supplied_by_model": 0, "backend": backend,
                                   "container_rebuilt_functions": sorted(rebuilt),
                                   "container_rebuild_reason": "production patch has no granular signature/block-parameter/insert/delete primitive; exact selected node changes only",
                                   "intermediate_candidates_admitted": False, "source_published": False}
    return verified, receipt
