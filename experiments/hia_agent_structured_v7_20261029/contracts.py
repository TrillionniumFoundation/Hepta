"""Response syntax derived only from the complete public editable catalogue.

This is a decoding aid, never an admission authority. It deliberately leaves
replacement values open. Revision, unique/disjoint edits, syntax, type, owner,
resource, compiler and behavior checks still run on every whole candidate.
No task, reference, example, hidden case or selected-answer import belongs here.
"""
from __future__ import annotations

import copy

from experiments.hia_agent_structured_v7_20261029 import editing

PROFILE = "public-node-catalogue-decoder.v1"
TASK_QUERY_SCHEMA = "hepta.agent.structured-task-query.v1"


def _sealed(value, schema):
    if type(value) is not dict or value.get("schema") != schema:
        raise ValueError("E_NODE_CONTRACT_QUERY_SCHEMA")
    unsigned = {key: item for key, item in value.items() if key != "query_sha256"}
    if value.get("query_sha256") != editing.digest(unsigned):
        raise ValueError("E_NODE_CONTRACT_QUERY_DIGEST")


def _object(properties, required=()):
    return {"type": "object", "properties": properties, "required": list(required),
            "additionalProperties": False}


def response_schema(query):
    """Enumerate EVERY editable ID/field; never pick nodes or replacement values."""
    _sealed(query, TASK_QUERY_SCHEMA)
    inner = query.get("edit_query")
    _sealed(inner, editing.SCHEMA)
    language = query.get("language")
    if language not in {"hia", "rust"} or inner.get("language") != language:
        raise ValueError("E_NODE_CONTRACT_LANGUAGE")
    nodes = inner.get("nodes")
    if type(nodes) is not list or not 1 <= len(nodes) <= editing.MAX_NODES:
        raise ValueError("E_NODE_CONTRACT_NODE_BUDGET")
    groups, seen = {}, set()
    for node in nodes:
        if (type(node) is not dict or type(node.get("id")) is not str
                or node["id"] in seen or type(node.get("fields")) is not list
                or any(type(field) is not str for field in node["fields"])
                or len(set(node["fields"])) != len(node["fields"])):
            raise ValueError("E_NODE_CONTRACT_CATALOGUE")
        seen.add(node["id"])
        fields = tuple(sorted(node["fields"]))
        if fields:
            groups.setdefault(fields, []).append(node["id"])
    if not groups:
        raise ValueError("E_NODE_CONTRACT_NO_EDITABLE_NODES")
    text = {"type": "string"}
    strings = {"type": "array", "items": text}
    parameter = _object({"name": text, "type": text}, ("name", "type"))
    parameters = {"type": "array", "items": parameter}
    operation = _object({"op": text, "args": strings, "out": parameters,
                         "attrs": {"type": "object"}}, ("op", "args", "out", "attrs"))
    field_types = {"text": text} if language == "rust" else {
        "params": parameters, "returns": strings, "op": text, "args": strings,
        "out": parameters, "attrs": {"type": "object"}, "delete": {"const": True},
        "operations": {"type": "array", "minItems": 1,
                       "maxItems": editing.MAX_INSERTED_OPERATIONS, "items": operation},
        "term": {"type": "object"},
    }
    variants = []
    for fields, ids in sorted(groups.items()):
        if any(field not in field_types for field in fields):
            raise ValueError("E_NODE_CONTRACT_UNKNOWN_PUBLIC_FIELD")
        properties = {field: copy.deepcopy(field_types[field]) for field in fields}
        if language == "rust":
            if fields != ("text",):
                raise ValueError("E_NODE_CONTRACT_RUST_FIELDS")
            changes = _object(properties, ("text",))
        else:
            # oneOf alone would reject valid edits containing several fields.
            # anyOf requires at least one public field, without picking which.
            # Each arm is a complete object schema: grammar compilers need not
            # implement intersections between outer properties and anyOf.
            changes = {"anyOf": [_object(copy.deepcopy(properties), (field,))
                                 for field in fields]}
        variants.append(_object({"node": {"enum": sorted(ids)}, "changes": changes},
                                ("node", "changes")))
    items = variants[0] if len(variants) == 1 else {"oneOf": variants}
    return _object({"edits": {"type": "array", "minItems": 1,
                              "maxItems": editing.MAX_EDITS, "items": items}}, ("edits",))


def binding(query):
    schema = response_schema(query)
    nodes = query["edit_query"]["nodes"]
    return {"profile": PROFILE, "query_sha256": query["query_sha256"],
            "source_revision": query["source_revision"], "schema_sha256": editing.digest(schema),
            "catalogue_nodes": len(nodes), "editable_nodes": sum(bool(n["fields"]) for n in nodes),
            "answer_values_embedded": False, "selected_answer_nodes_embedded": False,
            "all_public_editable_nodes_included": True, "admission_authority": False}
