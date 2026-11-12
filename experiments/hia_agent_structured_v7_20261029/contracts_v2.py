"""Public category-aware node syntax with selection before replacement.

Only complete public queries and the already disclosed finite language grammar
are inputs. This module does not import tasks, correct answers or hidden cases.
Expression strings and HIA values remain untrusted and require whole admission.
"""
from __future__ import annotations

import copy
import hashlib
import json

from experiments.hia_agent_structured_v7_20261029 import contracts, editing
from experiments.hia_agent_structured_v7_20261029.rust_syntax import SCALARS

PROFILE = "public-node-category-selection-first.v2"
PUBLIC_RUST_TYPES = tuple(sorted([*SCALARS, "Vec<u8>"]))


def ordered_wire(value):
    """Schema order is a wire contract, separate from canonical value identity."""
    return json.dumps(value, sort_keys=False, separators=(",", ":"), allow_nan=False).encode()


def response_schema(query):
    schema = contracts.response_schema(query)  # full seal/language/ID validation
    if query["language"] == "hia":
        return schema
    groups = {}
    for node in query["edit_query"]["nodes"]:
        if not node["fields"]:
            continue
        category = node.get("category")
        if category not in {"type", "expression"}:
            raise ValueError("E_NODE_CONTRACT_PUBLIC_CATEGORY")
        groups.setdefault(category, []).append(node["id"])
    variants = []
    for category, ids in sorted(groups.items()):
        text = {"enum": list(PUBLIC_RUST_TYPES)} if category == "type" else {"type": "string"}
        changes = contracts._object({"text": text}, ("text",))
        # Insertion order is intentional: the actual completion body preserves
        # it, unlike canonical digests/retained semantic request JSON.
        variants.append(contracts._object({"node": {"enum": sorted(ids)}, "changes": changes},
                                         ("node", "changes")))
    items = variants[0] if len(variants) == 1 else {"oneOf": variants}
    result = copy.deepcopy(schema)
    result["properties"]["edits"]["items"] = items
    return result


def variants(schema):
    item = schema["properties"]["edits"]["items"]
    return item.get("oneOf", [item])


def require_selection_first(schema):
    for variant in variants(schema):
        if list(variant["properties"]) != ["node", "changes"]:
            raise ValueError("E_NODE_CONTRACT_PROPERTY_ORDER")


def check_actual_grammar(schema, grammar):
    """Verify actual b11669 edit-object rules; no grammar or answer rewriting."""
    require_selection_first(schema)
    if type(grammar) is not str:
        raise ValueError("E_NODE_CONTRACT_ACTUAL_GRAMMAR_MISSING")
    rules = [line for line in grammar.splitlines()
             if "::=" in line and "-node-kv" in line.split("::=", 1)[1]
             and "-changes-kv" in line.split("::=", 1)[1]]
    if len(rules) != len(variants(schema)) or any(
            line.split("::=", 1)[1].index("-node-kv") > line.split("::=", 1)[1].index("-changes-kv")
            for line in rules):
        raise ValueError("E_NODE_CONTRACT_ACTUAL_GRAMMAR_ORDER")
    return {"edit_object_rules": len(rules), "selection_before_replacement": True,
            "rules": rules, "does_not_prove_candidate_semantics": True}


def binding(query):
    schema = response_schema(query)
    require_selection_first(schema)
    return {**contracts.binding(query), "profile": PROFILE,
            "schema_sha256": editing.digest(schema),
            "ordered_schema_sha256": hashlib.sha256(ordered_wire(schema)).hexdigest(),
            "selection_before_replacement": True,
            "public_language_type_literals_embedded": query["language"] == "rust",
            "task_or_reference_replacement_values_embedded": False}
