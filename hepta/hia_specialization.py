"""Bounded guarded scalar specialization proposals over canonical HIA.

The guard is executable Core, not a trusted profile assumption. The generic
path remains available for every other input. This module constructs candidates
only; independent all-input translation validation remains mandatory at use.
"""
from __future__ import annotations

import copy

from .hia_program import HIAProgramRejected, WIDTHS, integer_range, verify_program
from .hia_translation_validation import MAX_BLOCKS, MAX_OPERATIONS, _OutsideProfile, _profile


def _reject(message):
    raise HIAProgramRejected(message, "E_HIA_SPECIALIZATION")


def _fresh(stem, used):
    serial = 0
    while f"{stem}_{serial}" in used:
        serial += 1
    name = f"{stem}_{serial}"
    used.add(name)
    return name


def _clone_blocks(fn, stem, used_values, used_blocks):
    blocks = copy.deepcopy(fn["blocks"])
    values = {}
    identifiers = {}
    for block in blocks:
        identifiers[block["id"]] = _fresh(stem, used_blocks)
        for definition in block["params"] + [out for op in block["ops"] for out in op["out"]]:
            values[definition["name"]] = _fresh(stem, used_values)
    for block in blocks:
        block["id"] = identifiers[block["id"]]
        for param in block["params"]:
            param["name"] = values[param["name"]]
        for op in block["ops"]:
            op["args"] = [values[name] for name in op["args"]]
            for out in op["out"]:
                out["name"] = values[out["name"]]
        term = block["term"]
        if term["op"] == "ret":
            term["values"] = [values[name] for name in term["values"]]
        elif term["op"] in {"jump", "branch"}:
            edges = [term] if term["op"] == "jump" else [term["then"], term["else"]]
            if term["op"] == "branch":
                term["cond"] = values[term["cond"]]
            for edge in edges:
                edge["target"] = identifiers[edge["target"]]
                edge["args"] = [values[name] for name in edge["args"]]
    return blocks, identifiers[fn["entry"]]


def propose_guarded_specializations(document, *, function, assumptions, max_candidates=8):
    """Propose one equality-guarded clone per distinct scalar assumption.

    ``assumptions`` is a bounded list of exactly ``parameter`` and ``value``.
    Only a public acyclic scalar function with the existing scalar trap profile
    is accepted. No calls, memory, resource or cyclic execution is introduced.
    The caller's document and all other functions/exports remain unchanged.
    These proposals establish no safety, equivalence or performance authority.
    """
    if type(max_candidates) is not int or not 1 <= max_candidates <= 8:
        _reject("candidate limit must be an exact integer in 1..8")
    if type(assumptions) is not list or not 1 <= len(assumptions) <= 8:
        _reject("one to eight explicit scalar assumptions are required")
    before = verify_program(document)
    if type(function) is not str or function not in before.scalar_entrypoints:
        _reject("function must name a public scalar entrypoint")
    original = before.as_dict()
    fn = next(row for row in original["functions"] if row["name"] == function)
    try:
        _profile(fn)
    except _OutsideProfile as error:
        _reject("outside the existing scalar proof profile: " + str(error))
    if 2 * len(fn["blocks"]) + 1 > MAX_BLOCKS or 2 * sum(len(b["ops"]) for b in fn["blocks"]) + 2 > MAX_OPERATIONS:
        _reject("guarded clones exceed the existing scalar proof budget")
    parameters = {row["name"]: (index, row["type"]) for index, row in enumerate(fn["params"])}
    validated = []
    # Validate the complete request even when the output limit is lower.
    for assumption in assumptions:
        if type(assumption) is not dict or set(assumption) != {"parameter", "value"}:
            _reject("assumption requires only parameter and value")
        name, value = assumption["parameter"], assumption["value"]
        if type(name) is not str or name not in parameters:
            _reject("assumption names an unknown parameter")
        index, typ = parameters[name]
        if typ == "bool":
            if type(value) is not bool:
                _reject("Boolean specialization requires an exact Boolean")
        elif typ in WIDTHS:
            if type(value) is not int or not integer_range(typ)[0] <= value <= integer_range(typ)[1]:
                _reject("integer specialization value is outside its exact type")
        else:
            _reject("only integer and Boolean parameters may be specialized")
        validated.append((name, value, index, typ))
    proposals, seen = [], set()
    for name, value, index, typ in validated:
        candidate = copy.deepcopy(original)
        target = next(row for row in candidate["functions"] if row["name"] == function)
        used_values = {p["name"] for p in fn["params"]}
        used_blocks = set()
        generic, generic_entry = _clone_blocks(fn, "hia_generic", used_values, used_blocks)
        specialized, specialized_entry = _clone_blocks(fn, "hia_specialized", used_values, used_blocks)
        guard_entry = _fresh("hia_guard", used_blocks)
        constant, condition = _fresh("hia_value", used_values), _fresh("hia_match", used_values)
        ordinary_args = [p["name"] for p in fn["params"]]
        specialized_args = list(ordinary_args)
        specialized_args[index] = constant
        guard = {"id": guard_entry, "params": copy.deepcopy(fn["params"]), "ops": [
            {"op": "const", "args": [], "out": [{"name": constant, "type": typ}], "attrs": {"value": value}},
            {"op": "compare.eq", "args": [name, constant], "out": [{"name": condition, "type": "bool"}], "attrs": {}},
        ], "term": {"op": "branch", "cond": condition,
                    "then": {"target": specialized_entry, "args": specialized_args},
                    "else": {"target": generic_entry, "args": ordinary_args}}}
        target["entry"] = guard_entry
        target["blocks"] = [guard, *generic, *specialized]
        checked = verify_program(candidate)
        if checked.sha256 not in seen:
            seen.add(checked.sha256)
            proposals.append({"id": "s" + checked.sha256[:31],
                              "action": f"guarded_scalar_parameter:{name}={value}",
                              "program": checked.as_dict()})
        if len(proposals) == max_candidates:
            break
    return proposals
