"""Deterministic finite proposals over the existing, verified scalar HIA Core.

These are candidate construction recipes, never proof or performance claims.
Every consumer must independently validate translation on the exact before and
after documents.  The recipes are restricted to total scalar acyclic code so
dead-code removal cannot erase a specified trap, resource effect, or call.
"""
from __future__ import annotations

import copy

from .hia_program import HIAProgramRejected, WIDTHS, verify_program
from .hia_program_runtime import execute_program
from .hia_translation_validation import _OutsideProfile, _profile

_TOTAL = frozenset({
    "const", "select", "int.cast", "int.add.wrap", "int.sub.wrap", "int.mul.wrap",
    "bit.and", "bit.or", "bit.xor", "bit.not", "bool.and", "bool.or", "bool.not",
    "compare.eq", "compare.ne", "compare.lt", "compare.le", "compare.gt", "compare.ge",
})


def _reject(message):
    raise HIAProgramRejected(message, "E_HIA_FINITE_ACTION")


def _function(document, name):
    return next(fn for fn in document["functions"] if fn["name"] == name)


def _constant(typ, value, name):
    return {"op": "const", "args": [], "out": [{"name": name, "type": typ}],
            "attrs": {"value": value}}


def _fold_value(op, known, types, schema):
    """Use the existing executable scalar semantics, not Python operator guesses."""
    constants = [_constant(types[name], known[name], name) for name in dict.fromkeys(op["args"])]
    tiny = {"schema": schema, "module": "finite_constfold", "functions": [{
        "name": "fold", "params": [], "returns": [out["type"] for out in op["out"]],
        "effects": [], "entry": "entry", "blocks": [{"id": "entry", "params": [],
            "ops": constants + [copy.deepcopy(op)],
            "term": {"op": "ret", "values": [out["name"] for out in op["out"]]}}],
    }]}
    return execute_program(tiny, "fold", [], max_steps=16)["values"][0]


def _replace_block_uses(block, old, replacement):
    for op in block["ops"]:
        op["args"] = [replacement if name == old else name for name in op["args"]]
    term = block["term"]
    if term["op"] == "ret":
        term["values"] = [replacement if name == old else name for name in term["values"]]
    elif term["op"] == "jump":
        term["args"] = [replacement if name == old else name for name in term["args"]]
    elif term["op"] == "branch":
        if term["cond"] == old:
            term["cond"] = replacement
        for edge in (term["then"], term["else"]):
            edge["args"] = [replacement if name == old else name for name in edge["args"]]


def _identity_recipe(document, name):
    fn = _function(document, name)
    for block in fn["blocks"]:
        known = {}
        types = {p["name"]: p["type"] for p in block["params"]}
        kept = []
        for op in list(block["ops"]):
            opcode, args = op["op"], op["args"]
            output = op["out"][0]
            types[output["name"]] = output["type"]
            if opcode == "const":
                known[output["name"]] = op["attrs"]["value"]
            replacement = None
            if opcode in {"int.add.wrap", "bit.or", "bit.xor"}:
                if args[1] in known and known[args[1]] == 0:
                    replacement = args[0]
                elif args[0] in known and known[args[0]] == 0:
                    replacement = args[1]
            elif opcode == "int.sub.wrap" and args[1] in known and known[args[1]] == 0:
                replacement = args[0]
            elif opcode == "int.mul.wrap":
                if args[1] in known and known[args[1]] == 1:
                    replacement = args[0]
                elif args[0] in known and known[args[0]] == 1:
                    replacement = args[1]
            elif opcode in {"bit.and", "bit.or"} and args[0] == args[1]:
                replacement = args[0]
            elif opcode == "int.cast" and types[args[0]] == output["type"]:
                replacement = args[0]
            elif opcode == "select":
                if args[0] in known:
                    replacement = args[1] if known[args[0]] else args[2]
                elif args[1] == args[2]:
                    replacement = args[1]
            elif opcode in {"bool.and", "bool.or"}:
                identity = opcode == "bool.and"
                if args[1] in known and known[args[1]] is identity:
                    replacement = args[0]
                elif args[0] in known and known[args[0]] is identity:
                    replacement = args[1]
            if replacement is None:
                kept.append(op)
            else:
                _replace_block_uses(block, output["name"], replacement)
                if replacement in known:
                    known[output["name"]] = known[replacement]
        block["ops"] = kept


def _constant_recipe(document, name):
    for block in _function(document, name)["blocks"]:
        known = {}
        types = {p["name"]: p["type"] for p in block["params"]}
        for index, op in enumerate(block["ops"]):
            output = op["out"][0]
            if op["op"] == "const":
                known[output["name"]] = op["attrs"]["value"]
            elif all(arg in known for arg in op["args"]):
                value = _fold_value(op, known, types, document["schema"])
                block["ops"][index] = _constant(output["type"], value, output["name"])
                known[output["name"]] = value
            types[output["name"]] = output["type"]


def _dead_recipe(document, name):
    for block in _function(document, name)["blocks"]:
        term = block["term"]
        if term["op"] == "ret":
            live = set(term["values"])
        elif term["op"] == "jump":
            live = set(term["args"])
        else:
            live = {term["cond"], *term["then"]["args"], *term["else"]["args"]}
        retained = []
        for op in reversed(block["ops"]):
            outputs = {out["name"] for out in op["out"]}
            if live & outputs:
                retained.append(op)
                live -= outputs
                live.update(op["args"])
        block["ops"] = list(reversed(retained))


def _reassociate_recipe(document, name):
    fn = _function(document, name)
    names = {p["name"] for block in fn["blocks"] for p in block["params"]}
    names.update(p["name"] for block in fn["blocks"] for op in block["ops"] for p in op["out"])
    for block in fn["blocks"]:
        known, definitions = {}, {}
        types = {p["name"]: p["type"] for p in block["params"]}
        for index, op in enumerate(block["ops"]):
            output = op["out"][0]
            types[output["name"]] = output["type"]
            if op["op"] == "const":
                known[output["name"]] = op["attrs"]["value"]
            if op["op"] == "int.add.wrap":
                for inner_name, outer_constant in (op["args"], op["args"][::-1]):
                    inner = definitions.get(inner_name)
                    if outer_constant not in known or inner is None or inner["op"] != "int.add.wrap":
                        continue
                    for base, inner_constant in (inner["args"], inner["args"][::-1]):
                        if inner_constant not in known:
                            continue
                        typ = output["type"]
                        value = (known[inner_constant] + known[outer_constant]) % (1 << WIDTHS[typ])
                        if typ.startswith("i") and value >= 1 << (WIDTHS[typ] - 1):
                            value -= 1 << WIDTHS[typ]
                        serial = 0
                        fresh = "hia_reassoc_constant"
                        while fresh in names:
                            serial += 1
                            fresh = f"hia_reassoc_constant_{serial}"
                        block["ops"].insert(index, _constant(typ, value, fresh))
                        op["args"] = [base, fresh]
                        return  # One deterministic local reassociation per proposal.
            definitions[output["name"]] = op


def propose_candidates(document, *, function, max_candidates=8):
    """Return at most eight unique canonical proposals, in frozen recipe order.

    A proposal has exactly ``id``, ``action`` and ``program``.  IDs are derived
    from complete canonical candidate hashes.  The caller's input is never
    mutated.  Unsupported or potentially trapping inputs are rejected rather
    than weakened to fit a recipe.  No proposal includes an approval receipt.
    """
    if type(max_candidates) is not int or not 1 <= max_candidates <= 8:
        _reject("candidate count must be an integer in 1..8")
    checked = verify_program(document)
    core = checked.as_dict()
    if type(function) is not str or function not in checked.scalar_entrypoints:
        _reject("candidate target must be a public scalar function")
    fn = _function(core, function)
    try:
        _profile(fn)
    except _OutsideProfile as exc:
        _reject("outside finite scalar proposal profile: " + str(exc))
    if fn["effects"] or any(
        op["op"] not in _TOTAL or op["op"] == "int.cast" and op["attrs"]["mode"] != "wrap"
        for block in fn["blocks"] for op in block["ops"]
    ) or any(block["term"]["op"] == "trap" for block in fn["blocks"]):
        _reject("proposals require total effect-free scalar operations")
    recipes = (
        ("remove_scalar_identities", (_identity_recipe,)),
        ("fold_scalar_constants", (_constant_recipe,)),
        ("reassociate_wrapping_add", (_reassociate_recipe,)),
        ("remove_dead_total_operations", (_dead_recipe,)),
        ("identities_then_dead_operations", (_identity_recipe, _dead_recipe)),
        ("constants_then_identities_then_dead", (_constant_recipe, _identity_recipe, _dead_recipe)),
        ("reassociate_then_identities_then_dead", (_reassociate_recipe, _identity_recipe, _dead_recipe)),
        ("combined_finite_recipes", (_constant_recipe, _reassociate_recipe, _identity_recipe, _dead_recipe)),
    )
    seen, result = {checked.sha256}, []
    for action, transformations in recipes:
        candidate = copy.deepcopy(core)
        for transformation in transformations:
            transformation(candidate, function)
        verified = verify_program(candidate)
        if verified.sha256 not in seen:
            seen.add(verified.sha256)
            result.append({"id": "c" + verified.sha256[:31], "action": action,
                           "program": verified.as_dict()})
            if len(result) == max_candidates:
                break
    return result
