"""Pruned scalar SSA for a deliberately restricted, already checked Hepta CFG.

Dominance-frontier phi placement and dominator-tree renaming cover normal
scalar locals, assignments, branches and while loops. The representation is
not executable, and does NOT qualify borrow, drop, provenance, native lowering,
for/range induction, match payload binding, unsafe, calls or whole-language SSA.
Unsupported semantics fail closed; no fallback to text-based rewriting.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json

from .cfg import CFGSnapshot
from .cfg_analysis import CFGAnalysisRejected, analyze_cfg


class SSARejected(ValueError):
    pass


@dataclass(frozen=True)
class SSASnapshot:
    schema: str
    canonical_json: str
    sha256: str

    def as_dict(self) -> dict:
        if sha256(self.canonical_json.encode("utf-8")).hexdigest() != self.sha256:
            raise SSARejected("E_SSA_HASH: output snapshot altered")
        return {**json.loads(self.canonical_json), "sha256": self.sha256}


_SCALAR = frozenset({"i8", "i16", "i32", "i64", "i128", "isize",
                     "u8", "u16", "u32", "u64", "u128", "usize",
                     "bool", "f32", "f64"})
_BINARY = frozenset({"+", "-", "*", "/", "%", "==", "!=", "<", "<=", ">", ">=",
                     "&&", "||", "&", "|", "^", "<<", ">>"})
_ALLOWED_EFFECTS = frozenset({"panic"})
_ALLOWED_RESOURCES = {"heap_allocations": 0, "may_block": False,
                      "may_suspend": False, "may_spawn": False}
_MAX_EXPRESSION_DEPTH = 64
_MAX_DEFINITIONS = 8192


def _type(value: object, context: str) -> str:
    if not isinstance(value, dict) or value.get("type") not in _SCALAR or value.get("args") or value.get("length") is not None:
        raise SSARejected(f"E_SSA_TYPE: unsupported {context} type")
    return value["type"]


def _expr(expr: object, *, version_of=None, expected_types=None, depth=0) -> tuple[dict, set[str]]:
    """Copy closed scalar typed expression, annotating variable uses by SSA version."""
    if depth > _MAX_EXPRESSION_DEPTH or not isinstance(expr, dict) or expr.get("node") != "expr":
        raise SSARejected("E_SSA_EXPRESSION: missing typed scalar expression or depth limit")
    ty = _type(expr.get("result_type"), "expression")
    kind, operands, value = expr.get("operation"), expr.get("operands"), expr.get("value")
    if not isinstance(operands, list) or expr.get("type_args") not in ([], None):
        raise SSARejected("E_SSA_EXPRESSION: unrecognized operands or generic arguments")
    arity = {"name": 0, "int": 0, "float": 0, "bool": 0, "binary": 2, "unary": 1, "cast": 1}.get(kind)
    if arity is None or len(operands) != arity:
        raise SSARejected(f"E_SSA_UNSUPPORTED: expression operation {kind!r}")
    if kind == "binary" and value not in _BINARY:
        raise SSARejected(f"E_SSA_UNSUPPORTED: binary operator {value!r}")
    if kind == "unary" and value not in {"-", "!"}:
        raise SSARejected(f"E_SSA_UNSUPPORTED: effectful unary operator {value!r}")
    if kind == "cast":
        if _type(value, "cast target") != ty:
            raise SSARejected("E_SSA_TYPE: cast target and result disagree")
    if kind == "name":
        if not isinstance(value, str) or not value or "::" in value:
            raise SSARejected("E_SSA_NAME: source is not a scalar local variable")
        if expected_types is not None:
            if value not in expected_types or expected_types[value] != ty:
                raise SSARejected("E_SSA_NAME: unknown variable or inconsistent type")
        if version_of is None:
            return dict(expr), {value}
        out = dict(expr)
        out["ssa_ref"] = version_of(value)
        return out, {value}
    if kind == "int" and (not isinstance(value, int) or isinstance(value, bool)):
        raise SSARejected("E_SSA_LITERAL: malformed integer")
    if kind == "bool" and not isinstance(value, bool):
        raise SSARejected("E_SSA_LITERAL: malformed boolean")
    if kind == "float" and not isinstance(value, (int, float)):
        raise SSARejected("E_SSA_LITERAL: malformed floating literal")
    if kind in {"int", "bool", "float"} and value is None:
        raise SSARejected("E_SSA_LITERAL: missing literal")
    children, read = [], set()
    for operand in operands:
        child, names = _expr(operand, version_of=version_of,
                             expected_types=expected_types, depth=depth+1)
        children.append(child)
        read |= names
    out = dict(expr)
    out["operands"] = children
    return out, read


def _validated_assignment(inst: dict, types: dict[str, str], mutability: dict[str, bool]) -> tuple[str | None, dict | None]:
    kind = inst.get("operation")
    if kind not in {"let", "assign", "expr"}:
        raise SSARejected(f"E_SSA_UNSUPPORTED: instruction {kind!r}")
    f = inst.get("fields")
    if not isinstance(f, dict) or f.get("expr") is None:
        raise SSARejected("E_SSA_INSTRUCTION: expression required")
    value = f["expr"]
    ty = _type(value.get("result_type") if isinstance(value, dict) else None, "value")
    if kind == "let":
        name = f.get("name")
        if not isinstance(name, str) or not name or name in types:
            raise SSARejected("E_SSA_BINDING: invalid or shadowing binding")
        if f.get("type") is not None and _type(f["type"], "binding") != ty:
            raise SSARejected("E_SSA_TYPE: binding initializer mismatch")
        types[name] = ty
        mutability[name] = f.get("mutable") is True
        return name, value
    if kind == "assign":
        target = f.get("target")
        if not isinstance(target, dict) or target.get("operation") != "name" or target.get("operands") != []:
            raise SSARejected("E_SSA_UNSUPPORTED: only simple scalar local assignments")
        name = target.get("value")
        if not isinstance(name, str) or name not in types or not mutability.get(name):
            raise SSARejected("E_SSA_BINDING: assignment to immutable or unbound variable")
        if _type(target.get("result_type"), "assignment target") != types[name] or ty != types[name]:
            raise SSARejected("E_SSA_TYPE: assignment type mismatch")
        return name, value
    return None, value


def _term_expr(term: dict) -> dict | None:
    kind = term.get("kind")
    if kind == "branch":
        value = term.get("condition")
        if not isinstance(value, dict) or value.get("result_type", {}).get("type") != "bool":
            raise SSARejected("E_SSA_CONDITION: branch requires a typed bool")
        return value
    if kind == "return":
        return term.get("value")
    if kind == "goto" or kind == "fallthrough":
        return None
    raise SSARejected(f"E_SSA_UNSUPPORTED: terminator {kind!r}; range/match/unsafe not supported")


def _checked_contract(fn: dict) -> tuple[list[str], list[str], dict]:
    """Keep effects and resource clauses attached to scalar SSA, never drop them.

    This preserves already-checked source metadata; it is NOT a second effect
    checker or a proof of whole-process resource bounds.
    """
    declared = fn.get("declared_effects")
    inferred = fn.get("inferred_transitive_effects")
    resources = fn.get("resource_contract")
    if (not isinstance(declared, list) or not isinstance(inferred, list)
            or any(type(effect) is not str for effect in [*declared, *inferred])
            or declared != sorted(set(declared))
            or inferred != sorted(set(inferred))
            or not set(inferred).issubset(declared)
            or (set(declared) | set(inferred)) - _ALLOWED_EFFECTS):
        raise SSARejected("E_SSA_EFFECT: scalar SSA requires closed pure/panic effect metadata")
    if (not isinstance(resources, dict)
            or any(key not in _ALLOWED_RESOURCES or
                   type(value) is not type(_ALLOWED_RESOURCES.get(key)) or
                   value != _ALLOWED_RESOURCES.get(key)
                   for key, value in resources.items())):
        raise SSARejected("E_SSA_RESOURCE: unsupported or malformed resource contract")
    return list(declared), list(inferred), dict(resources)


def _run_function(fn: dict, analysis: dict) -> dict:
    blocks = fn.get("blocks")
    if not isinstance(blocks, list):
        raise SSARejected("E_SSA_SHAPE: block list missing")
    entry = fn.get("entry")
    params = fn.get("param_types", [])
    if not isinstance(params, list):
        raise SSARejected("E_SSA_PARAMETERS: malformed signature")
    declared_effects, inferred_effects, resource_contract = _checked_contract(fn)
    return_type = fn.get("return_type")
    unit_return = return_type == {"type": "Unit", "args": [], "length": None}
    if not unit_return:
        return_ty = _type(return_type, "return")
    types: dict[str, str] = {}
    mutability: dict[str, bool] = {}
    for p in params:
        if not isinstance(p, dict) or p.get("ownership") != "value" or not isinstance(p.get("name"), str):
            raise SSARejected("E_SSA_PARAMETERS: only owned-by-value scalars supported")
        name = p["name"]
        if not name or name in types:
            raise SSARejected("E_SSA_PARAMETERS: duplicate or empty name")
        types[name] = _type(p.get("type"), "parameter")
        mutability[name] = False
    definition_sites = {name: {entry} for name in types}
    defnames: dict[str, list[str | None]] = {}
    for block in blocks:
        bid = block["id"]
        instructions = block.get("instructions")
        if not isinstance(instructions, list):
            raise SSARejected("E_SSA_SHAPE: missing instruction list")
        names = []
        for inst in instructions:
            if not isinstance(inst, dict):
                raise SSARejected("E_SSA_INSTRUCTION: malformed instruction")
            name, _ = _validated_assignment(inst, types, mutability)
            names.append(name)
            if name is not None:
                definition_sites.setdefault(name, set()).add(bid)
        defnames[bid] = names
        term = block["terminator"]
        value = _term_expr(term)
        if term["kind"] == "fallthrough" and not unit_return:
            raise SSARejected("E_SSA_RETURN: non-Unit function may not fall through")
        if term["kind"] == "return" and (value is None) != unit_return:
            raise SSARejected("E_SSA_RETURN: missing or unexpected return value")
        if term["kind"] == "return" and value is not None and _type(value.get("result_type"), "return") != return_ty:
            raise SSARejected("E_SSA_RETURN: mismatched return type")
    if sum(len(x) for x in defnames.values()) > _MAX_DEFINITIONS:
        raise SSARejected("E_SSA_LIMIT: instruction budget exceeded")
    upward: dict[str, set[str]] = {}
    defined: dict[str, set[str]] = {}
    for block in blocks:
        bid = block["id"]
        uses, kills = set(), set()
        for inst, name in zip(block["instructions"], defnames[bid]):
            _, reads = _expr(inst["fields"]["expr"], expected_types=types)
            uses |= reads - kills
            if name is not None:
                kills.add(name)
        term_value = _term_expr(block["terminator"])
        if term_value is not None:
            _, reads = _expr(term_value, expected_types=types)
            uses |= reads - kills
        upward[bid], defined[bid] = uses, kills
    succ = analysis["successors"]
    preds = analysis["predecessors"]
    live_in = {b["id"]: set() for b in blocks}
    live_out = {b["id"]: set() for b in blocks}
    changed = True
    while changed:
        changed = False
        for block in reversed(blocks):
            bid = block["id"]
            out = set().union(*(live_in[x] for x in succ[bid])) if succ[bid] else set()
            into = upward[bid] | (out - defined[bid])
            if out != live_out[bid] or into != live_in[bid]:
                live_out[bid], live_in[bid] = out, into
                changed = True
    frontier = analysis["dominance_frontiers"]
    phi_places: dict[str, set[str]] = {b["id"]: set() for b in blocks}
    for name, defs in sorted(definition_sites.items()):
        work, visited = sorted(defs), set(defs)
        while work:
            source = work.pop(0)
            for target in frontier[source]:
                if name in live_in[target] and name not in phi_places[target]:
                    phi_places[target].add(name)
                    if target not in visited:
                        visited.add(target)
                        work.append(target)
    idom = analysis["immediate_dominators"]
    children: dict[str, list[str]] = {b["id"]: [] for b in blocks}
    for bid, parent in idom.items():
        if parent is not None:
            children[parent].append(bid)
    for values in children.values():
        values.sort()
    counters = {name: 0 for name in types}
    stack: dict[str, list[str]] = {name: [] for name in types}
    result_blocks: dict[str, dict] = {}
    initial_params = []

    def fresh(name: str, scope: str) -> dict:
        number = counters[name]
        counters[name] += 1
        return {"variable": name, "ssa_name": f"{name}@{number}",
                "type": types[name], "defined_in": scope}

    def current(name: str) -> str:
        if not stack.get(name):
            raise SSARejected(f"E_SSA_UNDEFINED: {name!r} has no dominating definition")
        return stack[name][-1]

    incoming: dict[tuple[str, str], list[dict]] = {}

    def rename(bid: str, depth: int = 0):
        if depth > 512:
            raise SSARejected("E_SSA_LIMIT: dominator tree too deep")
        block = blocks[int(bid[1:])]
        pushed = []
        phis = []
        for name in sorted(phi_places[bid]):
            defin = fresh(name, bid)
            stack[name].append(defin["ssa_name"])
            pushed.append(name)
            phis.append({"result": defin, "incoming": []})
        out_instructions = []
        for inst, name in zip(block["instructions"], defnames[bid]):
            expr, _ = _expr(inst["fields"]["expr"], version_of=current, expected_types=types)
            output = {"operation": inst["operation"], "ssa_value": expr,
                      "span": inst.get("span")}
            if name is not None:
                defin = fresh(name, bid)
                stack[name].append(defin["ssa_name"])
                pushed.append(name)
                output["definition"] = defin
            out_instructions.append(output)
        term = dict(block["terminator"])
        term_expr = _term_expr(term)
        if term_expr is not None:
            annotated, _ = _expr(term_expr, version_of=current, expected_types=types)
            if term["kind"] == "branch":
                term["condition"] = annotated
            else:
                term["value"] = annotated
        result_blocks[bid] = {"id": bid, "phis": phis, "instructions": out_instructions,
                              "terminator": term}
        for target in sorted(set(succ[bid])):
            for name in sorted(phi_places[target]):
                value = current(name)
                incoming.setdefault((target, name), []).append({"from": bid, "ssa_ref": value})
        for child in children[bid]:
            rename(child, depth+1)
        for name in reversed(pushed):
            stack[name].pop()

    for p in params:
        defin = fresh(p["name"], entry)
        stack[p["name"]].append(defin["ssa_name"])
        initial_params.append(defin)
    rename(entry)
    for bid, block in result_blocks.items():
        for phi in block["phis"]:
            name = phi["result"]["variable"]
            phi["incoming"] = sorted(incoming.get((bid, name), []), key=lambda x: x["from"])
            if [x["from"] for x in phi["incoming"]] != sorted(preds[bid]):
                raise SSARejected("E_SSA_PHI: missing, repeated or spurious predecessor input")
    return {"name": fn["name"], "entry": entry, "parameters": initial_params,
            "blocks": [result_blocks[b["id"]] for b in blocks],
            # These declarations are part of the source contract even when the
            # scalar optimizer does not interpret memory or allocator effects.
            "declared_effects": declared_effects,
            "inferred_transitive_effects": inferred_effects,
            "resource_contract": resource_contract,
            "scalar_types": dict(sorted(types.items())),
            "definitions": sum(counters.values()),
            "phi_count": sum(len(b["phis"]) for b in result_blocks.values())}


def lower_cfg_scalar_ssa(cfg: CFGSnapshot) -> SSASnapshot:
    """SSA over deliberately pure scalar CFGs; no fallback on unsupported IR."""
    if not isinstance(cfg, CFGSnapshot) or cfg.schema != "hepta.cfg.v0":
        raise SSARejected("E_SSA_INPUT: structural CFG snapshot required")
    if sha256(cfg.canonical_json.encode("utf-8")).hexdigest() != cfg.sha256:
        raise SSARejected("E_SSA_INPUT: CFG SHA-256 mismatch")
    try:
        analysis = analyze_cfg(cfg).as_dict()
        payload = json.loads(cfg.canonical_json)
        by_name = {f["name"]: f for f in analysis["functions"]}
        if len(by_name) != len(analysis["functions"]):
            raise SSARejected("E_SSA_FUNCTION: duplicate function name")
        functions = [_run_function(f, by_name[f["name"]]) for f in payload["functions"]]
    except CFGAnalysisRejected as exc:
        raise SSARejected("E_SSA_CFG: invalid structural control flow: " + str(exc)) from exc
    output = {"schema": "hepta.ssa.scalar.v0", "status": "scalar_ssa_subset_not_backend_qualified",
              "source_cfg_sha256": cfg.sha256, "source_analysis_sha256": analysis["sha256"],
              "functions": functions,
              "claims": {"scalar_ssa_subset_constructed": True, "phi_inputs_checked": True,
                         "effect_resource_metadata_retained": True,
                         "whole_language_ssa_complete": False, "for_range_implemented": False,
                         "match_payloads_supported": False, "borrow_drop_proven": False,
                         "pointer_provenance_proven": False,
                         "semantic_equivalence_proven": False,
                         "native_backend_refinement_proven": False}}
    canonical = json.dumps(output, sort_keys=True, ensure_ascii=False, allow_nan=False,
                           separators=(",", ":"))
    return SSASnapshot("hepta.ssa.scalar.v0", canonical, sha256(canonical.encode()).hexdigest())
