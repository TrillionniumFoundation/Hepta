"""Opt-in LLVM layout for disjoint, effect-free unsigned entry guards.

This is a code-layout transformation, not a Core rewrite. Complete branch
components are emitted by the ordinary function emitter. The dispatch keeps the
actual unsigned guard and passes every argument unchanged. Its optional empty
edge substitutes zero only after an equality test. Unknown CFG shapes are
refused; no operation, allocator call, trap or resource release is erased here.

The compiler/backend remains trusted. Structural correspondence is not a
machine-checked LLVM refinement theorem or a performance qualification.
"""
from __future__ import annotations

from copy import deepcopy

from .hia_program import WIDTHS

LAYOUT = "guarded-outline-v1"
CANONICAL = "canonical"
LAYOUTS = frozenset({CANONICAL, LAYOUT})


def _successors(block):
    term = block["term"]
    if term["op"] == "jump":
        return [term["target"]]
    if term["op"] == "branch":
        return [term["then"]["target"], term["else"]["target"]]
    return []


def entry_plan(function):
    """Recognize a complete partition, independently of generated block names.

    Callers must first verify the full immutable Core. Returning None keeps
    unsupported shapes outside this opt-in layout. The original initialization
    decision is inherited by both components; outlining cannot authorize a new
    malloc/zero-elision path.
    """
    params = function["params"]
    returns = function["returns"]
    if (any(p["type"] not in WIDTHS for p in params)
            or len(returns) != 1 or returns[0] not in WIDTHS):
        return None
    blocks = {b["id"]: b for b in function["blocks"]}
    entry = blocks[function["entry"]]
    if entry["params"] != params or len(entry["ops"]) != 2:
        return None
    constant, comparison = entry["ops"]
    if (constant["op"] != "const" or constant["args"]
            or len(constant["out"]) != 1
            or constant["out"][0]["type"] != "usize"
            or set(constant["attrs"]) != {"value"}):
        return None
    bound = constant["attrs"]["value"]
    if type(bound) is not int or not 0 <= bound <= 2**64 - 1:
        return None
    limit = constant["out"][0]["name"]
    if (comparison["op"] != "compare.le"
            or len(comparison["args"]) != 2 or comparison["args"][1] != limit
            or len(comparison["out"]) != 1
            or comparison["out"][0]["type"] != "bool" or comparison["attrs"]):
        return None
    argument = comparison["args"][0]
    matches = [i for i, p in enumerate(params)
               if p["name"] == argument and p["type"] == "usize"]
    if len(matches) != 1:
        return None
    term = entry["term"]
    arguments = [p["name"] for p in params]
    if (term["op"] != "branch" or term["cond"] != comparison["out"][0]["name"]
            or term["then"]["args"] != arguments
            or term["else"]["args"] != arguments):
        return None
    components = []
    for arm in ("then", "else"):
        root = term[arm]["target"]
        reached, pending = set(), [root]
        while pending:
            name = pending.pop()
            if name == entry["id"] or name not in blocks:
                return None
            if name in reached:
                continue
            reached.add(name)
            successors = _successors(blocks[name])
            # A native function's entry parameters are not a backedge phi.
            if root in successors:
                return None
            pending.extend(successors)
        selected = [deepcopy(b) for b in function["blocks"] if b["id"] in reached]
        if ([p["type"] for p in blocks[root]["params"]]
                != [p["type"] for p in params]):
            return None
        component = deepcopy(function)
        component.update(entry=root, params=deepcopy(blocks[root]["params"]), blocks=selected)
        components.append(component)
    left = {b["id"] for b in components[0]["blocks"]}
    right = {b["id"] for b in components[1]["blocks"]}
    if left & right or left | right | {entry["id"]} != set(blocks):
        return None
    return {"argument": argument, "parameter_index": matches[0], "maximum": bound,
            "components": components, "entry": entry["id"],
            "operation_count": sum(len(b["ops"]) for b in function["blocks"]),
            "component_operation_counts": [
                sum(len(b["ops"]) for b in child["blocks"]) for child in components]}


def render_entry(parent, function, number, helper_start, plan):
    """Emit complete components and a value-preserving dispatch.

    The function emitter defines every buffer operation, allocation/refusal,
    checked arithmetic and trap exactly as it does for canonical Core. Inherit
    its original whole-function initialization choice, even if a separated
    component would qualify for a stronger initialization analysis by itself.
    """
    from . import hia_program_llvm as native

    zero_bytes = "false" if native._can_elide_zero_initialization(function) else "true"
    bodies = []
    for offset, component in enumerate(plan["components"]):
        emitter = native._FunctionEmitter(parent, component, helper_start + offset)
        emitter.zero_bytes = zero_bytes
        bodies.append(emitter.render())
    params = function["params"]
    result = native._return_type(function["returns"])
    types = [native._llvm_type(p["type"]) for p in params]
    arguments = ", ".join(t + " %entry_" + str(i) for i, t in enumerate(types))
    position = plan["parameter_index"]
    zero_arguments = ", ".join(
        t + (" 0" if i == position else " %entry_" + str(i))
        for i, t in enumerate(types))
    length = "%entry_" + str(position)
    fast = result + " @__hia_fn_" + str(helper_start)
    slow = result + " @__hia_fn_" + str(helper_start + 1)
    dispatch = "\n".join([
        "define internal " + result + " @__hia_fn_" + str(number) + "(" + arguments + ") {",
        "entry:",
        "  %empty = icmp eq i64 " + length + ", 0",
        "  br i1 %empty, label %zero, label %guard",
        "zero:",
        "  %zero_result = call " + fast + "(" + zero_arguments + ") alwaysinline",
        "  ret " + result + " %zero_result",
        "guard:",
        "  %eligible = icmp ule i64 " + length + ", " + str(plan["maximum"]),
        "  br i1 %eligible, label %fast, label %fallback",
        "fast:",
        "  %fast_result = tail call " + fast + "(" + arguments + ") noinline",
        "  ret " + result + " %fast_result",
        "fallback:",
        "  %slow_result = tail call " + slow + "(" + arguments + ") noinline",
        "  ret " + result + " %slow_result",
        "}",
    ])
    return [dispatch, *bodies]
