"""Finite live payload-byte upper bound for existing verified HIA Core.

This is a strictly opt-in resource-budget analysis, not a second ownership
checker. The canonical HIA verifier provides SSA, typed ownership and CFG
validity. We refuse unknown allocation extents, owner-valued call boundaries,
loops and recursion instead of inventing bounds from caller assumptions.
The bound counts requested live byte payload, NOT allocator overhead or RSS.
"""
from __future__ import annotations

from .hia_program import verify_program

MAX_REQUEST = (1 << 63) - 1
# Versioned closed interpretation: a future schema could change the semantics
# of an existing opcode and must never inherit this byte bound automatically.
_ALLOWED_SCHEMAS = frozenset(f"hepta.hia.program.v{version}" for version in range(1, 7))
# New executable Core opcodes must be explicitly audited before any native
# resource policy can rely on this analysis. Never guess "does not allocate".
_NO_ALLOCATION_OPS = frozenset({
    "int.cast", "int.neg.checked", "select",
    "bool.not", "bool.and", "bool.or",
    "bit.and", "bit.or", "bit.xor", "bit.not",
    "compare.eq", "compare.ne", "compare.lt", "compare.le", "compare.gt", "compare.ge",
    "int.add.checked", "int.sub.checked", "int.mul.checked",
    "int.add.wrap", "int.sub.wrap", "int.mul.wrap",
    "int.div.checked", "int.rem.checked", "int.shl.checked", "int.shr.checked",
    "buffer.len", "borrow.read", "borrow.mut", "loan.end",
    "buffer.load", "buffer.store", "buffer.fill", "buffer.copy",
    "buffer.move_within", "buffer.fill_range", "buffer.copy_range", "buffer.swap",
})


class HIAHeapBoundRejected(ValueError):
    def __init__(self, code: str, detail: str):
        self.code = code
        super().__init__(f"{code}: {detail}")


def _reject(detail: str) -> None:
    raise HIAHeapBoundRejected("E_HIA_BUDGET_UNBOUNDED", detail)


def _paths(term: dict) -> list[dict]:
    if term["op"] == "jump":
        return [{"target": term["target"], "args": term["args"]}]
    if term["op"] == "branch":
        return [term["then"], term["else"]]
    return []


def _dag(names, edges, context):
    # Share the established cycle policy rather than weakening it.
    from .hia_static_budget import _topological
    return _topological(names, edges, context)


def _merge(previous, proposed, label):
    """Join two verified CFG edges with a per-owner conservative maximum."""
    old_owners, old_constants = previous
    new_owners, new_constants = proposed
    if old_owners.keys() != new_owners.keys():
        _reject(f"{label}: incompatible owner inventory at a CFG join")
    owners = {key: max(old_owners[key], new_owners[key]) for key in old_owners}
    constants = {key: value for key, value in old_constants.items()
                 if key in new_constants and type(new_constants[key]) is type(value)
                 and new_constants[key] == value}
    return owners, constants


def _function(fn: dict, functions: dict[str, dict], calculated: dict[str, int]) -> int:
    from .hia_program import WIDTHS

    if any(param["type"] in {"buffer", "readbuf", "mutbuf"} for param in fn["params"]):
        _reject(f"{fn['name']}: resource arguments have unbounded external extent")
    if any(t in {"buffer", "readbuf", "mutbuf"} for t in fn["returns"]):
        _reject(f"{fn['name']}: owned return needs a caller-size invariant")
    blocks = {b["id"]: b for b in fn["blocks"]}
    edges = {key: {e["target"] for e in _paths(block["term"])}
             for key, block in blocks.items()}
    order = _dag(list(blocks), edges, f"{fn['name']} heap control flow")
    states = {fn["entry"]: ({}, {})}  # owner SSA name -> bound, scalar name -> constant
    peak = 0
    for name in order:
        if name not in states:
            _reject(f"{fn['name']}: missing reachable CFG input")
        owner, known = (dict(row) for row in states[name])
        block = blocks[name]
        peak = max(peak, sum(owner.values()))
        for ins in block["ops"]:
            op, args, outputs, attrs = ins["op"], ins["args"], ins["out"], ins["attrs"]
            out_names = [p["name"] for p in outputs]
            if op == "const":
                value = attrs["value"]
                if type(value) in {int, bool}:
                    known[out_names[0]] = value
                # unit constants are intentionally not used as sizes.
            elif op in {"buffer.new", "buffer.try_new"}:
                size = known.get(args[0])
                if type(size) is not int or size < 0 or size > MAX_REQUEST:
                    _reject(f"{fn['name']}/{name}: allocator extent is not a finite constant")
                owner[out_names[0]] = size
                peak = max(peak, sum(owner.values()))
            elif op == "owner.move":
                if args[0] not in owner:
                    _reject(f"{fn['name']}/{name}: owner move has no bounded source")
                owner[out_names[0]] = owner.pop(args[0])
            elif op == "owner.drop":
                if args[0] not in owner:
                    _reject(f"{fn['name']}/{name}: drop has no bounded source")
                owner.pop(args[0])
            elif op == "call":
                child = functions[attrs["function"]]
                if (any(p["type"] in {"buffer", "readbuf", "mutbuf"} for p in child["params"])
                        or any(t in {"buffer", "readbuf", "mutbuf"} for t in child["returns"])):
                    _reject(f"{fn['name']}/{name}: interprocedural resource transfer requires a separate proof")
                if child["name"] not in calculated:
                    _reject(f"{fn['name']}/{name}: callee heap bound not available")
                peak = max(peak, sum(owner.values()) + calculated[child["name"]])
            elif op not in _NO_ALLOCATION_OPS:
                _reject(f"{fn['name']}/{name}: unreviewed opcode {op} has no heap accounting")
            # Audited nonallocating scalar/memory operations produce unknown
            # scalar values; unknowns cannot later qualify allocation size.
        for edge in _paths(block["term"]):
            target = blocks[edge["target"]]
            next_owner, next_known = {}, {}
            for source_name, param in zip(edge["args"], target["params"]):
                if param["type"] == "buffer":
                    if source_name not in owner:
                        _reject(f"{fn['name']}/{name}: missing bounded owner at edge")
                    next_owner[param["name"]] = owner[source_name]
                elif (param["type"] in WIDTHS or param["type"] in {"bool", "unit"}) and source_name in known:
                    next_known[param["name"]] = known[source_name]
            proposed = (next_owner, next_known)
            dest = edge["target"]
            states[dest] = (_merge(states[dest], proposed, f"{fn['name']}/{dest}")
                            if dest in states else proposed)
    return peak


def analyze_constant_live_heap(program) -> dict:
    """Bound all function entries; verified program is the *sole* admission.

    The result's integer is a conservative peak of requested live HIA buffer
    payload bytes on normal, nontrapping CFG paths. It never bounds allocator
    metadata, transient OS memory or native process RSS.
    """
    checked = verify_program(program)
    document = checked.as_dict()
    if type(document) is not dict or document.get("schema") not in _ALLOWED_SCHEMAS:
        _reject("unknown HIA executable schema needs a fresh heap-bound review")
    functions = document["functions"]
    by_name = {fn["name"]: fn for fn in functions}
    calls = {fn["name"]: {ins["attrs"]["function"]
                          for block in fn["blocks"] for ins in block["ops"]
                          if ins["op"] == "call"} for fn in functions}
    order = _dag(list(by_name), calls, "HIA heap call graph")
    calculated = {}
    for fn_name in reversed(order):
        calculated[fn_name] = _function(by_name[fn_name], by_name, calculated)
    return {fn["name"]: calculated[fn["name"]] for fn in functions}
