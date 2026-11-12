"""Small, independently checked unsigned invariants for guarded Core rewrites.

An invariant is never trusted because a producer emitted it. Entry and every
control-flow edge must establish it; each removed checked operation must be
nontrapping at its actual position. Resource operations are unchanged barriers.
Their successful scalar outputs are arbitrary values of the declared widths.
This overapproximates memory and therefore cannot silently assume buffer data.
"""
from __future__ import annotations

from .hia_program import SCALARS, WIDTHS
from .hia_optimization import PURE, _Encoder, _fresh


UNSIGNED = frozenset({"u8", "u16", "u32", "u64", "usize"})
MAX_CONSTRAINTS = 4096
MAX_FACTOR = 65535
WIDE = 128


def validate_invariants(function, raw):
    blocks = {block["id"]: block for block in function["blocks"]}
    if type(raw) is not dict or len(raw) != len(blocks) or set(raw) != set(blocks):
        raise ValueError("each guarded block must have an explicit invariant list")
    result, total = {}, 0
    for name, block in blocks.items():
        constraints = raw[name]
        if type(constraints) is not list:
            raise ValueError("invariant constraints must be lists")
        total += len(constraints)
        if total > MAX_CONSTRAINTS:
            raise ValueError("invariant constraint budget exceeded")
        types = {p["name"]: p["type"] for p in block["params"]}
        copied = []
        for item in constraints:
            if type(item) is not dict or type(item.get("op")) is not str:
                raise ValueError("invalid invariant predicate")
            op = item["op"]
            expected = ({"op", "left", "limit"} if op == "le_const" else
                        {"op", "left", "right", "factor"} if op == "scaled_le" else
                        {"op", "left", "right"} if op in {"le", "lt", "eq"} else None)
            if expected is None or set(item) != expected:
                raise ValueError("unsupported or inexact invariant predicate")
            for key in ("left", "right"):
                if key in item and (type(item[key]) is not str or types.get(item[key]) not in UNSIGNED):
                    raise ValueError("invariants refer only to unsigned block parameters")
            if op == "le_const" and (type(item["limit"]) is not int or not 0 <= item["limit"] < 2**64):
                raise ValueError("invalid invariant constant")
            if op == "scaled_le" and (type(item["factor"]) is not int or not 0 <= item["factor"] <= MAX_FACTOR):
                raise ValueError("invalid invariant multiplier")
            copied.append(dict(item))
        result[name] = copied
    return result


def predicate(z, context, env, constraints):
    def wide(name):
        value, typ = env[name]
        if typ not in UNSIGNED:
            raise ValueError("an unsigned invariant received a different scalar type")
        return z.ZeroExt(WIDE - WIDTHS[typ], value)

    terms = []
    for c in constraints:
        left = wide(c["left"])
        if c["op"] == "le_const":
            term = z.ULE(left, z.BitVecVal(c["limit"], WIDE, ctx=context))
        else:
            right = wide(c["right"])
            if c["op"] == "scaled_le":
                # The largest product is (2**64-1)*65535 < 2**80. Widening
                # prevents a producer from exploiting multiplication wrap.
                term = z.ULE(left, right * c["factor"])
            elif c["op"] == "le":
                term = z.ULE(left, right)
            elif c["op"] == "lt":
                term = z.ULT(left, right)
            else:
                term = left == right
        terms.append(term)
    return z.And(*terms) if terms else z.BoolVal(True, ctx=context)


def check_function(z, context, function, guard, invariants, changes, discharge):
    """Discharge complete entry/edge and local no-overflow obligations.

    `discharge` owns the whole-request deadline and evidence. It raises on any
    result other than UNSAT. No native code or candidate interpreter is used.
    """
    blocks = {b["id"]: b for b in function["blocks"]}
    entry = blocks[function["entry"]]
    prefix = function["name"] + "."
    inputs = {p["name"]: _fresh(z, prefix + "entry:" + p["name"], p["type"], context)
              for p in entry["params"] if p["type"] in SCALARS}
    value, typ = inputs[guard["argument"]]
    actual_guard = z.ULE(value, z.BitVecVal(guard["maximum"], WIDTHS[typ], ctx=context))
    discharge({"function": function["name"], "kind": "guard_establishes_entry"},
              z.And(actual_guard, z.Not(predicate(z, context, inputs, invariants[entry["id"]]))))
    for block in function["blocks"]:
        bid = block["id"]
        env = {p["name"]: _fresh(z, prefix + bid + ".input:" + p["name"], p["type"], context)
               for p in block["params"] if p["type"] in SCALARS}
        assumption = predicate(z, context, env, invariants[bid])
        encoder = _Encoder(z, env, context)
        for index, op in enumerate(block["ops"]):
            if op["op"] in PURE:
                before_trap = encoder.trap
                encoder.operation(op)
                if (bid, index) in changes:
                    discharge({"function": function["name"], "block": bid,
                               "operation": index, "kind": "removed_check_cannot_trap"},
                              z.And(assumption, before_trap == 0, encoder.trap != 0))
            else:
                # Successful effect outputs are unconstrained typed values.
                # Any actual effect trap stops both programs at this barrier.
                for output in op["out"]:
                    if output["type"] in SCALARS:
                        encoder.env[output["name"]] = _fresh(
                            z, prefix + bid + f".effect:{index}:" + output["name"],
                            output["type"], context)
        term = block["term"]
        if term["op"] == "jump":
            edges = [(term, z.BoolVal(True, ctx=context))]
        elif term["op"] == "branch":
            condition, typ = encoder.env[term["cond"]]
            if typ != "bool":
                raise ValueError("nonboolean branch in verified program")
            edges = [(term["then"], condition), (term["else"], z.Not(condition))]
        else:
            edges = []
        for edge, condition in edges:
            target = blocks[edge["target"]]
            transported = {p["name"]: encoder.env[a] for p, a in zip(target["params"], edge["args"])
                           if p["type"] in SCALARS}
            discharge({"function": function["name"], "block": bid,
                       "target": target["id"], "kind": "inductive_edge"},
                      z.And(assumption, encoder.trap == 0, condition,
                            z.Not(predicate(z, context, transported, invariants[target["id"]]))))
