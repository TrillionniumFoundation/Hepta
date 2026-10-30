"""Closed runtime-context specialization for a selected scalar leaf Core.

The proposer has no authority. Admission checks the entire guarded candidate,
including guard misses, against the original over every input bitvector. No
assumption about a later workload is imported into that proof. This pass has
no memory operations; budgets for instruction count must be requalified.
"""
from __future__ import annotations
from copy import deepcopy
from hashlib import sha256
import json
import time
from .hia_program import verify_program
from .hia_optimization import _fresh, PINNED_Z3_VERSION, _solver_identity
from .hia_scalar_lowering_check import _reference

class ContextSpecializationRejected(ValueError):
    pass

def _require(value, message):
    if not value:
        raise ContextSpecializationRejected(message)

def selected_leaf(program, function):
    checked = verify_program(program)
    document = checked.as_dict()
    found = [f for f in document["functions"] if f["name"] == function]
    _require(len(found) == 1, "unknown selected function")
    fn = found[0]
    _require(len(fn["blocks"]) == 1 and len(fn["params"]) <= 8
             and fn["returns"] == ["i32"] and fn["effects"] == ["trap"]
             and all(p["type"] == "i32" for p in fn["params"]),
             "only a bounded i32 scalar leaf is admitted")
    block = fn["blocks"][0]
    _require(block["term"]["op"] == "ret" and len(block["ops"]) <= 32,
             "selected leaf must return directly")
    _require(all(o["op"] in {"const", "int.div.checked", "int.rem.checked",
        "int.add.checked", "int.sub.checked", "int.mul.checked", "bit.and",
        "bit.or", "bit.xor", "int.add.wrap", "int.sub.wrap", "int.mul.wrap"}
        for o in block["ops"]), "resource/call/unsupported operation rejected")
    return verify_program({"schema": document["schema"], "module": "selected_context_leaf",
                           "exports": [function], "functions": [deepcopy(fn)]})

def propose_context_specialization(program, *, parameter, value):
    base = verify_program(program)
    source = base.as_dict()
    _require(len(source["functions"]) == 1, "one selected leaf required")
    base = selected_leaf(base, source["functions"][0]["name"])
    source = base.as_dict()
    fn = source["functions"][0]
    _require(type(parameter) is int and 0 <= parameter < len(fn["params"]), "invalid parameter")
    _require(type(value) is int and -(1 << 31) <= value < (1 << 31), "i32 context required")
    _require(all(not p["name"].startswith("ctx_") for p in fn["params"])
        and all(not o["out"][0]["name"].startswith("ctx_") for o in fn["blocks"][0]["ops"]),
        "reserved context identifier collision")
    original = deepcopy(fn["blocks"][0])
    def clone(prefix, identifier):
        block = deepcopy(original)
        mapping = {p["name"]: prefix + p["name"] for p in block["params"]}
        mapping.update({p["name"]: prefix + p["name"] for o in block["ops"] for p in o["out"]})
        block["id"] = identifier
        for p in block["params"]: p["name"] = mapping[p["name"]]
        for o in block["ops"]:
            o["args"] = [mapping[a] for a in o["args"]]
            for p in o["out"]: p["name"] = mapping[p["name"]]
        block["term"]["values"] = [mapping[a] for a in block["term"]["values"]]
        return block
    fallback = clone("ctx_f_", "ctx_fallback")
    hot = clone("ctx_h_", "ctx_hot")
    name = fn["params"][parameter]["name"]
    hot_name = "ctx_h_" + name
    hot["ops"].insert(0, {"op": "const", "args": [], "out": [{"name": "ctx_bound", "type": "i32"}], "attrs": {"value": value}})
    for operation in hot["ops"][1:]:
        operation["args"] = ["ctx_bound" if arg == hot_name else arg for arg in operation["args"]]
    hot["term"]["values"] = ["ctx_bound" if arg == hot_name else arg for arg in hot["term"]["values"]]
    names = [p["name"] for p in fn["params"]]
    entry = {"id": "ctx_guard", "params": deepcopy(fn["params"]), "ops": [
        {"op": "const", "args": [], "out": [{"name": "ctx_value", "type": "i32"}], "attrs": {"value": value}},
        {"op": "compare.eq", "args": [name, "ctx_value"], "out": [{"name": "ctx_match", "type": "bool"}], "attrs": {}}
    ], "term": {"op": "branch", "cond": "ctx_match", "then": {"target": "ctx_hot", "args": names}, "else": {"target": "ctx_fallback", "args": names}}}
    fn["entry"] = "ctx_guard"
    fn["blocks"] = [entry, hot, fallback]
    return verify_program(source)

def verify_context_specialization(base, candidate, *, timeout_ms=5000):
    """All-input selected return/abort relation, with fail-closed SMT result.

    The current encoder observes abort, not the diagnostic identity of two
    different traps. Therefore this closed profile admits exactly one checked
    divide operation in the source and its duplicated guarded copies, preserving
    its exact operation/arguments on each path. It does not accept a general
    semantics-changing candidate solely from a matching return/abort formula.
    """
    import z3 as z
    _require(type(timeout_ms) is int and 1 <= timeout_ms <= 30000, "invalid proof budget")
    _require(z.get_version_string() == PINNED_Z3_VERSION, "pinned Z3 required")
    a, b = verify_program(base), verify_program(candidate)
    ad, bd = a.as_dict(), b.as_dict()
    _require(len(ad["functions"]) == len(bd["functions"]) == 1, "one function required")
    af, bf = ad["functions"][0], bd["functions"][0]
    _require(af["name"] == bf["name"] and af["params"] == bf["params"]
             and af["returns"] == bf["returns"] and af["effects"] == bf["effects"], "interface/effects changed")
    a = selected_leaf(a, af["name"])
    normalized = a.as_dict()
    _require(bd["schema"] == normalized["schema"], "semantic version drift requires an explicit adapter")
    _require(bd.get("exports") == normalized["exports"], "public exports changed")
    source_block = af["blocks"][0]
    _require(len(source_block["ops"]) == 1 and source_block["ops"][0]["op"] == "int.div.checked"
             and len(af["params"]) == 2 and source_block["ops"][0]["args"] == [p["name"] for p in af["params"]],
             "admission currently requires the exact two-argument checked divide leaf")
    blocks = {block["id"]: block for block in bf["blocks"]}
    _require(set(blocks) == {"ctx_guard", "ctx_hot", "ctx_fallback"} and bf["entry"] == "ctx_guard", "guarded shape changed")
    guard, hot, fallback = (blocks[name] for name in ("ctx_guard", "ctx_hot", "ctx_fallback"))
    _require(len(guard["ops"]) == 2 and guard["ops"][0]["op"] == "const", "guard constant missing")
    value = guard["ops"][0]["attrs"].get("value")
    # Independent structural obligations. Do not invoke the proposer here.
    _require(type(value) is int and 2 <= value <= (1 << 31)-1, "selected divisor must be positive and at least two")
    names = [p["name"] for p in af["params"]]
    expected_guard = {"id": "ctx_guard", "params": af["params"], "ops": [
        {"op": "const", "args": [], "out": [{"name": "ctx_value", "type": "i32"}], "attrs": {"value": value}},
        {"op": "compare.eq", "args": [names[1], "ctx_value"], "out": [{"name": "ctx_match", "type": "bool"}], "attrs": {}}
    ], "term": {"op": "branch", "cond": "ctx_match", "then": {"target": "ctx_hot", "args": names}, "else": {"target": "ctx_fallback", "args": names}}}
    _require(guard == expected_guard, "guard/transfer differs")
    # Only one source operation is allowed, so validate its alpha-renamed
    # operands, result and exact terminator explicitly, independent of cloning.
    source_op = source_block["ops"][0]
    out_name = source_op["out"][0]["name"]
    _require(source_op["out"] == [{"name": out_name, "type": "i32"}]
             and source_op["attrs"] == {} and source_block["term"] == {"op": "ret", "values": [out_name]},
             "source is outside the selected divide-and-return relation")
    expected_fallback = {"id": "ctx_fallback", "params": [{"name": "ctx_f_" + n, "type": "i32"} for n in names],
        "ops": [{"op": "int.div.checked", "args": ["ctx_f_" + n for n in names],
            "out": [{"name": "ctx_f_" + out_name, "type": "i32"}], "attrs": {}}],
        "term": {"op": "ret", "values": ["ctx_f_" + out_name]}}
    _require(fallback == expected_fallback, "fallback must preserve the original instruction and trap")
    expected_hot = {"id": "ctx_hot", "params": [{"name": "ctx_h_" + n, "type": "i32"} for n in names],
        "ops": [{"op": "int.div.checked", "args": ["ctx_h_" + names[0], "ctx_bound"],
            "out": [{"name": "ctx_h_" + out_name, "type": "i32"}], "attrs": {}}],
        "term": {"op": "ret", "values": ["ctx_h_" + out_name]}}
    expected_hot["ops"].insert(0, {"op": "const", "args": [], "out": [{"name": "ctx_bound", "type": "i32"}], "attrs": {"value": value}})
    _require(hot == expected_hot, "hot path differs from the guarded substitution")
    before = sha256(__import__("pathlib").Path(__file__).read_bytes()).hexdigest()
    context = z.Context()
    inputs = {p["name"]: _fresh(z, p["name"], p["type"], context) for p in af["params"]}
    ar, aa, astep = _reference(z, context, af, inputs, ad)
    # Case splitting is justified by the separately checked exhaustive guard.
    # Bind the selected parameter before encoding the hot source. This is
    # congruence under d == K, not an unchecked workload precondition, and
    # avoids asking a bit-blaster to rediscover symbolic division congruence.
    hot_inputs = dict(inputs)
    hot_inputs[names[1]] = (z.BitVecVal(value, 32, ctx=context), "i32")
    hot_source, hot_abort, _ = _reference(z, context, af, hot_inputs, ad)
    hot_fn = dict(bf, entry="ctx_hot", params=hot["params"], blocks=[hot])
    fallback_fn = dict(bf, entry="ctx_fallback", params=fallback["params"], blocks=[fallback])
    hr, ha, hstep = _reference(z, context, hot_fn,
        {"ctx_h_"+n: inputs[n] for n in names}, bd)
    fr, fa, fstep = _reference(z, context, fallback_fn,
        {"ctx_f_"+n: inputs[n] for n in names}, bd)
    def disagreement(left, left_abort, right, right_abort):
        return z.Or(left_abort != right_abort,
            z.Or(*[path for path, _ in left]) != z.Or(*[path for path, _ in right]),
            *[z.And(lp, rp, lv != rv) for lp, lv in left for rp, rv in right])
    match = inputs[names[1]][0] == z.BitVecVal(value, 32, ctx=context)
    mismatch = z.Or(z.Not(z.Or(match, z.Not(match))),
        disagreement(hot_source, hot_abort, hr, ha), disagreement(ar, aa, fr, fa))
    bstep = 3 + hstep + fstep
    solver = z.Solver(ctx=context); solver.set(timeout=timeout_ms); solver.add(mismatch)
    query = solver.sexpr(); started = time.monotonic_ns(); result = solver.check(); wall = time.monotonic_ns()-started
    _require(before == sha256(__import__("pathlib").Path(__file__).read_bytes()).hexdigest(), "checker changed during proof")
    return {"schema": "hepta.hia.context-specialization.v1", "verified": result == z.unsat,
        "status": "verified" if result == z.unsat else "refuted" if result == z.sat else "unknown",
        "source_sha256": a.sha256, "candidate_sha256": b.sha256, "checker_sha256": before,
        "solver": _solver_identity(z), "smt2": query, "smt2_sha256": sha256(query.encode()).hexdigest(),
        "solver_wall_ns": wall, "all_i32_input_pairs": 1 << 64, "external_preconditions": [], "proof_partition": ["exhaustive equality guard", "hot parameter substitution", "unchanged fallback"],
        "guard_value": value, "resources": "no owned resources or allocation operations",
        "preserved": ["return value", "first divide trap and diagnostic", "public signature", "empty ordered resource trace"],
        "budgets_requalified": ["ticks", "native code bytes", "compile wall time", "switch and retirement costs"],
        "source_symbolic_steps": astep, "candidate_symbolic_steps": bstep,
        "machine_code_proof": False, "host_and_compiler_remain_trusted": True}
