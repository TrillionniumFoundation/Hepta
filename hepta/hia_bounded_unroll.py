"""All-input checked finite unfolding of one scalar feedback edge.

The proposer is not an admission authority.  The validator reconstructs the
reference from canonical source bytes, proves its truncation edge unreachable,
then invokes the existing acyclic value/first-trap checker.  A guessed trip
count, serialized receipt, sampled execution, or solver timeout cannot admit a
candidate.  The graph copier and SMT encoder remain trusted implementations;
this is not a machine-checked proof of the compiler or original C frontend.
"""
from __future__ import annotations

from collections import deque
import copy
from hashlib import sha256
from pathlib import Path

from .hia_program import HIAProgramRejected, verify_program
from .hia_translation_validation import (
    MAX_BLOCKS, MAX_OPERATIONS, MAX_TIMEOUT_MS, QUALIFIED_CORE_SCHEMAS,
    _Encoder, _OutsideProfile, _profile, _signature, _z3_module,
    validate_translation,
)

SCHEMA = "hepta.hia.bounded-unroll-validation.v1"
PROFILE = "hia.scalar-single-feedback-unfold.v1"
MAX_BACKEDGES = 32


def _reject(message):
    raise HIAProgramRejected(message, "E_HIA_BOUNDED_UNROLL")


def checker_identity():
    digest = sha256()
    for name in ("hia_bounded_unroll.py", "hia_translation_validation.py", "hia_program.py", "hia_opcodes.py", "hia_semantic_kernel.py"):
        digest.update(name.encode() + b"\0" + Path(__file__).with_name(name).read_bytes() + b"\0")
    return digest.hexdigest()


def _edges(block):
    term = block["term"]
    return ([term] if term["op"] == "jump" else
            [term["then"], term["else"]] if term["op"] == "branch" else [])


def _source(document, function, maximum):
    if type(maximum) is not int or not 0 <= maximum <= MAX_BACKEDGES:
        _reject("feedback traversal budget must be an exact integer in 0..32")
    checked = verify_program(document)
    if checked.structured_bytes is not None or checked.as_dict()["schema"] not in QUALIFIED_CORE_SCHEMAS:
        _reject("only qualified primitive v1-v7 Core is supported")
    if type(function) is not str or function not in checked.scalar_entrypoints:
        _reject("a public scalar function is required")
    fn = next(f for f in checked.as_dict()["functions"] if f["name"] == function)
    try:
        _profile(fn)
    except _OutsideProfile as error:
        if str(error) != "cyclic_cfg_outside_profile":
            _reject(str(error))
    else:
        _reject("a cyclic scalar function is required")
    blocks = {b["id"]: b for b in fn["blocks"]}
    colors, feedback = {}, set()

    def visit(ident):
        colors[ident] = 1
        for target in sorted({e["target"] for e in _edges(blocks[ident])}):
            if colors.get(target) == 1:
                feedback.add((ident, target))
            elif not colors.get(target):
                visit(target)
        colors[ident] = 2

    visit(fn["entry"])
    for ident in sorted(blocks):
        if not colors.get(ident):
            visit(ident)
    if len(feedback) != 1:
        _reject("exactly one DFS feedback edge is supported")
    return checked, fn, next(iter(feedback))


def _unfold(document, function, maximum):
    original, fn, feedback = _source(document, function, maximum)
    blocks = {b["id"]: b for b in fn["blocks"]}
    initial = (fn["entry"], 0)
    pending, states, indices = deque([initial]), [], {initial: 0}
    operations = 0
    while pending:
        state = pending.popleft()
        states.append(state)
        ident, traversals = state
        operations += len(blocks[ident]["ops"])
        if len(states) + 1 > MAX_BLOCKS or operations + len(states) + 1 > MAX_OPERATIONS:
            _reject("unfolded scalar proof budget exceeded")
        for edge in _edges(blocks[ident]):
            following = traversals + ((ident, edge["target"]) == feedback)
            if following > maximum:
                continue
            target = (edge["target"], following)
            if target not in indices:
                if len(indices) + 2 > MAX_BLOCKS:
                    _reject("unfolded block budget exceeded")
                indices[target] = len(indices)
                pending.append(target)
    renamed, unfolded = {}, []
    for state in states:
        block, index = blocks[state[0]], indices[state]
        definitions = block["params"] + [p for op in block["ops"] for p in op["out"]]
        names = {p["name"]: f"unroll_{index}_v_{i}" for i, p in enumerate(definitions)}
        if state == initial:
            names.update({p["name"]: p["name"] for p in block["params"]})
        renamed[state] = names
    # Synthetic names use an entirely separate namespace, except the mandatory
    # original entry parameters. Reject collisions instead of shadowing inputs.
    all_names = [name for names in renamed.values() for name in names.values()]
    if len(all_names) != len(set(all_names)) or "unroll_limit_value" in all_names:
        _reject("input names collide with bounded unfolding namespace")
    for state in states:
        ident, traversals = state
        block, names = copy.deepcopy(blocks[ident]), renamed[state]
        block["id"] = f"unroll_{indices[state]}"
        for param in block["params"]:
            param["name"] = names[param["name"]]
        for op in block["ops"]:
            op["args"] = [names[name] for name in op["args"]]
            for out in op["out"]:
                out["name"] = names[out["name"]]
        term = block["term"]
        if term["op"] == "ret":
            term["values"] = [names[name] for name in term["values"]]
        elif term["op"] == "branch":
            term["cond"] = names[term["cond"]]
        for edge in _edges(block):
            following = traversals + ((ident, edge["target"]) == feedback)
            if following > maximum:
                edge.update(target="unroll_limit", args=[])
            else:
                edge["target"] = f"unroll_{indices[(edge['target'], following)]}"
                edge["args"] = [names[name] for name in edge["args"]]
        unfolded.append(block)
    unfolded.append({"id": "unroll_limit", "params": [], "ops": [],
                     "term": {"op": "trap", "code": "user"}})
    reference = original.as_dict()
    target = next(f for f in reference["functions"] if f["name"] == function)
    target.update(entry="unroll_0", blocks=unfolded,
                  effects=sorted(set(fn["effects"]) | {"trap"}))
    checked = verify_program(reference)
    # This independently checks that no cycle survived the graph construction.
    _profile(next(f for f in checked.as_dict()["functions"] if f["name"] == function))
    return original, checked, feedback


def propose_bounded_unroll(document, *, function, max_backedges):
    """Return an untrusted, finite candidate; its bound is not an assumption."""
    before, after, feedback = _unfold(document, function, max_backedges)
    return {"schema": "hepta.hia.bounded-unroll-proposal.v1", "base_sha256": before.sha256,
            "function": function, "max_backedges": max_backedges,
            "feedback_edge": list(feedback), "program": after.as_dict(),
            "authorizes_execution": False}


def _marker(reference, function):
    fn = next(f for f in reference.as_dict()["functions"] if f["name"] == function)
    fn["returns"] = ["bool"]
    for index, block in enumerate(fn["blocks"]):
        limit = block["id"] == "unroll_limit"
        if limit or block["term"]["op"] == "ret":
            name = "unroll_limit_value" if limit else f"unroll_marker_{index}"
            definitions = {p["name"] for b in fn["blocks"] for p in b["params"]}
            definitions.update(p["name"] for b in fn["blocks"] for op in b["ops"] for p in op["out"])
            if name in definitions:
                _reject("marker namespace collision")
            block["ops"].append({"op": "const", "args": [],
                "out": [{"name": name, "type": "bool"}], "attrs": {"value": limit}})
            block["term"] = {"op": "ret", "values": [name]}
    return verify_program({"schema": "hepta.hia.program.v1", "module": "bounded_marker",
                           "functions": [fn]})


def validate_bounded_translation(before, after, *, function, max_backedges, timeout_ms=2000):
    """Prove the bound and then compare values/first traps for all typed inputs.

    The timeout applies separately to the bound and equivalence SMT queries.
    No wall-clock deadline or unbounded-loop/general resource proof is claimed.
    """
    result = {"schema": SCHEMA, "profile": PROFILE, "status": "unknown",
        "function": function, "max_backedges": max_backedges, "timeout_ms": timeout_ms,
        "before_sha256": None, "after_sha256": None, "reference_sha256": None,
        "checker_sha256": checker_identity(), "reason": None, "counterexample": None,
        "bound_solver": {"result": "not_run", "version": None}, "equivalence": None,
        "claims": {"all_input_bound_proved": False, "all_input_behavior_equivalence_proved": False,
                   "first_trap_code_preserved": False, "resource_safety_proved": False,
                   "frontend_refinement_proved": False, "machine_code_refinement_proved": False,
                   "encoder_refinement_machine_proved": False,
                   "serialized_receipt_authorizes_execution": False}}
    if type(timeout_ms) is not int or not 1 <= timeout_ms <= MAX_TIMEOUT_MS:
        result["reason"] = "invalid_solver_timeout"
        return result
    try:
        original, reference, feedback = _unfold(before, function, max_backedges)
        candidate = verify_program(after)
        result.update(before_sha256=original.sha256, after_sha256=candidate.sha256,
                      reference_sha256=reference.sha256, feedback_edge=list(feedback))
        left, right = original.as_dict(), candidate.as_dict()
        if {k: v for k, v in left.items() if k != "functions"} != {k: v for k, v in right.items() if k != "functions"}:
            _reject("candidate changes module interface")
        if [f["name"] for f in left["functions"]] != [f["name"] for f in right["functions"]]:
            _reject("candidate changes function inventory")
        for first, second in zip(left["functions"], right["functions"]):
            if first["name"] != function and first != second:
                _reject("candidate changes an unproved function")
            if first["name"] == function:
                if _signature(first) != _signature(second):
                    _reject("candidate changes selected signature")
                _profile(second)
        marker = _marker(reference, function)
        fn = marker.as_dict()["functions"][0]
        graph = _profile(fn)
    except (HIAProgramRejected, _OutsideProfile) as error:
        result["reason"] = "outside_profile: " + str(error)
        return result
    try:
        z = _z3_module()
    except (ImportError, OSError):
        result["reason"] = "solver_unavailable"
        return result
    try:
        encoder = _Encoder(z)
        inputs = [encoder.input(i, p["type"]) for i, p in enumerate(fn["params"])]
        tag, values = encoder.function(fn, inputs, *graph)
        solver = z.Solver(ctx=encoder.context)
        solver.set(timeout=timeout_ms)
        solver.add(z.Or(tag < 0, z.And(tag == 0, values[0])))
        verdict = solver.check()
        result["bound_solver"].update(result=str(verdict), version=z.get_version_string())
        if verdict != z.unsat:
            result["reason"] = "bound_unknown" if verdict != z.sat else "bound_exceeded_for_typed_input"
            if verdict == z.sat:
                from .hia_program_runtime import execute_program
                model = solver.model()
                arguments = [encoder.concrete(model, v, p["type"]) for v, p in zip(inputs, fn["params"])]
                observation = execute_program(marker, function, arguments,
                                              max_steps=MAX_OPERATIONS + MAX_BLOCKS + 2)
                if observation["values"] != [True]:
                    result["reason"] = "bound_counterexample_replay_disagrees"
                    return result
                result["status"] = "disproved"
                result["counterexample"] = {"arguments": arguments, "marker_values": observation["values"]}
            else:
                result["bound_solver"]["reason_unknown"] = solver.reason_unknown()
            return result
    except z.Z3Exception as error:
        result["reason"] = "solver_error: " + str(error)
        return result
    result["claims"]["all_input_bound_proved"] = True
    proof = validate_translation(reference, candidate, function=function, timeout_ms=timeout_ms)
    result["equivalence"] = proof
    result["status"], result["reason"] = proof["status"], proof["reason"]
    if proof["status"] == "proved":
        result["claims"].update(all_input_behavior_equivalence_proved=True, first_trap_code_preserved=True)
    elif proof["status"] == "disproved":
        result["counterexample"] = proof["counterexample"]
    return result


def verify_bounded_translation_receipt(before, after, receipt, *, function, max_backedges, timeout_ms=2000):
    """Recompute both obligations at use; a forged receipt cannot authorize code."""
    if type(receipt) is not dict or receipt.get("status") != "proved":
        _reject("a proved bounded translation receipt is required")
    fresh = validate_bounded_translation(before, after, function=function,
                                        max_backedges=max_backedges, timeout_ms=timeout_ms)
    keys = ("schema", "profile", "function", "max_backedges", "before_sha256", "after_sha256",
            "reference_sha256", "checker_sha256")
    if fresh["status"] != "proved" or any(receipt.get(k) != fresh[k] for k in keys):
        _reject("bounded proof is stale, forged or cannot be recomputed")
    return fresh
