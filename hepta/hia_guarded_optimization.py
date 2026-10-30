"""Proof-checked guarded reduction with a complete original Core fallback.

The untrusted proposer identifies simple counted byte reductions. An independent
inductive checker establishes every block invariant and proves each removed
overflow check unreachable under the input guard. A canonical Core composition
places that guard before any original effect, clones the original slow CFG,
and carries the same resources through exactly one chosen body. Compilation
uses the existing standalone verifier/emitter/publication gate without custom IR.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import time

from .hia_program import verify_program, SCALARS, WIDTHS, HIAProgramRejected
from .hia_optimization import (OptimizationRejected, DEFAULT_POLICY, PINNED_Z3_VERSION,
                               _policy, _solver_identity, _digest, _wire, checker_identity)
from .hia_inductive import UNSIGNED, MAX_CONSTRAINTS, validate_invariants, check_function


SCHEMA = "hepta.hia.guarded-reduction-proposal.v1"
VERIFY_SCHEMA = "hepta.hia.guarded-optimization-verification.v1"
BYTE_SUM_LIMIT = (2**64 - 1) // 255


def guarded_checker_identity():
    h = sha256(checker_identity().encode())
    for name in ("hia_guarded_optimization.py", "hia_inductive.py", "hia_guarded_native_binding.py"):
        h.update(name.encode() + b"\0" + Path(__file__).with_name(name).read_bytes() + b"\0")
    return h.hexdigest()


def _aliases(function):
    """Untrusted finite origin propagation used only to propose invariants."""
    blocks = {b["id"]: b for b in function["blocks"]}
    origins = {b["id"]: {p["name"]: frozenset() for p in b["params"]} for b in function["blocks"]}
    entry = origins[function["entry"]]
    for p in function["params"]:
        entry[p["name"]] = frozenset({p["name"]})
    pending = [function["entry"]]
    seen = set()
    while pending:
        bid = pending.pop()
        block, env = blocks[bid], dict(origins[bid])
        for op in block["ops"]:
            for out in op["out"]:
                env[out["name"]] = frozenset({None})
        term = block["term"]
        edges = [term] if term["op"] == "jump" else [term["then"], term["else"]] if term["op"] == "branch" else []
        for edge in edges:
            target = edge["target"]
            changed = target not in seen
            for p, a in zip(blocks[target]["params"], edge["args"]):
                old = origins[target][p["name"]]
                combined = old | env[a]
                if None in combined or len(combined) > 1:
                    combined = frozenset({None})
                if old != combined:
                    origins[target][p["name"]] = combined
                    changed = True
            if changed:
                pending.append(target)
                seen.add(target)
    return origins


def propose_guarded_reduction(program, maximum=None):
    original = verify_program(program)
    data, fast = original.as_dict(), original.as_dict()
    if maximum is None:
        maximum = BYTE_SUM_LIMIT
    if type(maximum) is not int or not 0 <= maximum <= BYTE_SUM_LIMIT:
        raise OptimizationRejected("E_HIA_GUARD_LIMIT: expected an unsigned safe byte-count limit")
    guards, invariants, changes = [], {}, []
    for fn, rewritten in zip(data["functions"], fast["functions"]):
        blocks = {b["id"]: b for b in fn["blocks"]}
        rewritten_blocks = {b["id"]: b for b in rewritten["blocks"]}
        aliases = _aliases(fn)
        candidates = []
        for header in fn["blocks"]:
            term = header["term"]
            if term["op"] != "branch" or len(header["ops"]) != 1:
                continue
            compare = header["ops"][0]
            if compare["op"] != "compare.lt" or compare["out"][0]["name"] != term["cond"]:
                continue
            index, limit = compare["args"]
            hp = {p["name"]: p for p in header["params"]}
            if index not in hp or limit not in hp or hp[index]["type"] != "usize" or hp[limit]["type"] != "usize":
                continue
            limit_origin = aliases[header["id"]][limit]
            if len(limit_origin) != 1 or None in limit_origin:
                continue
            argument = next(iter(limit_origin))
            body = blocks[term["then"]["target"]]
            if body["term"]["op"] != "jump" or body["term"]["target"] != header["id"]:
                continue
            mapping = {a: p["name"] for a, p in zip(term["then"]["args"], body["params"])}
            if index not in mapping or limit not in mapping:
                continue
            outputs = {out["name"]: op for op in body["ops"] for out in op["out"]}
            incoming = {p["name"]: a for p, a in zip(header["params"], body["term"]["args"])}
            step = outputs.get(incoming[index])
            if not step or step["op"] != "int.add.checked" or step["args"][0] != mapping[index]:
                continue
            one = outputs.get(step["args"][1])
            if not one or one["op"] != "const" or one["attrs"].get("value") != 1:
                continue
            for param in header["params"]:
                acc = param["name"]
                if param["type"] != "u64" or acc not in mapping:
                    continue
                add = outputs.get(incoming[acc])
                if not add or add["op"] != "int.add.checked" or mapping[acc] not in add["args"]:
                    continue
                other = add["args"][1] if add["args"][0] == mapping[acc] else add["args"][0]
                cast = outputs.get(other)
                if not cast or cast["op"] != "int.cast" or cast["out"][0]["type"] != "u64":
                    continue
                value = outputs.get(cast["args"][0])
                if not value or len(value["out"]) != 1 or value["out"][0]["type"] != "u8":
                    continue
                candidates.append((argument, header, body, index, limit, acc, mapping, add))
        if not candidates:
            continue
        argument = candidates[0][0]
        chosen = [c for c in candidates if c[0] == argument]
        guard = {"function": fn["name"], "argument": argument, "maximum": maximum}
        guards.append(guard)
        inv = {b["id"]: [{"op": "le_const", "left": p["name"], "limit": maximum}
                         for p in b["params"] if p["type"] in UNSIGNED
                         and aliases[b["id"]][p["name"]] == frozenset({argument})]
               for b in fn["blocks"]}
        for _, header, body, index, limit, acc, mapping, add in chosen:
            inv[header["id"]] += [{"op": "le", "left": index, "right": limit},
                                   {"op": "scaled_le", "left": acc, "right": index, "factor": 255}]
            inv[body["id"]] += [{"op": "lt", "left": mapping[index], "right": mapping[limit]},
                                 {"op": "scaled_le", "left": mapping[acc], "right": mapping[index], "factor": 255}]
            oi = body["ops"].index(add)
            rewritten_blocks[body["id"]]["ops"][oi]["op"] = "int.add.wrap"
            changes.append({"function": fn["name"], "block": body["id"], "operation": oi})
        invariants[fn["name"]] = inv
    if not changes:
        raise OptimizationRejected("E_HIA_GUARD_NO_CANDIDATE: no supported counted byte reduction")
    return {"schema": SCHEMA, "base_sha256": original.sha256, "fast_core": verify_program(fast).as_dict(),
            "guards": guards, "invariants": invariants, "changes": changes}


def _freeze(base, proposal):
    original = verify_program(base)
    if (type(proposal) is not dict or len(proposal) != 6
            or set(proposal) != {"schema", "base_sha256", "fast_core", "guards", "invariants", "changes"}):
        raise ValueError("exact guarded proposal fields required")
    if proposal["schema"] != SCHEMA or proposal["base_sha256"] != original.sha256:
        raise ValueError("guarded proposal source identity mismatch")
    fast = verify_program(proposal["fast_core"])
    left, right = original.as_dict(), fast.as_dict()
    if {k: v for k, v in left.items() if k != "functions"} != {k: v for k, v in right.items() if k != "functions"}:
        raise ValueError("guarded rewrite changes module interface")
    if len(left["functions"]) != len(right["functions"]):
        raise ValueError("guarded rewrite changes function inventory")
    functions = {f["name"]: f for f in left["functions"]}
    guards = proposal["guards"]
    if type(guards) is not list or not 1 <= len(guards) <= len(functions):
        raise ValueError("invalid guard inventory")
    guardmap = {}
    for guard in guards:
        if type(guard) is not dict or set(guard) != {"function", "argument", "maximum"}:
            raise ValueError("invalid guard fields")
        name = guard["function"]
        if type(name) is not str or name not in functions or name in guardmap:
            raise ValueError("guard references an unknown or duplicate function")
        params = {p["name"]: p["type"] for p in functions[name]["params"]}
        arg = guard["argument"]
        if type(arg) is not str or params.get(arg) not in UNSIGNED:
            raise ValueError("guard requires an actual unsigned function argument")
        if type(guard["maximum"]) is not int or not 0 <= guard["maximum"] < 2**WIDTHS[params[arg]]:
            raise ValueError("guard constant is outside its argument type")
        guardmap[name] = dict(guard)
    raw = proposal["invariants"]
    if type(raw) is not dict or len(raw) != len(guardmap) or set(raw) != set(guardmap):
        raise ValueError("invariants must exactly cover guarded functions")
    invariants, constraint_count = {}, 0
    for name in guardmap:
        checked = validate_invariants(functions[name], raw[name])
        constraint_count += sum(map(len, checked.values()))
        if constraint_count > MAX_CONSTRAINTS:
            raise ValueError("whole-proposal invariant budget exceeded")
        invariants[name] = checked
    actual = []
    for lf, rf in zip(left["functions"], right["functions"]):
        if {k: v for k, v in lf.items() if k != "blocks"} != {k: v for k, v in rf.items() if k != "blocks"} or len(lf["blocks"]) != len(rf["blocks"]):
            raise ValueError("fast rewrite changes a function interface or CFG")
        for lb, rb in zip(lf["blocks"], rf["blocks"]):
            if {k: v for k, v in lb.items() if k != "ops"} != {k: v for k, v in rb.items() if k != "ops"} or len(lb["ops"]) != len(rb["ops"]):
                raise ValueError("fast rewrite changes CFG edges or block parameters")
            for oi, (lo, ro) in enumerate(zip(lb["ops"], rb["ops"])):
                if lo == ro:
                    continue
                expected = {**lo, "op": "int.add.wrap"}
                if lo["op"] != "int.add.checked" or ro != expected or lo["out"][0]["type"] not in UNSIGNED or lf["name"] not in guardmap:
                    raise ValueError("only witnessed unsigned checked-add removal is supported")
                actual.append({"function": lf["name"], "block": lb["id"], "operation": oi})
    declared = proposal["changes"]
    if type(declared) is not list or len(declared) != len(actual):
        raise ValueError("changed-operation inventory length is invalid")
    for change in declared:
        if (type(change) is not dict or set(change) != {"function", "block", "operation"}
                or type(change["function"]) is not str or type(change["block"]) is not str
                or type(change["operation"]) is not int):
            raise ValueError("changed-operation inventory fields are invalid")
    if not actual or declared != actual:
        raise ValueError("changed-operation inventory is incomplete or forged")
    if set(x["function"] for x in actual) != set(guardmap):
        raise ValueError("every guarded function must have a checked change")
    frozen = {"schema": SCHEMA, "base_sha256": original.sha256, "fast_core": right,
              "guards": list(guardmap.values()), "invariants": invariants, "changes": actual}
    return original, fast, frozen


def _clone_blocks(function, prefix):
    value_names = {p["name"] for b in function["blocks"] for p in b["params"]}
    value_names.update(out["name"] for b in function["blocks"] for op in b["ops"] for out in op["out"])
    names = {name: prefix + name for name in value_names}
    result = json.loads(json.dumps(function["blocks"]))
    for b in result:
        b["id"] = prefix + b["id"]
        for p in b["params"]:
            p["name"] = names[p["name"]]
        for op in b["ops"]:
            op["args"] = [names[a] for a in op["args"]]
            for out in op["out"]:
                out["name"] = names[out["name"]]
        term = b["term"]
        if term["op"] == "ret":
            term["values"] = [names[a] for a in term["values"]]
        elif term["op"] == "jump":
            term["target"] = prefix + term["target"]
            term["args"] = [names[a] for a in term["args"]]
        elif term["op"] == "branch":
            term["cond"] = names[term["cond"]]
            for key in ("then", "else"):
                term[key]["target"] = prefix + term[key]["target"]
                term[key]["args"] = [names[a] for a in term[key]["args"]]
    return result


def _compose(original, fast, proposal):
    data = original.as_dict()
    fast_functions = {f["name"]: f for f in fast.as_dict()["functions"]}
    guards = {g["function"]: g for g in proposal["guards"]}
    for fn in data["functions"]:
        if fn["name"] not in guards:
            continue
        guard = guards[fn["name"]]
        params = fn["params"]
        used = {p["name"] for p in params}
        limit, cond = "hia_guard_limit", "hia_guard_test"
        while limit in used or cond in used:
            limit, cond = "x_" + limit, "x_" + cond
        typ = next(p["type"] for p in params if p["name"] == guard["argument"])
        entry = {"id": "hia_guard_entry", "params": json.loads(json.dumps(params)),
                 "ops": [{"op": "const", "args": [], "out": [{"name": limit, "type": typ}],
                          "attrs": {"value": guard["maximum"]}},
                         {"op": "compare.le", "args": [guard["argument"], limit],
                          "out": [{"name": cond, "type": "bool"}], "attrs": {}}],
                 "term": {"op": "branch", "cond": cond,
                          "then": {"target": "gf_" + fn["entry"], "args": [p["name"] for p in params]},
                          "else": {"target": "gs_" + fn["entry"], "args": [p["name"] for p in params]}}}
        blocks = [entry] + _clone_blocks(fast_functions[fn["name"]], "gf_") + _clone_blocks(fn, "gs_")
        fn["blocks"], fn["entry"] = blocks, entry["id"]
    return verify_program(data)


class _Unproved(Exception):
    def __init__(self, status, reason):
        self.status, self.reason = status, reason


def verify_guarded_optimization(base, proposal, policy=None):
    started = time.monotonic_ns()
    policy = _policy({**DEFAULT_POLICY, "timeout_ms": 30000} if policy is None else policy)
    report = {"schema": VERIFY_SCHEMA, "status": "unknown", "target": policy["target"],
              "policy": policy, "policy_sha256": _digest(policy),
              "checker_sha256": guarded_checker_identity(), "obligations": [],
              "claims": {"deployment_authority": False, "backend_refinement_proved": False,
                         "whole_language_soundness_proved": False, "performance_qualified": False}}

    def finish(status, reason):
        report.update(status=status, reason=reason, elapsed_ns=time.monotonic_ns() - started)
        report["verification_sha256"] = _digest(report)
        return report

    try:
        original, fast, frozen = _freeze(base, proposal)
        composed = _compose(original, fast, frozen)
    except (ValueError, HIAProgramRejected, KeyError, TypeError) as exc:
        return finish("rejected", "guarded admission failed: " + str(exc))
    report.update(base_sha256=original.sha256, candidate_sha256=composed.sha256,
                  fast_core_sha256=fast.sha256, proposal_sha256=_digest(frozen),
                  preconditions=frozen["guards"], changes=frozen["changes"],
                  target_constraints={"triple": policy["target"], "foreign_abi": "unchanged scalar C exports",
                                      "guard_before_effects": True, "original_fallback": True},
                  resource_delta={"peak_live_bytes_change_under_core_model": None,
                                  "allocation_failure_sequence_preserved": False,
                                  "ordered_resource_instructions_unchanged": True,
                                  "resource_trace_equivalence_checked": False,
                                  "code_size_and_compile_cost_may_increase": True,
                                  "vm_steps_preserved": False})
    count = sum(len(b["ops"]) for f in original.as_dict()["functions"] for b in f["blocks"])
    if count > policy["max_scalar_operations"]:
        return finish("unknown", "symbolic operation budget exceeded")
    deadline = started + policy["timeout_ms"] * 1_000_000
    if time.monotonic_ns() >= deadline:
        return finish("timeout", "verification deadline exhausted before solving")
    try:
        import z3 as z
        if z.get_version_string() != PINNED_Z3_VERSION:
            return finish("unknown", "SMT version differs from the qualified profile")
        report["solver"] = _solver_identity(z)
    except (ImportError, OptimizationRejected) as exc:
        return finish("unknown", "qualified SMT unavailable: " + str(exc))
    context = z.Context()

    def discharge(label, counterexample):
        remaining = (deadline - time.monotonic_ns()) // 1_000_000
        if remaining <= 0:
            raise _Unproved("timeout", "total proof deadline exhausted")
        if len(report["obligations"]) >= policy["max_obligations"]:
            raise _Unproved("unknown", "proof obligation budget exceeded")
        solver = z.Solver(ctx=context)
        solver.add(counterexample)
        smt = solver.to_smt2()
        if len(smt.encode()) > 2 * 1024 * 1024:
            raise _Unproved("unknown", "symbolic query byte budget exceeded")
        remaining = (deadline - time.monotonic_ns()) // 1_000_000
        if remaining <= 0:
            raise _Unproved("timeout", "proof deadline exhausted while encoding")
        solver.set(timeout=int(remaining))
        outcome = solver.check()
        evidence = {**label, "result": str(outcome), "smt2": smt,
                    "smt2_sha256": sha256(smt.encode()).hexdigest()}
        report["obligations"].append(evidence)
        if time.monotonic_ns() >= deadline:
            raise _Unproved("timeout", "total proof deadline exhausted during solving")
        if outcome == z.sat:
            evidence["counterexample"] = {str(k): str(solver.model()[k]) for k in solver.model().decls()}
            raise _Unproved("rejected", "an invariant or no-overflow counterexample exists")
        if outcome != z.unsat:
            reason = solver.reason_unknown()
            evidence["reason_unknown"] = reason
            raise _Unproved("timeout" if "timeout" in reason else "unknown", reason)

    try:
        functions = {f["name"]: f for f in original.as_dict()["functions"]}
        for guard in frozen["guards"]:
            name = guard["function"]
            changed = {(c["block"], c["operation"]) for c in frozen["changes"] if c["function"] == name}
            check_function(z, context, functions[name], guard, frozen["invariants"][name], changed, discharge)
        if guarded_checker_identity() != report["checker_sha256"] or _solver_identity(z) != report["solver"]:
            return finish("unknown", "checker or solver source changed during verification")
    except _Unproved as exc:
        return finish(exc.status, exc.reason)
    except (ValueError, KeyError, z.Z3Exception, OptimizationRejected) as exc:
        return finish("unknown", "unsupported symbolic correspondence: " + str(exc))
    if time.monotonic_ns() >= deadline:
        return finish("timeout", "verification deadline exhausted before admission")
    report["claims"].update(inductive_invariants_checked=True, removed_checks_nontrapping=True,
                            original_fallback_preserved=True, core_resource_trace_equivalence_checked=True)
    report["resource_delta"].update(peak_live_bytes_change_under_core_model=0,
                                    allocation_failure_sequence_preserved=True,
                                    resource_trace_equivalence_checked=True)
    return finish("verified", "guarded entry, every CFG edge, and removed-check obligations are UNSAT")


def guarded_program(base, proposal, policy=None):
    original, fast, frozen = _freeze(base, proposal)
    report = verify_guarded_optimization(original, frozen, policy)
    if report["status"] != "verified":
        raise OptimizationRejected("E_HIA_GUARD_NOT_VERIFIED: " + report["status"] + ": " + report["reason"])
    result = _compose(original, fast, frozen)
    if result.sha256 != report["candidate_sha256"]:
        raise OptimizationRejected("E_HIA_GUARD_BINDING: composed Core differs from proof")
    return result


def build_guarded_native(base, proposal, output, *, policy=None, clang="clang", kind="shared"):
    """Check the actual guarded proposal and bind every native identity before publication."""
    from .hia_guarded_native_binding import build_guarded_native_bound
    return build_guarded_native_bound(base, proposal, output, policy=policy, clang=clang, kind=kind)
