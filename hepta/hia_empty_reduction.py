"""Experimental empty-entry specialization of a freshly verified reduction.

This module is separate from the qualified reduction pipeline. The proposer
clones complete Core functions, including every resource opcode. The checker
independently reverses each clone's alpha-renaming and checks an executable
equality guard. No empty-owner semantics are assumed by admission. LLVM may
simplify the constant-zero clone through the existing emitter; neither that
simplification nor a performance improvement is proved here.
"""
from __future__ import annotations

import copy
from hashlib import sha256
from pathlib import Path
import time

from .hia_program import SCALARS, verify_program
from .hia_optimization import OptimizationRejected, _digest, _policy, _solver_identity
from .hia_reduction import (_freeze_pipeline, _verify_frozen,
                            reduction_checker_identity)
from .hia_guarded_optimization import _compose
from .hia_specialization import _clone_blocks, _fresh


SCHEMA = "hepta.hia.empty-reduction-candidate.v1"
VERIFY_SCHEMA = "hepta.hia.empty-reduction-verification.v1"


def empty_reduction_checker_identity():
    return sha256(reduction_checker_identity().encode() + b"\0" +
                  Path(__file__).read_bytes()).hexdigest()


def _guard_arguments(document, reduction):
    functions = {f["name"]: f for f in document["functions"]}
    result = {}
    for guard in reduction["guarded"]["guards"]:
        function, argument = guard["function"], guard["argument"]
        fn = functions[function]
        if (any(p["type"] not in SCALARS for p in fn["params"])
                or any(t not in SCALARS for t in fn["returns"])):
            raise OptimizationRejected("E_HIA_EMPTY_PROFILE: scalar interfaces required")
        typ = next(p["type"] for p in fn["params"] if p["name"] == argument)
        if typ != "usize":
            raise OptimizationRejected("E_HIA_EMPTY_PROFILE: reduction length must be usize")
        result[function] = argument
    return result


def _propose_specialization(program, reduction):
    data = program.as_dict()
    arguments = _guard_arguments(data, reduction)
    for fn in data["functions"]:
        if fn["name"] not in arguments:
            continue
        argument = arguments[fn["name"]]
        used_values = {p["name"] for p in fn["params"]}
        used_blocks = set()
        generic, generic_entry = _clone_blocks(fn, "hia_nonempty", used_values, used_blocks)
        empty, empty_entry = _clone_blocks(fn, "hia_empty", used_values, used_blocks)
        entry = _fresh("hia_empty_guard", used_blocks)
        zero = _fresh("hia_empty_zero", used_values)
        condition = _fresh("hia_empty_test", used_values)
        ordinary = [p["name"] for p in fn["params"]]
        specialized = [zero if name == argument else name for name in ordinary]
        guard = {"id": entry, "params": copy.deepcopy(fn["params"]), "ops": [
            {"op": "const", "args": [], "out": [{"name": zero, "type": "usize"}],
             "attrs": {"value": 0}},
            {"op": "compare.eq", "args": [argument, zero],
             "out": [{"name": condition, "type": "bool"}], "attrs": {}},
        ], "term": {"op": "branch", "cond": condition,
                    "then": {"target": empty_entry, "args": specialized},
                    "else": {"target": generic_entry, "args": ordinary}}}
        fn["entry"] = entry
        fn["blocks"] = [guard, *generic, *empty]
    return verify_program(data)


def propose_empty_reduction(base, reduction_proposal):
    """Construct an untrusted candidate; a supplied receipt grants no authority."""
    original, narrowed, fast, frozen = _freeze_pipeline(base, reduction_proposal)
    reduced = _compose(narrowed, fast, frozen["guarded"])
    candidate = _propose_specialization(reduced, frozen)
    return {"schema": SCHEMA, "base_sha256": original.sha256,
            "reduction": frozen, "candidate_core": candidate.as_dict()}


def _check_clone(original, clone):
    """Recover a bijection from definitions, independently of proposer names."""
    if len(original) != len(clone):
        raise ValueError("every original block must occur exactly once in each clone")
    blocks, values = {}, {}
    for before, after in zip(original, clone):
        blocks[after["id"]] = before["id"]
        if len(before["params"]) != len(after["params"]) or len(before["ops"]) != len(after["ops"]):
            raise ValueError("clone block parameters and operation counts must match")
        old_defs, new_defs = list(before["params"]), list(after["params"])
        for left, right in zip(before["ops"], after["ops"]):
            if len(left["out"]) != len(right["out"]):
                raise ValueError("clone operation result arity must match")
            old_defs.extend(left["out"])
            new_defs.extend(right["out"])
        for left, right in zip(old_defs, new_defs):
            values[right["name"]] = left["name"]
    if (len(set(blocks.values())) != len(blocks)
            or len(set(values.values())) != len(values)):
        raise ValueError("clone definitions must have a bijective renaming")
    normalized = copy.deepcopy(clone)
    for block in normalized:
        block["id"] = blocks[block["id"]]
        for p in block["params"]:
            p["name"] = values[p["name"]]
        for op in block["ops"]:
            op["args"] = [values[a] for a in op["args"]]
            for out in op["out"]:
                out["name"] = values[out["name"]]
        term = block["term"]
        if term["op"] == "ret":
            term["values"] = [values[a] for a in term["values"]]
        elif term["op"] in {"jump", "branch"}:
            edges = [term] if term["op"] == "jump" else [term["then"], term["else"]]
            if term["op"] == "branch":
                term["cond"] = values[term["cond"]]
            for edge in edges:
                edge["target"] = blocks[edge["target"]]
                edge["args"] = [values[a] for a in edge["args"]]
    if normalized != original:
        raise ValueError("clone changes scalar, resource, call, trap, or control-flow instructions")
    return blocks


def _check_specialization(reduced, candidate, reduction):
    before, after = reduced.as_dict(), candidate.as_dict()
    if ({k: v for k, v in before.items() if k != "functions"}
            != {k: v for k, v in after.items() if k != "functions"}
            or len(before["functions"]) != len(after["functions"])):
        raise ValueError("module interfaces and function inventory must remain unchanged")
    arguments = _guard_arguments(before, reduction)
    obligations = []
    for old, new in zip(before["functions"], after["functions"]):
        if old["name"] not in arguments:
            if new != old:
                raise ValueError("unselected functions must be unchanged")
            continue
        if ({k: v for k, v in old.items() if k not in {"blocks", "entry"}}
                != {k: v for k, v in new.items() if k not in {"blocks", "entry"}}):
            raise ValueError("specialized function interface changed")
        count = len(old["blocks"])
        if len(new["blocks"]) != 2 * count + 1:
            raise ValueError("exactly two complete clones and one entry guard are required")
        guard = new["blocks"][0]
        if (new["entry"] != guard["id"] or guard["params"] != old["params"]
                or len(guard["ops"]) != 2):
            raise ValueError("entry must be an effect-free equality guard")
        constant, comparison = guard["ops"]
        zero = constant["out"][0]["name"]
        condition = comparison["out"][0]["name"]
        argument = arguments[old["name"]]
        if constant != {"op": "const", "args": [],
                        "out": [{"name": zero, "type": "usize"}], "attrs": {"value": 0}}:
            raise ValueError("specialization constant must be usize zero")
        if comparison != {"op": "compare.eq", "args": [argument, zero],
                          "out": [{"name": condition, "type": "bool"}], "attrs": {}}:
            raise ValueError("guard must compare the actual reduction length with zero")
        generic = _check_clone(old["blocks"], new["blocks"][1:count + 1])
        empty = _check_clone(old["blocks"], new["blocks"][count + 1:])
        ordinary = [p["name"] for p in old["params"]]
        special = [zero if name == argument else name for name in ordinary]
        term = guard["term"]
        if (term["op"] != "branch" or term["cond"] != condition
                or empty.get(term["then"]["target"]) != old["entry"]
                or generic.get(term["else"]["target"]) != old["entry"]
                or term["then"]["args"] != special or term["else"]["args"] != ordinary):
            raise ValueError("both branches must pass equal values into their complete clones")
        obligations.append({"function": old["name"], "argument": argument,
                            "kind": "equality_guard_and_two_complete_alpha_clones",
                            "result": "checked", "blocks_per_clone": count,
                            "resource_instructions_preserved": True})
    return obligations


def _admit(base, proposal, policy):
    started = time.monotonic_ns()
    report = {"schema": VERIFY_SCHEMA, "status": "unknown", "obligations": [],
              "checker_sha256": empty_reduction_checker_identity(),
              "claims": {"all_scalar_inputs_checked": False,
                         "core_resource_trace_equivalence_checked": False,
                         "whole_language_soundness_proved": False,
                         "backend_refinement_proved": False,
                         "performance_qualified": False,
                         "vm_steps_preserved": False,
                         "deployment_authority": False}}

    def finish(status, reason, program=None):
        report.update(status=status, reason=reason, elapsed_ns=time.monotonic_ns() - started)
        report["verification_sha256"] = _digest(report)
        return report, program

    try:
        original = verify_program(base)
        if (type(proposal) is not dict
                or set(proposal) != {"schema", "base_sha256", "reduction", "candidate_core"}
                or any(type(k) is not str for k in proposal)
                or type(proposal["schema"]) is not str or proposal["schema"] != SCHEMA
                or type(proposal["base_sha256"]) is not str
                or proposal["base_sha256"] != original.sha256):
            raise ValueError("exact source-bound empty-reduction proposal required")
        stage = _freeze_pipeline(original, proposal["reduction"])
        candidate = verify_program(proposal["candidate_core"])
        reduced = _compose(stage[1], stage[2], stage[3]["guarded"])
        report["obligations"] = _check_specialization(reduced, candidate, stage[3])
        frozen = {"schema": SCHEMA, "base_sha256": original.sha256,
                  "reduction": stage[3], "candidate_core": candidate.as_dict()}
        report.update(base_sha256=original.sha256, reduction_sha256=reduced.sha256,
                      candidate_sha256=candidate.sha256, proposal_sha256=_digest(frozen))
        policy = _policy(policy)
    except (ValueError, KeyError, TypeError, IndexError) as exc:
        return finish("rejected", "empty-entry admission failed: " + str(exc))
    proof, admitted_reduction = _verify_frozen(*stage, policy)
    report["reduction_verification"] = proof
    if proof["status"] != "verified":
        return finish(proof["status"], "reduction stage: " + proof["reason"])
    # The structural check binds these obligations to the actual guard and
    # transported values. Every other parameter is passed identically. The
    # counterexample asks whether the zero replacement can differ on that edge.
    import z3 as z
    guard_proofs = []
    report["guard_proofs"] = guard_proofs
    try:
        context = z.Context()
        deadline = time.monotonic_ns() + policy["timeout_ms"] * 1_000_000
        for row in report["obligations"]:
            remaining = (deadline - time.monotonic_ns()) // 1_000_000
            if remaining <= 0 or len(guard_proofs) >= policy["max_obligations"]:
                return finish("unknown", "empty-guard proof budget exhausted")
            value = z.BitVec(row["function"] + "." + row["argument"], 64, ctx=context)
            zero = z.BitVecVal(0, 64, ctx=context)
            query = z.And(value == zero, value != zero)
            solver = z.Solver(ctx=context)
            solver.set(timeout=int(remaining))
            solver.add(query)
            smt = solver.to_smt2()
            outcome = solver.check()
            guard_proofs.append({"function": row["function"], "argument": row["argument"],
                                 "kind": "guard_implies_equal_substitution", "result": str(outcome),
                                 "smt2": smt, "smt2_sha256": sha256(smt.encode()).hexdigest()})
            if outcome != z.unsat:
                return finish("unknown", "empty-guard equality obligation was not UNSAT")
        if (time.monotonic_ns() >= deadline or admitted_reduction.sha256 != reduced.sha256
                or empty_reduction_checker_identity() != report["checker_sha256"]
                or _solver_identity(z) != proof["solver"]):
            return finish("unknown", "proof deadline or reduction/checker/solver identity changed")
    except (z.Z3Exception, OptimizationRejected, OSError) as exc:
        return finish("unknown", "empty-guard checker/solver unavailable: " + str(exc))
    report.update(input_assumptions=[], target=proof["target"], solver=proof["solver"],
                  trace_scope="Core scalar results, first specified trap, and ordered resource/call events; evaluator budgets excluded",
                  added_steps_per_specialized_invocation=3,
                  step_delta_baseline="verified reduction Core, per dynamic transformed-function entry")
    report["claims"].update(all_scalar_inputs_checked=True,
                            core_resource_trace_equivalence_checked=True)
    return finish("verified", "fresh reduction proofs and complete equality-guarded clones checked", candidate)


def verify_empty_reduction(base, proposal, policy=None):
    """Check actual Core and reduction proofs; serialized receipts are not read."""
    return _admit(base, proposal, policy)[0]


def empty_reduction_program(base, proposal, policy=None):
    """Return immutable Core only after fresh proof and structural admission."""
    report, program = _admit(base, proposal, policy)
    if report["status"] != "verified":
        raise OptimizationRejected("E_HIA_EMPTY_NOT_VERIFIED: " + report["status"] + ": " + report["reason"])
    return program
