"""Separate bounded scalar-call profile for exact return/first-trap validation.

The ordinary translation validator remains call-free.  This profile reuses its
bit-vector operation semantics and extends only direct acyclic call evaluation.
It does not inline programs to establish their equivalence, so a faulty inlining
proposal is compared against the original caller/callee execution.  No resource,
memory, indirect call, recursion or execution authority is added.
"""
from __future__ import annotations

import copy
from hashlib import sha256
import json
from pathlib import Path
import time

from .hia_program import HIAProgramRejected, verify_program
from .hia_program_runtime import HIAProgramTrap, execute_program
from .hia_translation_validation import (
    QUALIFIED_CORE_SCHEMAS, _Encoder, _OutsideProfile, _TRAP_TAGS, _profile,
    _signature, _z3_module,
)

PROFILE = "hia.scalar-acyclic-direct-calls-bitvector-first-traps.v1"
MAX_FUNCTIONS = 16
MAX_BLOCKS = 32
MAX_OPERATIONS = 512
MAX_CALL_EXPANSIONS = 32


def _closure(document, function):
    functions = {fn["name"]: fn for fn in document["functions"]}
    graphs, active = {}, set()
    blocks = operations = 0

    def visit(name):
        nonlocal blocks, operations
        if name in active:
            raise _OutsideProfile("recursive_call_graph")
        if name in graphs:
            return
        if len(graphs) + len(active) >= MAX_FUNCTIONS:
            raise _OutsideProfile("call_function_budget_exceeded")
        fn = functions[name]
        if len(fn["returns"]) != 1:
            raise _OutsideProfile("one_scalar_call_result_required")
        blocks += len(fn["blocks"])
        operations += sum(len(b["ops"]) for b in fn["blocks"])
        if blocks > MAX_BLOCKS or operations > MAX_OPERATIONS:
            raise _OutsideProfile("call_closure_program_budget_exceeded")
        shape, callees = copy.deepcopy(fn), []
        for block in shape["blocks"]:
            for op in block["ops"]:
                if op["op"] == "call":
                    if len(op["out"]) != 1:
                        raise _OutsideProfile("one_scalar_call_result_required")
                    callees.append(op["attrs"]["function"])
                    typ = op["out"][0]["type"]
                    op.update(op="const", args=[], attrs={"value": None if typ == "unit" else False if typ == "bool" else 0})
        # Only the graph/type/effect check uses a call-shaped placeholder.  The
        # encoder below reads the ORIGINAL blocks and actual callees, never it.
        _, order = _profile(shape)
        active.add(name)
        for callee in sorted(set(callees)):
            visit(callee)
        active.remove(name)
        graphs[name] = ({b["id"]: b for b in fn["blocks"]}, order)

    visit(function)
    return functions, graphs


class _Calls(_Encoder):
    def configure(self, functions, graphs):
        self.functions, self.graphs = functions, graphs
        self.expansions = 0
        self.incomplete = []

    def function(self, fn, inputs, blocks, order):
        self.expansions += 1
        if self.expansions > MAX_CALL_EXPANSIONS:
            raise _OutsideProfile("symbolic_call_expansion_budget_exceeded")
        return super().function(fn, inputs, blocks, order)

    def operation(self, op, env, types):
        if op["op"] != "call":
            return super().operation(op, env, types)
        callee = self.functions[op["attrs"]["function"]]
        tag, values = self.function(callee, [env[name] for name in op["args"]],
                                    *self.graphs[callee["name"]])
        self.incomplete.append(tag < 0)
        # The callee produces ONE already ordered first-trap tag.  These
        # mutually exclusive conditions enter the caller at the call's exact
        # position; later caller operations remain unreachable after any trap.
        return values[0], [(code, tag == value) for code, value in sorted(_TRAP_TAGS.items())]


def _observe(program, function, arguments):
    try:
        result = execute_program(program, function, arguments,
                                 max_steps=(MAX_OPERATIONS + MAX_BLOCKS) * MAX_CALL_EXPANSIONS)
        return {"status": "returned", "values": result["values"]}
    except HIAProgramTrap as error:
        return {"status": "trapped", "code": error.code}


def validate_scalar_calls(before, after, *, function, timeout_ms=10000):
    """Freshly compare a bounded direct-call closure, including first-trap code."""
    started = time.monotonic_ns()
    names = ("hia_scalar_call_validation.py", "hia_translation_validation.py", "hia_program.py",
             "hia_program_runtime.py", "hia_optimization.py")
    implementation = {name: sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() for name in names}
    report = {"schema": "hepta.hia.scalar-call-validation.v1", "profile": PROFILE,
              "status": "unknown", "function": function, "timeout_ms": timeout_ms,
              "implementation": implementation, "execution_authority": False,
              "claims": {"all_input_return_and_first_trap_equivalence": False,
                         "source_C_refinement_proved": False, "native_refinement_proved": False},
              "limits": {"functions": MAX_FUNCTIONS, "blocks": MAX_BLOCKS,
                         "operations": MAX_OPERATIONS, "call_expansions_per_side": MAX_CALL_EXPANSIONS}}
    try:
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 10000:
            raise _OutsideProfile("invalid_solver_timeout")
        checked = [verify_program(value) for value in (before, after)]
        if any(p.as_dict()["schema"] not in QUALIFIED_CORE_SCHEMAS or p.structured_bytes is not None
               or function not in p.scalar_entrypoints for p in checked):
            raise _OutsideProfile("public_primitive_scalar_function_required")
        report.update(before_sha256=checked[0].sha256, after_sha256=checked[1].sha256)
        closures = [_closure(p.as_dict(), function) for p in checked]
        selected = [f[function] for f, _ in closures]
        if _signature(selected[0]) != _signature(selected[1]):
            raise _OutsideProfile("signature_mismatch")
        z = _z3_module()
        from .hia_optimization import PINNED_Z3_VERSION, _solver_identity
        if z.get_version_string() != PINNED_Z3_VERSION:
            raise _OutsideProfile("pinned_solver_required")
        report["solver"] = _solver_identity(z)
        encoder = _Calls(z)
        inputs = [encoder.input(i, p["type"]) for i, p in enumerate(selected[0]["params"])]
        encoded, incomplete, expansions = [], [], []
        for fn, (functions, graphs) in zip(selected, closures):
            encoder.configure(functions, graphs)
            encoded.append(encoder.function(fn, inputs, *graphs[function]))
            incomplete.extend(encoder.incomplete)
            expansions.append(encoder.expansions)
        (ltag, left), (rtag, right) = encoded
        values_differ = [a != b for a, b, typ in zip(left, right, selected[0]["returns"]) if typ != "unit"]
        solver = z.Solver(ctx=encoder.context)
        solver.set(timeout=timeout_ms)
        solver.add(z.Or(encoder.any(incomplete), ltag < 0, rtag < 0, ltag != rtag,
                        z.And(ltag == 0, rtag == 0, encoder.any(values_differ))))
        verdict = solver.check()
        report.update(solver_result=str(verdict), call_expansions=expansions,
                      call_closures=[sorted(graphs) for _, graphs in closures])
        if verdict == z.unsat:
            report["status"] = "proved"
            report["claims"]["all_input_return_and_first_trap_equivalence"] = True
        elif verdict == z.sat:
            model = solver.model()
            arguments = [encoder.concrete(model, value, p["type"]) for value, p in zip(inputs, selected[0]["params"])]
            observations = [_observe(p, function, arguments) for p in checked]
            if observations[0] == observations[1]:
                report["reason"] = "counterexample_replay_disagrees_with_encoder"
            else:
                report.update(status="disproved", counterexample={"arguments": arguments,
                    "before": observations[0], "after": observations[1]})
        else:
            report["reason"] = solver.reason_unknown()
    except Exception as error:
        # A missing solver/library, malformed supported input or solver error
        # is an incomplete proof, never an approval or a reusable certificate.
        report["reason"] = str(error)
        report["error_type"] = type(error).__name__
    finally:
        report["wall_ns"] = time.monotonic_ns() - started
    return report


def inline_scalar_calls(document, *, function):
    """Propose structural direct-call substitution; a fresh proof is mandatory."""
    checked = verify_program(document)
    value = checked.as_dict()
    functions, _ = _closure(value, function)
    fn = functions[function]
    from .hia_specialization import _clone_blocks, _fresh
    used = {p["name"] for b in fn["blocks"] for p in
            [*b["params"], *[v for op in b["ops"] for v in op["out"]]]}
    used_blocks = {b["id"] for b in fn["blocks"]}
    attempts = 0
    while True:
        found = next(((b, i, op) for b in fn["blocks"] for i, op in enumerate(b["ops"])
                      if op["op"] == "call"), None)
        if found is None:
            break
        attempts += 1
        if attempts > MAX_CALL_EXPANSIONS:
            raise _OutsideProfile("inlining_expansion_budget_exceeded")
        block, index, call = found
        head, tail = block["ops"][:index], block["ops"][index + 1:]
        carried = [*block["params"], *[v for op in head for v in op["out"]]]
        cloned, callee_entry = _clone_blocks(functions[call["attrs"]["function"]], "stb_inline", used, used_blocks)
        continuation = _fresh("stb_continue", used_blocks)
        new_carried = [{"name": _fresh("stb_carry", used), "type": p["type"]} for p in carried]
        rename = {p["name"]: n["name"] for p, n in zip(carried, new_carried)}
        for op in tail:
            op["args"] = [rename.get(name, name) for name in op["args"]]
        term = block["term"]
        if term["op"] == "ret":
            term["values"] = [rename.get(name, name) for name in term["values"]]
        elif term["op"] in {"jump", "branch"}:
            if term["op"] == "branch":
                term["cond"] = rename.get(term["cond"], term["cond"])
            for edge in [term] if term["op"] == "jump" else [term["then"], term["else"]]:
                edge["args"] = [rename.get(name, name) for name in edge["args"]]
        following = {"id": continuation, "params": [*copy.deepcopy(call["out"]), *new_carried],
                     "ops": tail, "term": term}
        for child in cloned:
            extra = [{"name": _fresh("stb_pass", used), "type": p["type"]} for p in carried]
            child["params"].extend(extra)
            end = child["term"]
            if end["op"] == "ret":
                child["term"] = {"op": "jump", "target": continuation,
                                 "args": [*end["values"], *[p["name"] for p in extra]]}
            elif end["op"] in {"jump", "branch"}:
                for edge in [end] if end["op"] == "jump" else [end["then"], end["else"]]:
                    edge["args"].extend(p["name"] for p in extra)
        block.update(ops=head, term={"op": "jump", "target": callee_entry,
                                    "args": [*call["args"], *[p["name"] for p in carried]]})
        fn["blocks"].extend([*cloned, following])
        if len(fn["blocks"]) > MAX_BLOCKS or sum(len(b["ops"]) for b in fn["blocks"]) > MAX_OPERATIONS:
            raise _OutsideProfile("inlined_program_budget_exceeded")
    _profile(fn)
    return verify_program(value).as_dict()
