"""Conservative finite resource bounds for already-verified standalone HIA Core.

An opt-in bounded acyclic profile, NOT a new compiler/IR authority. The sole
HIA Core verifier remains mandatory. This counts potential allocator calls,
interpreter tick events and nested invocation depth; it does not bound process
RSS, native CPU time, stack bytes, foreign allocators or recursive programs.
"""
from __future__ import annotations

from collections import deque
from hashlib import sha256
import json


SCHEMA = "hepta.hia.static-budget.v1"
# The count of ticks and allocator events is versioned too: recursive owner
# destruction in v7 can perform arbitrarily many of both inside one opcode.
_ALLOWED_CORE_SCHEMAS = frozenset(f"hepta.hia.program.v{version}" for version in range(1, 7))
_ALLOCATOR_OPS = frozenset({"buffer.new", "buffer.try_new", "owner.drop"})


class HIAStaticBudgetRejected(ValueError):
    """A Core input lacks a finite structural bound or exceeds the policy."""

    def __init__(self, code: str, detail: str):
        self.code = code
        super().__init__(f"{code}: {detail}")


def _reject(code: str, detail: str) -> None:
    raise HIAStaticBudgetRejected(code, detail)


def _limit(value, label: str) -> None:
    if value is not None and (type(value) is not int or value < 0):
        _reject("E_HIA_BUDGET_POLICY", f"{label} must be a nonnegative integer")


def _topological(names: list[str], edges: dict[str, set[str]], context: str) -> list[str]:
    """Iterative stable DAG order, no recursion even for deeply nested graphs."""
    indegree = {name: 0 for name in names}
    for source, targets in edges.items():
        if source not in indegree or any(target not in indegree for target in targets):
            _reject("E_HIA_BUDGET_GRAPH", f"{context}: unknown dependency")
        for target in targets:
            indegree[target] += 1
    ready = deque(sorted(name for name, degree in indegree.items() if degree == 0))
    result = []
    while ready:
        name = ready.popleft()
        result.append(name)
        for target in sorted(edges[name]):
            indegree[target] -= 1
            if indegree[target] == 0:
                ready.append(target)
    if len(result) != len(names):
        _reject("E_HIA_BUDGET_UNBOUNDED", f"{context}: recursion or CFG cycle requires a separate invariant")
    return result


def _successors(term: dict) -> set[str]:
    kind = term["op"]
    if kind == "jump":
        return {term["target"]}
    if kind == "branch":
        return {term["then"]["target"], term["else"]["target"]}
    return set()


def _bound_function(fn: dict, calculated: dict[str, dict]) -> dict:
    blocks = {block["id"]: block for block in fn["blocks"]}
    successors = {name: _successors(block["term"]) for name, block in blocks.items()}
    order = _topological(list(blocks), successors, f"{fn['name']} control flow")
    values = {}
    for name in reversed(order):
        block = blocks[name]
        local_events = sum(ins["op"] in _ALLOCATOR_OPS for ins in block["ops"])
        # The current HIA Python evaluator ticks for every opcode and every
        # terminator, plus once on each function invocation (accounted below).
        local_ticks = len(block["ops"]) + 1
        max_depth = 1
        for ins in block["ops"]:
            if ins["op"] == "call":
                child = calculated[ins["attrs"]["function"]]
                local_events += child["max_allocator_interactions"]
                local_ticks += child["max_vm_ticks"]
                max_depth = max(max_depth, 1 + child["max_call_depth"])
        if successors[name]:
            local_events += max(values[target]["alloc"] for target in successors[name])
            local_ticks += max(values[target]["ticks"] for target in successors[name])
            max_depth = max(max_depth, *(values[target]["depth"] for target in successors[name]))
        values[name] = {"alloc": local_events, "ticks": local_ticks, "depth": max_depth}
    entry = values[fn["entry"]]
    return {"function": fn["name"],
            "max_allocator_interactions": entry["alloc"],
            "max_vm_ticks": entry["ticks"] + 1,
            "max_call_depth": entry["depth"]}


def qualify_vm_call_depth(program, *, max_call_depth: int) -> dict:
    """Prove ONLY root-inclusive synchronous HIA VM frames in v1..v7.

    The canonical executable Core is fully reverified. The direct call graph
    is closed and statically named. A cyclic call graph is rejected; CFG loops
    do not themselves add nested synchronous stack frames.

    This intentionally does NOT count allocator interactions, VM ticks,
    recursive-chain destruction, native stack bytes, task stacks, or CPU time.
    Those quantities must never inherit this narrow v7 certificate.
    """
    from .hia_program import verify_program

    if type(max_call_depth) is not int or not 1 <= max_call_depth <= 256:
        _reject("E_HIA_BUDGET_POLICY",
                "max_call_depth requires an integer 1..256 (root frame inclusive)")
    checked = verify_program(program)
    document = checked.as_dict()
    # Keep exact admitted ISA identities; a future version must be audited.
    if document["schema"] not in (set(_ALLOWED_CORE_SCHEMAS) | {"hepta.hia.program.v7"}):
        _reject("E_HIA_BUDGET_PROFILE",
                "synchronous VM frame budget requires an audited primitive v1..v7 Core")
    functions = document["functions"]
    named = {fn["name"]: fn for fn in functions}
    edges = {
        fn["name"]: {
            op["attrs"]["function"]
            for block in fn["blocks"] for op in block["ops"]
            if op["op"] == "call"
        }
        for fn in functions
    }
    # No trusted producer receipt or bounded-loop assertion can eliminate a
    # true recursive call edge. All definitions are checked, even if private.
    order = _topological(list(named), edges, "synchronous HIA call graph")
    depth = {}
    for name in reversed(order):
        depth[name] = 1 + max((depth[callee] for callee in edges[name]), default=0)
    rows = [{"function": fn["name"], "max_call_depth": depth[fn["name"]]}
            for fn in functions]
    if any(row["max_call_depth"] > max_call_depth for row in rows):
        _reject("E_HIA_BUDGET_EXCEEDED",
                "at least one verified function exceeds the synchronous VM frame limit")
    report = {
        "schema": "hepta.hia.vm-call-depth-budget.v1",
        "status": "qualified_root_inclusive_synchronous_vm_frames_only",
        "core_sha256": checked.sha256,
        "input_sha256": checked.input_sha256,
        "core_schema": document["schema"],
        "limit_frames": max_call_depth,
        "functions": rows,
        "claims": {
            "synchronous_hia_vm_frames_bounded": True,
            "whole_module_call_graph_acyclic": True,
            "vm_ticks_bounded": False,
            "allocator_interactions_bounded": False,
            "process_rss_or_native_stack_bytes_bounded": False,
            "async_task_stacks_bounded": False,
            "source_to_core_or_backend_refinement_proved": False,
            "whole_language_soundness_proved": False,
        },
    }
    raw = json.dumps(report, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False, allow_nan=False).encode("utf-8")
    report["sha256"] = sha256(raw).hexdigest()
    return report


def analyze_static_budget(program, *, max_allocator_interactions=None,
                          max_vm_ticks=None, max_call_depth=None,
                          max_live_heap_bytes=None) -> dict:
    """Reverify canonical HIA and reject any unbounded control/call graph.

    All limits are upper bounds per one public invocation, across any
    *feasible* execution path. The algorithm uses a conservative maximum over
    syntactic branches, so an impossible branch may cause a safe rejection.
    It counts owner drops even when the pointer is null; thus the allocator
    bound is conservative across zero-size/fallible allocation profiles.
    """
    from .hia_program import verify_program

    _limit(max_allocator_interactions, "max_allocator_interactions")
    _limit(max_vm_ticks, "max_vm_ticks")
    _limit(max_call_depth, "max_call_depth")
    _limit(max_live_heap_bytes, "max_live_heap_bytes")
    checked = verify_program(program)
    document = checked.as_dict()
    if document["schema"] not in _ALLOWED_CORE_SCHEMAS:
        _reject("E_HIA_BUDGET_PROFILE", "this analyzer supports primitive v1..v6; recursive-chain budgets need separate invariants")
    functions = document["functions"]
    by_name = {fn["name"]: fn for fn in functions}
    call_edges = {
        fn["name"]: {ins["attrs"]["function"]
                     for block in fn["blocks"] for ins in block["ops"]
                     if ins["op"] == "call"}
        for fn in functions
    }
    order = _topological(list(by_name), call_edges, "HIA call graph")
    calculated = {}
    for fn_name in reversed(order):
        calculated[fn_name] = _bound_function(by_name[fn_name], calculated)
    rows = [calculated[fn["name"]] for fn in functions]
    if max_live_heap_bytes is not None:
        # Opt-in payload-byte bound: run over the SAME verified executable
        # Core and reject unknown allocation extents, cycles or resource
        # arguments instead of importing assumptions from source metadata.
        from .hia_heap_bound import analyze_constant_live_heap
        bounds = analyze_constant_live_heap(checked)
        if (set(bounds) != {row["function"] for row in rows}
                or any(type(value) is not int or value < 0 for value in bounds.values())):
            _reject("E_HIA_BUDGET_GRAPH", "incomplete heap-bound inventory")
        for row in rows:
            observed = bounds[row["function"]]
            row["max_live_heap_bytes"] = observed
            if observed > max_live_heap_bytes:
                _reject("E_HIA_BUDGET_EXCEEDED",
                        f"{row['function']}: requested live payload bytes exceed explicit policy")
    for row in rows:
        for key, limit in (("max_allocator_interactions", max_allocator_interactions),
                           ("max_vm_ticks", max_vm_ticks),
                           ("max_call_depth", max_call_depth)):
            if limit is not None and row[key] > limit:
                _reject("E_HIA_BUDGET_EXCEEDED", f"{row['function']}: {key} exceeds explicit policy")
    result = {"schema": SCHEMA, "status": "finite_structural_upper_bound_not_native_time_proof",
              "core_sha256": checked.sha256, "functions": rows,
              "limits": {"max_allocator_interactions": max_allocator_interactions,
                         "max_vm_ticks": max_vm_ticks,
                         "max_call_depth": max_call_depth},
              "claims": {"finite_acyclic_cfg_and_call_graph_checked": True,
                         "allocator_interactions_upper_bounded": True,
                         "vm_tick_events_upper_bounded": True,
                         "native_cpu_time_or_rss_proved": False,
                         "full_source_to_core_refinement_proved": False,
                         "whole_language_soundness_proved": False}}
    if max_live_heap_bytes is not None:
        result["limits"]["max_live_heap_bytes"] = max_live_heap_bytes
        result["claims"]["requested_live_payload_bytes_upper_bounded"] = True
    content = json.dumps(result, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
    result["sha256"] = sha256(content).hexdigest()
    return result
