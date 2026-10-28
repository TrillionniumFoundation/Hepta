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

# These are audited operational profiles, not the current schema registry's
# open-ended feature set. A returned v8 loan creates/transfers a view at an
# existing ret event: it neither invokes a function nor adds a VM tick or HIA
# payload allocation. Recursive chain destruction, however, can perform an
# input-dependent number of ticks/frees inside one owner.drop.
_V8_SCHEMA = "hepta.hia.program.v8"
_V8_BYTE_TYPES = frozenset({
    "i8", "i16", "i32", "i64", "isize", "u8", "u16", "u32", "u64", "usize",
    "bool", "unit", "buffer", "readbuf", "mutbuf",
})
_V8_BYTE_OPS = frozenset({
    "const", "int.cast", "int.neg.checked", "select",
    "bool.not", "bool.and", "bool.or",
    "bit.and", "bit.or", "bit.xor", "bit.not",
    "compare.eq", "compare.ne", "compare.lt", "compare.le", "compare.gt", "compare.ge",
    "int.add.checked", "int.sub.checked", "int.mul.checked",
    "int.add.wrap", "int.sub.wrap", "int.mul.wrap",
    "int.div.checked", "int.rem.checked", "int.shl.checked", "int.shr.checked",
    "buffer.new", "buffer.try_new", "buffer.len", "borrow.read", "borrow.mut",
    "loan.end", "owner.move", "owner.drop", "buffer.load", "buffer.store",
    "buffer.fill", "buffer.copy", "buffer.move_within", "buffer.swap",
    "buffer.copy_range", "buffer.fill_range", "call",
})
_V8_CHAIN_OPS = frozenset({
    "chain.empty", "chain.try_push", "chain.pop", "chain.is_empty",
    "chain.head_read", "chain.head_mut",
})


def _audit_v8_resource_profile(document: dict, *, allow_chain: bool) -> None:
    """Check the entire already-verified module against one reviewed domain.

    This never replaces Core's alias, origin, CFG or effect validation. The
    explicit inventory also covers uncalled private functions, declarations
    and outputs, so a dynamically sized chain cannot hide behind owner.drop.
    """
    if document.get("schema") != _V8_SCHEMA:
        _reject("E_HIA_BUDGET_PROFILE", "returned-loan resource profile requires primitive v8")
    types = _V8_BYTE_TYPES | ({"chain"} if allow_chain else set())
    operations = _V8_BYTE_OPS | (_V8_CHAIN_OPS if allow_chain else set())
    for fn in document["functions"]:
        declared = [p["type"] for p in fn["params"]] + fn["returns"]
        for block in fn["blocks"]:
            declared.extend(p["type"] for p in block["params"])
            if block["term"]["op"] not in {"ret", "trap", "jump", "branch"}:
                _reject("E_HIA_BUDGET_PROFILE", "unreviewed v8 terminator")
            for instruction in block["ops"]:
                if instruction["op"] not in operations:
                    _reject("E_HIA_BUDGET_PROFILE",
                            f"{fn['name']}: opcode lacks this v8 resource-event review")
                declared.extend(p["type"] for p in instruction["out"])
        if any(typ not in types for typ in declared):
            _reject("E_HIA_BUDGET_PROFILE",
                    f"{fn['name']}: resource type lacks this v8 resource-event review")


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
    """Bound ONLY root-inclusive synchronous HIA VM frames in v1..v8.

    The canonical executable Core is fully reverified. The direct call graph
    is closed and statically named. A cyclic call graph is rejected; CFG loops
    do not themselves add nested synchronous stack frames.

    This intentionally does NOT count allocator interactions, VM ticks,
    recursive-chain destruction, native stack bytes, task stacks, or CPU time.
    Those quantities must never inherit this narrow frame certificate.
    V8 has a distinct receipt: returned-loan processing has been reviewed
    independently of the old tick/allocation and native admission profiles.
    """
    from .hia_program import verify_program

    if type(max_call_depth) is not int or not 1 <= max_call_depth <= 256:
        _reject("E_HIA_BUDGET_POLICY",
                "max_call_depth requires an integer 1..256 (root frame inclusive)")
    checked = verify_program(program)
    document = checked.as_dict()
    # Keep exact admitted ISA identities; a future version must be audited.
    returned_loans = document["schema"] == _V8_SCHEMA
    if returned_loans:
        _audit_v8_resource_profile(document, allow_chain=True)
    elif document["schema"] not in (set(_ALLOWED_CORE_SCHEMAS) | {"hepta.hia.program.v7"}):
        _reject("E_HIA_BUDGET_PROFILE",
                "synchronous VM frame budget requires an audited primitive v1..v8 Core")
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
    if returned_loans:
        report["schema"] = "hepta.hia.vm-call-depth-budget.v2"
        report["profile"] = "parameter-loan-synchronous-frames-v8"
        report["claims"]["canonical_return_origins_reverified"] = True
        report["claims"]["returned_view_creation_adds_synchronous_frames"] = False
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
    returned_loans = document["schema"] == _V8_SCHEMA
    if returned_loans:
        _audit_v8_resource_profile(document, allow_chain=False)
    elif document["schema"] not in _ALLOWED_CORE_SCHEMAS:
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
    if returned_loans:
        result["schema"] = "hepta.hia.static-budget.v2"
        result["profile"] = "acyclic-byte-owner-parameter-loans-v8"
        result["core_schema"] = document["schema"]
        result["input_sha256"] = checked.input_sha256
        result["claims"]["canonical_return_origins_reverified"] = True
        result["claims"]["recursive_chain_costs_bounded"] = False
        result["claims"]["runtime_view_storage_or_native_stack_bounded"] = False
    if max_live_heap_bytes is not None:
        result["limits"]["max_live_heap_bytes"] = max_live_heap_bytes
        result["claims"]["requested_live_payload_bytes_upper_bounded"] = True
    content = json.dumps(result, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
    result["sha256"] = sha256(content).hexdigest()
    return result
