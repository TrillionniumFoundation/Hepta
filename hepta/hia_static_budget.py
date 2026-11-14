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
import os


SCHEMA = "hepta.hia.static-budget.v1"
# Historical receipts retain their v1-v6 meaning. V7 byte-only programs need
# the explicit operational audit below: recursive chain destruction can do
# arbitrarily much work inside one owner.drop despite an acyclic instruction CFG.
_ALLOWED_CORE_SCHEMAS = frozenset(f"hepta.hia.program.v{version}" for version in range(1, 7))
_ALLOCATOR_OPS = frozenset({"buffer.new", "buffer.try_new", "owner.drop"})

# These are audited operational profiles, not the current schema registry's
# open-ended feature set. A returned v8 loan creates/transfers a view at an
# existing ret event: it neither invokes a function nor adds a VM tick or HIA
# payload allocation. Recursive chain destruction, however, can perform an
# input-dependent number of ticks/frees inside one owner.drop.
_V8_SCHEMA = "hepta.hia.program.v8"
_V7_SCHEMA = "hepta.hia.program.v7"
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


def _reference_audit_resource_profile(document: dict, *, schema: str, allow_chain: bool) -> None:
    """Check the entire already-verified module against one reviewed domain.

    This never replaces Core's alias, origin, CFG or effect validation. The
    explicit inventory also covers uncalled private functions, declarations
    and outputs, so a dynamically sized chain cannot hide behind owner.drop.
    """
    if document.get("schema") != schema:
        _reject("E_HIA_BUDGET_PROFILE", f"resource profile requires {schema}")
    types = _V8_BYTE_TYPES | ({"chain"} if allow_chain else set())
    operations = _V8_BYTE_OPS | (_V8_CHAIN_OPS if allow_chain else set())
    for fn in document["functions"]:
        declared = [p["type"] for p in fn["params"]] + fn["returns"]
        for block in fn["blocks"]:
            declared.extend(p["type"] for p in block["params"])
            if block["term"]["op"] not in {"ret", "trap", "jump", "branch"}:
                _reject("E_HIA_BUDGET_PROFILE", f"unreviewed {schema} terminator")
            for instruction in block["ops"]:
                if instruction["op"] not in operations:
                    _reject("E_HIA_BUDGET_PROFILE",
                            f"{fn['name']}: opcode lacks this {schema} resource-event review")
                declared.extend(p["type"] for p in instruction["out"])
        if any(typ not in types for typ in declared):
            _reject("E_HIA_BUDGET_PROFILE",
                    f"{fn['name']}: resource type lacks this {schema} resource-event review")


def _native_owner():
    selected = os.environ.get('HEPTA_HIA_STATIC_BUDGET_MANIFEST')
    if selected is None:
        return None
    if not selected:
        raise ValueError('static-budget selector must not be empty')
    from .hia_static_budget_native import installed_static_budget
    return installed_static_budget(selected)


def _audit_resource_profile(document: dict, *, schema: str, allow_chain: bool) -> None:
    native = _native_owner()
    if native is None:
        _reference_audit_resource_profile(document, schema=schema, allow_chain=allow_chain)
    else:
        native.audit_profile(document, schema=schema, allow_chain=allow_chain)


def _audit_v8_resource_profile(document: dict, *, allow_chain: bool) -> None:
    _audit_resource_profile(document, schema=_V8_SCHEMA, allow_chain=allow_chain)


def _audit_v7_byte_resource_profile(document: dict) -> None:
    # These v7 instructions have the same per-op tick and byte-owner events as
    # the already reviewed v8 byte profile. No chain type or opcode, including
    # in unused definitions or block parameters, can inherit that accounting.
    _audit_resource_profile(document, schema=_V7_SCHEMA, allow_chain=False)


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


def _reference_topological(names: list[str], edges: dict[str, set[str]], context: str) -> list[str]:
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


def _topological(names: list[str], edges: dict[str, set[str]], context: str) -> list[str]:
    native = _native_owner()
    return (_reference_topological(names, edges, context) if native is None
            else native.topological(names, edges, context))


def _successors(term: dict) -> set[str]:
    kind = term["op"]
    if kind == "jump":
        return {term["target"]}
    if kind == "branch":
        return {term["then"]["target"], term["else"]["target"]}
    return set()


def _reference_bound_function(fn: dict, calculated: dict[str, dict]) -> dict:
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


def _bound_function(fn: dict, calculated: dict[str, dict]) -> dict:
    native = _native_owner()
    return (_reference_bound_function(fn, calculated) if native is None
            else native.function(fn, calculated))


def _reference_frame_rows(functions, edges):
    order = _topological([fn['name'] for fn in functions], edges, 'synchronous HIA call graph')
    depth = {}
    for name in reversed(order):
        depth[name] = 1 + max((depth[callee] for callee in edges[name]), default=0)
    return [{'function': fn['name'], 'max_call_depth': depth[fn['name']]} for fn in functions]


def _reference_first_exceeded(rows, limits, fields):
    for row in rows:
        for key in fields:
            if limits[key] is not None and row[key] > limits[key]:
                return row['function'], key
    return None


def _first_exceeded(rows, limits, fields):
    native = _native_owner()
    return (_reference_first_exceeded(rows, limits, fields) if native is None
            else native.first_exceeded(rows, limits, fields))


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
    native = _native_owner()
    rows = (_reference_frame_rows(functions, edges) if native is None
            else native.depths(functions, edges))
    if _first_exceeded(rows, {'max_call_depth': max_call_depth}, ('max_call_depth',)) is not None:
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
    byte_v7 = document["schema"] == _V7_SCHEMA
    if returned_loans:
        _audit_v8_resource_profile(document, allow_chain=False)
    elif byte_v7:
        _audit_v7_byte_resource_profile(document)
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
        exceeded = _first_exceeded(rows, {'max_live_heap_bytes': max_live_heap_bytes},
                                   ('max_live_heap_bytes',))
        if exceeded is not None:
            _reject("E_HIA_BUDGET_EXCEEDED",
                    f"{exceeded[0]}: requested live payload bytes exceed explicit policy")
    exceeded = _first_exceeded(rows, {
        'max_allocator_interactions': max_allocator_interactions,
        'max_vm_ticks': max_vm_ticks, 'max_call_depth': max_call_depth},
        ('max_allocator_interactions', 'max_vm_ticks', 'max_call_depth'))
    if exceeded is not None:
        _reject("E_HIA_BUDGET_EXCEEDED", f"{exceeded[0]}: {exceeded[1]} exceeds explicit policy")
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
    elif byte_v7:
        result["schema"] = "hepta.hia.static-budget.v3"
        result["profile"] = "acyclic-byte-owner-v7"
        result["core_schema"] = document["schema"]
        result["input_sha256"] = checked.input_sha256
        result["claims"]["canonical_byte_only_resource_profile_reverified"] = True
        result["claims"]["zero_length_owner_operations_counted"] = True
        result["claims"]["recursive_chain_costs_bounded"] = False
        result["claims"]["runtime_view_storage_or_native_stack_bounded"] = False
    if max_live_heap_bytes is not None:
        result["limits"]["max_live_heap_bytes"] = max_live_heap_bytes
        result["claims"]["requested_live_payload_bytes_upper_bounded"] = True
    content = json.dumps(result, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
    result["sha256"] = sha256(content).hexdigest()
    return result



def qualify_bounded_resources(program, *, limits: dict) -> dict:
    """Compose existing analyses for every explicit public scalar export.

    This is an optional production admission profile, not another Core or
    opcode semantics. It accepts no proof receipt: the same immutable Core
    is reverified and all quantities are freshly computed by the existing
    event/CFG and requested-payload analyzers. A normal application error is
    still a Core return, with Core's existing owner/loan obligations.

    Primitive v1..v6 use the existing all-function payload analysis. V8 uses
    the reviewed borrowed-call local-peak analysis independently for each
    public entry. V7 and nominal inputs retain their existing standalone
    support but need a separate composed-profile review. In particular, a
    schema relabel is never used to import a newer resource interpretation.
    """
    from .hia_program import verify_program
    from .hia_heap_bound import analyze_constant_live_heap, qualify_entry_live_heap_budget

    keys = {"max_allocator_interactions", "max_vm_ticks", "max_call_depth",
            "max_live_heap_bytes"}
    if type(limits) is not dict:
        _reject("E_HIA_BUDGET_POLICY", "bounded resource limits must be a plain object")
    # One capture of immutable built-in integers; later caller edits cannot
    # widen the policy between analysis and execution/native publication.
    policy = limits.copy()
    if (set(policy) != keys or any(type(value) is not int or value < 0
                                   for value in policy.values())
            or not 1 <= policy["max_vm_ticks"] <= 10_000_000
            or not 1 <= policy["max_call_depth"] <= 256
            or policy["max_live_heap_bytes"] > 1024 * 1024 * 1024):
        _reject("E_HIA_BUDGET_POLICY",
                "complete exact integer limits required: allocator interactions >=0, "
                "VM ticks 1..10000000, call frames 1..256, payload bytes 0..1073741824")
    checked = verify_program(program)
    document = checked.as_dict()
    if (checked.structured_bytes is not None
            or document["schema"] not in _ALLOWED_CORE_SCHEMAS | {_V8_SCHEMA}):
        _reject("E_HIA_BUDGET_PROFILE",
                "bounded resources require explicit primitive v1..v6 or reviewed byte-only v8 Core")
    exports = document.get("exports")
    if type(exports) is not list or not 1 <= len(exports) <= 128:
        _reject("E_HIA_BUDGET_PROFILE", "bounded resources require 1..128 explicit scalar exports")
    # This checks *all* definitions and call edges, including private code.
    # Traps and allocator refusal do not erase a syntactic possible path.
    events = analyze_static_budget(checked,
        max_allocator_interactions=policy["max_allocator_interactions"],
        max_vm_ticks=policy["max_vm_ticks"],
        max_call_depth=policy["max_call_depth"])
    event_rows = {row["function"]: row for row in events["functions"]}
    heaps = []
    if document["schema"] == _V8_SCHEMA:
        for name in exports:
            heaps.append(qualify_entry_live_heap_budget(checked, name,
                max_live_heap_bytes=policy["max_live_heap_bytes"]))
        peaks = {row["function"]: row["peak_bound_bytes"] for row in heaps}
    else:
        peaks = analyze_constant_live_heap(checked)
        if _first_exceeded([{'function': name, 'max_live_heap_bytes': value}
                            for name, value in peaks.items()], policy, ('max_live_heap_bytes',)) is not None:
            _reject("E_HIA_BUDGET_EXCEEDED", "requested payload peak exceeds bounded resource policy")
    rows = [{**event_rows[name], "max_live_heap_bytes": peaks[name]} for name in exports]
    report = {
        "schema": "hepta.hia.bounded-resources.v1",
        "profile": "explicit-scalar-exports-acyclic-byte-resources-v1",
        "status": "qualified_structural_events_and_requested_payload_only",
        "core_schema": document["schema"],
        "core_sha256": checked.sha256,
        "input_sha256": checked.input_sha256,
        "limits": policy,
        "exports": rows,
        "static_events": events,
        "borrowed_entry_payload": heaps,
        "claims": {
            "canonical_core_reverified": True,
            "every_explicit_public_export_covered": True,
            "acyclic_control_and_call_graphs_checked": True,
            "allocator_interactions_and_vm_ticks_bounded": True,
            "root_inclusive_synchronous_vm_frames_bounded": True,
            "requested_live_hia_byte_payload_bounded": True,
            "normal_return_resource_obligations_checked": True,
            "program_traps_excluded": False,
            "allocator_success_guaranteed": False,
            "checker_to_formal_model_refinement_proved": False,
            "source_to_core_or_native_backend_refinement_proved": False,
            "process_rss_or_native_stack_bytes_bounded": False,
            "whole_language_soundness_proved": False,
            "retained_receipt_grants_admission": False,
        },
    }
    raw = json.dumps(report, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False, allow_nan=False).encode("utf-8")
    report["sha256"] = sha256(raw).hexdigest()
    return report
