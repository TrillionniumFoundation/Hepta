"""Shared executable resource, control-flow and evaluator-limit rules.

These functions are production dependencies, not an alternative admission
authority. The verifier still checks every instruction and both CFG arms. The
VM and LLVM emitter use the same ordered successor relation and parallel edge
binding. Native execution does not acquire VM fuel/heap/depth limits merely by
using this module. Independent backend-refinement proofs remain outstanding.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from .hia_opcodes import BYTE_RESOURCES, OWNERS, RESOURCES


SCHEMA = "hepta.hia.semantic-kernel.v1"
CHAIN_NODE_BYTES = 24
MAX_OBJECT_BYTES = (1 << 63) - 1


class SemanticRejected(ValueError):
    def __init__(self, message, code):
        self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class Capability:
    typ: str
    root: str
    parent: str | None = None
    external: bool = False
    origin: str | None = None


def successors(term):
    """The ordered edge relation: a branch's true edge precedes its false edge."""
    op = term["op"]
    if op == "jump":
        return ({"target": term["target"], "args": term["args"]},)
    if op == "branch":
        return (term["then"], term["else"])
    if op in {"ret", "trap"}:
        return ()
    raise SemanticRejected("unknown control terminator", "E_HIA_CFG")


def selected_successor(term, condition=None):
    edges = successors(term)
    if term["op"] == "jump":
        return edges[0]
    if term["op"] != "branch" or type(condition) is not bool:
        raise SemanticRejected("branch selection requires an exact bool", "E_HIA_CFG")
    return edges[0 if condition else 1]


def parallel_edge_values(arguments, parameters, lookup):
    """Snapshot every source before publishing any destination binding.

    Used for VM block arguments and LLVM edge/phi tuples. It deliberately does
    not zip-truncate a malformed edge, even after ordinary static admission.
    """
    if len(arguments) != len(parameters):
        raise SemanticRejected("edge arity differs from target block", "E_HIA_CFG")
    names = [param["name"] for param in parameters]
    if len(names) != len(set(names)):
        raise SemanticRejected("duplicate destination block parameter", "E_HIA_CFG")
    return tuple(lookup(name) for name in arguments)


def children(caps, name):
    return [other for other, cap in caps.items() if cap.parent == name]


def ancestors(caps, name):
    result = set()
    while caps[name].parent is not None:
        name = caps[name].parent
        if name in result or name not in caps:
            raise SemanticRejected("invalid loan parent graph", "E_HIA_LOAN")
        result.add(name)
    return result


def require_owner_free(caps, name, typ):
    if typ not in OWNERS:
        raise SemanticRejected("operation requires an owner", "E_HIA_TYPE")
    if any(cap.root == name and other != name for other, cap in caps.items()):
        raise SemanticRejected("owner moved/dropped/returned while borrowed", "E_HIA_LOAN")


def require_access(caps, name, typ, mutable=False):
    if typ not in ({"mutbuf"} if mutable else {"readbuf", "mutbuf"}):
        raise SemanticRejected("memory access requires appropriate view", "E_HIA_TYPE")
    if children(caps, name):
        raise SemanticRejected("parent view is suspended until child loans end", "E_HIA_LOAN")


def borrowed_capability(caps, source, typ, mutable, *, chain_head=False):
    allowed = {"chain"} if chain_head else ({"buffer", "mutbuf"} if mutable else BYTE_RESOURCES)
    if typ not in allowed:
        raise SemanticRejected("invalid borrow permission", "E_HIA_LOAN")
    root = caps[source].root
    permitted = ancestors(caps, source) | {source}
    others = [cap for name, cap in caps.items() if cap.root == root and name not in permitted]
    if (mutable and others) or (not mutable and any(cap.typ == "mutbuf" for cap in others)):
        raise SemanticRejected("conflicting live borrow", "E_HIA_LOAN")
    return Capability("mutbuf" if mutable else "readbuf", root, source,
                      origin=caps[source].origin)


def require_loan_end(caps, name):
    if caps[name].external:
        raise SemanticRejected("callee cannot end its caller's loan", "E_HIA_LOAN")
    if children(caps, name):
        raise SemanticRejected("end child loans before their parent", "E_HIA_LOAN")


def transfer_capabilities(arguments, actual_types, parameters, caps):
    """Linear CFG renaming, preserving parent/root/formal-origin identity."""
    if len(arguments) != len(actual_types) or actual_types != [p["type"] for p in parameters]:
        raise SemanticRejected("edge values do not match block parameter types", "E_HIA_CFG")
    if len({p["name"] for p in parameters}) != len(parameters):
        raise SemanticRejected("duplicate destination block parameter", "E_HIA_CFG")
    resources = [name for name, typ in zip(arguments, actual_types) if typ in RESOURCES]
    if len(resources) != len(set(resources)):
        raise SemanticRejected("linear capability duplicated across an edge", "E_HIA_RESOURCE")
    required = {name for name, cap in caps.items() if not cap.external}
    if not required.issubset(resources):
        raise SemanticRejected("edge drops a live owner or local loan", "E_HIA_RESOURCE")
    remap = {name: p["name"] for name, p in zip(arguments, parameters) if p["type"] in RESOURCES}
    result = {}
    for name, param in zip(arguments, parameters):
        if param["type"] not in RESOURCES:
            continue
        cap = caps[name]
        if cap.root not in remap or (cap.parent is not None and cap.parent not in remap):
            raise SemanticRejected("loan must travel with its owner/parent capability", "E_HIA_LOAN")
        result[param["name"]] = Capability(cap.typ, remap[cap.root],
            remap[cap.parent] if cap.parent is not None else None, cap.external, cap.origin)
    return result


def require_clean_return(names, types, origins, caps):
    """Normal, failure-as-value and cooperative-cancel returns have one rule.

    Return a new state; a rejected return never partially consumes the caller's
    state. A trap has no implicit cleanup and does not use this transition.
    """
    if len(names) != len(types) or len(names) != len(origins):
        raise SemanticRejected("return type/arity mismatch", "E_HIA_TYPE")
    state = dict(caps)
    loans = [name for name, typ in zip(names, types) if typ in {"readbuf", "mutbuf"}]
    if len(loans) != len(set(loans)):
        raise SemanticRejected("same loan capability returned twice", "E_HIA_LOAN")
    for name, typ, origin in zip(names, types, origins):
        if typ not in {"readbuf", "mutbuf"}:
            continue
        cap = state[name]
        parent = state.get(cap.parent)
        if (cap.origin != origin or children(state, name)
                or not (cap.external or parent is not None and parent.external)):
            raise SemanticRejected("returned loan must be its declared parameter or a direct child", "E_HIA_LOAN")
    for name in loans:
        del state[name]
    owners = [name for name, typ in zip(names, types) if typ in OWNERS]
    if len(owners) != len(set(owners)):
        raise SemanticRejected("same owner returned twice", "E_HIA_RESOURCE")
    for name in owners:
        require_owner_free(state, name, state[name].typ)
        del state[name]
    if any(not cap.external for cap in state.values()):
        raise SemanticRejected("return leaves live owner/local loan", "E_HIA_RESOURCE")
    return state


def step_charge(used, limit):
    """The failed attempted tick is reported; no operation runs after it."""
    return used + 1, used < limit


def call_entry_allowed(depth, limit):
    """Root depth zero occupies frame one; reject before its entry tick."""
    return depth < limit


def allocation_admission(size, live_bytes, limit):
    """Classify before touching malloc/failure counters, in semantic order."""
    if size == 0:
        return "empty"
    if size > MAX_OBJECT_BYTES:
        return "object_size"
    if size > limit - live_bytes:
        return "heap_budget"
    return "attempt"


def contract():
    return {
        "schema": SCHEMA,
        "implementation_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
        "shared_production_rules": ["ordered_CFG_successors", "parallel_edge_values",
            "linear_resource_edge_renaming", "loan_conflict_and_suspension",
            "normal_return_resource_balance", "VM_step_call_and_allocation_admission"],
        "outcomes": {
            "returned": "all local loans/owners discharged; includes failure-as-value and cooperative cancellation",
            "trapped": "aborting program outcome; stopped resources reported; no destructor-cleanup claim",
            "budget_exceeded": "analysis/evaluator stop, not a program trap or allocation failure"},
        "cancellation": "explicit cooperative control flow and balanced normal return; no async/preemptive cleanup",
        "budgets": {"VM_step": "one per call entry, operation, terminator and destroyed chain node",
            "VM_call_depth": "root is frame one; rejection precedes entry tick",
            "VM_live_bytes": "owned payload plus 24 bytes per chain node; excludes host allocator/Python/stack overhead",
            "zero_size_owner": "linear capability without allocator attempt or injected failure",
            "native_limits": "not implied by VM limits; separately qualified runtime/policy required"},
        "chain_node_bytes": CHAIN_NODE_BYTES,
        "trusted_boundary": ["Python checker/kernel", "composite elaborator", "VM implementation",
            "LLVM lowering", "Clang/LLVM", "allocator/OS/hardware", "any admitted foreign wrapper"],
        "claims": {"shared_executable_rules": True, "complete_operational_semantics_generated": False,
            "whole_language_soundness_proved": False, "backend_refinement_proved": False,
            "native_VM_budget_equivalence": False, "asynchronous_cancellation_safe": False},
    }
