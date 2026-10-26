"""One finite, fail-closed static resource policy shared by IR and LLVM.

This checks only the already-modelled Hepta source *effect bounds*: zero
declared heap allocations, no blocking/spawn/suspend. It is NOT an overall
process memory, stack, CPU, real-time or FFI budget proof. Both the owned
LLVM backend and the resource abstractor must use the same predicate.
"""
from __future__ import annotations


def finite_static_contract_allowed(fn, checked) -> bool:
    """Accept typed no-cost clauses only when transitive effects agree.

    Python bool is a subclass of int; use exact identity/type checks so a
    forged JSON 0/1 cannot masquerade as a valid false/true proof obligation.
    Unknown resource keys and unknown inferred effect inventories fail closed.
    """
    clauses = getattr(fn, "resources", None)
    declared = getattr(fn, "effects", None)
    effects = getattr(checked, "effects", None)
    name = getattr(fn, "name", None)
    if type(clauses) is not dict or type(declared) is not set or not isinstance(effects, dict):
        return False
    if not isinstance(name, str) or not name:
        return False
    # The real frontend materializes transitive effects for every function.
    # A missing entry is an unverified graph, not an empty/pure effect set.
    if name not in effects:
        return False
    inferred = effects[name]
    if type(inferred) is not set or any(type(v) is not str for v in inferred | declared):
        return False
    upper = declared | inferred
    for key, value in clauses.items():
        if key == "heap_allocations":
            if type(value) is not int or value != 0 or "alloc" in upper:
                return False
        elif key == "may_block":
            if value is not False or "block" in upper:
                return False
        elif key == "may_spawn":
            if value is not False or "spawn" in upper:
                return False
        elif key == "may_suspend":
            if value is not False or "suspend" in upper:
                return False
        else:
            return False
    return True
