"""One finite, fail-closed static resource policy shared by IR and LLVM.

This checks only the already-modelled Hepta source *effect bounds*: zero
declared heap allocations, no blocking/spawn/suspend. It is NOT an overall
process memory, stack, CPU, real-time or FFI budget proof. Both the owned
LLVM backend and the resource abstractor must use the same predicate.
"""
from __future__ import annotations

from .checker import EFFECTS as _CHECKED_EFFECTS


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
    # A plausible effect inventory is not evidence that the actual frontend
    # accepted the source. Only the successful checker result can authorize a
    # source-level resource contract. bool/int impersonation must not pass.
    if getattr(checked, "ok", None) is not True:
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
    if upper - _CHECKED_EFFECTS:
        return False
    # This finite Owned LLVM policy cannot infer the allocation or blocking
    # behavior of arbitrary foreign, unsafe or host-I/O operations. Their
    # absence is a required assumption for a nonempty no-cost contract.
    if clauses and upper & {"ffi", "unsafe", "io"}:
        return False
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
            # Hepta's current checked effect vocabulary has no independent
            # 'suspend' effect. A block/spawn operation cannot be certified as
            # non-suspending merely because that nonexistent tag is absent.
            # This finite native profile declines those ambiguous effects.
            if value is not False or upper & {"suspend", "block", "spawn"}:
                return False
        else:
            return False
    return True
