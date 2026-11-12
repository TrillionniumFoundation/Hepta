"""The sequential Core's explicit capability renaming boundary.

This function is used by the production CFG checker.  Its specification is
the injective, closed renaming in formal/HiaCapabilityRenaming.lean.  The Lean
model proves relational facts; it does not prove this Python interpreter or
the complete instruction/LLVM semantics.  Runtime admission remains mandatory.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Capability:
    typ: str
    root: str
    parent: str | None = None
    external: bool = False
    # This is a function parameter identity, not a block-local SSA name.
    origin: str | None = None


class CapabilityFlowRejected(ValueError):
    def __init__(self, message, code="E_HIA_RESOURCE"):
        self.code = code
        super().__init__(message)


def rename_capabilities(capabilities, remap):
    """Run the explicitly selected native edge policy, with no selected fallback."""
    import os
    path = os.environ.get('HEPTA_HIA_CAPABILITY_RENAMING_MANIFEST')
    if path:
        from .hia_capability_renaming_native import installed_capability_renaming
        return installed_capability_renaming(path).rename(capabilities, remap)
    return _reference_rename_capabilities(capabilities, remap)


def _reference_rename_capabilities(capabilities, remap):
    """Carry the selected closed resource graph through an injective SSA map.

All local owners/loans must survive.  Unselected *external* loans may be
forgotten, as in the existing Core.  A surviving loan carries its root and
parent.  Type, external status, and original parameter origin never change.
The inputs are verifier-owned dictionaries, not an untrusted wire interface.
"""
    if (type(capabilities) is not dict or type(remap) is not dict
            or any(type(k) is not str or type(v) is not Capability
                   for k, v in capabilities.items())
            or any(type(k) is not str or type(v) is not str
                   for k, v in remap.items())):
        raise CapabilityFlowRejected("exact internal capability graph and name map required")
    if len(set(remap.values())) != len(remap):
        raise CapabilityFlowRejected("linear capability duplicated across an edge")
    if not set(remap).issubset(capabilities):
        raise CapabilityFlowRejected("edge names an absent capability")
    if any(not cap.external and name not in remap
           for name, cap in capabilities.items()):
        raise CapabilityFlowRejected("edge drops a live owner or local loan")
    result = {}
    for name, target in remap.items():
        cap = capabilities[name]
        if cap.root not in remap or cap.parent is not None and cap.parent not in remap:
            raise CapabilityFlowRejected("loan must travel with its owner/parent capability", "E_HIA_LOAN")
        result[target] = Capability(cap.typ, remap[cap.root],
                                   remap[cap.parent] if cap.parent is not None else None,
                                   cap.external, cap.origin)
    return result
