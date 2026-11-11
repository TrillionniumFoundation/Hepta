"""No-heap host dynamic ABI profile for checked scalar SSA/LLVM code.

Reuses the one independently reviewed ELF64 dynamic-symbol parser. This
additional allowlist is narrower than the owned-memory LLVM profile: no
allocator, free, memcpy or arbitrary foreign import is permitted from the
finite scalar source grammar. Binary inspection is not semantic refinement.
"""
from __future__ import annotations

from .elf_shared_abi import ELFSharedABIRejected, inspect_owned_shared_elf


_SCALAR_IMPORTS = frozenset({
    "abort",
    "__cxa_finalize",
    "_ITM_registerTMCloneTable",
    "_ITM_deregisterTMCloneTable",
    "__gmon_start__",
})


def inspect_scalar_host_elf(data: bytes, exports: tuple[str, ...]) -> dict:
    """Require an exact source export list and bounded nonallocating imports."""
    report = inspect_owned_shared_elf(data, exports)
    actual = report.get("unresolved_imports")
    if (type(actual) is not list
            or any(type(name) is not str or name not in _SCALAR_IMPORTS
                   for name in actual)):
        raise ELFSharedABIRejected(
            "E_LLVM_SSA_HOST_ABI: scalar native code contains unsupported memory/foreign import")
    return report
