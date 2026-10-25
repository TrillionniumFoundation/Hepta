# P5 source-bound native LLVM SSA compilation (optional strict mode)

Both native compile APIs now accept `ssa=... , cfg=...`. If both are provided,
`require_exact_ssa_origin` independently verifies the original SSA/CFG,
regenerates LLVM from that exact pair and demands complete
`SSA_LLVM_IR` dataclass equality (text, digest, function inventory,
source SSA and verification digests). Rehashed, vocabulary-compliant but
semantically altered pure i32 LLVM text is rejected BEFORE invoking Clang,
and the native report sets `ssa_cfg_origin_rechecked=true`.

Supplying only one snapshot rejects; the previous snapshot-free API remains
available for limited legacy callers but reports
`ssa_cfg_origin_rechecked=false`, cannot claim source provenance and is
still a separately unqualified machine-code route.

The new scope does not prove that the supplied CFG was faithfully generated
from a fully type-safe Hepta project, that SSA/LLVM lowering is semantically
correct for all inputs, or that any foreign or target ABI obligation was
discharged. General Ownership, Provenance, Drop, Effects and formal backend
refinement remain P1/P5 production blockers.
