# Preserve historical Core while isolating x86 experimental operations

This Draft continuation of #932 fixes six previously failing *frozen*
Core-only original-source comparisons without editing or weakening those
tests or their original fixtures. The experimental MFENCE/INVLPG opcode
catalog now sits outside the historical 50-opcode `OPCODES` registry and is
selected only for the two explicit kernel schemas. The fixed v1–v8
`PRIMITIVE_SCHEMAS` set is retained; admission of the isolated kernel grammar
uses the explicit `PRIMITIVE_PROFILES` registry.

The historical `Code` class and `_Function` lowering remain structurally
identical to the frozen originals. Kernel-specific instruction bytes reside
in `KernelCode`; kernel lowering in `_KernelFunction`. Their direct native
emitter selects the experimental classes *only* for the two named schemas.
Independent GNU-as byte comparisons, NOP replacement checks, original
direct machine equivalence tests, and legacy refusal tests remain mandatory.

This preserves the old native HIA Core source/ABI invariants while
keeping the experimental new instruction path reachable. No change is a
CPL0 capability, CR3 ownership proof, selfhost_elf lowering, authenticated
IPI/remote-CPU action, or full Linux closure. All 17 HeptaKernel acceptance
gates and 422 syscall rows remain HOLD pending actual implementation.
