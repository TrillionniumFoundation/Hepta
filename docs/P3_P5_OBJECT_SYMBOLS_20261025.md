# P3/P5: native object export/import verification

The five-target scalar LLVM backend now inspects bounded native ELF64,
COFF and Mach-O symbol tables before publishing a native object. It requires
the defined externally exported functions to match the source LLVM function
inventory exactly and unresolved externals to be a subset of `abort`.

A malicious or misconfigured compiler output with an absent function, an
additional exported function or an unreviewed foreign call fails closed.
Rehashed LLVM input alone cannot introduce new declarations because
`SSA_LLVM_IR.check_identity` also validates the reviewed LLVM grammar.

These checks retain all format and payload bounds from `object_structure`.
Tests include real object generation and symbol name mutation on five targets.
The parser is deliberately not a general ELF/PE/Mach-O ABI implementation:
it does not verify code semantics, relocations' target meanings, loading,
exceptions or the correctness of external `abort` at runtime.

The source-to-IR theorem, physical platform execution, full C ABI and broad
foreign-library support remain OPEN.
