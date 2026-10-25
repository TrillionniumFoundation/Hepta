# P3/P5: Hepta source to Linux GCC-linked scalar ABI acceptance

Stacked exact base PR #80: `ba40ef583d9a2f2f3223f7a90f10024d870ae56a`.

## Real Hepta source requirement

Unlike the independent hand-authored LLVM IR probe,
`tests/test_hepta_source_linux_c_abi.py` parses a real Hepta language
source, requires actual pinned `rustc_checked` native reference validation,
projects through the sole canonical HSIR, CFG and independent scalar SSA
verification, and emits a direct LLVM i32 object for Linux x86_64.

The object must pass strict ELF section extents and defined exported symbol
checks **before** publication. A separately GCC-compiled C caller links
that object at -O0/-O2 and executes 417 bounded input values. The C
driver is its own reference oracle, and the intentionally wrong GCC
implementation must exit with the designated mismatch code 17.

## Actual local vs unexecuted evidence

Independent Linux x86_64 LLVM IR/GCC native ABI probe already executed
4 correct and 4 wrong-code-control optimized combinations with 2001
inputs per program. It is not a Hepta language compilation.

The new end-to-end test source is committed but was **not executed**
against a pinned Hepta/rustc toolchain in this session. No CI status
is needed to continue development and none is used as a pass claim.

Still not proven: generic source/LLVM semantic refinement, pointer/owner
lowering, real Windows/macOS/ARM ABI, memory safety of foreign calls,
physical devices, GPU, and whole-project P0-P7/P01-P12 closure.
`whole_project_blockers_closed=false`.

Run on a fully provisioned Linux host:

    python -m unittest tests.test_hepta_source_linux_c_abi -v
