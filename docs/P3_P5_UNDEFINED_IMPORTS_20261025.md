# P3/P5 cross-object undefined dependency boundary

After the exact ELF/COFF/Mach-O object-format checks and before publishing an
SSA object, the compiler now enumerates undefined external/weak symbol table
entries on each of the five supported targets. Only C `abort` is allowed,
because the bounded checked-i32 overflow path may terminate via abort.
Any other unresolved symbol, malformed symbol table, string offset or
unrecognized Darwin encoding is rejected. Export verification is retained.

Source: `hepta.llvm_ssa_target._undefined_externals`.
Tests: `tests.test_llvm_ssa_undefined_externals`.

## Actual independently executed witness

Real Clang 17 emitted ten native objects (five targets x original/mutated
LLVM text) and the symbol parser extracted precisely `{abort}` and
`{abort, puts}` for every pair. The latter is forbidden from Hepta object
publication. The local raw receipt is checked in as
`evidence/llvm_ssa_undefined_imports_20261025.json`.

These cross-target bytes prove neither runtime interoperability nor
source/SSA/backend refinement. A parser finding no unknown symbols does
not establish that arbitrary object code is semantically safe.
All broad P0-P7/P01-P12 production acceptance blockers remain open.
