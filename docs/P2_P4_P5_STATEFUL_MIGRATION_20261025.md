# P2/P4/P5 stateful Clang migration: two native backend differential checks

## Added subset, not arbitrary C/C++ conversion

The original `hepta.c_migrate._function` remains the unique lowering authority
for the strict C11 and C++20 L1 candidate paths. It now handles initialized
automatic scalar locals as a function-prefix, direct assignments to those
locals and compound-body while loops with Boolean comparisons. Clang VarDecl
IDs are preserved for each local read and write. Nested declarations,
shadowing, uninitialized variables, static/thread-local storage, pointer
access, function calls, compound assignment and unrelated C++ semantics
reject the entire candidate before publication.

## Real ABI cross-backend gate

`tests.test_stateful_migration_llvm` starts with original C++20 source and
uses Clang AST migration to Hepta. The same candidate is checked by pinned
rustc and lowered to canonical HSIR, CFG, SSA, independently structurally
verified SSA and direct LLVM i32 PHI machine code. It separately compiles
the same Hepta source through the independent C backend. A Clang++ original
through an explicit C ABI wrapper serves as the finite reference oracle.
Negative control executes a deliberately incorrect original implementation.

The test does not claim native C++ name-mangling compatibility, whole-language
semantic refinement, safe foreign-pointer contracts or universal functional
equivalence. All broader P0-P7/P01-P12 blockers remain open.

## Reproduction

Requires Python 3.12, GCC, Clang/Clang++, and the pinned rustc 1.90.0 reference.

    python -m unittest tests.test_c_migrate tests.test_cpp2hepta_l1 -v
    python -m unittest tests.test_stateful_migration_llvm -v

Any successful qualification must be associated with the exact unchanged
source SHA, compiler identities, negative controls, and unmodified fixtures.
