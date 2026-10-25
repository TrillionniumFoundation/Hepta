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

## Explicit resource contract

The shared strict scalar lowerer emits checked Hepta resource clauses for
zero modeled allocator interactions and no blocking, suspension or spawn.
No foreign functions are allowed inside this profile. The clauses are
validated with the standard frontend, without creating a second
resource-checking authority or claiming whole-process memory bounds.

## Counted-for loops in strict scalar L1

The shared AST lowerer also accepts exactly five-slot Clang ForStmt nodes:
direct assignment initializer to a previously checked automatic local,
no for-condition variable declaration, required Boolean comparison condition,
direct scalar assignment or standalone ++/-- step on an initialized local,
and a compound statement body. The output preserves init/body/step order:
init; while (condition) { body; step; }. Signed arithmetic may abort on
otherwise undefined source inputs; unsigned ++/-- use wrapping arithmetic.
The earlier assignment-only restriction was superseded by the scoped
single-scalar declaration profile described below. Multiple or uninitialized
for-initializer declarations, nonautomatic storage, missing condition, nested
body declarations, break/continue/goto, compound assignments and unbraced loop
bodies still reject rather than silently changing source semantics.

C11 and C++20 finite-domain native ABI differential tests are added.
Passing those tests is not proof of whole-program L2/L3 source equivalence.

## P5 integration coverage for counted-for

The existing pinned-rustc-required native LLVM differential source is now
a strict C++20 counted-for fixture. Its generated Hepta is checked to contain
the normalized while/step form before canonical HSIR/CFG/SSA/LLVM processing.
Clang++ original/C wrapper, Hepta/C and LLVM SSA execution remain separate.
Like the other tests, this targets finite defined-input semantics only.

## P2 strict C preprocessor snapshot identity

The strict C single-file migration now records a Clang C11 preprocessed
source digest before AST capture and re-runs Clang -E -P immediately before
no-replace publication. Its report binds the preprocessed SHA-256, so a
local-header macro edit during conversion fails with E_C_PREPROCESS_RACE
even if the .c file itself is unchanged. Tests include a real source
that includes a macro header plus a deliberate header mutation.

This is an incremental TOCTOU defense, not a hermetic C build graph,
complete transitive dependency manifest, or protection from noncooperating
filesystem writes in the final instant before the no-replace link.
Use the existing compile_commands.json project migrator for full configuration
capture, multi-TU coverage and per-header dependency/identity evidence.

## Declared for-initializer scopes (P2/P4 follow-up)

The shared AST converter now accepts one explicitly initialized automatic
scalar VarDecl in a Clang five-slot ForStmt initializer. It checks the source
declaration's AST ID and lexical location, rejects storage-class/TLS or multiple
declarators and requires the same restricted Boolean condition, scalar step
and compound body as assignment-initializer loops.

A stable source-byte-offset-derived Hepta local name avoids reusing the
source spelling when two disjoint for scopes both declare `i`. A fresh
lexical mapping retains the Clang VarDecl ID; nested loops may shadow source
names without conflating ownership. The emitted Copy-only local can live
through the containing Hepta block because this subset forbids destructors,
pointers, retained borrows, captured closures and external effects. The
generated name is deterministic for one frozen input AST, not a C++ ABI symbol.

Native differential tests include repeated `for(int i=...)` in C11 and
nested `for(int i=...)` in C++20, plus rejected uninitialized or multi-variable
initializers. Translation remains a strict L1 candidate; no general C/C++
scope/lifetime equivalence or L2/L3 proof is inferred.

Unsigned for-init locals use the built-in `wrapping_add`/`wrapping_sub` with
AST-driven emitted names, not whole-string replacement (which could corrupt
builtin spellings containing the source variable name). Regression tests also
cover for-declaration shadowing of a function parameter; the parameter must
retain its own Clang ParmVarDecl identity outside the loop. Local Clang AST
acceptance alone is not counted as a Hepta native build pass.
