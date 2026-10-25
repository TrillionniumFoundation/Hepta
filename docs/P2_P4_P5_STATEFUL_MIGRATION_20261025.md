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
All forms with an initializer declaration, missing condition, nested variable
declaration, break/continue/goto, compound assignment, or unbraced loop body
reject, rather than hiding scope/lifetime and control-flow differences.

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


## Explicit for-initializer declarations with scope hygiene

The shared C11/C++20 scalar migrator can now convert one explicitly initialized
automatic scalar `for (int i = ...; comparison; increment)` declaration into
`let mut hepta_for_<source-byte-offset>_i = ...; while (...) {...; increment;}`.
Each reference is resolved against its exact Clang VarDecl ID. Scoped bindings are
copied into the loop, so nested and repeated `i` declarations cannot escape
or shadow parameters in the emitted code. Every generated identifier is checked
against the original function's declared names; an accidental or adversarial
collision fails closed rather than silently changing the semantics.

Only scalar automatic declarations, explicit comparisons, ordinary assignments
or standalone ++/-- steps, and braced bodies are supported. Initializers that
refer to the future local itself, declarations of multiple variables, static or
thread-local storage, break/continue/goto, pointer/class/destructor operations
or extra condition declarations reject. This is L1 candidate translation, not
proof of complete C++ source or ABI equivalence. Clang and Hepta/C native
differential tests cover multiple declarations, nested loops, parameter
shadowing, unsigned semantics, and invalid source controls.


## Braced, no-declaration do-while subset

The shared Clang AST scalar lowering additionally recognizes a braced
`do { body; } while (comparison);` without declarations, return, break,
continue, goto, for or nested do-loops inside the body. It emits one
`body` execution followed by `while (comparison) { body }`, preserving
the source's at-least-once behavior and test-after-body ordering. Body
duplication is capped at 32 KiB and limited to effect-free scalar operations
already accepted by the shared converter. Unknown statement kinds reject.
It does not alter the existing source-only L1 safety tier or claim a
general control-flow equivalence theorem. C11 and C++20 original-versus-Hepta/C
native differential tests cover defined-input examples and negative cases.

## Independently executed native do-while oracle

`tools/probe_strict_do_while.py --output /tmp/strict-do-while-oracle.json`
runs C11 and C++20 Clang native compilers against a fixed, defined-input
source/normalized pair and wrong-implementation control, then runs UBSan
comparison binaries. In the recorded Clang 17 local execution there were
2024 matched scalar calls, 2024 wrong implementations detected and 2258
UBSan pair calls without a sanitizer failure. See
`evidence/do_while_native_oracle_20261025.json`. The receipt **does not**
claim the Hepta parser/checker, native C backend, arbitrary C++ features,
whole-language safety, or full C++ ABI passed.

## Pure scalar ternary return and assignment

Only Clang `ConditionalOperator` with three operands, an explicit scalar
comparison condition, and side-effect-free typed scalar branches is accepted
for a direct function return or assignment to an initialized automatic local.
The shared lowering converts `return test ? a : b` into two explicit
`if/else` returns and converts `local = test ? a : b` into two
`if/else` assignments, preserving short-circuit branch evaluation without
adding an unmodeled expression feature to Hepta.

GNU omitted-middle ternaries, nested ternaries, calls, side-effecting
increments in branches, pointer/aggregate expressions, implicit numeric
conversions not already checked by the strict `_expr` helper, and arbitrary
expression contexts remain unsupported. This is a narrow L1 candidate
extension, not source equivalence proof. C11/C++20 native differential
tests cover min/max-like functions and boundary integer inputs.
