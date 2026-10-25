# P4: Strict C++ L1 source migration using existing C lowering

## Strict i32/u32/i64/u64 value signature extension

The strict Clang++20 L1 subset now admits by-value `int`, `unsigned int`,
`long long` and `unsigned long long` parameters/returns for the already
supported standalone `noexcept` functions. The *same* C-shaped scalar
lowerer handles typed arithmetic and unsigned modular wrap. Mixed signatures
may be accepted only when their specific expression types are proven by that
lowerer; unmodeled promotions, pointers, overloads, RAII, exceptions and
preprocessing still reject. Signed overflowing inputs remain outside original
C++ defined behavior. Generated exports use explicit C ABI, not C++ mangling.

A real C++ original-vs-Hepta/C differential regression is required before
this candidate can be classified beyond L1. No new native/full-project
qualification or source-equivalence proof is claimed for this draft.


This additive prototype is stacked on PR #43, preserving the PR #14
`hepta.c_migrate._function` rules as the only C-style scalar
expression/statement lowering authority. It does NOT copy PR #36's
second C-to-Hepta lowerer or claim general C++20 grammar support.

Strict source profile: standalone `.cc`/`.cpp`/`.cxx` files, no
preprocessing, matching the current x86-64/AArch64 64-bit native host/Clang target, and top-level distinct `noexcept int(int...)` functions,
only the shared C scalar lowering's return/if/scalar expression subset plus
function-prefix, single-initializer scalar locals, direct scalar assignments
and explicit Boolean while loops. Local identifiers are checked against their
Clang declaration IDs; shadowing, nested declarations, static/thread-local storage, uninitialized locals,
indirect writes, pointer locals, compound assignments and general C++ control
flow remain outside this L1 profile. New support shares the same _function
with strict C migration: no second expression lowering authority. Clang++20
must accept the entire translation unit with warning errors; unsupported
top-level declarations, defaults, attrs, templates, pointers, classes,
exceptions or overloaded symbols reject all output. The generated
Hepta uses `export "C"` and does NOT preserve original C++ mangling.

The L1 tool now resolves and records its exact Clang++ executable SHA-256, rejects a foreign target or 32-bit pointer data model, and rehashes the executable after AST capture and immediately before publication. This catches changed compiler files but is not a complete hermetic build/foreign ABI proof.

Execution: the bounded real differential test compares a Clang++-compiled
original through its explicit C wrapper with the same generated Hepta
through its independent C11 backend on finite C++-defined integer inputs.

The frontend-checked result remains L1 with `native_validation=not_run`,
`cpp_abi_preserved=false`, and
`behavioral_equivalence_proved=false`, even if a separate test happens
to execute successfully. L0 C++ native interop already lives in PR #14
and includes selected stdlib/Boost calls; it is not source migration.
L2 requires checked dynamic memory rules and measured costs.
L3 would require actual complete static memory-safety evidence.
All broad C++ class/RAII/virtual/template/STL migration is still OPEN.

The strict expression subset contains no allocation, blocking, suspension,
spawning or indirect calls. Migrated functions therefore carry explicit
`heap_allocations=0`, `may_block=false`, `may_suspend=false`,
and `may_spawn=false` Hepta resource clauses, checked by the Hepta frontend.
These are per-function checked-profile constraints, not process-wide
C/C++ execution resource bounds or evidence about unconverted foreign code.
