# P4: Strict C++ L1 source migration using existing C lowering

## Bounded unsigned C/C++ shifts (L1, defined-input domain)

The single shared `hepta.c_migrate._expr` scalar lowering now accepts
`<<` and `>>` only when the checked result and both admitted operands are
compatible fixed-width **unsigned** scalars. The Hepta operators retain the
same bit-width wrap/logical shift result for counts in `[0, width)`.
The original C11/C++20 languages do not define out-of-range shift counts;
Hepta's checked shift may abort on those inputs without claiming to match
undefined original behavior. Mixed-width operands, signed shifts, arbitrary
casts, pointer shifts and complex expressions remain rejected.

Two native differential regression tests compare GCC C11 and Clang++20
originals to Hepta/C through the normal frontend/independent C backend.
The separate host-only original C/C++ defined-domain oracle checked
80 finite cases; this is **not** an executed Hepta compiler proof.
`whole_project_blockers_closed=false`.

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

## P3/P4 defined-domain division and Boolean short-circuit (2026-10-25)

The canonical strict C/C++ scalar lowerer now accepts same-type integer `/` and
`%` with Clang-checked operand/result types; only a directly widened
representable integer literal may use an implicit integral promotion.
C11/C++20 defined signed division truncates toward zero; both Hepta's checked
integer division and C reject zero divisors and signed MIN / -1 through
their respective undefined/abort boundaries. Thus no equivalence is claimed on
C-undefined inputs.

Boolean conditions can contain pure, explicitly Boolean comparisons combined
with `&&`, `||` and `!`. The original left-to-right short-circuit order
is retained in generated Hepta. Implicit integer truthiness, calls, user effects
and unreviewed casts still reject rather than translating speculatively.
Native C11 and C++20 original-vs-Hepta/C differential tests are added, but do
not prove universal source equivalence or L2/L3 safety.

## Unsigned unary arithmetic and bitwise complement

The same canonical C/C++ expression lowerer now preserves source `-u32/-u64`
by emitting `wrapping_sub(0, operand)` and unsigned `~u32/~u64` through
Hepta's fixed-width integer `!operand`. Strict operand and result types are
required. Signed `~`, narrow-integer promotions and nonliteral casts remain
explicitly unsupported. Generated Hepta/C native differential regressions
exercise wraparound edge values in C11 and C++20. These are L1 candidate
checks, not universal source equivalence or an ABI/safety certification.
