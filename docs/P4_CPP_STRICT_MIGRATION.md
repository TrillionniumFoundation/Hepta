# P4: Strict C++ L1 source migration using existing C lowering

This additive prototype is stacked on PR #43, preserving the PR #14
`hepta.c_migrate._function` rules as the only C-style scalar
expression/statement lowering authority. It does NOT copy PR #36's
second C-to-Hepta lowerer or claim general C++20 grammar support.

Strict source profile: standalone `.cc`/`.cpp`/`.cxx` files, no
preprocessing, top-level distinct `noexcept int(int...)` functions,
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

## Source-level top-level declaration denominator

The strict standalone C++20 L1 report now records `source_sha256` and
`top_level_declarations` (original source-byte span, Clang kind/name,
and AST-candidate versus unsupported status). The
`top_level_inventory_complete` flag becomes true only after the entire
top-level AST list has been traversed without a source-location loss.
`top_level_declaration_count`, `top_level_L1_candidates` and
`top_level_unsupported` are kept even if an unsupported class or
declaration causes the entire output to reject. A function may be
an AST candidate yet later fail the canonical scalar lowerer, frontend,
or native qualification: candidate does not mean converted.

This denominator is one active standalone translation unit under the
explicit C++20 compiler/configuration, not all C++ declarations in a
repository, inactive preprocessor branches, class members, dependency
headers or a compile database. A source-ranged AST declaration with no
usable source location rejects coverage rather than disappearing silently.
No partial .hepta file is published when any top-level declaration is
unsupported.
