# Post-test C loops in captured-project migration

The captured C project translator now lowers `do body while (condition)` into
the ordinary checked Hepta source and standalone HIA Core. The implementation
extends `CTranslator`, so the record/view frontend uses the same lowering. It
does not change the older strict scalar L1 importer, whose separate do-loop
profile duplicates a more restricted body.

## Semantics and admission

The generated shape is:

```text
let mut fresh_first: bool = true;
while fresh_first || original_condition {
    fresh_first = false;
    original_body
}
```

The existing source compiler lowers `||` into short-circuit Core control flow.
The condition is skipped on the first header visit and evaluated only after a
completed body. The body is emitted once, so its local declarations retain
their iteration scope and nested loops do not multiply the generated source.
An early return skips the condition. Generated control names are disjoint from
the C parameter/local names introduced by this translator.

The condition must be a supported scalar truth expression with no modeled
mutation. The body may contain the existing supported declarations, assignments,
calls, structured loops, and conditional returns. `break`, `continue`, `goto`,
labels and other unsupported control forms remain refusals. Supporting a do
loop does not add a new escape path around statement or expression admission.
The existing HIA checker can still refuse a source whose return completeness
cannot be established through the generated structured loop.

For deferred scalar initialization, the definite-assignment pass first checks
the body. Only its surviving paths reach the condition and successor. Their
assigned state therefore applies to both; a pre-test loop still grants no
assignment merely because its body would assign. All structured live paths
must assign before a read. The generated zero initialization remains an
unobservable implementation detail within this admitted profile.

## Actual differential cases

`tests/test_hia_c_do_while.py` uses actual Clang capture and verifies that the
captured inputs remain unchanged. The positive scalar cohort contains eight
functions and 48 input pairs for each function. It covers first-entry behavior,
a condition that would divide by zero if evaluated too early, nested loops,
local shadowing, unbraced bodies, deferred initialization, and early returns.
The reference results come from independently written integer formulas and
from compiled C11 and C++20. The target observations come from the standalone
HIA interpreter and its direct LLVM native library. Rust backend entrypoints
are patched to fail if invoked.

The C++ arm compiles the C-compatible reference source as C++20. It is a
semantic reference, **not an automatic C++ translation result**.

The project cohort copies the pinned Ring-Buffer and musl components used by
`hia_legacy_queue` into a temporary project. It applies one authored maintenance
edit to `ring_buffer_queue_arr`: the original for-loop becomes an explicitly
zero-guarded post-test loop. That changed upstream-derived body, the remaining
original bodies and the authored checksum helper are captured through Clang
and lowered into standalone Core. Original repository fixture bytes remain
unchanged; the edited body is not described as an untouched upstream body.

Twelve checksum inputs are compared with the compiled changed C project and
an independent checksum oracle. A separate zero-length call actually invokes
the migrated queue operation with an empty view; this prevents the application
entrypoint's earlier zero-count return from hiding an incorrect queue loop.
HIA observations also require all owners to be released and loans settled.

Negative cases retain rejection of uninitialized paths, first-body reads,
uninitialized postconditions, unsupported jump controls, expression increments,
and mutating call conditions. The pre-existing scalar, record/view, and HIA
migration suites remain the neighboring regression checks.

## Reproduction

Provide actual Clang/Clang++ for the new native cases. The neighboring Rust
bridge regression tests additionally require the repository's pinned Rust
compiler.

```sh
python3 -m unittest tests.test_hia_c_do_while \
  tests.test_c_scalar_control tests.test_hia_c_project_views \
  tests.test_hia_migration_edges -v
```

Native comparisons establish only this finite captured-source cohort. They do
not prove general source equivalence, full C/C++ coverage, whole-language
soundness, native backend refinement, an Agent productivity advantage, or a
performance improvement. The new cases can serve as actual maintenance tasks
for a future model study; no model was invoked in this implementation work.
