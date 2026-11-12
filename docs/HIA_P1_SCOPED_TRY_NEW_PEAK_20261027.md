# P1 HIA: strict block-local fallible Owner peak in CFG cycles

**Exact parent:** PR #278 `64645ceb8f0158e97d06926d02296cf07494bdf8`.
**Executable authority:** unchanged `hepta.hia_program.verify_program`.
**New proof scope:** peak requested-live byte *payload*, never process memory,
allocator metadata, cumulative allocation attempts, native code, or CPU ticks.

## Why the narrow fallible case is safe

The canonical HIA semantics of `buffer.try_new(size)` are disjoint:

- Success: one Owner holding up to `size` requested bytes and `true`.
- Failure: one valid but empty Owner, zero requested-live bytes and `false`.

The strict scope analyzer counts the full proven maximum of `size` for
**either** outcome, then requires consumption of that same Owner before
*every* ordinary CFG edge. This overapproximates actual live bytes on a
failure path, and cannot silently infer that a fallible allocation succeeds.

A canonical `verify_program` pass first checks output arity and type,
owner movement/drop/borrows, SSA, effects and edge resource flow. The new
optional analyzer accepts only the existing `buffer.try_new` instruction
beside `buffer.new`, `owner.move`, `owner.drop` and the prior closed
scalar whitelist. It reads no caller receipt or user assertion.

A positive allocation-size upper bound must be proved in the same block.
Exact-zero-only sizes remain refused to retain the prior separate scope
boundary. Fallible allocation with unknown size, ownership crossing blocks,
loans, foreign calls and v7 resources remain refused.

## Tests / scope

```sh
python -m unittest tests.test_hia_scoped_alloc_loops \
    tests.test_hia_zero_heap_loops tests.test_hia_heap_bound -v
python -m unittest tests.test_hia_program tests.test_hia_static_budget -v
```

Added real-HIA test fixtures for success/failure injection at several
iteration indices, observed allocations/frees/attempts/drops, positive
constant 9-byte peak admission, u8-bounded variable size, owner-leak refusal
at a CFG edge, and explicit rejection by the cumulative-budget analyzer.

An independent CPython 3.13 *mathematical-only* execution of 32,640
finite synthetic profiles found no peak upper-bound violations. This
does **not** establish actual HIA VM, Rust, LLVM, native, external allocation,
hardware, or exact-checkout test execution. The complete repository suite
has not executed here due absent full checkout and pinned toolchain.

`whole_project_blockers_closed=false`.
