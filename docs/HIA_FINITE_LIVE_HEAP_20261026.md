# HIA finite live-heap payload admission (P1/P2, 2026-10-26)

**Status:** implemented as a *strictly optional* conservative admission
profile on the existing verified executable HIA Core. It does not replace
`hia_program.verify_program`, the Resource IR checker, the native LLVM
emitter, or the source/Rust qualification gate.

## New checked-source policy

```sh
python tools/build_checked_hia_source.py src/main.hepta -o native.o \
  --kind object --profile owned --max-live-heap-bytes 4096
```

The new policy keyword is `max_live_heap_bytes`. It can be combined with
`max_allocator_interactions`, `max_vm_ticks`, and `max_call_depth`. Without
it, the previously accepted program semantics and receipt schema are unchanged.

`hepta.hia_heap_bound.analyze_constant_live_heap` always rechecks the
canonical `hepta.hia_program.verify_program` input and uses the existing
DAG/call-cycle rejection rule from `hia_static_budget`. It does not parse
source, infer C/C++ ownership, mint device capabilities or interpret foreign
memory. Owner moves and drops transfer/remove their *already verified* SSA
capabilities; multiple simultaneously live owners add their byte extents.
At joins, differing incoming sizes conservatively combine by maximum for each
owned block parameter. Scalar-only nested calls add their own peak to the
caller's live payload while active. A fallible allocation is conservatively
counted at its possible successful extent.

## Explicitly refused, not guessed

- Dynamic/unknown allocation size (including a function input passed to
  `buffer.new` or `buffer.try_new`); only exactly typed integer constants
  that dominate the allocation and propagate through existing CFG parameters
  are admitted. Calculated values are unknown for this initial profile.
- Any resource-typed function argument/return or interprocedural Owner/Loan
  transfer, pending a source-bound extent invariant.
- A CFG loop, direct or mutual recursion, inconsistent owner inventories at
  a CFG join, or allocation size above the selected signed 64-bit object
  extent ceiling.
- Malformed/forged canonical programs, unknown opcodes, undeclared effects
  and invalid resource flows: these are already refused by the mandatory
  existing HIA Core verifier and are never upgraded by this analyzer.
- Future opcodes are independently refused by this budget analyzer until
  each operation is added to its explicit nonallocation whitelist or given
  a reviewed allocation transition. A canonical-verifier upgrade alone
  cannot silently lower an established byte budget.

The metric is **requested simultaneously live Buffer payload bytes** for
finite normal paths under admitted constant extents, *not* an exact number of
allocated bytes when the allocator can refuse, and not real native RSS,
allocator metadata, cache usage, stack usage, DMA buffers, device memory,
runtime overhead or elapsed time. A valid report asserts
`requested_live_payload_bytes_upper_bounded=true`, while
`native_cpu_time_or_rss_proved=false` and
`whole_language_soundness_proved=false` remain mandatory. A failure
is `E_HIA_BUDGET_UNBOUNDED` or `E_HIA_BUDGET_EXCEEDED`.

The checked-source native gate checks the new policy and claim *before*
calling `emit_program_llvm`; no existing output may be overwritten.
Standalone Core native callers do not silently gain this optional source policy.

## Evidence and acceptance

New in-repo test `tests/test_hia_heap_bound.py` exercises owner move/drop,
two simultaneously live allocations (12 bytes), joined alternative owners
(2 versus 9 bytes), nested scalar-only calls (3+7 bytes), nonconstant
allocation rejection, resource-return rejection, default compatibility and
the opt-in budget threshold. CLI forwarding is covered by
`tests/test_hia_static_budget_cli.py`.

The new module and test bytes have been locally Python-compiled. Four
isolated algorithm smoke checks used **mocked canonical HIA verification**
and are not counted as full Hepta/native passes. The exact-HEAD integration
tests, pinned rustc and Clang native runs have **not** been executed in the
current network-isolated container.

Run from the full exact commit checkout:

```sh
python -m unittest tests.test_hia_heap_bound tests.test_hia_static_budget \
  tests.test_hia_static_budget_cli tests.test_hia_program \
  tests.test_hia_program_llvm -v
```

P0–P7 safety/refinement/ABI/migration/Agent/hardware/production release
blockers remain open beyond this finite checked payload budget:
`whole_project_blockers_closed=false`.
