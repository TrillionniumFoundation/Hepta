# HIA P1: interval-derived nonnegative bitmask heap bound (2026-10-26)

## Existing owner and exact source scope

Based on PR #253 `e974271dafaed1fe0c5a01cbcfdc0d0e9afdd974`.
Reuse the ONE existing canonical `hepta.hia_program.verify_program`
verifier, `hia_heap_bound.analyze_constant_live_heap` transfer and
`hia_static_budget.analyze_static_budget` native admission gate.
No second IR, numeric interpreter, Owner checker or LLVM emitter.

## Proven incremental transfer

For any validated same-type HIA machine integers `x,m`, if a verified
abstract interval for `m` is `[lo,hi]` with `lo >= 0`, then for every
runtime value represented by that interval:

    0 <= (x & m) <= m <= hi

The bit property holds for signed negative `x` too (two's-complement
bitwise semantics); the nonnegative operand is the mask. No assumption is
made on unknown `x` or a caller-selected finite witness. Either operand
may be the nonnegative mask. For two independently nonnegative intervals,
the smaller upper bound remains sound.

Implement only for existing `bit.and`. Preserve existing exact
constant folding before the interval transfer. Negative/potentially
negative masks alone, wrong types, unknown values and all other unreviewed
bitwise operations continue to fail closed. Transfer only changes the
resource *payload-byte upper bound*, never an operational HIA value,
ownership/loan permission, machine instruction or the source contract.

## Real graph regressions committed

`tests/test_hia_heap_interval_mask.py` uses actual
`verify_program -> analyze_constant_live_heap -> analyze_static_budget`
and the independent VM for:
- unknown full-width u64/i64 input with a dynamic selected positive
  mask interval (e.g. 15 or 63) — bound must be 63;
- public u8 mask widened to u64 while value remains unknown u64 —
  bound must be 255;
- both signed negative inputs and zero masks;
- negative/unknown mask interval rejection without a forged small budget;
- strict resource max-minus-one refusals and conditional native LLVM
  emission/runtime differential when pinned Clang20 is actually available.

## Independently executed arithmetic control (NOT full Hepta)

A standalone Python 3.13 same-rule control exercised 613,280
nonnegative-mask bit operations: all 8-bit unsigned/signed inputs paired
with every representable nonnegative mask, exhaustive small non-exact
interval choices, and 500,000 seeded signed/unsigned 64-bit random
inputs and bounded mask intervals. No underbound was observed; negative
mask-only cases were refused.

This is mathematical evidence for this narrow transfer, NOT proof of
source->Core, LLVM semantics, RSS/allocator overhead, Rust parity,
native ABI, arbitrary C/C++ safety or production performance.

## Exact checkout commands

    python -m unittest tests.test_hia_heap_interval_mask \
        tests.test_hia_heap_modulo tests.test_hia_heap_cast_domains \
        tests.test_hia_heap_scalar_exact tests.test_hia_heap_intervals \
        tests.test_hia_heap_bound tests.test_hia_program -v
    python tools/release_check.py

The test suite has NOT been executed on a full checkout of this exact
commit in the current container. Ignore CI queues as an engineering
stop, NOT as permission to report unrun native tests passed.
`whole_project_blockers_closed=false`.
