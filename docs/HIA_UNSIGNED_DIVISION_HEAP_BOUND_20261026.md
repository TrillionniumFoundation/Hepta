# P1 HIA v6: finite unsigned quotient resource intervals

**Engineering change; no whole-project closure asserted.**
Exact parent: PR #253 code SHA `e974271dafaed1fe0c5a01cbcfdc0d0e9afdd974`.
The existing canonical `hia_program.verify_program`, VM, LLVM emitter and
`hia_heap_bound._bounded_divrem` remain sole authorities. No second parser,
resource checker, compiler, migration engine or Agent Workspace is created.

## Semantics and proof obligation

For verified `int.div.checked` of the same unsigned machine type T
(u8/u16/u32/u64/usize) and a divisor interval `d in [d_min,d_max]`
with **d_min > 0**, a dividend interval `x in [x_min,x_max]` gives:

    floor(x_min / d_max) <= x / d <= floor(x_max / d_min)

If the dividend is unknown, use the **entire** type domain `[0,2^width-1]`;
never infer a small caller input or a sampled bound. The proven interval
holds for all valid inputs. Unsigned integer division does not overflow,
and zero division is excluded by the positive lower-bound requirement.
An impossible or malformed direct abstract-domain value is rejected rather
than qualifying any allocation size.

This is a static requested-*payload*-byte bound, **not** process RSS,
allocator overhead, physical RAM availability, liveness or maximum call
execution time. The existing `MAX_REQUEST = 2^63-1` and final
`max_live_heap_bytes` admission remain enforced: e.g., an unknown u64
divided by 1 has an upper bound above MAX_REQUEST and is still rejected.

### Why it matters

A public unknown u64 divided by `u64::MAX` can produce only 0 or 1;
a divisor selected from `[2^63,2^64-1]` gives the same upper bound,
despite unknown caller input. The previous exact-only transfer failed to
recognize this safe one-byte maximum. The change admits these precise
proof-bounded programs and does not turn unknown, signed, maybe-zero or
unsupported opcodes into safe code.

Existing signed exact truncation-toward-zero, unsigned remainder, checked
casts, Owner/Loan and CFG merge rules are unchanged. No new instructions
are accepted into Core v6.

## Committed acceptance inputs

- `tests/test_hia_heap_division_bounds.py`: HIA verifier -> static budget
  -> independent VM for u8/u64/usize and runtime-selected positive
  denominator; max-1 refusal; explicit zero and signed negatives.
- Exhaustive u8 mathematical oracle (65,280 valid positive divisor pairs).
- Deterministic 50,000-case 64-bit divisor-interval arithmetic control.
- An opt-in **actual Hepta LLVM emission** and native comparison with the
  same VM, only when pinned Clang is available.
- Existing modulo test is updated to reflect the new strictly checked
  unsigned division bound; modulo proof is not weakened.

Run in an exact complete checkout:

    python -m unittest tests.test_hia_heap_division_bounds tests.test_hia_heap_modulo \
      tests.test_hia_heap_cast_domains tests.test_hia_heap_scalar_exact \
      tests.test_hia_heap_bound tests.test_hia_program tests.test_hia_program_llvm -v

Do not treat missing tools, skipped native cases, static receipt success,
or standalone arithmetic smoke as a complete exact-source native test.

## Blockers that remain OPEN

General interprocedural Owner/Loan/Provenance soundness, source-to-Core and
LLVM refinement proofs, arbitrary C/C++ L2/L3 migration, cross-platform
compiler ABI, actual Agent task A/B productivity, physical MMIO/IRQ/DMA/GPU,
production p99/allocator accounting and formal final release.

`whole_project_blockers_closed=false`.
