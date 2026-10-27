# HIA P1: conservative bit.or / bit.xor resource intervals

**Exact source:** based on PR #256 `e81ada7347c679b00993c41985961a52b59dbac6`
which already contains verified `bit.and` mask intervals and exact
`bit.not` word complement. This change modifies the same single
resource abstract interpreter, not the HIA verifier/VM/LLVM authorities.

## Bit-level proof

For verified HIA integers `a in [a_lo,a_hi]` and `b in [b_lo,b_hi]`,
require **both** independently proven intervals to be nonnegative.
Let `k = bit_length(max(a_hi,b_hi))`. Neither runtime operand can set
any bit at position `>=k`, so both `a | b` and `a ^ b` are in
`[0,2**k-1]`. Signed typed nonnegative operands never set their
sign bit; the ceiling must still fit the verified output machine type.
Negative/unbounded inputs or unreviewed opcodes never mint this bound.
No arbitrary `u64` input is assumed small. Max-live allocation byte
budget remains checked by the preexisting unchanged native gate.

## In-repository executable contracts

`tests/test_hia_heap_or_xor.py` uses the canonical verified Core,
resource analyzer and independent VM for:

- unknown signed/unsigned 64-bit input masked by already-proved
  positive [3,5] → dynamic OR 6 → XOR 1; extent <= 7;
- two independent public u16 inputs through OR or XOR with a conservative
  complete type-domain limit of 65535;
- unknown full-width `u64` OR/XOR without preceding mask refusal;
- potentially negative interval refusal and exact resource max-minus-one
  rejection;
- small exhaustive bit-envelope assertion;
- opt-in pinned Clang20 true HIA Core→emitted LLVM→native shared library
  differential comparison, never assumed passed when unavailable.

## Executed independent proof control, limits

A standalone Python 3.13 finite bitwise control checked **839,584**
signed/unsigned nonnegative envelope cases: all 4-bit upper-bound
pairs, and 400,000 seeded 32-bit-sized upper bound/input pairs
(two operations per pair), with zero observed underbounds. This
does not establish whole-language soundness or execute the repository.

Actual Core/VM tests and Clang20 native tests on this new Git SHA have
NOT run in the container (no full checkout/pinned toolchain).
Ignore CI queue as engineering stop but never upgrade unrun evidence.

    python -m unittest tests.test_hia_heap_or_xor \
        tests.test_hia_heap_bitnot tests.test_hia_heap_interval_mask \
        tests.test_hia_heap_scalar_exact tests.test_hia_heap_modulo \
        tests.test_hia_heap_cast_domains tests.test_hia_program -v

P0–P7 general soundness, ABI, C/C++ L2/L3, Agent A/B, physical
GPU/DMA/IRQ, production performance and formal release remain open;
`whole_project_blockers_closed=false`.
