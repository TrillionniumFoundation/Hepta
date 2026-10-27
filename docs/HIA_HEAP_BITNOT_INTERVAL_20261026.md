# HIA P1: exact interval transfer for typed bitwise NOT

**Scope:** one narrowly reviewed transfer in existing
`hepta.hia_heap_bound`, stacked on #254 (nonnegative bitmask intervals).
The canonical HIA Core verifier, VM, LLVM backend and static resource
admission remain the sole existing authorities.

## Mathematical result

For an already-verified machine-width integer interval `x in [lo,hi]`:

- Signed two's complement: `~x = -x - 1`, so
  `~x in [-hi-1, -lo-1]`.
- Unsigned `w` bits: `~x = ((1 << w) - 1) - x`, so
  `~x in [(2**w-1)-hi, (2**w-1)-lo]`.

Both are monotonically decreasing affine transformations. They preserve
the full validated signed/unsigned word domain and do not require
implied caller restrictions, speculative no-overflow, fast-math or
an untrusted proof claim. Reject intervals extending outside the actual
source machine type. If no input interval exists (e.g. arbitrary u64),
keep the result UNKNOWN.

The calculated value is only a **requested live payload-byte bound**;
not an operational instruction rewrite, allocator metadata or total RSS.
A subsequent checked `int.cast` may narrow successful paths by trapping
negative or out-of-range values; this is the existing HIA cast rule.

## Regression fixes

New `tests/test_hia_heap_bitnot.py` exercises:
- selected u8 interval [240,254] -> complement [1,15];
- dynamic u8 input -> [0,255], actual Core/VM returns 255-x;
- signed dynamic i8 input -> signed complement, and checked conversion to
  usize traps for negative results, allowing [0,127] successful path;
- unbounded u64 input and out-of-type intervals remain rejected;
- exact byte-domain checks and optional pinned Clang20 actual HIA LLVM
  compiled differential.

The old scalar regression expected dynamic u8 bit.not to be rejected
even though u8 itself has a proven finite domain. It is updated to
require an accepted 255-byte bound **and** reject 254-byte admission.
Other unbounded unknown arithmetic remains rejected.

## Independent executed mathematical control

Python 3.13 isolated arithmetic controls enumerated every 8-bit signed
and unsigned interval and each value within it, plus 300,000 seeded
64-bit signed/unsigned interval points: **5,958,112** checks, zero
underbound failures. This is NOT an in-repository or native HIA run.

## Exact-source acceptance

    python -m unittest tests.test_hia_heap_bitnot \
        tests.test_hia_heap_interval_mask tests.test_hia_heap_scalar_exact \
        tests.test_hia_heap_intervals tests.test_hia_heap_cast_domains \
        tests.test_hia_heap_modulo tests.test_hia_program -v

A full repository checkout / pinned Clang20 toolchain was unavailable
to this isolated environment. Tests were committed as real acceptance
inputs but NOT represented as having run on this exact Git HEAD.
CI queue is not a development stop.

**P1 full ownership/provenance soundness, P2 native refinement,
P3 ABI, P4 arbitrary C++ L2/L3, P5 real-model agent A/B,
P6 physical DMA/GPU/IRQ and production p99, P7 formal publication
all remain OPEN/PARTIAL.** `whole_project_blockers_closed=false`.
