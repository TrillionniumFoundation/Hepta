# HIA P1: bounded bitwise-AND with proven nonnegative mask intervals

**Exact upstream:** PR #255 `3ab90b7cd9bbe1210ce145a72d278f869b76332e`.
**Scope:** One additive transfer rule in the existing verified HIA v6
`hia_heap_bound` analyzer; no new parser, verifier, compiler, foreign ABI
authority, Owner/Loan checker or migration tool.

## Abstract transfer

HIA's `bit.and` uses fixed-width two's-complement machine integer
semantics. For any typed machine integer `x` and independently proven
mask `m` with `0 <= m <= M`, we have:

    0 <= (x & m) <= M

This holds when `x` is a negative signed number too, because all bit
positions set in `x & m` must also be set in the nonnegative `m`.
The static proof is valid for an *interval* `m in [lo,hi]` where
`0 <= lo <= hi <= type_max`, not just for an exact constant. If both
operands have valid nonnegative bounds, the stronger minimum of their
upper bounds applies. The old exact-value constant folder is unchanged;
the interval rule is a fallback only for nonexact `bit.and`.

Unknown bounds, negative/maybe-negative masks, out-of-type maxima,
other bit operators, pointer masks and unverified input assumptions do
not produce a certificate.

### Whole-program example

A public `u64` or signed `i8` value may be masked by a runtime
`select(pick, 7, 15)`. Its bitwise result has an exact safe upper
bound of 15 regardless of the public value, so an allocation of the
resulting `usize` can be admitted under `max_live_heap_bytes=15`.
Budget 14 must reject. Selecting signed masks `(-1,7)` has no
nonnegative guarantee and remains unqualified.

This is a requested live *payload* bound on nontrapping paths,
NOT an allocator RSS, stack, CPU, termination, SIMD/backend
refinement, physical MMIO or complete Owner/Loan soundness proof.

## Evidence and acceptance

- Added `tests/test_hia_heap_interval_bitmask.py`: canonical HIA Core
  verification, VM, static-budget acceptance/refusal, signed-negative
  input controls, definitely negative and mixed masks refused.
- Independent exhaustive 294,912 u8/i8 signed and unsigned interval
  transfer cases executed successfully, including signed negative inputs.
- Clang17 x86-64 C11 native signed/unsigned AND controls: 34,048 passed.
  Control native ELF SHA-256
  `6f60e7c36741a56919f5c438750d3e36fd4eebb106b16d886cb1bf46171b7635`.
  This is **hand-authored C**, NOT native emitted Hepta.
- Test includes an opt-in actual Hepta HIA LLVM→native→VM comparison
  requiring the pinned compiler. Full in-repository acceptance is not run
  on this exact source head in the current environment.

Run with the exact checkout:

    python -m unittest tests.test_hia_heap_interval_bitmask \
      tests.test_hia_heap_division_bounds tests.test_hia_heap_modulo \
      tests.test_hia_heap_bound tests.test_hia_heap_intervals \
      tests.test_hia_program tests.test_hia_program_llvm -v

Remaining blockers: interprocedural Owner/Loan/Provenance soundness,
general source→Core→LLVM refinement, C/C++ L2/L3, all-platform ABI,
real-model Agent trials, physical DMA/GPU/IRQ, sustained production
resource/performance and formal release.

`whole_project_blockers_closed=false`.
