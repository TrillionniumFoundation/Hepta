# HIA P1: source-verified signed positive-divisor interval admission

Exact base: P1/P7 integrated PR #261 at
`63c74114912e8ec255f90557bdf8b13ffb258fa9`.
One existing HIA resource analyzer remains authoritative. The verifier,
VM, LLVM backend, C/C++ migrators and security observer are unchanged.

## Finite mathematical rule (no caller assumptions)

For a signed w-bit numerator `n in [n_lo,n_hi]` and a **proven**
strictly positive signed divisor `d in [d_lo,d_hi]`, with
`1 <= d_lo <= d_hi <= signed_type_max`, HIA's checked division uses
truncation towards zero. On every nontrapping path:

    -(abs(min(n_lo, 0)) // d_lo) <= trunc(n/d)
    trunc(n/d) <= max(n_hi, 0) // d_lo

The interval is conservative: it may include zero even when the
real quotient cannot be zero. A numerator with no existing SSA
interval is assigned the **entire machine signed type domain**,
not an assumed caller sample. No direct cast or negation of signed
minimum occurs in native code because this is mathematical abstract
interpretation. A positive divisor cannot trigger MIN / -1 overflow.

For the corresponding checked signed remainder, the HIA VM uses
`r = n - trunc(n/d)*d`. It satisfies `abs(r) < d`, so its
range is `[-(d_hi-1), d_hi-1]`. A separately proven entirely
nonnegative or nonpositive numerator tightens the opposite endpoint
to zero.

The existing checked `int.cast` converts only in-range values;
negative values may trap before the allocation. Propagation of a
positive bound applies to successful paths ONLY. Neither unknown
nonpositive divisors, intervals containing zero, out-of-type
intervals, nor a signed MIN/-1 possibility grants a finite bound.
Exact operand pairs retain the original signed division/remainder
implementation and overflow checks. The global MAX_REQUEST and
requested live payload budget remain unchanged.

## Actual committed acceptance

`tests/test_hia_heap_signed_divrem.py` uses the original canonical
`verify_program`, independent VM and static heap admission for:

- arbitrary i64 divided by i64::MAX, bounded signed quotient [-1,1],
  with checked usize continuation admitting a 1-byte policy and
  rejecting zero-byte policy;
- arbitrary i64 rem 7, bounded signed remainder [-6,6],
  accepting 6 bytes for all successful positive remainder paths;
- exhaustive -128..127 i8 values with runtime-selected positive
  divisors (3/7), checking both quotient and remainder, traps,
  allocator cap refusal and owner cleanup;
- forbidden zero/potentially-zero/negative/out-of-type divisor
  intervals and unchanged MIN/-1 runtime trap;
- optional genuine Core -> LLVM -> Clang20 native differential on
  safe positive signed inputs (not falsely counted when unavailable).

Existing `test_hia_heap_modulo.py` and
`test_hia_heap_division_bounds.py` had obsolete
`None` expectations for unknown signed positive-divisor cases.
Their negative test scopes are preserved while expected verified
signed bounds are updated.

## Independently executed control; NOT release qualification

An isolated Python 3.13 arithmetic model evaluated **450,048**
signed quotient/remainder containment assertions across complete
i8 numerators, positive-divisor interval samples and fixed-seed
i16/i64 random controls; **zero underbounds**. This is not running
the repository verifier/VM/LLVM/compiler on the new SHA.

Run in a complete exact checkout, without waiting on CI:

    python -m unittest tests.test_hia_heap_signed_divrem \
      tests.test_hia_heap_modulo tests.test_hia_heap_division_bounds \
      tests.test_hia_heap_cast_domains tests.test_hia_heap_or_xor \
      tests.test_hia_p1_p7_convergence tests.test_hia_program -v
    python tools/release_check.py

Broader P0–P7 executable provenance/lifetime, independent native
refinement, ABI, arbitrary legacy C++ conversion, real Agent A/B,
physical DMA/GPU, production RSS/p99 and formal proof remain OPEN.
`whole_project_blockers_closed=false`.
