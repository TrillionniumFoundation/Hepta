# HIA P1 finite-heap resource bounds: exact scalar transfer

This increment extends the **existing** optional
`hepta.hia_heap_bound.analyze_constant_live_heap` resource-bound analyzer,
not the canonical HIA verifier, LLVM backend, or runtime. It is stacked on
PR #243 exact head `29812f0e9f6e5c2481aa8d159c8500e8095c14a6`,
which already includes PR #244's safe checked-negation interval transfer.

## Why this incremental work is needed

Prior to this change, verified HIA v1–v6 `bit.*`, `compare.*`,
`int.div/rem.checked` and `int.shl/shr.checked` were allowed and VM/LLVM
had executable semantics, but the finite-live-heap admission analyzer lost
known scalar values through those instructions. AI-generated bitmasked,
compared or exact quotient-derived allocation sizes therefore could not
qualify even a finite, small payload budget.

## Strict transfer boundary

The new `_exact_scalar` only propagates values when **all operands are
already independently known exact values** and the opcode is on a closed
audited list. It uses fixed-width modular bitwise semantics and truncation-
toward-zero signed division/remainder exactly as the HIA Python VM does.
Known zero divisors, MIN/-1 signed overflow, and out-of-range shifts refuse
the bound with the existing `E_HIA_BUDGET_UNBOUNDED`. Unknown operands in operations without a proved transfer rule, partial
intervals, floating values and Boolean-as-integer confusion cannot forge an
allocation size. A separate audited `bit.and` transfer accepts an **unknown
machine-width operand only when the other operand is an already proven exact,
nonnegative mask**: the result is then guaranteed to lie within [0, mask].
This remains valid for signed two's-complement inputs because the positive mask
cannot retain a sign bit. A negative mask or an unconstrained `bit.not`
result does not qualify an external dynamic byte count.

The preexisting P1 checked-negation interval rule is retained unchanged.
All owner roots, borrow/Loan/Drop and CFG validation remain exclusively
the responsibility of `hia_program.verify_program`; this analyzer cannot
convert raw pointers, forge a capability or certify foreign/physical memory.

## In-repository acceptance inputs

```sh
python -m unittest tests.test_hia_heap_scalar_exact tests.test_hia_heap_negation \
  tests.test_hia_heap_intervals tests.test_hia_heap_bound -v
python -m unittest tests.test_hia_program tests.test_hia_program_llvm -v
```

New tests include actual Core verifier + VM + static-budget comparisons,
the expected 11/12/6/2/3-byte peaks, plus 0/7/15-byte dynamic nonnegative-mask bounds with all 256 signed/unsigned 8-bit inputs; exact known-trap negatives, unsigned
zero/shift edges, signed negative quotient/remainder, truly unknown inputs,
Boolean-as-int and exhaustive 8-bit scalar transfer controls.

**Evidence limits:** The in-repository tests require a complete Hepta source
checkout, which was not available in the current container. Isolated arithmetic
checks are not qualification of the full checked-source LLVM/native path.
No Rust/Cargo compilation, actual GPU/physical DMA/IRQ, real C++ L2/L3,
true AI-provider A/B, or sustained service p99 is implied.

`whole_project_blockers_closed=false`.
