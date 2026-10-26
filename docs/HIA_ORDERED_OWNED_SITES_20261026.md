# HIA P1/P2: verified straight-line owner operation order

Status: **finite source-bound incremental check, NOT executable owned SSA v1**.
Exact integration base: PR #174 `fcb78eddb1a8a236773df59f727d257476081052`.
Do not replace the canonical checked Hepta syntax, Resource IR verifier, native
Owner LLVM emitter, C/C++ migrators or publication authority.

## Existing gap

PR #174 requires exact per-function **counts** of emitted `buffer`,
`try_buffer`, and `drop` sites from the independently verified, source-derived
Resource IR. Equal totals alone allow accidental *reordering* of two
different resource operations. In a one-block, normal-return function,
such a reorder would differ from the source's intended evaluation order.

## Code

- `owned_operation_witness.py` now extracts the immutable source-site
  sequence only when a checked Resource IR function has **exactly one**
  entry block ending in a normal `return`.
- The Owner LLVM emitter counts real emitted calls as before, and also
  records their lexical order *after* the required native call (and
  infallible buffer's abort edge) has been appended to its LLVM output.
- `_Function.render` requires equal counts for **every** function and an
  exactly equal ordered site stream for the one-block eligible subset.
  Reordering fails before LLVM source is returned or native publication
  begins. This leverages the existing checker; there is no new parser,
  resource verifier, LLVM emitter, runtime monitor or native fallback.
- Multi-block branches, loops, `match`, exceptional exits, indirect
  foreign effects, generic specialization resource paths and value/loan
  semantics are **not** claimed ordered or proven equivalent. The
  `require_ordered` result is `False` on unsupported non-linear CFG,
  with the original full static site-quantity gate still required.

## Verification

Offline Python 3.13 on a close, locally exercised copy of the witness
logic: **5/5 pure protocol tests passed**, including a one-block
buffer/drop stream, swapped operation order, fallible allocation kind,
forged metadata, branch non-claim and no-op stream. The exercised offline
copy differs in pre-existing comments/limits from the exact merged
repository module and **is not a full Hepta end-to-end test**.

Committed in-repository regressions require actual complete Hepta sources
and native gates:

    python -m unittest tests.test_owned_operation_witness -v
    python -m unittest tests.test_llvm_owned_backend tests.test_owned_drop_sites_llvm -v

No exact-head pinned rustc/Clang build or full release qualification has
been executed. Previous passed results from older SHAs are not inherited.

## Still blocked

This closes only the **bounded straight-line static emission-order check**.
It does not prove full AST-to-Core refinement, dynamic allocation/drop
order along branches, strict pointer provenance, typed numerical/Memory SSA,
actual source-level/machine-code equivalence or universal Rust safety.
The full HIA v1 plan requires a single executable Owner/Loan/Memory/Value
SSA verified as a graph and consumed *exclusively* by native codegen.

`whole_project_blockers_closed=false`.
