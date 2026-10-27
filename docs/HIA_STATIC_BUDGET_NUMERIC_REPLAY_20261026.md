# HIA P2 — Numeric static-budget receipt replay (2026-10-26)

This candidate is stacked on P1 borrowed-byte-interval PR #215, exact commit
`f066048b2a361272d02eafcd1bcebc3b2737fe10`. It strengthens the
**existing** source-native final-use resource gate; it creates no new ISA,
numeric analyzer, compiler backend or admission authority.

## Trust-boundary defect

The previous `_validate_static_budget_receipt` checked a complete
function denominator, schema, typed numeric fields, upper-limit inequality,
claims and SHA-256. But a fabricated `max_live_heap_bytes = 0` could
be self-rehashed and still pass these **metadata-only** checks if the
true bound was 12 and the user-supplied policy ceiling was 12.

The ordinary producer calls `analyze_static_budget` in the same process;
this mismatch is primarily a defense-in-depth and substituted-result
failure mode, **not** evidence that a public remote caller can directly
inject a receipt. A hash is not a proof of arithmetic correctness.

## Implemented gate

- Reverify the immutable `VerifiedProgram` bytes and full function inventory.
- Strictly validate the existing receipt's types, requested policy,
  proof-scope flags, canonical identity and hash as before.
- **Independently replay from canonical HIA bytes** through the existing
  deterministic `analyze_static_budget` implementation and require
  exact equality of the complete report, including every numeric row.
- Keep one established numeric algorithm: replay does **not** prove the
  analyzer's mathematical soundness and does not make LLVM or Rust verified.
- Capture the analyzer's original module import binding for replay so a
  later replacement of the builder's runtime analyzer call does not
  automatically replace the validator's reference. This is not protection
  from arbitrary trusted-process compromise or edits to installed source.

The replay is opt-in and performed only when a static budget policy was
requested for a checked-source native build. This doubles the requested
static-analysis work in that branch; no production overhead measurement has
been made. Failure rejects **before LLVM emission and publication**.

## Regression inputs

`tests/test_hia_budget_numeric_replay.py` contains:

1. Genuine complete budget receipt accepted on exact canonical HIA.
2. Correctly rehashed, type-correct but numerically fabricated
   heap/allocator/VM-tick/call-depth rows rejected.
3. Source-native builder with substituted forged analyzer return rejects
   before `emit_program_llvm`, and publishes no artifact.

Reproduction:

```bash
python -m unittest tests.test_hia_budget_numeric_replay \
  tests.test_hia_budget_receipt_guard tests.test_hia_heap_borrowed \
  tests.test_hia_static_budget tests.test_hia_heap_intervals -v
python tools/release_check.py
```

These are **new committed tests, not executed results**. Exact checkout and
pinned native Rust/Clang are not present here. Missing compiler tools do not
grant a passing status.

Remaining P0–P7 blockers: formal HIA byte/resource SSA and translation
refinement; unbounded code/memory/FFI; general C/C++ L2–L3; real Agent
A/B; physical GPU, MMIO/DMA/IRQ; sustained RSS/p99. Maintain
`whole_project_blockers_closed=false`.
