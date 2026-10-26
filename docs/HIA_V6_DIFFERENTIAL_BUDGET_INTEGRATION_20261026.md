# HIA P1/P2 — one source replay for static budgets and native differential

**Status:** bounded engineering increment on HIA v6, no whole-language proof.

## Converged source-qualified path

`qualify_checked_hia_source(..., static_resource_limits=...)` can now
request the existing opt-in static policy from the canonical
`build_checked_hepta_hia_native` source/native builder.

The builder already (1) checks the pinned Rust source, (2) lowers the sole
existing executable HIA v6 Core, (3) runs the existing conservative static
resource analyzer, (4) independently replays its numeric receipt from Core
bytes, and (5) generates and verifies LLVM machine code before publication.

**New final-use guard:** after native compilation, the differential wrapper
independently reloads current checked Hepta source, re-lowers the same HIA
Core, and invokes the existing `_validate_static_budget_receipt` against the
exact requested limits and the claimed native resource receipt. That
validator re-executes the original budget analyzer on actual Core bytes:
a forged but correctly rehashed report is rejected **before any ctypes child
invocation or native-vs-VM comparison**.

When the optional policy is absent, no finite static resource claim is made;
an unexpectedly returned budget receipt rejects. When provided and
qualified, the differential report includes
`claims.source_static_resource_budget_replayed=true`,
`static_resource_budget_sha256`, and exact `static_resource_limits`.
Native codegen, source/CORE/publisher verifications remain mandatory.
Unknown limits, wrong scalar types, negative numbers or Boolean masquerading
as numbers reject.

## Acceptance

New real-program regression in `tests/test_hia_v6_differential.py`:
- source-derived Owned Core with 4-byte owner and real Drop;
- mocked native producer substitutes a correct-format, self-rehashed
  but **numerically understated** live-payload budget;
- final-use gate rejects without invoking native observer;
- asserts the requested policy was forwarded unchanged;
- existing end-to-end pinned Clang20/rustc source-native test now requests
  the 4-byte limit and asserts the returned qualified resource identity.

Reproduce on **exact full candidate checkout**:

    python -m unittest tests.test_hia_v6_differential \
      tests.test_hia_budget_numeric_replay \
      tests.test_hia_native_differential -v

A small pure-helper Python smoke passed separately for ABI arity control.
Full in-repository, rustc, LLVM/QEMU and physical hardware suites have NOT
been executed from this turn; no CI queue wait is required for engineering.

## Proof limits

These are conservative limits on the HIA static analyzer's requested
payload bytes, VM ticks and allocator interactions for the supported
acyclic finite profile, **not** general native process RSS, allocator
overhead, CPU cycles, hard real-time bounds, concurrent/device memory or
proof of source-to-machine semantics.

whole_project_blockers_closed=false
