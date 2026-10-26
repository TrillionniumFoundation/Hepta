# P1/P2: source binding for the finite HIA byte oracle

Engineering increment, **not** HIA Core v1 closure.

Exact integration parent: PR #178 head da42019e4e5ab11210738de4136cfe6b9f8fae5b.
Reuse canonical hepta.semantic_ir, hepta.resource_lowering, hepta.resource_ir,
hia_boolean_trace and hia_byte_trace. No second parser, borrow verifier,
numeric SSA interpreter, C/C++ migration, LLVM emitter or runtime.

## Source-facing interface

    from hepta.hia_source_byte import replay_source_byte_path
    receipt = replay_source_byte_path(
        "project/src/module.hepta", "case",
        boolean_arguments={"enabled": True, "second": False},
        actions=({"kind": "alloc", "bytes": 4},),
        native=False,  # explicitly frontend-only
    )

Native defaults to True, demanding a fresh successful pinned Rust reference.
Frontend-only is explicitly labelled and never promoted to native verification.
Inputs use source parameter names and map in declaration order to independently
lowered Resource IR p0/p1 slots. Caller-provided graphs and receipts are NOT
admitted.

The wrapper reloads actual source and checks its project identity; regenerates
canonical typed HSIR and the existing Resource IR; rejects foreign/volatile
obligations; invokes the existing independent Resource IR verifier and finite
Boolean/byte memory interpreters; rechecks source identity afterward.
Byte actions are copied to immutable bounded canonical JSON before replay.
The returned byte witness must retain original function/schema/status, the
resource hash, all seven exactly-FALSE proof claims and its unaltered wire hash.

## Strict limits and open blockers

- Allocation sizes, memory indices and written bytes in actions are still
  EXTERNAL test values, not computed source expression/SSA values.
- One finite owner/loan/drop path is checked, not arbitrary loop termination
  or whole-program behavior.
- General typed numerical-and-owned SSA, source-to-Core/backend refinement,
  pointer provenance and arbitrary C/C++ migration are NOT proved.
- Owned LLVM remains partially AST-driven. ABI cross-target, hardware/DMA,
  real AI-model A/B, production performance and full formal proofs remain open.
- Checked source identities and byte observations are not a malicious-host
  filesystem sandbox.

## Executed validation and required exact-head tests

Local Python 3.13 executed 8/8 isolated protocol tests against the *actual
new module* and mocked compiler/Resource/byte-oracle dependencies. Covered
boolean input order, native/frontend distinction, stale data, forged proof
claims and byte trace hash mismatch. The ninth checked-source integration
test is included but NOT executed against a complete Hepta repository:
the working container has no GitHub network/DNS route, and full repository
clone could not be completed. No complete rustc/Clang/QEMU/physical/formal
qualification is claimed.

Run on the exact checkout, without waiting on remote CI:

    python -m unittest tests.test_hia_source_byte \
      tests.test_hia_resource_trace tests.test_hia_boolean_trace \
      tests.test_hia_byte_trace tests.test_hia_core tests.test_hia_oracle -v

whole_project_blockers_closed=false.
