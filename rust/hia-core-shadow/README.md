# Independent finite HIA Rust shadow

The Python Core verifier remains the production admission authority. This crate
is an independent checking and execution oracle, not a native backend or a
whole-language safety proof.

## Owned-memory execution profiles v2/v3

`--owned-run FUNCTION JSON_ARGS [MAX_STEPS MAX_HEAP_BYTES FAIL_AT|none]` uses
`bounded-cfg-byte-owner-v2` for byte-only modules and
`bounded-cfg-owned-memory-v3` when a module contains bulk operations or chains.
Both use the same verified primitive v1–v7 Machine and execute:

- closed SSA blocks, branches, loops and internal direct calls;
- internal owning parameters/results and nonescaping read/mutable call loans;
- the ten byte-owner operations: `buffer.new`, `buffer.try_new`,
  `buffer.len`, `borrow.read`, `borrow.mut`, `loan.end`, `owner.move`,
  `owner.drop`, `buffer.load`, `buffer.store`;
- one shared resource ledger across frames, exact allocation-failure injection,
  and root-inclusive 32-frame, step and live-byte limits.

The v3 capability set additionally executes the version-correct operations
`buffer.fill`, `buffer.copy`, `buffer.move_within`, `buffer.swap`,
`buffer.copy_range`, `buffer.fill_range`, and the v7 chain operations
`chain.empty`, `chain.try_push`, `chain.pop`, `chain.is_empty`,
`chain.head_read`, `chain.head_mut`. Chain nodes charge 24 bytes to the same
heap/failure sequence as payload buffers. Node destruction is iterative and
ticks once per node, retaining the actual partial ledger on a step stop.
Chains can move through CFG edges and internal consuming calls/results.

The selected public function must have scalar parameters **and** scalar results,
even when an explicit export list is absent. Resource helpers remain internal.
The whole document is checked before execution, including nonexported helpers.
Direct nominal/composite input remains refused. Existing canonical Python
lowering can turn its records/enums/cooperative tasks into executable primitive
Core; the original input and normalized bytes are retained in the v3 corpus.
The scalar-only mode retains its original restrictions.

Calls consume owner arguments before entering a callee; borrowing preserves the
caller loan and its root. Two shared formal parameters may alias one actual loan.
A shared reborrow through one formal does not forbid reads through the other.
Parent writes, mutable-child suspension and early loan termination remain
checked. A trap or budget stop reports the actual live resources and does not
claim unwinding or cleanup that did not execute.

Source projection-borrow-return helpers use the existing frontend's checked
inlining. Their parent/child loans execute and end in the caller before later
mutation/destruction. This does **not** enable primitive cross-call Loan
returns, explicit lifetime returns or stored returned source borrows.

## Reproducible checks

```sh
cargo test --locked --offline --manifest-path rust/hia-core-shadow/Cargo.toml
python -m unittest tests.test_hia_rust_owned_vm tests.test_hia_rust_owned_cfg tests.test_hia_rust_owned_memory -v
python tools/qualify_hia_rust_owned_cfg.py --output /tmp/hia-owned-cfg.json
python tools/qualify_hia_rust_owned_memory.py --output /tmp/hia-owned-memory.json
```

The differential corpus includes loop-carried owners/loans, fallible branches,
owner-consuming/replacement calls, shared alias/reborrow behavior, recursion,
every executed step boundary, hidden unsupported operations and invalid resource
transfers. It compares return values, trap/budget reasons, step counts and every
resource-ledger field. The qualification report retains each program, each pair
of actual VM observations, source hashes, toolchain identity and failures/skips.
Passing this corpus establishes only the named finite execution profile.

The v3 corpus additionally executes real source projection helpers and generic
owned records/results, nominal stored reborrows and cooperative cancellation,
all six bulk operations, chain payload/node failures, and every executed step
cut of selected source/aggregate/chain cleanup paths. Its collector retains
raw process stdout/stderr, original inputs, canonical programs, both complete
reports, rejected inputs, actual binary/toolchain identities and unchanged
source inventories. See [the v3 scope](../../docs/HIA_RUST_OWNED_MEMORY_VM_20261028.md).
