# Independent finite HIA Rust shadow

The Python Core verifier remains the production admission authority. This crate
is an independent checking and execution oracle, not a native backend or a
whole-language safety proof.

## Byte-owner execution profile v2

`--owned-run FUNCTION JSON_ARGS [MAX_STEPS MAX_HEAP_BYTES FAIL_AT|none]` uses
`bounded-cfg-byte-owner-v2`. It executes verified primitive v1–v7 programs with:

- closed SSA blocks, branches, loops and internal direct calls;
- internal owning parameters/results and nonescaping read/mutable call loans;
- the existing ten byte-owner operations: `buffer.new`, `buffer.try_new`,
  `buffer.len`, `borrow.read`, `borrow.mut`, `loan.end`, `owner.move`,
  `owner.drop`, `buffer.load`, `buffer.store`;
- one shared resource ledger across frames, exact allocation-failure injection,
  and root-inclusive 32-frame, step and live-byte limits.

The selected public function must have scalar parameters **and** scalar results,
even when an explicit export list is absent. Resource helpers remain internal.
The whole document is checked before execution, including nonexported helpers.
Chain types/operations, bulk operations and direct nominal/composite input are
still refused. The scalar-only mode retains its original restrictions.

Calls consume owner arguments before entering a callee; borrowing preserves the
caller loan and its root. Two shared formal parameters may alias one actual loan.
A shared reborrow through one formal does not forbid reads through the other.
Parent writes, mutable-child suspension and early loan termination remain
checked. A trap or budget stop reports the actual live resources and does not
claim unwinding or cleanup that did not execute.

## Reproducible checks

```sh
cargo test --locked --offline --manifest-path rust/hia-core-shadow/Cargo.toml
python -m unittest tests.test_hia_rust_owned_vm tests.test_hia_rust_owned_cfg -v
python tools/qualify_hia_rust_owned_cfg.py --output /tmp/hia-owned-cfg.json
```

The differential corpus includes loop-carried owners/loans, fallible branches,
owner-consuming/replacement calls, shared alias/reborrow behavior, recursion,
every executed step boundary, hidden unsupported operations and invalid resource
transfers. It compares return values, trap/budget reasons, step counts and every
resource-ledger field. The qualification report retains each program, each pair
of actual VM observations, source hashes, toolchain identity and failures/skips.
Passing this corpus establishes only the named finite execution profile.
