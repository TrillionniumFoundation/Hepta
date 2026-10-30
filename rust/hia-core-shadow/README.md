# Independent finite HIA Rust shadow

The Python Core verifier remains the production admission authority. This crate
is an independent checking and execution oracle, not a native backend or a
whole-language safety proof.

The opt-in bound-v3 and bound-v4 protocols reuse this same Machine and ByteMemory
with explicit language call frames. V3 admits up to 256 root-inclusive frames,
10,000,000 ticks and 1 GiB of logical payload; v4 additionally binds ordered
list/tuple arguments and exact positive failure indices beyond u64 within its
1024-byte policy. Legacy protocols retain their original limits and receipts.
See [v3 budgets](../../docs/HIA_RUST_BOUND_BUDGET_V3.md),
[v4 API](../../docs/HIA_RUST_BOUND_API_V4.md), and
[sealed executable custody](../../docs/HIA_RUST_EXECUTABLE_CUSTODY.md).

For an exact invocation comparison, `--owned-run-bound` wraps the same Machine
report with a canonical request binding the Core, entry, arguments and policy.
The Python `crosscheck_rust_execution` API checks both full execution outcomes
and stopped resource ledgers using the pinned executable. Legacy reports are
unchanged. See [the invocation contract](../../docs/HIA_RUST_BOUND_EXECUTION.md).

The separate `--owned-run-bound-v2 FUNCTION JSON_ARGS JSON_POLICY` command
selects an explicit depth in 1–32 on the same Machine. Its strict policy and
fresh comparison API are documented in [bound depth v2](../../docs/HIA_RUST_BOUND_DEPTH_V2.md);
legacy modes remain fixed at 32 and retain their existing reports.

## Byte-owner execution profile v3

`--owned-run FUNCTION JSON_ARGS [MAX_STEPS MAX_HEAP_BYTES FAIL_AT|none]` uses
`bounded-cfg-byte-owner-bulk-v3`. It executes verified primitive v1–v7 programs with:

- closed SSA blocks, branches, loops and internal direct calls;
- internal owning parameters/results and nonescaping read/mutable call loans;
- the ten byte-owner operations: `buffer.new`, `buffer.try_new`,
  `buffer.len`, `borrow.read`, `borrow.mut`, `loan.end`, `owner.move`,
  `owner.drop`, `buffer.load`, `buffer.store`;
- versioned `buffer.fill`/`buffer.copy` (v2), `buffer.move_within` (v3),
  `buffer.swap` (v4), `buffer.copy_range` (v5) and `buffer.fill_range` (v6);
- one shared resource ledger across frames, exact allocation-failure injection,
  and root-inclusive 32-frame, step and live-byte limits.

The v5 chain capability set composes those bulk instructions with the v7/v8 operations
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

Both extents are checked before a copy writes any byte. Overlapping movement
uses snapshot-equivalent `copy_within`; distinct-owner copies use fixed
4096-byte stack scratch rather than a host allocation proportional to the
range. Zero-length extents allow an exact-end offset, not an offset beyond the
end. They retain the distinct-owner rule. One bulk instruction consumes one VM
operation tick, matching Python; this is not a constant wall-clock cost claim.

Calls consume owner arguments before entering a callee; borrowing preserves the
caller loan and its root. Two shared formal parameters may alias one actual loan.
A shared reborrow through one formal does not forbid reads through the other.
Parent writes, mutable-child suspension and early loan termination remain
checked. A trap or budget stop reports the actual live resources and does not
claim unwinding or cleanup that did not execute.

## Parameter-bound returned-loan profile v4

Primitive v8 uses the separate execution profile
`bounded-cfg-byte-owner-loan-returns-v4` for modules without chains; v1–v7
modules without chains keep the exact `bounded-cfg-byte-owner-bulk-v3` profile.
Any v7/v8 module containing a chain signature or opcode instead selects
`bounded-cfg-owned-memory-v5`, with the v8 returned-loan claim when applicable.
The same independent Rust ownership checker validates optional `return_loans`
annotations, result arity, original input parameter identity, permissions,
CFG-origin joins and call-result aliasing. Each borrowed result must be its
declared input loan or that input's direct child. Local-owner escape, deeper
descendants, duplicate result handles, active child returns and incompatible
actual call aliases reject before running the Machine.

The existing Machine creates one fresh child when a function forwards its
input loan; an already-created direct child transfers without another loan
event. Parent/input binding survives CFG renaming and recursion. The same
rules compose with byte-owner loops, scalar/multiple results, fallible
allocation and the bulk operations; traps and budget stops retain their
actual live ledgers.

Static `--owned-shadow` receipts for v8 use
`hepta.hia.rust-owner-shadow.v2` and the exact boolean
`v8_parameter_bound_loan_returns_checked`. Older receipts and missing,
downgraded or integer-valued v8 claims cannot corroborate a v8 program.
The scalar shadow still supports only v1–v7. The whole-module execution
whitelist and independent verifier reject unknown schemas, operations and
illegal graphs even inside unused helpers. Chain execution has its own v5
profile; it is never silently added to a v3/v4 receipt.

Public capabilities, arbitrary lifetimes, external callbacks, cancellation,
whole-language soundness and switching production authority remain outside
these finite profiles. See [the v8 contract](../../docs/HIA_RUST_RETURNED_LOANS_V8.md).

## Reproducible checks

```sh
cargo test --locked --offline --manifest-path rust/hia-core-shadow/Cargo.toml
python -m unittest tests.test_hia_rust_owned_vm tests.test_hia_rust_owned_cfg tests.test_hia_rust_bulk_vm -v
python tools/qualify_hia_rust_owned_cfg.py --output /tmp/hia-owned-cfg.json
python -m unittest tests.test_hia_rust_returned_loans tests.test_hia_rust_crosscheck -v
python tools/qualify_hia_rust_owned_cfg.py --returned-loans --output /tmp/hia-returned-loans.json
python tools/qualify_hia_rust_owned_memory.py --output /tmp/hia-owned-memory.json
python tools/qualify_hia_rust_returned_chains.py --output /tmp/hia-returned-chains.json
```

The differential corpus includes loop-carried owners/loans, fallible branches,
owner-consuming/replacement calls, shared alias/reborrow behavior, recursion,
every executed step boundary, hidden unsupported operations and invalid resource
transfers. It compares return values, trap/budget reasons, step counts and every
resource-ledger field. Bulk coverage adds all six instructions, overlapping
ranges, zero/end/overflow bounds, copies crossing stack-scratch chunks, and
composition with calls, reborrows, loop-carried loans and failure/step stops.
The qualification report retains each program, each pair
of actual VM observations, source hashes, toolchain identity and failures/skips.
Passing this corpus establishes only the named finite execution profile.

The owned-memory corpus additionally executes real source projection helpers and generic
owned records/results, nominal stored reborrows and cooperative cancellation,
all six bulk operations, chain payload/node failures, and every executed step
cut of selected source/aggregate/chain cleanup paths. Its collector retains
raw process stdout/stderr, original inputs, canonical programs, both complete
reports, rejected inputs, actual binary/toolchain identities and unchanged
source inventories. See [the owned-memory scope](../../docs/HIA_RUST_OWNED_MEMORY_VM_20261028.md).

## Logical roots and borrowed call scopes

Byte storage and language ownership are separate identities. A chain head loan
keeps a typed chain root and the byte-owner ID of its payload; an unrelated
byte owner with the same numeric ID cannot alias that chain. Shape changes
require that all loans rooted in the chain have ended. `buffer.len` observes
the payload extent rather than a chain or header identity.

Each borrowed call parameter receives a distinct scope witness linked to its
actual caller loan. These witnesses do not change source borrow/end counters.
A local child suspends its own formal while another readonly formal can still
read the same actual root. Returning an original formal materializes one new
counted child; returning an existing direct child rebinds that child to the
selected actual without another event. Nested calls, CFG names and recursion
therefore preserve exact origins, permissions and stopped source ledgers.

The [v5 composition corpus](../../docs/HIA_RUST_RETURNED_CHAINS_V8.md) includes
original-parameter chain-head returns, typed-ID collisions, aliased call
formals, every selected execution cut and the exact existing cross-target
Core corpus. Its native controls are retained separately; Rust execution does
not grant native refinement, general lifetimes or production authority.
