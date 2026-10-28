# One Rust execution Machine for chains and v8 returned loans

`bounded-cfg-owned-memory-v5` combines the primitive chain implementation from
the resource increment with the qualified v8 returned-loan contract. The
existing Rust `Machine` executes scalar instructions, CFG edges, calls and
destructor ticks; its `ByteMemory` owns the shared byte, loan and chain ledger.
There is no second resource executor and no Python receipt admission shortcut.
Canonical Python Core remains the production admission authority.

## Versioned contract

| Whole-module features | Execution profile |
| --- | --- |
| Primitive v1–v7 without chain signatures or operations | `bounded-cfg-byte-owner-bulk-v3` |
| Primitive v8 without chain signatures or operations | `bounded-cfg-byte-owner-loan-returns-v4` |
| Primitive v7/v8 containing chain signatures or operations | `bounded-cfg-owned-memory-v5` |

The report schema remains `hepta.hia.rust-byte-owner-execution.v1`. The v3/v4
envelopes retain their previous capability claims. The v5 envelope enables
`chain_and_bulk_execution`, `chain_execution`,
`interprocedural_chain_execution`, `separate_logical_and_storage_identities`
and `distinct_call_formal_loan_identities`. A v8 document additionally carries
`parameter_bound_returned_loans_execution=true`. Static verification retains
the independent version-specific owned-shadow receipt, including v8's exact
boolean `v8_parameter_bound_loan_returns_checked`.

The complete document is independently checked before any execution. Unknown
operations, wrong-version features, illegal parameter origins, aliasing,
unconsumed owners and public resource handles reject even in an uncalled
helper or behind a tiny budget/allocation failure. Scalar mode keeps its
original v1–v7 boundary. Direct nominal input still requires canonical
lowering before Rust receives primitive Core bytes.

## Roots, payload storage and call scopes

The donor independent-v7 implementation identified two distinctions worth
preserving in the shared Machine. First, numeric IDs live in separate typed
namespaces: `Root::Owner(id)` and `Root::Chain(id)`. A chain-head loan records
its chain root, the payload's byte-owner storage ID and its parent capability.
It cannot alias an independent byte owner merely because their integer IDs
match. A live head or descendant prevents chain move, pop, push or drop.
`buffer.len` and bulk operations use the payload storage extent, never the
chain descriptor or 24-byte header extent.

Second, each borrowed formal receives a distinct runtime scope witness linked
to its actual caller loan. The complete actual argument list is checked before
creating witnesses, so duplicate readonly actuals do not spuriously suspend
one another during call binding. A reborrow through one formal suspends that
formal; another readonly formal can still read its aliased root. Exclusive
actual aliases and readonly-to-mutable upgrades remain rejected independently
by the Rust verifier and runtime checks.

These scope witnesses are not source borrow events and do not appear in
`loans_started`, `loans_ended` or `live_local_loans`. Normal call completion
removes its remaining witnesses. Forwarding an original v8 formal materializes
one fresh counted child of the actual caller. Returning an already-created
direct child rebinds that child to the actual, with no extra event. Recursive
returns repeat this rebinding without adding one loan per frame. Static
original-parameter identity still controls admission across renamed CFG
parameters and all mutable/shared result positions.

## Exact stop accounting

Chain descriptor creation/consumption and node creation/destruction remain
separate ledger events. A successful push allocates a 24-byte node and creates
a real empty fallback owner; failed optional header allocation creates and
drops its internal empty owner, then returns the original payload through the
fallback. Payloads, headers and other byte owners share one allocation failure
sequence and one live-byte limit.

Chain destruction consumes its descriptor before a tick for each node. A stop
between nodes therefore leaves no live chain descriptor but retains the
remaining node/payload owners, bytes and node count. Host Rust container
destruction never becomes a reported source free. Trap, heap, call and step
stops retain the actual source prefix, including partially-created returned
loans; external formal witnesses do not inflate those counters.

The finite limits remain 32 root-inclusive frames, 1,000,000 operation ticks
and 16 MiB of payload/node bytes. The byte ledger excludes host map/vector
metadata and is not a whole-process RSS or native performance bound.

## Reproducible composition evidence

```sh
cargo test --locked --offline --manifest-path rust/hia-core-shadow/Cargo.toml
python -m unittest tests.test_hia_rust_returned_chains -v
python tools/qualify_hia_rust_returned_chains.py --expected-head COMMIT --output /tmp/hia-returned-chains.json
python tools/qualify_hia_rust_owned_memory.py --output /tmp/hia-owned-memory.json
```

The returned-chain qualifier requires a clean unchanged source commit. It
retains each complete canonical program, the exact Rust CLI process and
stdout/stderr, both full execution reports, input policy, raw method log,
binary identity and both Rust static/execution refusals for each invalid input.
Development observations remain unqualified until source identity is frozen.

The corpus includes the exact preexisting v8 cross-target Core and independent
value/allocator specification, chain-head forwarded/created/mixed results,
original-formal recursion, descriptor-owning recursion, typed-ID collisions,
all six bulk operations, duplicate readonly actuals, payload length, selected
full step sweeps and allocation/heap stop positions. The scalar pipeline
fixture is available for separate direct-native controls; the Rust/Python
runner does not claim it executed a native binary. Native value/allocator observations are
distinct from VM loan counters, which native lowering erases.

The collision pipeline returns the exact little-endian observation bytes
`44, 7, 7, 44, 11, 88, 5` packed into `u64` value `1504179890095916`. Its normal
payload allocations are 5 and 5 bytes plus one 24-byte node, so peak bytes are
34 and allocations/frees are both 3. These expectations come from the
declared byte transforms and resource operations, independently of either VM.

No test-count denominator includes execution rows or refusal rows. Each
receipt belongs to its recorded source/binary identity; historic v7 or v8
qualification is not reused as qualification of the merge. This finite
increment does not close general recursive ADTs, arbitrary lifetime returns,
foreign callback lifetimes, asynchronous cancellation, whole-language
soundness, LLVM refinement or the entire Rust authority-switch gate.
