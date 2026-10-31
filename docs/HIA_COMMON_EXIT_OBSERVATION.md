# Shared execution outcome and resource observation contract

`hepta.hia_opcodes.validate_execution_observation` now checks the common resource
equations before the Python interpreter emits a report and before the Rust raw
byte-DAG route accepts a report. Call expansion executes through that same Python
interpreter. The validator is a closed accounting boundary, not a second Core
verifier or proof that a producer reported its real state.

The defect reproduced against base `3201298a9828927452d42bcac146e610e1348a7f`
was at the Rust response boundary: a real bounds trap or step-quota stop could
retain one four-byte owner and one loan, yet a captured response modified to
erase the live-loan count, overstate ended loans, erase live bytes, erase live
owners, or erase allocations was accepted. All ten stopped-response negative
controls now reject. These controls do **not** demonstrate an actual leak or
incorrect execution by the Rust Machine; they demonstrate acceptance of
self-contradictory wire observations.

## Outcome distinctions

| Case | Report status | Resource obligation |
| --- | --- | --- |
| Normal scalar return | `returned` | No invocation-owned byte owners, local loans, chains or chain nodes remain. |
| Error represented as a value | `returned` | The same return rule; an error tag supplies no exemption. |
| Fallible allocation failure | Ordinary control flow | `buffer.try_new` produces an empty linear owner and false; the owner must still be consumed. |
| Infallible allocation failure | `trapped`, `allocation` | Preserve the actual stopped ledger; no implicit unwind. |
| Program trap | `trapped`, one of the closed trap codes | Preserve the stopped prefix, including retained owners and loans. |
| Cooperative cancellation encoded by the program | Ordinary control flow, often `returned` | Explicit release before scalar return; no new asynchronous cancellation status. |
| Step, heap or call quota | `budget_exceeded` | Preserve the stopped prefix; quota exhaustion is distinct from program allocation failure. |
| Injected host scratch allocation failure in Python bulk operations | `budget_exceeded`, `host_memory` | A Python-only evaluator stop; this code is not accepted from the Rust profile. |

Unknown statuses, error codes, fields and nonexact integer counters reject.
The execution `steps` field is also an **exact Python integer** (not `bool` or
`float`), with `1 <= steps <= max_steps` for ordinary return/trap/other quota
outcomes. A tick-quota stop alone requires exactly `steps == max_steps + 1`,
still an integer. This prevents `True`, `1.0`, and fractional ticks from
passing Python numeric comparison and avoids leaking `TypeError` for nonnumbers.
These are wire-shape checks, not a guarantee that a producer reported its true
execution count; the independent source and binary identity requirements remain.
The validator checks allocation/owner conservation, exact loan start/end
conservation, existence of a live byte owner for any live local loan, positive
payload consistency, peak/live heap policy, and the exact step-stop boundary.
Primitive v7/v8 observations additionally check chain/node conservation and
two live byte owners per live node. Empty owners remain real capabilities.
An interrupted chain destructor may have consumed its chain token while
retaining nodes; that valid stopped state remains accepted.

### Executed-tick ceiling for allocation attempts

The concrete Python scalar VM calls `tick()` before every executed opcode.
Only `buffer.new`, `buffer.try_new` and `chain.try_push` can invoke the
counted nonempty allocator, each at most once per executed opcode. Zero-sized
owners and extra empty fallback owners do not increment the attempt counter.
Consequently the additional necessary execution-summary condition is

`allocation_attempts <= steps`.

A forged receipt that increments only the attempt count above the observed
VM ticks must be rejected, even when the existing allocation/owner and
live-byte equations all hold. The regression retains real return, bounds-trap
and heap-quota-stop observations and mutates only that one counter. This
predicate is deliberately necessary but not sufficient to authenticate the
producer or prove individual allocation events. No ASYNC cancellation,
external FFI, whole-program refinement or native ABI claim is added.

The scope is scalar interpreter entry/exit. Internal functions may transfer
owners and loans through checked signatures. The existing explicit Rust
scoped-abort-cleanup profile still validates its separate before/after journal;
this common contract checks its initial execution observation and does not
invent successful cleanup.

Call expansion may reduce ticks or call depth. The common exit equations apply
on both sides, but a `candidate_requalified` contract may intentionally change
which quota is reached. A retained example changes a source call-depth stop
into a candidate return. No exact budget-stop equivalence is claimed.

## Live recursive-chain storage in stopped receipts

The v7/v8 chain model has a 24-byte storage allocation for every still-live
chain node, distinct from its payload owner. The central opcode/observation
contract names this size as `CHAIN_NODE_STORAGE_BYTES`; the Python VM imports
it rather than maintaining an independent literal.

For any admitted stopped-chain resource summary, in addition to the existing
owner and allocation count equations, the validator requires
`live_bytes >= 24 * live_chain_nodes` and
`allocations - frees >= live_chain_nodes`. A retained real v7 heap-stop
fixture has one live node, two nonempty allocations and 25 live bytes.
Mutants that lower the same stopped ledger to 2 or 23 live bytes must refuse,
even though they satisfy the older count-only equations.

A successful node creation also requires a distinct nonempty storage
allocation, and a completed node destruction frees its nonempty storage owner.
Therefore `chain_nodes_created <= allocations` and
`chain_nodes_dropped <= frees` are mandatory cumulative invariants. A new
negative case preserves the live-node, live-byte and owner equations while
falsely claiming one or two completed node destructions without any frees;
those stopped summaries must refuse. A real successful chain cancellation
provides the positive release control.

Recursive nodes also require a **historical chain-token lifecycle**, not merely
a sufficient number of byte allocations. Every node creation occurs inside a
push on an already-created chain generation; each completed node destruction
is preceded by consuming a chain generation (either through pop or, during
iterative drop, after the earlier successful pushes). The additional necessary
cumulative constraints are `chain_nodes_created <= chains_created` and
`chain_nodes_dropped <= chains_consumed`.

Two stopped-prefix regression controls first retain actual VM heap and tick
quota reports, then forge the chain-generation counters while preserving
their internal creation/consumption equation. The previous independent node,
byte, and owner equations alone cannot detect those cases. The new checks
reject them without requiring a live chain token for nodes held by an
**interrupted iterative destructor**. These inequalities are necessary
receipt-consistency conditions, not a sufficient full operational semantics
or a cryptographic attestation of the emitting process.

This is **a consistency constraint on declared receipts**, not evidence of an
honest remote producer, memory-address provenance, whole-runtime proof, or
native machine-code equivalence. Malformed reports do not gain authority.

## Independent small model

`formal/hia_exit_accounting.py` is separate from the production interpreter and
defines mathematical count transitions. Z3 checks 15 induction/exit obligations,
15 satisfiable-antecedent controls, and four satisfiable counterexamples to
broken transitions or missing release guards. Each query is retained as SMT2.
`unknown`, timeout or an unexpected answer makes qualification fail.

```sh
python tools/verify_hia_exit_accounting.py --output /tmp/hia-exit-accounting
```

This establishes only the stated abstract integer ledger invariants. It does
not prove production refinement, concrete object identity, borrow exclusion
for individual owners, native lowering, recursive-chain layout, machine-counter
overflow, FFI, concurrency, OS cleanup or asynchronous cancellation. Z3 and the
query generator are trusted; no new Lean-kernel proof is claimed.

## Reproduce the execution boundary

Build the unchanged Rust crate in an environment containing its exact lockfile
dependencies, or select an explicitly identified existing binary. The qualifier
always records that it did not build the supplied executable itself.

```sh
cargo build --locked --offline --manifest-path rust/hia-core-shadow/Cargo.toml
python tools/qualify_hia_exit_contract.py \
  --rust-executable /absolute/path/to/hia-core-shadow \
  --rust-sha256 EXPECTED_SHA256 \
  --output /tmp/hia-exit-observations
python -m unittest tests.test_hia_execution_contract tests.test_hia_exit_accounting
```

The qualifier retains nine real Rust processes, full Python comparisons, ten
captured-response refusal controls and five call-expansion observations. The
current evidence reuses binary SHA-256
`1ffdd14ee444830980b8f844ecbd932d2e39dc6fd9d0b749ae5fbc14e65f8fcf`;
its current Rust source and lockfile match the earlier frozen source manifest.
Two fresh offline-build attempts failed because required dependency cache
entries were absent. They remain in the evidence. This source comparison is
not a fresh source-to-binary rebuild or cryptographic artifact attestation.

The same increment fixes versioned catalog discovery: every `type_groups`
member is now visible in that schema's `types` list. In particular, schemas
v1-v6 no longer advertise the v7 `chain` owner. No primitive grammar, opcode,
latest-v8 catalog contents, native authority or universal safety claim expands.
