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
The validator checks allocation/owner conservation, exact loan start/end
conservation, existence of a live byte owner for any live local loan, positive
payload consistency, peak/live heap policy, and the exact step-stop boundary.
Primitive v7/v8 observations additionally check chain/node conservation and
two live byte owners per live node. Empty owners remain real capabilities.
An interrupted chain destructor may have consumed its chain token while
retaining nodes; that valid stopped state remains accepted.

The scope is scalar interpreter entry/exit. Internal functions may transfer
owners and loans through checked signatures. The existing explicit Rust
scoped-abort-cleanup profile still validates its separate before/after journal;
this common contract checks its initial execution observation and does not
invent successful cleanup.

Call expansion may reduce ticks or call depth. The common exit equations apply
on both sides, but a `candidate_requalified` contract may intentionally change
which quota is reached. A retained example changes a source call-depth stop
into a candidate return. No exact budget-stop equivalence is claimed.

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
