# Explicit Rust cleanup for a stopped finite byte-owner invocation

`raw-byte-dag-finite-heap-cleanup-v1` adds an opt-in abort phase to the existing
independent Rust byte-DAG and finite-entry heap admission. The same owned
checker, static DAG bounds, private immutable Core snapshot and existing
Machine execute the program. No alternative Core or Python semantic authority
is introduced. Default, source, nominal and native admission do not change.

This profile terminates an entire private scalar invocation. It has no caller
resource inputs or resource outputs, no external callbacks, and no escaped
resource handles. Internal borrowed parameters are views of owners created in
that invocation; they are not externally owned resources. Cleanup does not
resume an interrupted caller, invoke a user destructor, repair a failed result,
or convert a trap/budget stop into successful program execution.

The original profiles remain unchanged. In particular,
`raw-byte-dag-finite-heap-v1` still reports the owners, loans and live payload
present at a stop. The new profile is separately selected and separately
request-bound.

## Entry points

The actual Rust CLI takes raw primitive v7/v8 JSON on stdin:

```text
hia-core-shadow --byte-dag-heap-cleanup-admit-run FUNCTION JSON_ARGUMENTS \
  JSON_STATIC_POLICY JSON_HEAP_POLICY JSON_CLEANUP_POLICY JSON_V4_POLICY
```

`JSON_STATIC_POLICY` retains the three existing unsigned limits:
`max_allocator_interactions`, `max_vm_ticks`, `max_call_depth`.
`JSON_HEAP_POLICY` remains `{"max_live_heap_bytes": N}`.
`JSON_CLEANUP_POLICY` has exactly one field, `{"max_cleanup_actions": N}`, with
an exact integer in `0..32768`. Duplicate fields, extra fields, floats, bools,
oversized policies and unsupported inputs refuse before language execution.

The Python transport exposes the same explicit selection:

```python
execute_rust_byte_dag(
    raw_core, function, arguments, executable,
    executable_sha256=exact_binary_sha256,
    static_policy=limits,
    max_static_live_heap_bytes=heap_limit,
    max_cleanup_actions=32768,
    max_steps=steps, max_heap_bytes=runtime_heap, max_call_depth=depth,
    allocation_fail_at=failure_index,
)
```

Omitting `max_cleanup_actions` preserves the prior selected profile. Supplying
it without finite-entry heap admission is rejected. The Rust library entry is
`admit_and_run_byte_dag_heap_cleanup`; its report status must be checked, just
as the original runtime status must be checked for traps and budget stops.
Imported reports cannot construct the private admitted snapshot.

## Reservation before execution

Let `A` be the selected function's independently derived structural allocator
interaction bound, `T` its structural VM tick bound, and `P` the largest number
of borrowed parameters in any function of the admitted module. The cleanup
action reservation is the conservative upper bound:

```text
B = A + T * (1 + P)
```

Every `buffer.new` or `buffer.try_new` creates at most one owner, including a
logical empty owner after a failed optional request. Every source borrow uses
an instruction tick. Every invocation creates at most `P` extra call-formal
loan witnesses and has an entry tick. Returned-loan materialization and
reparenting reuse existing identities; they do not mint an uncounted witness.
Consequently remaining owner and loan records at any execution prefix are
bounded by these cumulative creation bounds. This formula is deliberately
conservative and uses the full module's maximum formal width.

Arithmetic overflow in this bound, `B` above the requested reservation, or a
requested limit above 32768 rejects admission. A finite-heap-admitted program
can fail this additional gate. There is no claim that all finite-heap programs
have obtained cleanup authorization.

The typed event journal calls `try_reserve_exact(B)` before Machine creation
and before any language entry tick or allocation. Failure to reserve rejects
before execution. Successful cleanup does not grow this journal. The ordinary
execution still uses its exact v4 step, heap, call-depth and allocation-failure
policy. Cleanup has its own precommitted logical action budget; exhausting the
ordinary step budget does not borrow unreported ordinary execution ticks.

`A` and `T` describe the ordinary execution prefix. Cleanup's additional
owner releases and loan endings are recorded in its separate actions and
post-ledger. They are not hidden inside the original allocator/tick bounds.
The heap bound remains a logical live-payload bound; cleanup never allocates
a new language owner or increases its payload peak.

## Explicit release semantics

The original Machine stop is first recorded without changing its status,
error code, values, ticks, policy or resource ledger. The byte storage still
exists in that same Machine at this point; the report is not obtained by
observing process exit or Rust host destruction.

Before releasing anything, the new phase audits the complete remaining
inventory. It checks the reserved record count, owner/allocator/loan counters,
payload totals, root and storage identities, and each loan's parent. Every
parent loan must still be present and have a strictly older identity, matching
root/storage and sufficient mutability. This establishes an acyclic parent
forest and a release order. Chains are refused. Failed validation preserves
the inventory and returns a failed cleanup observation. Audited-record visits
include a partially rejected audit rather than being imputed zero.

The phase then ends loans in descending identity order, so every child ends
before its parent. This order includes scoped call-formal witnesses and local
loans. A call-formal witness is not counted as a source `borrow` event; ending
it does not inflate `loans_ended`. If a returned formal was already materialized
as a source loan, it is counted and ended exactly once. Aliased readonly formals
share their actual root but keep distinct witness identities.

After all loans are ended, owners are released in descending identity order
through the existing `drop_owner` implementation. Each logical empty owner
increments `owners_dropped` but not `frees`; each nonempty owner releases its
actual byte storage and increments both relevant counters. Moved owners,
partially initialized normalized records, failed optional allocations and
owners transferred into a stopped callee remain in the invocation inventory
and are discharged exactly once.

The phase checks `is_clean()` on the still-live ByteMemory object. A normal
scalar return must already have a clean ledger; abort cleanup does not repair
a leaked normal return. Normal returns report `not_needed` with no events.

## Reports and failure handling

The new outer request and run schemas are
`hepta.hia.rust-byte-dag-heap-cleanup-request.v1` and
`hepta.hia.rust-byte-dag-heap-cleanup-run.v1`. Their request identity binds the
original raw input, canonical Core, exact entry/arguments, all ordinary limits,
heap limit and cleanup policy. The ordinary `runtime` envelope remains the
unchanged v4 observation, including the original pre-cleanup resource ledger.

`cleanup_bound` records the independent reservation formula and its inputs.
`cleanup` records the before and after ledgers, actual ordered release events,
local/formal classification, actual record inspections and used actions. A
completed stop has zero live owners, local loans, formal witnesses and payload;
the original peak and allocation-attempt counters are preserved.

Cleanup overrun, root/parent/counter inconsistency or failure to reach a clean
state is not successful cleanup. Its before/after ledgers, original runtime
stop and partial journal remain in a `cleanup_failed` report. The CLI retains
that JSON in stdout, emits `E_HIA_CLEANUP_INTERNAL` and returns nonzero. The
Python transport rejects nonzero or inconsistent reports. No cleanup receipt
alone grants admission or authorizes replayed code.

The Python consumer checks the full wire parent/root graph, order, exact
counter deltas, empty-owner accounting, request hash, scope and reservation.
It does not interpret the Core or recompute language ownership semantics.
The pinned Rust binary, runtime loader, host process and kernel remain trusted;
wire consistency is not cryptographic attestation of an arbitrary producer.

## Limits and validation

This is explicit logical resource discharge for admitted byte-owner DAGs,
not a general exception or recovery theorem. Chains, cycles, recursion,
foreign resources, user destructors, callbacks, asynchronous cancellation,
caller-owned external handles and source/native refinement remain outside
this profile. Full language soundness and Rust performance superiority are
not asserted.

The reserved journal does not guarantee success under host allocator panic,
host OOM, OS failure or process termination. JSON report construction and
serialization occur after the discharge and may require host allocations.
Allocator release behavior, these report allocations, tree-map costs and OS
reclamation are not bounded by the logical action count as CPU or RSS. An
absent/incomplete terminal report cannot be promoted to observed cleanup.

The regression suite reuses the earlier finite-heap matrix with the new
explicit profile, compares the original Rust prefix against the independent
Python VM and heap analysis, and separately checks actual discharge. It is not
a new holdout. Additional cases cover aliased formal parents, returned-loan
materialization, empty failed owners, all modeled trap kinds, all ordinary
budget-stop kinds, pre-execution reservation refusal, malformed wire policies,
rehashed reply mutations and semantic-import isolation. Rust internal tests
also corrupt a parent/root/formal inventory and use an insufficient reserved
budget, checking that no cleanup success or erased prefix is fabricated.

Run the real processes and preserve their development/focused evidence with:

```sh
HEPTA_RUST_SCOPED_CLEANUP_EVIDENCE_DIR=/absolute/new-output/actual \
  python -B -m unittest -v tests.test_hia_rust_scoped_cleanup
cargo test --locked --offline --manifest-path rust/hia-core-shadow/Cargo.toml
```

The collector retains build output, every direct Rust process, raw Core
inputs, failed controls, independent prefix comparisons and cleanup reports.
An outer runner must still record source/tool identities and total costs.
Development runs do not qualify a later integration commit; the final shared
implementation must run its own qualification.
