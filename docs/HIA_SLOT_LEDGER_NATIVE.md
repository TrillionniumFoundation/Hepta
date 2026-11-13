# Native Agent slot, version and lease decisions

This component assigns the ordinary Agent's slot ledger decisions to
`examples/hia_bootstrap/slot_ledger.hepta`. The selected HIA image validates
canonical generation and epoch fields, compares conditional observations,
advances the retained generation high-water mark, selects rollback epochs and
admits retained lease identities.

The ordinary CLI, request service, SQLite engine, artifact admission and native
process owner still have hosted responsibilities. This component does not
replace `ScalarMultiversionRuntime` or establish whole-product native delivery.
The current qualification outcome belongs to the exact source and receipts
listed in [CURRENT](CURRENT.md); this contract is not a successful-run receipt.

## Explicit selection and custody

The selector is `HEPTA_HIA_SLOT_LEDGER_MANIFEST`, the factory is
`NativeSlotLedger`, and the manifest schema is
`hepta.hia.slot-ledger-native.v1`. The image uses the existing six-argument
byte ABI and Linux x86-64 native image admission. Its source is an explicit
installed resource; an installed package cannot fall back to a checkout.

The strict builder admits the matching-source cold compiler and captures its
source and emitted image identities. The runtime adapter admits the pinned
manifest, packaged source, compiler identity, image bytes and exact factory
before creating the service's state directory, database or profile artifacts. A selected image never falls back to the hosted
policy. A worker may select it through the same administrator-pinned
[native helper bundle](HIA_NATIVE_HELPER_WORKER.md). The original process/thread
owner and post-effect bundle identity checks remain required.

`HEPTA_HIA_SLOT_LEDGER_COLD_REPORT` is the test/build selector for a matching
current-source cold replay. The explicit
`HEPTA_HIA_SLOT_LEDGER_DEVELOPMENT_COMPILER` is a test-only development input;
it cannot override a requested cold report or become a production fallback.

## Original durable state

The existing `slots`, `versions` and `leases` tables remain authoritative.
The adapter uses the service's original SQLite connection. It does not create
a replacement database, maintain an authoritative process cache, or migrate
the original rows into a different namespace.

| Operation | Native decision | Existing effect boundary |
| --- | --- | --- |
| Snapshot | Interpret empty/current slot state and return the retained observation | Original slot/version reads and active-lease count across all generations |
| Conditional request | Validate canonical u64 generation/epoch and compare both fields exactly | Original adoption or rollback request transaction |
| Evaluation acceptance | Interpret complete observed JSON values, require the frozen completion/outcome policy and refuse unmet net benefit | Original receipt/proof checks, measurement/cost reads and adoption transaction |
| First adoption | Retain the baseline at generation 0 and choose the first successor | Original slot and version inserts |
| Subsequent adoption | Fold every retained generation, choose maximum plus one and increment epoch | Original version insert and slot update |
| Rollback | Admit the requested retained generation and increment epoch | Original slot update; retained versions and leases survive |
| Acquire | Select the current retained generation for a new lease | Original local-consumer transaction |
| Invoke admission | Match active state and the complete retained lease identity | Frozen descriptor from the admitted database row |
| Release | Admit the same retained lease and mark it inactive once | Original local-consumer transaction |

Generation and epoch values use canonical unsigned 64-bit decimal strings.
The maximum is `18446744073709551615`. Leading zeros, non-ASCII digits,
negative values and out-of-range values cannot acquire a valid ledger
observation. Overflow remains an error; values never wrap.

Adoption computes the next generation from **all retained versions**, including
versions newer than a rolled-back current generation. It does not use SQLite's
lexicographic maximum of TEXT values or cast u64 values through signed SQL
integers. The HIA fold consumes rows incrementally, without adding a history
row-count limit or a bounded sequence counter.

Rollback increments epoch even when the requested retained generation is
already current. It changes future acquisition only. It does not reverse
previous side effects, delete retained versions or release existing leases.

## Transaction and diagnostic ordering

Business receipt, proof, evaluation, native artifact and ABI admission keep
their existing order. The selected ledger now owns the ordinary adoption
completion, outcome and net-benefit decisions. It receives the complete
canonical JSON bytes for each observed value, never a hosted eligibility or
truth-value flag. HIA computes truthiness for the existing decoded JSON domain
and admits `improved`, or `unchanged` when the frozen objective allows it.
Incomplete evaluation and required-but-unestablished net benefit retain
`E_HIA_EVALUATION_REQUIRED` and `E_HIA_COST_INCOMPLETE` respectively.

The three completion fields are consumed in their original order; an earlier
refusal does not read a later missing or malformed field. Outcome policy follows
those fields. Actual measurement and full-cost artifacts are read before the
net-benefit policy. Non-hashable outcome arrays/objects retain the original
membership operation's error. Signed numeric zero, empty containers, empty
strings and null retain the original JSON value truthiness. Syntax/tree
admission and finite numeric value production remain with the existing bounded
JSON/foreign-object bridge; the ledger is not a second general JSON decoder.

Complete receipt/context/installation structural binding, proof requirements,
native artifact admission and ABI checks retain their existing owners. No
evaluation policy decision bypasses them, changes the SQLite transaction owner
or grants an incomplete measurement adoption authority.

The generation/epoch range checks precede snapshot comparison. A stale
conditional request retains the original `E_HIA_GENERATION_STALE` behavior.
Its pending slot snapshot is published only after the failed effect transaction
has rolled back, so the diagnostic artifact remains readable.

Both request journals retain their existing transaction owner. Slot changes
and the completed response are committed on the same connection. The native
journal's acknowledgement still precedes the actual SQLite COMMIT; an
acknowledgement alone does not establish durability. A COMMIT failure or lost
terminal result must retain the original failure/unknown-outcome semantics
and must not authorize an effect retry under a new request identity.

Acquire and release keep their original local-consumer transactions. The
ledger adapter does not begin or commit a nested transaction inside an
adoption or rollback request.

## Lease identity and invocation

Admission compares the lease id, slot, generation, complete artifact
descriptor and active state. Matching only an artifact SHA-256 is insufficient:
the issued artifact's id and URI are part of the retained identity.

The admitted descriptor is detached from the caller's mutable dictionary and
is constructed from the actual retained row. Native invocation, returned
generation/artifact identity and captured-buffer metadata use that descriptor.
They must not reread the caller's alias after a child executes.

An old lease remains callable after rollback. A newly acquired lease observes
the new current generation. The snapshot's in-flight count includes active
leases from every generation of the slot. Releasing a lease prevents new
admission through it; release does not cancel an invocation that has already
admitted its retained descriptor.

## Source, installation and qualification

The source contract includes the generator, builder, HIA program, adapter,
both slot test modules and this document. Package construction includes the
actual `.hepta` resource. The public builder participates in the existing
absolute-path, Python-isolation checks, and the worker allowlist names only
the exact `NativeSlotLedger` factory.

The original native/installed controls remain registered. Added slot controls
must exercise real SQLite connections, both request journals, retained
generations above the current generation, u64 boundaries, rollback to the
current generation, leases across rollback, caller mutation, restart, stale
CAS, acknowledgement/COMMIT failures and installed source/image refusal.
The selected implementation must execute with the replaced hosted ledger
policy refused while retaining the required business admission.

The CI and complete qualification entry run both
`tests.test_hia_slot_ledger_native` and
`tests.test_hia_slot_ledger_native_integration` with one matching cold source.
`HEPTA_HIA_SLOT_LEDGER_EVIDENCE` identifies the original evidence root;
integration controls use its `integration/` subdirectory. A development
fixture, a source-only check or a passing subset cannot qualify the installed
component or the complete retained regression.

Evaluation controls compare HIA decisions with independent JSON-value
semantics in both the Core VM and the emitted machine image. Ordinary service
controls obtain real evaluations, accept allowed unchanged content, refuse
disallowed unchanged/incorrect/incomplete/net-benefit requests, and replay the
exact completed or rejected response after closing and reopening the original
SQLite state. Both journal owners and the existing commit-loss/death controls
remain in scope. These observations do not select the helper for a running
worker or establish whole-product deployment.

All previous test identities and resource bounds remain in force. Whole-product
native replacement and removal of the remaining hosted owners require their
own ordinary-caller, installation and recovery closure.
