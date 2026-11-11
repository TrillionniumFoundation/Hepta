# Native slot, generation and lease ledger

Status: explicitly selected development owner. The confirmed `69e97bbc` direct
input narrowing has a native object-transport repair with independent VM and
actual machine/domain controls. Integration and matching-source cold/full
qualification remain separate gates. The independent reference baseline is
Hepta `63fa2e7351c6b7e787e3834cbdbfe2307a08d872`; historical failures below remain
unchanged evidence and are not implied passes of the revised source.

The owner covers the original `main.slots`, `main.versions` and `main.leases`
ledger: observation, exact generation/epoch CAS, first baseline retention,
maximum-retained-generation allocation, rollback, lease acquisition, exact
retained-row admission and release. It preserves the original database and WAL.

## Boundaries

The selected owner requires explicitly admitted native namespace and request
journal dependencies before writable state is created. It cannot fall back to a
hosted transaction when a selected native capability is unavailable. Adoption
and rollback borrow the exact current request `_EffectConnection`; they do not
own request reservation, response history, COMMIT or ROLLBACK. Lease acquisition
and release use the native namespace's original-connection scope and native
epoch. Standalone observations grant no mutation authority.

HIA retains each operation's original inputs, owner and connection identity,
scope nonce/epoch/callback token, observed rows, generation/epoch, effect sequence
and pending outcome. A side effect requires a consumed native preclaim and a
matching outcome. Losing a result, receipt, SQL or commit acknowledgement cannot
restore an old action's authority. The existing request or namespace owner alone
controls transaction cleanup.

Adoption and rollback return staged results to their request owner. The exact
response and slot writes still commit together. Direct acquire/release have no
durable request key in the original API; this work will not invent historical
idempotency or infer lost completion merely from current row equality.

## Original behavior retained

- Adoption retains generation 0 baseline on an empty slot, allocates one above
  every retained generation, and increments epoch without u64 wrap.
- Rollback selects an existing generation and increments epoch. It never deletes
  versions or artifacts or reverses already performed calls.
- A lease is an active retained row, not a one-shot execution token. Repeated and
  concurrent invocations remain supported. Each invocation freezes the retained
  lease identity before running the foreign child.
- With the original built-in SQLite bindings, release marks the lease inactive
  for future admission. It neither drains nor
  cancels already admitted calls and does not hold the Store lock across the
  native child. Active lease count is not actual executing-child count.
- Stale CAS details are published only after the enclosing atomic request
  transaction is confirmed rolled back. The snapshot remains advisory.

## Explicit residual owners

Context, installed profile, build/proof/evaluation evidence validation, native
ABI admission and the actual subprocess runner remain separate existing owners.
A native ledger does not make these foreign business/checker components, the
Python worker protocol, CLI or Rust MCP/process runtime native. Existing namespace,
execution-budget and request-journal owners are reused, not recreated. No default
activation, state reset, live migration, garbage collection or old-code deletion
is part of this development checkpoint.

The full read-only baseline audit also identifies hosted context creation and
candidate-attempt authority, cost ledger, cursors, discovery profile/manifest
construction, tool orchestration, output schemas and worker/process reporting as
remaining work. Their native dependencies do not imply those policies are done.

## Required qualification

Independent HIA VM and actual machine state observations must cover wrong
instance/scope tokens, sequence exhaustion, stale and replayed outcomes, row and
buffer corruption, true concurrent CAS, lost SQL/native/commit receipts and
retained unknown owners. The old tool/campaign/byte lifecycle/lease-alias and
request-atomicity tests remain independent references and keep their original
limits. Selected execution must pass with old ledger bodies poisoned, include
real child use and installed-wheel resource custody, and preserve all original
failures as evidence. Development compiler reuse is not matching-source cold or
whole-stack qualification.

## Selection and source custody

`HEPTA_HIA_SLOT_LEDGER_MANIFEST` selects the installed native image. Both
`HEPTA_HIA_ARTIFACT_NAMESPACE_MANIFEST` and
`HEPTA_HIA_REQUEST_JOURNAL_MANIFEST` must already have admitted their real native
owners. Image/source admission happens before a new Store directory is created.
An absent dependency, changed image, changed packaged HIA source or incompatible
owner refuses selection. Selecting the ledger does not select other owners by
implication. The hosted reference remains available only when the ledger is not
selected; a selected failure never enters it.

`tools/build_hia_slot_ledger.py` requires an actual matching-source cold report
and compiler. It admits that report before creating the output directory, checks
the HIA source against the full admitted source manifest, compiles it, then
rechecks compiler, report, full source and image bytes. Its build receipt keeps
whole-stack rewriting, default activation, arbitrary-input equivalence and old
code deletion false. The generated HIA asset is included in the installed wheel.

The test fixture honors `HEPTA_HIA_SLOT_LEDGER_COLD_REPORT` for the ledger and its
namespace/request/budget/publication dependency builds. An explicit
`HEPTA_HIA_SLOT_LEDGER_DEVELOPMENT_COMPILER` cannot be combined with a cold report.
Standalone compiler reuse is labelled `DEVELOPMENT_REUSED_COMPILER`; standalone
seed/B1/B2 construction is labelled `DEVELOPMENT_B0_B1_B2`. Evidence is retained
under `HEPTA_HIA_SLOT_LEDGER_EVIDENCE`. Neither mode grants cold qualification.

## Covered caller paths within the selected profile

| Existing entry | Selected authority and ordering |
| --- | --- |
| `inspect_slot` / `_slot_snapshot` | Read slot, active version and count of active leases; return an advisory snapshot without a mutation capability. |
| `_conditional_slot` | Validate generation then epoch, observe the same rows, and compare both original values in HIA. |
| `_hia_adopt` | Preserve context/evaluation/build/proof/cost/native-ABI checks, then retain baseline if empty, fold every retained generation, insert the new version and CAS the original slot. The request owner publishes the response and commits. |
| `_hia_rollback` | Validate retained generation before expected generation/epoch, select the retained image, verify native ABI, reobserve the original slot, then CAS to that generation with incremented epoch. The request owner commits. |
| `acquire_slot` | Observe active generation with the original argument bindings, validate the native image, obtain OS entropy, format the UUID in HIA, execute the original INSERT, then require the native namespace's confirmed commit certificate. The output retains the original target object. |
| `_lease` / `invoke_lease` | Admit the exact active retained row and produce a detached lease value. The unchanged invocation body freezes arguments/metadata and runs the existing child outside the ledger lock. |
| `release_slot` | Admit the active row in the original comparison order, execute the original UPDATE using its newly retained row ID, then require the confirmed namespace epoch. No extra caller-object binding is introduced. |

Seven original ledger method bodies are preserved under `_..._reference` names;
their arguments, decorators and bodies remain the baseline reference. The
`invoke_lease` body is unchanged. Native wrappers use retained HIA results for
generation, epoch, slot, artifact and lease identity. They do not reproduce these
decisions from Python booleans after an interruption.

All fixed ledger SQL uses `main.`. TEMP tables cannot shadow the official
`slots`, `versions` or `leases` tables. The conditional update binds the exact
old name, generation, epoch, context and ABI hash, requires one affected row,
and requires exact readback. Retained-version insertion is also read back.
Allocation uses the maximum of all retained generation rows, so rollback cannot
make a previously used generation available again.

## Retained native state and wire protocol

The flat native entry takes six machine arguments: request pointer/size, result
pointer/capacity, retained-state pointer/capacity. The fixed prefix is 4096 bytes;
the only variable state suffix is canonical ABI JSON, bounded by 8 MiB. The
adapter reserves the required extent before the operation begins. A caller may
not treat a shorter result, mismatched state copy or malformed packet as success.

Each request begins with 32 little-endian u64 words (`HIASLQ01`), followed by at
most eleven length-prefixed tagged byte fields. The header binds operation nonce,
official connection nonce, actual connection nonce, scope kind, scope epoch,
scope nonce, callback token, native scope-owner identity and exact sequence.
Unused header words and fields must be canonical zero/absent. Field tags denote
absent, UTF-8 transport, canonical artifact-reference bytes, exact integer
transport and raw bytes. HIA admits the values after this fixed transport step.
State version 1 covers the bounded tool/adoption/rollback protocol and its
retained raw controls. Version 2 covers direct operations 8–11. Those requests
carry only native-owned opaque result handles, exact boolean observations or
sixteen entropy bytes; original input and row objects are not encoded into
bounded byte fields.

| Event | Meaning |
| --- | --- |
| 0 | Initialize a fresh zeroed state with immutable operation and input-identity bindings. Original direct Python object contents retain their original mutability. |
| 2 | Consume the exact next effect token before an effect may begin. |
| 3 | Accept only the matching effect outcome and exact row/byte observations. |
| 4 | Accept the matching native namespace commit certificate for direct lease mutation. |
| 5 | Record a known validator refusal or, for direct operations, a returned foreign exception with a matching native receipt. An unconfirmed outcome cannot restore a consumed claim. |
| 90 | Validate and copy retained native state for observation only. |

Phases distinguish ready, pending effect, staged transaction result, confirmed
completion, known refusal and unknown outcome. Sequence and generation/epoch
exhaustion refuse instead of wrapping. A checksum covers the entire canonical
header and captured byte extent, including direct handle identities. It does
not hash mutable Python object contents. It detects accidental corruption; it is not a
security boundary against malicious code in the same process recomputing it.

The adapter roots `LedgerState` in `NativeSlotLedgerStore.pending` before native
initialization or any external effect. That object retains the native buffer,
last confirmed Python receipt, cursor, returned value, original exception and
connection/scope binding. If native state advances but receipt assignment is
interrupted, the old receipt cannot authorize replay: the retained pending owner
and native sequence still prevent a new operation. Even loss of a later Python
fence diagnostic does not clear that pending owner.

## Transaction ownership and uncertain results

Adoption and rollback require the exact native request `_EffectConnection`
class, same Store, original process/thread and currently active callback token.
The request capability permits only the fixed existing SQL aliases plus the
identity-bound conditional slot update. A capability from another Store, a
subclass, a revoked callback or a replay-only response cannot become writable
by substituting the official connection. Ledger code never commits or rolls
back a borrowed request transaction.

Direct acquire/release use the same official Store connection under the shared
Store lock and the native namespace's legacy transaction owner. After the
transaction context returns, the ledger reads the retained native namespace
state and requires exact owner, epoch and nonce; idle phase/action; no pending
effect, error or forced rollback; no consumed rollback for this epoch; and a
nonzero sequence. A false `db.in_transaction`, an equal current row or a Python
COMMIT return value alone is not this certificate.

Unknown SQL effects, native acknowledgements, result handoffs and COMMIT outcomes
raise `SlotLedgerUnknown`, which is outside the terminal service rejection
formatter. The connection's existing transaction owner alone decides cleanup.
The ledger preserves the pending operation and forbids implicit retry. A lost
COMMIT ACK can therefore leave a durable active lease row while issuing no lease
to the caller. This is observable custody, not a fabricated successful result.

Request-only uncertainty does not suppress an independent advisory slot read
on the official connection. It still fences every mutation. Namespace or ledger
uncertainty fences their dependent operations. Reentrant calls during one ledger
operation refuse without replacing the outer state. The lock is released before
an admitted invocation starts its child; release may proceed while that child is
in flight, and future admission sees the inactive lease.

## Tool profile and the frozen direct-domain failure

The tool catalog's `target_slot` pattern permits 1..192 ASCII characters. The
original authorized local `inspect_slot` and `acquire_slot` methods do not pass
through that schema: they pass the original argument directly to SQLite. The
frozen `69e97bbc` HIA profile accepts text up to 192 **UTF-8 bytes**, including
empty text, embedded NUL and non-ASCII text within that byte extent. It does not
enforce the tool pattern. These two domains must not be conflated.

Within the bounded tool protocol, generated context and lease identifiers fit
the corresponding retained fields. Artifact references
must be the exact canonical three-field issued form, with lowercase hex and
independent identifier/URI UUIDs. Integer row values must be canonical unsigned
decimal within u64. Corrupt rows, manually fabricated wider identifiers and
arbitrary private-helper inputs are not silently coerced into public values.
The revised direct consumer protocol does not apply those field limits or extra
row canonicalization to the original SQLite/Python API. The observed narrowing
below was a blocker to default replacement in frozen `69e97bbc`, not a missing
optional test. Its repair does not qualify the unrelated remaining whole stack.

An actual comparison on the immutable `69e97bbc` source observed:

| Direct input | Original `inspect_slot` | Selected `inspect_slot` |
| --- | --- | --- |
| 192 ASCII bytes | Returns advisory snapshot | Returns advisory snapshot |
| 193 ASCII bytes | Returns advisory snapshot | Rejects `E_HIA_SLOT` |
| 64 `雪` characters, 192 UTF-8 bytes | Returns advisory snapshot | Returns advisory snapshot |
| 65 `雪` characters, 195 UTF-8 bytes | Returns advisory snapshot | Rejects `E_HIA_SLOT` |
| Empty text or embedded NUL | Returns advisory snapshot | Returns advisory snapshot |
| SQLite-bindable integer `7` or `None` | Returns advisory snapshot | Rejects `E_HIA_SLOT` |

A stronger control built and admitted a real native image, then explicitly
seeded a retained 193-byte slot row in its isolated fixture. The original API
acquired its lease and the real child returned `[1]` for input `[250]`. The
selected owner rejected inspection/acquisition and rejected invocation/release
of that valid retained lease; its row remained active. The original release then
completed. The foreign image checker was not stubbed. This demonstrates a real
retained-state compatibility gap, not just a diagnostic difference on an absent
row. Neither the fixture row nor this observation is claimed to have passed the
public tool catalog's schema.

The follow-up requirements were to retain original SQLite-bindable arguments without coercion or
cached adaptation, preserve TEXT affinity and original binding/comparison/error
order, support the complete original text extent without a new arbitrary cap,
and keep HIA responsible for operation/effect/transaction decisions. Changing
192 to another fixed ceiling or falling back to old ledger policy does not close
the gap. Frozen `69e97bbc` development results remain unchanged evidence.

SQLite execution, Python object/UTF-8 transport, OS entropy, existing semantic
evidence/native-image validation and subprocess execution remain foreign
adapters or separate owners. Native byte publication supplies ABI hashing;
there is no selected Python hash fallback. No extra database, durable journal,
lease history, garbage collector or live-service migration is introduced.

## Development observations and remaining qualification

The first actual development machine/source suite passed 19 tests under genuine
Python 3.13.5, including eight independent source/VM controls and eleven native
machine/SQLite controls. The default Python 3.12 run remains a recorded failure:
that interpreter lacks the required `fcntl.F_ADD_SEALS` constant and the real
byte publisher refused before ledger SQL. No seal shim or weakened admission
was introduced. The local dependency versions were Z3 4.15.4 and jsonschema
4.26.0; remote pinned prerequisites are recorded separately, not called identical.

The first original 48-test selected end-to-end run recorded 45 passes and three
time-limit failures: two fixture preparations exhausted the unchanged 3000 ms
context budget before the second emission, and the 1 ms native-timeout case
returned later than its unchanged five-second outer assertion. These original
failures remain evidence. A same-host comparison reproduced all three failures
with the selected ledger, with the same source and the ledger deselected, and
with the unchanged `5d5424a3` baseline and its own source-bound native dependency
builds. The three selected-ledger controls invoked no ledger operation. This
locates the observed failures outside new ledger operation execution; it does
not qualify those failed time limits. Installed-wheel custody and real concurrent
invoke/release controls are recorded separately. No successful rerun erases an
earlier failure.

Three additional controls passed on the unchanged `69e97bbc` development export
under Python 3.13.5: wrong owner/corrupt row/sequence exhaustion, actual installed
wheel operation with no authoring imports and changed-source refusal, and two
real concurrent invocations finishing after lease release. They ran in 29.187
seconds with zero failures, errors or skips. The separate eight-case direct-domain
observation and actual long-slot child completed in 13.454 seconds and confirmed
the blocker above. Passing the supported-profile controls does not override it.

The suite contains source/VM tests, actual machine protocol controls, same-WAL
transactions with original policies poisoned, source/image drift refusal,
installed package-only operation, all original 48 callers, and real concurrent
invocations surviving release. Final integration still requires the exact union
source contract, a fresh matching-source cold build and the full zero-skip
regression. Test receipts, not this document, report the precise executed scope
and outcomes of each immutable development or qualification run.

## Original direct object transport revision and development evidence

The `84d13f08` documentation checkpoint did not close every direct-object
lifetime. A subsequent preserved actual-machine witness found that a temporary
comparison result's `__del__` ran too late because the original registry kept
every returned object. Its false truth value followed by a destructor changing
the caller's generation made original `release_slot` reject `E_HIA_LEASE` and
retain the active row, while that native revision incorrectly released it.
The 20 machine and nine VM/source passes below remain their exact scoped
results; they do not supersede this additional failure or prove full API parity.

The follow-up source adds HIA operations 8–11 for direct snapshot, acquisition,
lease admission and release. Existing bounded tool/adopt/rollback protocols are
retained. Each operation roots its original Python argument in an opaque object
registry before native initialization. HIA allocates the subsequent result
handles, binds them to the operation nonce and original connection/transaction,
and owns every branch, refusal, effect preclaim and terminal/commit transition.
Handle capacity bounds this finite operation protocol; it does not impose a
length or type ceiling on a SQLite parameter or returned row field.

The fixed bridge passes the same original object at each original SQL binding.
It does not call `str`, JSON serialization or `sqlite3.adapt` ahead of SQLite.
The original three snapshot bindings and fourth acquisition binding therefore
retain stateful `__conform__` behavior. Lease field lookup occurs after the ID
query and at the original comparison positions. Python inequality and truth
conversion are separate foreign primitives with separate HIA claims. The two
successful artifact decodes remain in their original positions. HIA controls
whether the next primitive is admitted; the bridge never performs the complete
old lease-admission predicate.

Direct acquisition deliberately returns the caller's original target object.
SQLite TEXT affinity may store a different value; the original API could return
a lease whose original target does not compare equal to that stored value.
The revision preserves that behavior instead of silently canonicalizing it.
Release uses the newly retained row ID and the original single UPDATE statement.
No extra binding of caller objects is introduced for a new readback. The lease
dictionary itself never grants execution: each invocation performs fresh native
admission against the actual retained row. SQL exceptions confirmed by a matching
native outcome retain their original exception object; interrupted or lost
outcomes remain fenced and are never implicitly retried.

For example, a process-global custom string adapter can bind the ID normally
during lease admission and select no row at the UPDATE binding. The original
direct API then returns `released=True` with the row still active. The revision
preserves that original observable behavior; it does not secretly add a rowcount
predicate or a second adaptation/readback. Arbitrary Python adapter behavior is
a foreign primitive, not a security boundary against hostile code in the same
process. Ordinary bindings retain the normal future-admission revocation.

The version-2 state keeps the next object handle in word 20, observed row/version
handles in 22–23, snapshot field handles in 24–28, retained lease field handles
in 29–32, temporary/cursor handles in 33–35, launch/mutation claim counts in
36–37, result shape in 40 and namespace certificate sequence in 41. Scope-owner
identity remains in 43–44, extent in 55 and checksum in 63. A result handle must
be exactly the next native allocation; stale or substituted outcomes do not
advance state. The registry is strongly rooted before any admitted foreign
operation. Interruption before storing a returned comparison cannot clear its
preclaim or drop the original input's custody.

### Follow-up native lifetime protocol

The follow-up direct state is version 3. Word 21 records issued live handles;
word 45 records the exact handles the next native action may consume. A
matching effect preclaim is required before any transfer. Successful and
confirmed exceptional outcomes consume that mask and clear every native field
aliasing those handles. No second preclaim is admitted while an outcome is
pending. The fixed operation allocates fewer than 64 handles, independent of
the size or type of any caller value; the 64-bit mask adds no input ceiling.

Fixed bridge expressions move preclaimed temporary operands directly out of
the registry. A conditional inequality keeps rich comparison, operand release
and truth conversion in one CPython conditional expression. HIA still chooses
each individual field and performs the original short circuit between fields;
there is no hosted copy of the whole lease predicate. Cursor, SQL parameter,
set, wire and decode temporaries use the same move boundary. Unused checker and
SQL cursor returns are discarded at their original expression boundary, and
HIA emits an explicit preclaim to release completed snapshot/lease row scopes.
The extra `returned` transport reference is cleared only after its result is
rooted in the registry or represented by an immutable scalar payload.

Completed-owner diagnostics retain native bytes and binding identity, without
retaining the operation's foreign-object registry or exception traceback.
An interrupted move, scope release or acknowledgement instead keeps the
original pending owner and its remaining actual references fenced; it never
recreates a consumed handle, repeats the primitive or treats missing Python
state as confirmation. Lifecycle qualification for this follow-up is reported
separately from the frozen version-2 successes and failure above.

Product checkpoint `fb6348a1` and test-only correction/controls `6e3e79ae` were
tested from a separate immutable development export. Its before-tree is
`5c2c539dd4fdbe8cabed21219c83ee1ce1d4c96c`; after adding the five declared owner
contract paths in the development export only, its tested tree is
`941a2bb8896c54eb1cd97fc0a3215de8b1266f3f`.

- All 20 actual machine controls passed, with zero failures, errors or skips,
  in 95.279 seconds under genuine Python 3.13.5. They include 16 SQLite binding
  domain/error cases, unchanged repeated stateful adaptation, original rich
  comparison/truth/field-read order, exact foreign exception identity, the
  zero-row legacy UPDATE behavior, and a 65,550-byte retained slot with real
  old-lease/new-lease native invocation and release. No foreign image-checker
  or child-runner stub was used for that long-slot lifecycle.
- Actual opcode interruption after comparison return retains the original
  opaque object through garbage collection and refuses replay. Existing lost
  SQL/native/COMMIT acknowledgement, request atomicity/CAS/restart, source drift,
  installed wheel and concurrent invocation/release controls also passed.
- All nine independent source/VM controls passed in 261.177 seconds, with zero
  failures, errors or skips. They execute both bounded and direct HIA protocols.
  Both runs rechecked the exact source manifest after completion.
- The first direct revision's 18-test run remains a failure: 17 passed and one
  old INSERT fault-test assertion still expected action 14 instead of the new
  direct INSERT action 124. The test-only correction binds that original fault
  assertion to the actual new action; its original failed log is preserved.

The actual HIA source SHA-256 is
`92fbfd240dca5093b10544b5dbea4f40120dd353e9b6f216730f9df9499a21d1`;
the generated image SHA-256 is
`d599088b2eff28edb42d678161c032688c75cf76b49ae49526d126e6ba49f3e4`.
The runs reuse the explicitly recorded predecessor compiler and do not grant
matching-source cold qualification. The final documentation commit changes no
product or test code. Original 48-test caller qualification still belongs to
the exact integrated source and original deadlines.

The frozen `69e97bbc` remote r4 run separately recorded 22/23 outer passes and
45/48 old caller passes: two failures and one error, zero skips, source unchanged.
One fixture exhausted its unchanged budget during encoding; another reached its
test callback after its original context deadline, whose assertion became a
retained `RequestJournalUnknown`. The third expected `budget_exceeded` from the
direct child runner but observed `faulted`; the original log did not capture the
child's full report. That separate unresolved observation must not be relabeled
as a timing-only failure or as a pass by these direct-ledger controls.

### Version-3 lifetime development result

Product/test checkpoint `666818720ba9995cb96168bd6c8ef446f6f2b5da`
has tree `97490f93c84533310f592e748c9b9c399b112039`. The separate development
export added the same five owner paths to its contract, producing tested tree
`ec27de423e7b8c5b6e95a88685225b5f814a5507`; all 2,962 exported source files
were unchanged after execution. No root contract or original export was edited.

All 24 scoped actual-machine controls passed with zero failures, errors or skips
in 127.897 seconds. All nine independent source/VM controls passed with zero
failures, errors or skips in 287.516 seconds. The new controls cover temporary
comparison destructors before each following field read, a self-removing
comparison operand whose destructor precedes truth conversion, an adapted SQL
ID whose destructor changes later lease fields, an unused image-checker return
whose destructor changes the fourth slot binding, and collection of completed
inputs without a permanent diagnostic root. An actual `take` RETURN_VALUE
interruption leaves both already-consumed handles absent, its native claim
pending, the original input rooted and the row active; a later call emits no
comparison or mutation. The retained long-slot, real child, source-drift,
installed-wheel, transaction and concurrent-invocation controls also passed.

The exact original temporary-result witness was additionally replayed without
editing its script. Both original and selected-native public `release_slot`
now record `compare`, `truth`, `truth-finalized`, reject `E_HIA_LEASE` and retain
the active row. The earlier version-2 failure remains a separate immutable
observation. This repeat is a direct before/after witness, not a replacement
for the separately recorded 24-test and nine-test runs.

The tested source is 226,969 bytes with 61 functions, 1,135 total blocks,
82 blocks per function at most, 3,537 total instructions, 37 instructions in
one block at most, eight block parameters at most and seven function parameters
at most. The original limits remain 128 functions, 1,536 total blocks, 256
blocks per function, 8,192 instructions and 16 parameters. The actual source
SHA-256 is `6c964438433ade22db1e3ba25758e7937e889a77fd27d6f4effbe936351441c2`;
the actual image SHA-256 is
`742596671cf73dedbf3f5c8b12345fc255e9d884b0958b0120bc696833e2c782`.

These are explicitly development results using predecessor compiler
`0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8`,
genuine Python 3.13.5, Z3 4.15.4.0 and jsonschema 4.26.0. They do not claim the
remote/CI jsonschema 4.25.1 environment, matching-source cold qualification,
the original 48-test caller gate or whole-stack/default replacement. The
subsequent evidence-only documentation commit does not change product bytes.
