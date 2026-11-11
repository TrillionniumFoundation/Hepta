# Native slot, generation and lease ledger

Status: explicitly selected development owner with a confirmed direct-API domain
gap. It is not an equivalent replacement for every original direct slot/lease
input. Integration and matching-source cold/full qualification are separate
gates. The independent
reference baseline is Hepta `63fa2e7351c6b7e787e3834cbdbfe2307a08d872`.

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
- Release marks the lease inactive for future admission. It neither drains nor
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
| `acquire_slot` | Observe active generation, validate the native image, obtain OS entropy, format the UUID in HIA, insert and exactly read back an active lease, then require the native namespace's confirmed commit certificate. |
| `_lease` / `invoke_lease` | Admit the exact active retained row and produce a detached lease value. The unchanged invocation body freezes arguments/metadata and runs the existing child outside the ledger lock. |
| `release_slot` | Admit the exact active row, update that same identity to inactive, read it back, then require the confirmed namespace epoch. |

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

| Event | Meaning |
| --- | --- |
| 0 | Initialize a fresh zeroed retained state with immutable operation inputs. |
| 2 | Consume the exact next effect token before an effect may begin. |
| 3 | Accept only the matching effect outcome and exact row/byte observations. |
| 4 | Accept the matching native namespace commit certificate for direct lease mutation. |
| 5 | Record the known foreign image-validator refusal, or an unconfirmed outcome, without restoring a consumed claim. |
| 90 | Validate and copy retained native state for observation only. |

Phases distinguish ready, pending effect, staged transaction result, confirmed
completion, known refusal and unknown outcome. Sequence and generation/epoch
exhaustion refuse instead of wrapping. A checksum covers the entire canonical
header and captured byte extent. It detects accidental corruption; it is not a
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

## Supported profile and explicit limits

The tool catalog's `target_slot` pattern permits 1..192 ASCII characters. The
original authorized local `inspect_slot` and `acquire_slot` methods do not pass
through that schema: they pass the original argument directly to SQLite. The
selected HIA profile currently accepts text up to 192 **UTF-8 bytes**, including
empty text, embedded NUL and non-ASCII text within that byte extent. It does not
enforce the tool pattern. These two domains must not be conflated.

Generated context and lease identifiers fit the corresponding retained fields. Artifact references
must be the exact canonical three-field issued form, with lowercase hex and
independent identifier/URI UUIDs. Integer row values must be canonical unsigned
decimal within u64. Corrupt rows, manually fabricated wider identifiers and
arbitrary private-helper inputs are not silently coerced into public values.
This is not a claim of parity for every manually edited SQLite database, and the
observed direct-input narrowing below is a blocker to default replacement and
whole-stack closure. It cannot be dismissed as a missing optional test.

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

The follow-up must retain original SQLite-bindable arguments without coercion or
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
