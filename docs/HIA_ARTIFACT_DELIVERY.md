# Artifact provider delivery and resource custody

This candidate starts at `5da589f0bf6444c2c0acd95e2ba778c7e4ae1cfd`
(`c612c8795f59d1726ef404b5e9d678c69869ad87`). The original four public
arguments, six operations, filesystem sequence, exact-byte policy, SHA,
stdout, public stderr and public exit codes remain the reference contract.
The original 63 direct methods and Store caller gates are retained. The
complete additional NDU bridge 19, assembly 18 and native-tools 32 methods
make a separate unchanged 132-method provider caller inventory. The candidate
later advances without conflicts to `5bf69586b890706290c5fbfe93065ec0d3af40b1`;
those intervening metadata and source-classification fixes do not change the
frozen original provider bodies. This document describes the candidate
protocol; it is not execution qualification.

## Separate private entry

The normal executable still starts at `_start`. A second entry,
`_delivery_start`, is named by the `HIADELIV` ELF note. The note is inside the
same source-manifest-bound executable. No argv value, argv0, environment entry
or stdin payload selects it. A formerly invalid public operation remains
invalid. Copying or invoking the normal executable uses the ordinary public
entry and emits no control bytes on stderr.

The hosted custody bridge admits the original immutable executable with the
existing whole executable SHA and source manifest. Admission derives one
fixed private executable by changing exactly the ELF `e_entry` word at byte
24, after validating the complete note and all three program headers. It
does not vary with the call, nonce, ContextVar or observer. `_admitted_code`
and `_StoreAdmission` return those fixed bytes, and the sealed executable is
exactly equal to them. The build receipt binds both public and private SHA.
The original public file is unchanged. These fixed admitted bytes undergo
the original complete writes, kernel seals, extent and actual sealed-readback
checks. There remains exactly one executable descriptor in `pass_fds` and
exactly four arguments. No environment or argv control marker is added.

Only the separate private entry consumes a fixed 16-byte nonce prefix, then
passes all remaining stdin bytes to the original policy unchanged. It reads
the complete prefix before original admission or any artifact effect. A
short prefix cannot produce a confirmed ACK. A changed nonce is rejected by
the caller's exact nonce comparison. Public `_start` never recognizes this
prefix: every original payload, including one beginning with these bytes,
remains ordinary payload. The private ABI adds no payload quota.

The first unexecuted draft changed the sealed nonce bytes on every call. It
was rejected during static review because the original
`NativeLifecycleTests.test_tool_object_emission_needs_no_llvm_import_or_external_process`
requires the sealed bytes to equal `_admitted_code(selector)` exactly. The
stable admission design preserves that original assertion without changing
the test or making admission depend on its observer.

The ELF prefix grows from 176 to 352 bytes. The packer still writes its actual
load extent at bytes 96 and 104 and relocates the same three existing calls.
The extra program header is `PT_NOTE`, not a dynamic loader or interpreter.
Only the build-time fixed adapter assembly, the existing HIA policy and the
existing HIA SHA image execute in the native application.

Direct calls to the private Python `_execute_native` without an explicit
public invocation context retain their original sealed-descriptor test
surface and the fixed public entry's original stdin/bytes result. This is an
explicit direct API, never an error fallback. Canonical selected public calls
always claim a private invocation
and cannot fall back to this unacknowledged path. An absent private note is
rejected before any child starts. Its error is deferred through the original
seal/readback checks so existing real seal-fault first errors remain intact.
Manifests made by the original retained manual build fixtures still bind the
new explicit note through their complete public-image SHA and exact current
source set. A pre-capability manifest/source/image or absent note is not
interpreted as an acknowledged image. If either new public/private SHA field
is present, both must match the actual fixed bytes.

The public invocation's causal activation covers argument evaluation, but
its one-use protocol token is armed only after the final original argument
has been evaluated. The canonical `_execute_native` call also receives the
exact required invocation identity. It consumes and removes that token before
imports or admission. A root `__fspath__` that re-enters the old direct helper
therefore cannot steal the outer token. A canonical call with a missing or
wrong token refuses instead of executing the public direct entry. No stack
inspection or restriction of the original path/object domain is introduced.

## Fixed 128-byte acknowledgement

All fields are little-endian unsigned 64-bit words. The private entry writes
exactly one complete frame on stderr, after the original stdout operation.
The public entry continues to leave stderr empty. A truncated, extra, corrupt,
wrong-nonce, signal-exit or code-mismatched frame cannot confirm delivery.

| Byte offset | Field |
| --- | --- |
| 0 | `HIAPDLV1` magic |
| 8 | Version 1 |
| 16, 24 | Per-invocation 128-bit nonce |
| 32 | Actual admitted operation: 0 before admission, 1 publish, 2 verify, 3 withdraw, 4 store-put, 5 store-get, 6 store-hash |
| 40 | HIA disposition: 1 returned, 2 confirmed refusal, 3 unconfirmed |
| 48 | Original native exit code, checked against the actual child |
| 56 | Last adapter stage |
| 64 | Original HIA input/artifact byte count |
| 72 | Bytes actually accepted by stdout writes |
| 80 | Actual effect/cleanup facts, defined below |
| 88 | First refusal stage |
| 96 | Last cleanup stage |
| 104, 112 | First 128 bits of HIA SHA-256 over bytes 0 through 103 |
| 120 | `HIAPEND1` end marker |

The existing HIA SHA image seals the control fields, nonce and disposition.
The hosted checksum validates only this small transport frame, never artifact
payload bytes. The hosted bridge also runs the original public
JSON/shape/length checks. The HIA `delivery_terminal` function chooses the
disposition and formats the entire frame. A returned control frame remains
pending until the original public receipt passes. A confirmed negative frame
is confirmed before the unchanged `PublicationRejected` is raised. An error
after that confirmed terminal does not retroactively become a native loss.

## Stages and effect facts

| Stage | Actual boundary recorded |
| --- | --- |
| 0 | Process setup, argc, private prefix or initial mmap |
| 1 | Original argument/getcwd admission |
| 2 | Expected stdin acquisition |
| 3 | Original exact file verification |
| 4 | Generic no-replace link |
| 5 | HIA streaming SHA |
| 6 | Store root/random preparation |
| 7 | Store temporary creation |
| 8 | Temporary inode identity capture |
| 9 | Temporary file write |
| 10 | File fsync |
| 11 | Temporary post-write verification |
| 12 | Store no-replace link |
| 13 | Post-link verification |
| 14 | Directory fsync |
| 15 | Temporary cleanup |
| 16 | Store content-link cleanup |
| 17 | Generic link cleanup |
| 18 | Original conditional withdrawal |
| 19 | Original stdout delivery |

Facts are observations of the original syscalls and existing HIA comparisons;
they do not introduce new filesystem reads, deletes, retries or policy.

| Bit | Fact |
| --- | --- |
| 0 | This invocation created its temporary entry |
| 1 | Its temporary inode identity was captured |
| 2 | Temporary entry removal/absence was confirmed |
| 3 | Temporary cleanup remains unconfirmed |
| 4 | This invocation created the content/publication link |
| 5 | Its own link removal/absence was confirmed |
| 6 | Existing identity policy observed a competing link |
| 7 | Link cleanup remains unconfirmed |
| 8 | Original directory-fsync refusal permits a possible immutable content file |
| 9 | Original stdout delivery started |
| 10 | All original stdout bytes were accepted |
| 11 | HIA SHA/receipt preparation refused |
| 12 | Captured temporary identity no longer owns the temporary name |
| 13 | A mutating create/link syscall reported EINTR before its original retry |
| 14 | The separate private entry consumed its complete 16-byte prefix |

## Terminal matrix

| Original observation | Private terminal disposition |
| --- | --- |
| Original success, admitted operation and complete stdout | Returned; public receipt validation is still required |
| Refusal before publication/temporary creation | Confirmed refusal with the original code |
| Post-link refusal and confirmed own-link absence/removal | Confirmed refusal with the original code |
| Post-link refusal and original identity check finds a competing entry | Confirmed refusal; no authority to delete the competitor |
| File-fsync refusal and confirmed temporary cleanup | Confirmed refusal; no content issuance |
| Directory-fsync refusal and confirmed temporary cleanup | Confirmed refusal; preserve the original permitted immutable content residue and no issuance |
| Created temporary has no captured identity and cleanup ownership cannot be established | Unconfirmed |
| Original cleanup stat/unlink fails without confirming its disposition | Unconfirmed |
| Publication remains after an unconfirmed receipt/gate failure | Unconfirmed |
| Original stdout write starts and fails/short delivery remains | Unconfirmed, including exit 15 with zero delivered bytes |
| A mutating EINTR leaves a negative outcome without a complete successful observation | Unconfirmed |
| Missing/corrupt control frame, lost child result or mismatched actual exit | Unconfirmed in the hosted transport |
| Private prefix is short, its nonce changes, or control SHA is incomplete/incorrect | Unconfirmed; no code-only inference or retry |

The original public CLI still reports its original result in every row. The
private provider now distinguishes acknowledged original refusal from actual
undelivered effect/output. In particular, neither 15 nor 16 alone decides
confirmation. A complete negative acknowledgement does not claim rollback,
absence of an allowed immutable content file, or permission to retry.

## Exact resource lifetime

The shared delivery record can associate an already obtained Store object by
identity. It inherits only explicit resource scopes and real live foreign
ancestors. It never reads an arbitrary owner to guess a Store, DB or lock.
Unknown custody retains the actual object, so object-id reuse or reconstruction
of the same path cannot reassign a loss. Healthy bindings use weak references.

Store construction binds its lifetime without touching new Store attributes.
The selected lifecycle/artifact Frames explicitly associate their existing
Store argument. Original unselected public artifact routes enter an explicit
Store resource scope. A later `Store.close` checks this exact Store after its
existing lifecycle guard and before the original budget/SQLite cleanup. The
worker's original `finally: service.close()` order remains in place; there is
no process-wide skip-cleanup flag and unrelated resources remain closable.

`DeliveryRecord.check` rechecks the exact explicitly associated objects at
each effect/terminal guard. A loss newly recorded in another Context/thread
is resource evidence; it does not invent cross-thread native ancestry.
Normal foreign exceptions and an exception merely named Unknown create no
loss. Original MemoryError/RuntimeError/process-control identities are kept;
only the original request-rejection families are normalized after actual
recorded loss.

For a separately implemented suspended transaction, `resource_scope` has an
identity-only `deactivate()` operation. It never resets another Context's
token or rewrites a native record's creator. A pre-reserved
`reserve_resource_observation(owner, store)` token records the body outcome
before allocating the new actual advance. It is confirmed only by that
advance's complete HIA receipt and is not a reused native handoff. The
transaction owner remains a separate implementation and qualification.

## Explicit installed worker capsule

The `hepta.hia.native-helpers.v4` capsule binds an exact existing v1 helper
bundle and one exact artifact application manifest. Its ABI is
`hia-worker-artifact-delivery-v1`. This external executable has a distinct
entry and acknowledgement protocol and is never registered as a six-argument
helper. The administrator supplies both the capsule path and its SHA through
the original worker flags. Unselected and older helper scopes cannot borrow
the artifact selector, a code owner from another scope, or an unregistered
path or factory.

Admission captures the fixed public and private application bytes. Every
subsequent public artifact call, including a call-local Store admission,
repeats the complete original current-source admission. Installed admission
also checks the full production module inventory, including additions and
deletions, and every owned source asset. The same check participates in the
normal worker terminal identity check. Captured bytes and old path metadata
are never substituted for that complete scan. Scope exit restores selectors;
it does not claim a terminal scan occurred after every exceptional exit.

The new installed control builds a fresh wheel, verifies unique members and
its complete RECORD, then runs the original worker in an isolated child with
authoring imports and the selected retained Store/context/journal policy
forbidden. Store profile, context, journal and the private artifact provider
have separate startup, request and cleanup counters. The worker control
observes successful receipt, missing process ACK, actual nested context loss
that is swallowed or replaced, and process exit after durable file creation.
The unchanged durable running intent refuses replay; startup entries are
reported separately from zero request-level publication on replay. Later
close is observed at the actual frozen Store close alias, not an unused class
attribute. This control does not select the separate lifecycle image.

Fresh-scope controls cover an added, deleted or changed installed module,
changed manifest/image, wrong factory/path, actual other thread/process, and
an owner used after its scope ends. Installed source drift adds exactly one
LF and restores the bytes in `finally`. Old v2/v3 checks exercise their exact
existing registry lookup boundary; these tests do not claim to construct or
qualify their complete scheduling/report executable profiles.

## Original source provenance and validation scope

The original c019 D4 fixture remains byte-identical. D5 and the independent
transaction require an explicit successor composition for exactly five
files: the publication bridge, Store dispatcher, lifecycle selection,
shared delivery module and lifecycle adapter. Each reviewed successor binds
the original whole-file SHA, exact reversible byte changes and a fixed new
whole-file SHA. Admission accepts either the complete old baseline or the
complete reviewed new composition, never a partial reversion. The other 86
whole-file pins, other 20 shared pins and all 21 original definitions retain
their original checks. The original D4 test methods and budgets are unchanged;
its provenance helper is deliberately extended and is not described as
byte-identical. A draft composition cannot grant formal admission.

The original bridge accepts a `str` subclass for an operation. Its `__ne__`
can cause the original `withdraw` bridge to send nonempty input, while the
native withdrawal still consumes zero input bytes. The private ACK therefore
reports zero, not the length sent. `ArtifactInvocation.returned` uses only the
already-decoded integer operation to check this count: withdrawal is zero,
store-get is the observed stdout length, and other successful operations use
the sent payload length. This adds no comparison of the user's operation
object. Five separately frozen original observations and their actual-image
controls cover the discovered case and adjacent accepted/refused cases; the
existing 96 bridge cases and 44 terminal cases are unchanged.

`ArtifactDeliverySourceTests` contains three source/independent-oracle
methods. `ArtifactDeliveryNativeTests` contains eight complete real-image
controls. Its only fixture selectors are
`HEPTA_HIA_ARTIFACT_DELIVERY_COLD_REPORT` or the explicit development compiler
variable `HEPTA_HIA_ARTIFACT_DELIVERY_DEVELOPMENT_COMPILER`; exactly one must
be nonempty. `HEPTA_HIA_ARTIFACT_DELIVERY_EVIDENCE` names an exclusive evidence
directory. The formal application builder still requires a matching current
cold report. Test-only development compilation is clearly recorded and
cannot satisfy that formal admission. The new controls do not replace the
original 132 provider methods, original Store 130 methods, or the original
delivery and transaction gates.

## Explicit limits

Build/code admission, kernel process and descriptor transport, SQLite,
opaque Python object protocols and OS failures remain foreign providers.
This protocol does not introspect arbitrary provider internals or protect
direct raw connection closes performed outside the owned Store API. Generic
publication has no new artifact-size limit. The Agent byte layer retains
its original 64 MiB quota. No original wall deadline, VM budget, test method,
skip rule or assertion is widened. Whole-stack closure and deletion of the
remaining reference providers remain unqualified.
