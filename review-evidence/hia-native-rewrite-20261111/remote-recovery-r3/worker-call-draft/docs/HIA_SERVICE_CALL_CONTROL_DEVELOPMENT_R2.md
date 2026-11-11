# Selected service-call controller: development ABI r2

This is new, unexecuted HIA authoring. No HIA generation, bounded B3 compile, native entry, namespace effect, complete Worker invocation or installed dispatch has passed for this controller. The previously completed records component and current journal-bridge CI remain separate. The source implements the complete selected call control flow; its pending native peer implementations must be connected and independently exercised before ordinary routing can change.

Reference: exact 0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5, hepta/hia_agent_journal_native.py:call_with_native_journal and the original service, store and contract sources. Body source r4 follows three unexecuted drafts. r3 moves request_id decoding to its original main-scope point after successful prepare. r4 additionally preserves the original INSERT tuple order: key and digest properties precede the realtime clock. Earlier drafts are not test evidence.

## Ownership and boundary

The controller owns ordering, branches, native_step error classification, transaction unwind, cached early return, response assignment and finally writes. It emits fixed typed native peer invocations. A host may not interpret a semantic plan, manufacture peer results, choose a business branch, emulate Graph operations or perform an old Python fallback. A development fixture that supplies peer results proves only this component's orchestration, never namespace/business completion.

The independent HIA peer must own each semantic operation in the table below. Several are still pending: complete tool schema reconstruction, cached general-data materialization, high-level namespace, context/budget and business services. The original eleven business operations are all dispatched through their exact journal tool IDs 1..11. Resource-read alias 12 becomes read 3 before validation and does not run LOOKUP a second time. No smaller language, new value/node quota, clock clamp or host schema dispatch is introduced.

Every value field is an issued private lease, never a raw Graph node ID treated as storage authority. The fixed native coordinator owns the session registry, actual source/image binding, output extents and lifetime. Headers provide correlation only; matching nonce or shape does not authenticate an external replacement. Original immutable input leases must remain held. Namespace row/cursor receipts must preserve generation, all storage classes and full-row materialization.

## RWW frames and lifecycle

The first read buffer is an exactly 64-byte private context frame:
HIASCS01, invocationLease, callSequence, sourceEpoch, 0,0,0,0.
The second argument is borrowed read-only and is exactly 256 bytes. Initial HIASCC01 is:
magic, invocationLease, callSequence, selectedProfiles, integerDigits,
toolValueLease, argumentValueLease, catalogValueLease, toolSchemaCatalogLease,
installationIdentitiesLease, namespaceSessionLease, installationOwnerLease,
sourceEpoch, followed by 19 zero words.

All initial value/session handles are nonzero issued leases; JSON null is a value with its own nonzero handle. Zero is used only where the explicitly defined operation permits an absent value or an exact empty byte view. The original selected profile and integer-conversion limit are forwarded unchanged, not inferred from the raw program integer decoder. The initial 4096-byte workspace is zero. It contains only finite control metadata; peer Graph, bytes, arbitrary decimal clocks and error values keep their own existing bounds or growable storage. This control workspace is not a new input quota.

A successful native entry returns 512, ending a 32-word event at workspace offset 256. Fields:
magic HIASCE01; action; invocationLease; callSequence; eventSequence; resumePhase;
peerOperation; errorScope; six operation arguments;
returnValueLease; exceptionClass; exceptionValueLease; journalSessionLease;
toolID; contextIDLease; assignedResponseLease; transactionKind; nativeFailed;
selectedProfiles; integerDigits; sourceEpoch; mainTryEntered; protocolReason;
four zero words.

Action 1 requests exactly one peer operation. Action 0 returns the value lease.
Action 2 propagates the exact issued exception. Action 3 accompanies private
BAD=0xfffffffd. Every BAD immediately retires the invocation, even if a short
workspace could not store poison or event-sequence overflow left an old event.
A terminal invocation rejects later entries. No automatic retry is added.

The 256-byte HIASCA01 reply is:
magic, invocationLease, callSequence, previousEventSequence, exactPeerOperation,
failure(0/1), exceptionClass, exceptionValueLease,
16 result words, eight reserved zero words.
Successful replies have zero exception fields. Failed replies have a nonzero
issued exception class/value and zero result words. Each successful operation
has a fixed result count; the remainder is zero. A mutated/replayed/wrong-peer
reply is a private protocol refusal, not an ordinary business error.

Journal session identity remains a stable issued lease across growth and
semantic errors. Its internal state can change before cached-value conversion
fails; such a failure must not roll back that state. Temporary views expire
according to their actual owner. The coordinator retains or freezes a borrowed
value before any next call that may replace it.

## Complete peer table

The six request arguments are listed in the HIA source at each issue point.
These names define complete native semantics, not permission to call the old
Python methods.

| ID | Native operation | Result count |
|---:|---|---:|
| 1 | Actual monotonic nanoseconds, arbitrary integer value lease | 1 |
| 2 | Actual UUID entropy / UUID value | 1 |
| 3 | Exact unadmitted- plus lowercase UUID hexadecimal value | 1 |
| 4 | Fresh selected journal image admission and session creation | 1 |
| 5 | Original complete general-value wire encoding | 1 |
| 6 | Original general-data decode, including floats and selected profiles | 1 |
| 7 | Ordered original tool/arguments object construction | 1 |
| 8 | Actual native journal bridge, stage 0..10, complete reply projection | 13 |
| 9 | Exact resource-read required/optional keys check | 0 |
| 10 | Native store resolve_uri | 1 |
| 11 | Ordered alias arguments with original max_bytes default | 1 |
| 12 | Actual namespace BEGIN | 0 |
| 13 | Fixed relational operation and actual complete result receipt | 1 |
| 14 | Actual namespace COMMIT | 0 |
| 15 | Actual namespace ROLLBACK | 0 |
| 16 | Complete six-column row observation then lookup wire | 2 |
| 17 | Actual realtime nanoseconds | 1 |
| 18 | Exact INSERT prefix (mode 0), then complete six binds (mode 1) after realtime | 1 |
| 19 | Entire cached-value method, codec/profile/materialization/refusal order | 2 |
| 20 | Complete selected tool input schema | 0 |
| 21 | Exact catalog comparison and original rejection | 0 |
| 22 | Fresh installation identity acquisition and comparison | 0 |
| 23 | Original context membership/reference observation | 2 |
| 24 | Complete context resolution/profile/identity owner | 1 |
| 25 | Complete budget/attempt owner | 0 |
| 26 | Exact business owner, journal tool IDs 1..11 | 1 |
| 27 | Native complete successful response record | 1 |
| 28 | Complete output schema, result label | 0 |
| 29 | Complete cached verification replay owner | 0 |
| 30 | Exact native journal refusal exception | 0, always raises |
| 31 | Complete error response, including deferred snapshot publication | 1 |
| 32 | Original installation failure AgentRejected wrapper | 1 |
| 33 | Exact original str(tool), before the final monotonic observation | 1 |
| 34 | Exact current-minus-started then decimal TEXT, without clamp/narrowing | 1 |
| 35 | Six COST binds including complete UTF-8 details | 1 |
| 36 | Two UPDATE binds, full response then key | 1 |
| 37 | Original context ref id lookup after successful context resolution | 1 |
| 38 | Key ASCII conversion and lookup bind after successful BEGIN | 1 |
| 39 | Exact resource-read uri field lookup after keys check | 1 |
| 40 | Request ID property read after prepare, in the main scope | 1 |

Journal peer 8 returns: actual action, same stable journalSessionLease, raw
request-ID view, raw key view, raw digest view, toolID, flags, status enum,
response byte lease, cost byte lease, arena lease, refusal reason, native
tool-value lease. Raw identity views must not eagerly decode ASCII or perform
a property access. Peer 40 owns request-ID conversion at its original point;
peers 38/18/36 own their original key/digest reads. This preserves failures
that would otherwise move across BEGIN or native_step boundaries.

Peer 16 first uses the actual namespace cursor/row materializer for all six
columns. Only then does it form the digest/state observation. BLOB/INTEGER/
REAL/NULL are not coerced to TEXT merely because SQL declared a TEXT column.
Its second result is the exact response storage value. Peer 19 preserves bytes
versus text, full UTF-8-before-budget where selected, lazy binary64 admission,
complete numeric materialization before root .get refusal, and the already
committed journal state if materialization subsequently raises.

SQL is restricted to the original namespace operations 7,8,9,10 in this
controller. The entire service still needs the other original operations in
its business/context peers. No SQL string interpreter or reduced KV store
is substituted. A real row mutation receipt precedes journal ACK and actual
COMMIT. No fixture receipt establishes durability.

## Error order

Initial monotonic time and UUID precede installation and the main try/finally.
Only ValueError/OSError installation failures receive the original journal
wrapper and error record; they run no finish or COST/UPDATE.

Each call site stores its real exception scope. Native steps mark nativeFailed
before unwind only for non-domain errors; empty ACK steps mark it for every
error. SQL/body errors first receive their actual transaction rollback result.
Rollback may replace the error, but never clears an already set nativeFailed.
BEGIN failure does not roll back. COMMIT is issued after the controller clears
the active transaction, so COMMIT failure cannot add a second rollback/retry.

Successful response assignment precedes output-schema validation. Error-record
construction/publication failure sets nativeFailed and propagates; it cannot
finalize an old success response. Cached early return commits its transaction,
leaves assigned response absent, still calls finish(None), and only then returns
the cached value. Finally runs only if nativeFailed is false; COST precedes
the request UPDATE, and failures in finally are propagated directly.

The complete fixed native coordinator, all peer bindings, actual HIA generation,
bounded compiler run, full old/new trace/state cases, real namespace effects and
installed Worker remain required. This document grants none of those claims.

## Original INSERT evaluation boundary (r4 source)

Peer 18 mode 0 receives (0, journalSession, toolValue, 0,0,0). It reads the
actual key property, then digest property, and forms the first five immutable
bind values (key,digest,tool,running,null), preserving any refusal at this point.
Only after its successful result does the controller request peer 17's realtime
observation. Peer 18 mode 1 receives (1, prefixLease, clockIntegerLease,0,0,0),
performs the original decimal str conversion and publishes all six binds.
The controller then calls fixed namespace operation 8, journal reserved ACK and
COMMIT. This changes no language or clock quota and allows no retry of an ACK.

Peer 4 must not invoke bind_catalog again: the original selected call admits
the selected journal image and creates a fresh session. Catalog acquisition and
any earlier service-constructor validation keep their own original owner.

## New proposed compile and control evidence

compile_call_control_ci_r3.py and test_call_control_ci_r3.py are unexecuted
scripts, not evidence. The proposed test calls the exact unchanged reference
call_with_native_journal with controlled foreign peers, compares complete
observable order/result/errors against actual HIA entries, and disables the
retained call owners during the native interval. It tests control ownership
only: fake namespace, schema, business and value peers do not close production
semantics. Every injected error point must actually be reached on both sides.
Raw source/command/workspace before and after bytes are preserved as compressed
content-addressed records; native limits remain 90 CPU seconds and 1 GiB.
