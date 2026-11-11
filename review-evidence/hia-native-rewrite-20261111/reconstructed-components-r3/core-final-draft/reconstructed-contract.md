# Complete Core late admission: reconstructed r3 contract

RECONSTRUCTED-DESIGN-20261111-r1. This is a new reconstruction from retained design context after workspace replacement. It is not the unavailable original document with SHA256 bb65d400d426acd37dc81a245a588b18762cc838b941ff18f77db32c4bd59f0e. No execution, native image, or qualification is claimed for this text. The independent visitor implementation belongs to the native_checker agent.

## Scope

The fixed native pipeline produces an immutable, acyclic, completely issued Core value. Its scalar strings are already valid UTF8, its scalar integers are native u64 or bounded admitted source decimals, and no Python custom objects, cycles, mutations, or aliases can be substituted. This proposal replaces only the final bounded detached snapshot / structural byte admission of that value. It does not replace the initial public JSON profile, constructor semantics, full primitive Core verification, canonical serialization, or whole application qualification.

The complete input must still pass the original public raw JSON integer profile and detached canonical source ordering before constructor admission. Core insertion order must be preserved until the late checks: comparing only sorted JSON or dictionary equality cannot prove equivalent first errors.

No per-function output-size quota may be introduced. Every earlier function/helper semantic result and every later function error must occur before the original final Core size gate.

## Original snapshot order and composable summary

The retained bounded snapshot traverses depth-first, left-to-right in dictionary insertion order. Root depth is zero. Dictionary keys do not count as nodes; values do. At each visited node it increments visited and decrements queued, checks node/depth admission, then for containers checks the immediate child arity against the remaining queued-node budget before visiting children.

Let M=262144, maximum depth=64, and final byte budget=8388608. At every traversal point:

visited + queued = 1 + sum(immediate child arities of visited containers).

All arities are nonnegative. Before a queued-node violation, node-count overflow cannot precede the corresponding queue check. The first error is therefore determined by the first depth witness versus the monotone arity budget.

Each complete function/helper root occurs at depth 2 in the final outer document's functions list. Its summary is:
- rootKind, with map represented by 6;
- Ncap = min(total nodes, M+1);
- Dcap = the cumulative child arity before the first node at relative depth greater than 62, saturated at M+1; UINT64_MAX if none;
- exact ordered compact JSON byte length;
- actual native SHA256 of those exact JSON bytes;
- root key inventory, described below.

For an opaque object at final depth 2, its additional arity is N-1. Combining it with preceding outer arity P adds that arity with saturation, and shifts a present depth witness by P. Repeated references are charged on every occurrence. This is a summary of the actual issued complete object, not an authenticator for an external handle.

At complete outer traversal, with summary N,D:
1. if D != UINT64_MAX and D <= M-1, report the depth/node snapshot error;
2. otherwise, if N > M, report the queued-node error;
3. otherwise the snapshot succeeds.

Only after that, if the exact complete ordered JSON byte length is greater than 8388608, report the original byte-budget error.

Exact public errors:
1. E_HIA_LIMIT: caller-owned tree exceeds snapshot budget
2. E_HIA_LIMIT: caller-owned tree exceeds queued-node budget
3. E_HIA_LIMIT: program exceeds byte budget before encoding

The later retained _structure pass uses a different stack order and charges key bytes. Once the immutable snapshot has succeeded, all its node/depth/queue checks are necessarily satisfied; in the fixed valid scalar domain, only the same final byte-budget error remains. This proof does not cover arbitrary Python objects or foreign Core.

## Streaming visitor ABI

Outer RWW entry with two internal read buffers:
- first: original producer frame or protocol command;
- second: same actual SourceIndexLease, held private and read-only;
- mutable work: at least 131328 bytes, growable using offsets.

The visitor keeps only active traversal, container/key state, the current original frame, and source traversal positions. It need not retain a complete Core tree. Map arity must use pair remaining and parity, avoiding overflow in 2*arity. No preallocation proportional to an untrusted declared arity.

BEGIN is 80 bytes / 10Q:
[HIACSB01, lease, stream, producerMagic, action, request, serial, slots, mode, 0].
mode 1: a complete function/helper with relative root depth 0 and eventual outer depth 2.
mode 2: a complete outer root at depth 0.

CONT is 32 bytes / 4Q:
[HIACSC01, lease, stream, lastEventSequence].

Producer input is the original complete 64-byte frame plus its exact token payload. A frame is produced once, consumed by all required native consumers, and held immutable until those consumers finish. GROW replays CONT against the same frame, not the producer. Initial GROW must be explicitly distinguishable and replay the same immutable BEGIN.

Opaque summary reply is 128 bytes / 16Q:
[HIACSO01, lease, stream, lastEventSequence, handle, rootKind,
 Ncap, Dcap, jsonBytes, digest0, digest1, digest2, digest3, 0, 0, 0].
High opaque handles are permitted only in mode 2, only as value roots at depth 2. Mode 1 has no high opaque objects. The coordinator supplies an already issued summary and matching exact object bytes from its private registry.

Event is 128 bytes at workspace offset 1024, with native return 1152:
[HIACSE01, action, status, lease, stream, nextProducerSequence,
 eventSequence, rootKind, Ncap, Dcap, growNeeded, opaqueHandle,
 opaqueQuerySequence, snapshotLateStatus, rootKeyMask, rootUnknownKey].

Actions: 1 READY, 3 GROW, 4 OPAQUE, 5 DONE, 6 REFUSE, 7 ADMIT.
Status: 1 active, 2 complete, 3 poisoned.
Mode 1 reports snapshotLateStatus=0. Mode 2 may record snapshot error 1 or 2 at DONE but must not publish rejection before the original completion point.
Short workspaces or stale error frames require the final executor to discard the lease after every BAD return, regardless of whether poison could be stored.

## Root key inventory and exact rejection timing

The inventory is reported; it is not an early envelope gate.

| Bit | Key |
|---:|---|
| 0 | name |
| 1 | params |
| 2 | returns |
| 3 | effects |
| 4 | entry |
| 5 | blocks |
| 6 | return_loans |
| 7 | schema |
| 8 | module |
| 9 | exports |
| 10 | functions |

rootUnknownKey is 0 or 1. Full token/key validation still checks duplicate keys; a bit mask cannot replace that check.

The controller checks a complete function envelope only after the full function stream and its native final-state publication. It requires rootKind=6, unknown=0, and mask 63 or 127.

The controller checks a complete outer envelope after the complete outer stream but before final Core snapshot/byte admission. It requires rootKind=6, unknown=0, and mask 1920.

Existing helper reply validation retains its complete shape checks. A complete helper typed packet can be indexed and represented by one native-generated SourceRef ObjectToken frame for this generic visitor; that is a representation operation, not Python semantic interpretation.

## Final ADMIT

Only after complete outer traversal and actual complete native JSON counting/hashing, submit 80 bytes:
[HIACSA01, lease, stream, lastEventSequence, actualCompleteJsonBytes,
 digest0, digest1, digest2, digest3, 0].

Only one ADMIT is allowed, in the completed mode-2 state. The emitted action-7 event has eventSequence = prior sequence + 1, with no wrap. Snapshot errors retain priority over the later byte error.

The digest is computed by the actual native SHA stream over every actual JSON chunk that is written. It is not a caller claim and does not replace the private object registry's authority.

## Coordinator / spool obligations

All functions run in original order. Successful helpers are appended in the original order. The HIA outer owner retains the original late function/block inventory limits, export eligibility, sorting, and schema selection.

Each complete function/helper has a private object-spool interval and its native summary. The fixed executor can perform append, exact read, seal, allocation, protection, and image invocation. It must not decide traversal, envelope validity, service identity, count blocks, sort exports, or interpret an IR plan.

For a complete outer stream, the HIA controller resolves only its already issued opaque handles, registers exact lengths/digests with the native JSON consumer, and supplies exact immutable spool chunks. The JSON consumer verifies the complete opaque extent/digest. The visitor consumes the matching issued summary. All streams, counters, pending requests, and GROW calls remain separately correlated.

The final application must close every private buffer and file on successful exit or any semantic/transport refusal. No output is published as qualified Core until all required late gates and subsequent full primitive validation succeed.
