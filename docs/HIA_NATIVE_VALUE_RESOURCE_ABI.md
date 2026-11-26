# Shared native resource Value protocol

This is the candidate Q05 integration contract. Its source and mechanical bridge are under native qualification. The older Q04 record component has a separate qualified checkpoint; that checkpoint does not establish the resource, callable or complete public API behavior described here.

## One image and one arena

The complete resource image uses twelve fixed roles, in this order: owner, core, import, export, capture, format, number, dictionary iterator, classes, C3 MRO, records, resources. The native packer is `result_value_resources_packer.hepta`, authored by `tools/generate_hia_result_value_resources_packer.py`, with the mechanical bridge `tools/hia_result_value_resources_bridge.S`.

Its input is `HIABVP05`: count 12 at offset 8, twelve lengths at offsets 16 through 104, mode at 112, and concatenated role bytes at 120. Mode 1 produces the flat image; mode 0 produces the ELF object. Existing 4 MiB role and 16 MiB image bounds remain unchanged. The public image entry remains `hia_result_value` with its existing six-word ABI and a stable 256-byte context.

Every enclosing runtime, Future, callback and background owner must use the same captured entry and the same arena context. Matching image bytes in independently initialized arenas does not provide shared object identity or lifetime.

## Internal binding and destruction

The sole native owner captures these context fields mechanically. No request carries a function pointer.

| Context offset | Meaning |
| --- | --- |
| 120 | Actual in-flight entry count, incremented and decremented by the native bridge. |
| 128 | Fixed internal native finalizer entry. |
| 136 | Captured finalizer context address. |
| 144 | Finalizer context extent, exactly 256. |
| 152 | Actual owner binding nonce. |
| 160 | Destruction admission fence. |
| 168 | Fixed owner supported-kind mask, using bit 1 << kind. Runtime and lease support is 6; adding BackgroundOptimizer support gives 70. |
| 176 | Retained resource-finalizer queue count. |

Each direct consumer retains a real context token until its last internal call has returned. A destruction fence succeeds only while the Value mutex is held, no external capability or queued resource remains, and the only in-flight entry is the fence operation itself. The sole owner then destroys its actual carrier registry and releases the Value anchor. A refused carrier destruction must complete the explicit fence rollback before resuming admission.

The shared arena reserves offset 1024 for its canonical empty tuple, 1032 for the weak GenerationInfo identity index, 1040/1048/1056 for finalizer queue head, tail and count, and 1064 for the weak runtime ABI tuple index. These offsets do not overlap the canonical class table or allocator free lists.

## Q05 requests

The 128-byte header uses `HIABVQ05`. Capability triples A, B and C remain at 24/32/40, 48/56/64 and 72/80/88. Tail length is at 96; scalar arguments are at 104 and 112. Offsets 16 and 120 and all operation-specific unused fields are zero. Replies retain `HIABVR01`.

| Operation | Meaning |
| --- | --- |
| 48 | Capture an owner-bound resource. Argument 0 selects runtime 1, lease 2, function 3, bound method 4 builtin method 5, or BackgroundOptimizer 6. The fixed owner support mask must enable that kind before publication. The 24-byte tail is the actual independently retained carrier capability. A is the environment, B the bound self, and C the bound function. Success transfers that carrier reference into the native object. |
| 49 | Extract a resource binding from actual object A, optionally requiring the resource kind in argument 0. It verifies the private marker, actual binding nonce and live resource state. The returned carrier triple at reply offsets 24/32/40 is an internal owner transport, not a new Value capability; reply offset 16 contains its resource kind. |
| 50 | Construct a real native builtin-derived object from actual user-defined class A, environment B and inherited value C. Canonical builtin classes are refused with status 18. This extension leaves the earlier Q03 constructor domain unchanged. |
| 51 | Read actual capability, queue and in-flight counts at reply offsets 48, 56 and 64. |
| 52 | Begin destruction. The request contains only magic and operation. Status 0 establishes the fence; status 6 leaves it unchanged. |
| 53 | Roll back a destruction fence. The request contains only magic and operation. Only a valid status-0 reply proves rollback. |
| 54 | Look up an existing live GenerationInfo by exact generation integer A and the two actual runtime identity words in arguments 0 and 1. |
| 55 | Publish or reuse GenerationInfo A under that same actual runtime identity. The index is weak; object unlink removes its entry. |
| 56 | Retry retained native resource cleanup through the fixed finalizer. |
| 57 | Obtain canonical class 31 GenerationLease, 32 function, 33 method, 34 builtin_function_or_method or 35 BackgroundOptimizer. |
| 58, 59 | Internal graph-role claim and acknowledgement. The public Value entry rejects both. |
| 60 | Private actual GenerationInfo capture. Argument 0/1 contain the captured runtime identity; the tail is the actual complete HIAMVIR2 blob. It constructs real immutable records and ABI tuples, preserves same-generation Info and same-runtime ABI identity, and serializes the actual loaded mapping into canonical sorted compact bytes. |
| 61 | Private typed preparation under the actual lease mutex. It preserves Q04/45's 5264-byte request, 8344-byte response and error ordering, and requires the captured owner binding. Only automatic finalizer draining is deferred for this single entry. |
| 64 | Private Lease strong Info attachment. A is a live bound Lease resource, B is an actual weak-indexed GenerationInfo, and argument 0/1 is the captured runtime identity. The stored Runtime environment must be a live bound Runtime. It installs the first Info strong edge in the Lease base slot; attaching the identical object is idempotent and replacing it with another object is refused. It neither consumes B nor publishes a capability. |
| 65 | Private Lease Info lookup. A is a live bound Lease resource and all other fields are zero. It returns a fresh strong capability to the cached Info; status 6 means no cached Info. The cache is an ordinary graph edge, retained through Lease close and released only by actual resource retirement. |
| 66 | Private Runtime Info-cache reconciliation. A is a live bound Runtime or its Lease, B is an actual Info record or zero for pruning only, and argument 0/1 is the captured runtime identity. Its tail is the actual detached native runtime snapshot JSON. The Runtime base holds an immutable tuple of the shared ABI tuple and an immutable tuple of observed live-generation Info objects. A fully allocated replacement is attached atomically after validation; failure preserves the previous graph. Actual publication, cleanup and close must trigger this operation to release retired-generation edges promptly. |



The sole owner's public Value transport may expose 50, 51 and 57. It rejects the resource capture, extraction, destruction, identity-cache and cleanup control operations from external requests.

The sole owner initializes the supported-kind mask from its fixed dispatcher. A kind whose finalizer is absent is refused with known/unconsumed custody before any Value object is published. Merely adding a class does not enable resource dispatch.

A real resource is native kind 8 with an actual canonical class edge and a private immutable owner binding. Ordinary Q02 or Q03 objects cannot write that binding. Runtime class 20 continues to be the existing actual ScalarMultiversionRuntime class. A same-named class or an uninitialized instance grants no native resource authority.

The object keeps environment, bound self, class, name and bound function through the shared graph's strong edges. Capture does not complete until a Value capability has been published successfully. A failed pre-publication attempt leaves the caller's carrier reference unconsumed. The reply carries explicit ownership facts rather than inferring transfer from status.

### Capture ownership receipt

Operation 48 returns pending at 80, known at 88 and consumed at 96. Known 1 and consumed 0 prove that the supplied carrier reference has not transferred. Known 1 and consumed 1 prove transfer and always return the published nonzero Value capability at 24/32/40, including when status 11 reports pending finalization of other resources. A caller must retain that returned Value capability and must not drop the transferred raw carrier reference again. Unknown ownership requires custody quarantine.

All-zero environment/self/function triples are valid for runtime and lease capture; the environment becomes the actual None singleton. Operation 50 clones mutable list/dict bases and shares immutable inherited bases, while preserving the actual class graph.

An unrelated resource finalizer error cannot suppress an already-published ordinary create/retain result. Its queue custody remains explicit. Q02 ownership operations, capture 48 and retry 56 report pending cleanup or callback errors through their lifecycle contract.

### Actual information and locked typed calls

Operation 60 accepts no caller type bits. Its frame is 128 bytes followed by the captured 32-byte HIAMVIR2 header and JSON payload; tail length is exact, blob mode/reserved are zero, and its payload length matches. A, B and C are zero. The enclosing owner obtains the identity from the actual native Runtime while the registry mutex is held and retains the detached blob until conversion returns. It then actually frees that blob.

Native import and conversion keep a real internal capability on the partially built record across allocator collection and nested export. Function signatures become ScalarABI records with actual parameter tuples. The weak generation index uses runtime identity plus the exact unbounded generation integer. The separate weak ABI index preserves the runtime's shared signature tuple and members across generation records, while allowing independent retained ABI objects to outlive their Info object. No weak index is an extra collector root.

Operation 61 routes the same native typed policy as Q04/45. It retains arena locking, strict function/list/tuple/scalar validation, ABI comparison and queued resource graph roots. It does not change a shared context flag. After the real scalar call and original lease unlock, the enclosing owner performs actual Q02 argument-reference cleanup and fixed native resource cleanup before completing its lifecycle receipt. No host polling is part of that protocol.

## Native finalization

A zero-reference or unreachable resource enters the native queue before its graph edges can be released. Queued resources and their reachable graph are collector roots. The Value owner claims one entry under its actual mutex, releases that mutex, calls the internally captured native finalizer, reacquires the mutex, and acknowledges the returned facts. This order avoids holding the Value mutex while a carrier operation waits for a lease mutex.

States are live 0, queued 1, claimed 2, consumed with cleanup pending 3, and quarantined 4. The claimed record and its strong graph remain present until acknowledgement. A futex error during reacquisition does not discard the receipt: native CAS and sched_yield continue reacquisition, preserving the error for the final response.

The finalizer input and output are each 128 bytes:

| Request field | Offset |
| --- | --- |
| `HIAVRFQ1` | 0 |
| Operation: drop 0, already-consumed cleanup retry 1 | 8 |
| Captured binding nonce | 16 |
| Resource kind | 24 |
| Actual carrier capability triple | 32, 40, 48 |
| Reserved zero | 56 through 127 |

| Reply field | Offset |
| --- | --- |
| `HIAVRFR1` | 0 |
| Status | 8 |
| Known, consumed, pending facts | 16, 24, 32 |
| Actual carrier status, child return, retained and final return evidence | 40, 48, 56, 64 |
| Reserved zero | 72 through 127 |

A successful, known, consumed reference with no pending cleanup permits queue removal. A known consumed reference with pending cleanup is retried with operation 1 and is never dropped again. A retry may report consumption as an already-established fact or report no new consumption; the queued prior fact remains authoritative. Unknown consumption retains and quarantines custody.

Q02 capability-consumption facts remain tied to actual Value capability removal. Pending native resource cleanup cannot be presented as a cleared lifecycle. The new resource domain permits Q02 retry to drain that actual pending work; an active legacy context with no pending work retains its original status-6 behavior.

## Qualification boundaries

The final resource receipt must state the image protocol, role list, packer, mechanical source hashes, actual construction pins and independent native pack comparison. Separate evidence and flags are required for resource finalizers, same-arena Future ownership, runtime-owned GenerationInfo capture, actual native callable and bound-method execution, tuple and record equality/hash, arbitrary iterable dataclass behavior, and complete public runtime integration. No component flag substitutes for these behavior gates.
