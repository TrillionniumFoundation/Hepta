# Sole-owner sidecar and fixed code-provider binding

This profile adds a native-owned sidecar to the existing 2048-byte owner.
It preserves the original raw and provider-bound profiles, their public
request domains, and their context size. The new native image has two exports:
`hia_generation_lease_owner` and `hia_generation_lease_owner_sidecar`.
All code and Value calls resolve through fixed rel32 targets in that image.

The qualified mask-6 checkpoint initializes a real native code provider, but
does not yet enable public callable resource construction or invocation.
The separate code-enabled candidate has its own source, product and evidence;
its qualification is not implied by this checkpoint.

## Sidecar entry

Use the ordinary six-word ABI with the actual initialized owner as workspace.
The input is exactly 128 bytes: `HIAGSCQ1`, an operation at offset 8, and zero
bytes at offsets 16–127. Output is at least 128 bytes and the owner span is
exactly 2048 bytes. Requests cannot select callbacks, native entry addresses,
Value arenas, code contexts or implementation identities.

| Operation | Behavior |
| --- | --- |
| 0 | Bind once, using actual native allocation, random nonce and Value token |
| 1 | Close and retire the sidecar |
| 2 | Retry known pending initialization or retirement |
| 3 | Return a sealed FD containing the native cached temporary-directory path |
| 4 | Report current sidecar state |

The response begins with `HIAGSCR1`. Its u64 fields are:

| Offset | Field |
| --- | --- |
| 8 | Status |
| 16 | Actual error/detail |
| 24 | Pending custody |
| 32 | Sidecar actually retired |
| 40 | Ownership known |
| 48 | Sidecar state |
| 56 | Actual owned mapping extent |
| 64 | Current sidecar operation count |
| 72 | Actual Value context token still held |
| 80 | Native code provider initialized |
| 88 | Value destroy fence set |
| 96 | Transferred temporary-directory result FD, or u64 all-ones |
| 104 | FD byte length |
| 112 | FD seals |
| 120 | Pending continuation stage |

Statuses and delivery facts are independent. In particular, a successfully
transferred result FD remains caller-owned if a later mutex wake fails.
A zero ABI result or a zero status must not substitute for a trustworthy
known/nonpending/retired acknowledgement during teardown.

## Owner layout

The extension uses only the previously reserved bytes 1136–1279. The old
profile leaves them zero and does not activate them.

| Owner offset | Captured field |
| --- | --- |
| 1136 | `HIAGSCX1` |
| 1144 | 0 unbound, 1 initializing, 2 ready, 3 closing, 4 known pending, 5 quarantine |
| 1152 / 1160 | Actual native mapping address / 212992-byte extent |
| 1168 | Actual native random nonce |
| 1176 | Fixed sidecar entry |
| 1184 / 1192 / 1200 | Real Value context-token capability triple |
| 1208 | Sidecar active-operation count |
| 1216 | Continuation stage |
| 1224 | Reserved for the public constructor |
| 1232 | Fixed native temporary-directory entry |
| 1240 | Reserved for the fixed Clang outer |
| 1248 | Fixed native code-provider entry |
| 1256 | Last actual error |
| 1264 | Reserved |
| 1272 | Internal custody/fence flags |

Flags at 1272 record the long-lived owner guard, mapping ownership, initialized
code provider, requested close, code fence, Value fence, retired temporary
directory and retired code provider respectively. They are internal state,
never caller-supplied success flags.

Binding obtains an actual Value context token through Q01/21. It also holds
one persistent operation guard at owner offset 72 until the sidecar mapping is
really unmapped. This guard prevents the raw owner's destroy operation from
retiring the shared Value arena or finalizer while the sidecar still owns
resources, including after its context token has been consumed during close.

## Native mapping and fixed bindings

The actual `mmap` allocation is 212992 bytes:

| Sidecar offset | Size | Meaning in this checkpoint |
| --- | --- | --- |
| 0 | 1024 | Reserved global header |
| 1024 | 256 | Initialized native code provider |
| 1280 | 256 | Reserved Future global context, all zero |
| 1536 | 512 | Reserved Future resource provider, all zero |
| 2048 | 512 | Reserved Background registry, all zero |
| 4096 | 204800 | Native temporary-directory context |
| 208896 | 4096 | Reserved tail page |

The code provider's real init generates its own nonce. Only after that succeeds
does the native binder capture the shared Value arena address and entry in
code-context offsets 136/144. It records the fixed code entry, actual context,
extent 256 and code nonce in Value-context offsets 192/200/208/216.
There is exactly one Value arena and one Value implementation in this owner
image. Neither the code provider nor the temporary-directory capsule embeds
another Value implementation.

The fixed finalizer preserves the existing actual Runtime/Lease path. It also
has a separate native dispatch path for code kinds 3/4/5. That path validates
the original Value binding nonce, copies the private 128-byte finalizer
request, substitutes the captured code-provider nonce, and invokes the fixed
code entry. It forwards explicit known/consumed/pending facts. Mask 6 keeps
these callable kinds disabled in this qualified checkpoint.

Future and Background spans are reservations, not constructed objects. Their
resource kinds remain disabled until their actual providers and complete
lifetime gates are connected. The public Value dispatcher rejects the entire
private HIABVQ06 profile without writes.

## Retirement order and actual rollback

Close first retries code-provider pending work, then obtains its real
quiescence fence through operation 10. It consumes the sidecar's Value context
token using explicit Q02 consumption facts and drains any known pending
cleanup. It then requests the actual Value destroy fence.

If live external Value capabilities make that fence busy, the binder obtains a
new real context token and rolls back the code fence through operation 11.
The owner returns to ready without duplicating a capability or losing custody.

With the Value fence held, the binder retires the native temporary-directory
context, destroys the native code provider, clears the fixed code binding,
rolls back the temporary Value fence, and finally performs the actual sidecar
unmap. Only then does it clear the extension and release the persistent raw
owner guard. This sequence leaves the raw owner alive for its own later
destroy operation.

Known failures preserve the exact mapping, code/Value fence, token-consumption
facts and continuation. Operation 2 continues from those facts. Unknown
transport or ownership results keep custody quarantined. A failed close,
unmap, or token operation never frees the context prematurely. Receipt
processing after an actual mutex-wait error retains the receipt and acquires
the lock by native atomic retry before committing state.

## Packaging and evidence scope

The private sidecar packer uses HIAGSCP1, three roles and a 40-byte header:
policy, code-provider capsule and temporary-directory capsule. Its resulting
capsule is below the unchanged 4 MiB role limit.

The enclosing packer uses HIAGLOP3, 56 roles and a 464-byte header: the 55-role
provider-bound owner followed by that capsule. It binds every private role
statically and supplies the two exports. Product text stays below 16 MiB.
The old HIAGLOP1 and HIAGLOP2 products remain independently supported.

The receipt records the exact five newly compiled HIA modules, the frozen
Value13 dependency revision, native component pins and actual qualification
reports. Six new binder groups exercise real allocation, random identities,
token retention, 32 concurrent temporary-directory reads, duplicate bind,
eight-thread initialization, live-cap fence rollback, fork/copy/no-write guards
and real kernel failures during init and all three retirement layers.

The same native image also passed the original provider suite, 16 complete
owner/resource/typed/Future groups, 339 typed scalar comparisons, all seven
GenerationInfo identity/lifetime gates, the post-publication allocator-failure
gate and public Value62/63/67 checks. These original owner regressions use the
normal core entry; the six binder groups separately exercise the active
sidecar. The actual tests do not replace syscalls, native replies or contexts
with host callbacks.

Public ScalarMultiversionRuntime construction, immediate generation-cache
pruning after all public mutations, complete callable invocation, fused Future
and Background construction, and whole repository closure remain separate
unfinished obligations. No field in this component receipt claims them.
