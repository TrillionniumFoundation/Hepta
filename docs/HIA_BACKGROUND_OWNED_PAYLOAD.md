# Immutable native byte ownership

This component owns a byte string and independently allocated strong references.
The BG job/Future carrier and the rank result owner can each use a separate
context. It has no rank, validation, publication or job-replay authority.
Whole BackgroundOptimizer and rank qualification remain separate.

Each retain allocates a new native node and fresh 128-bit getrandom nonce.
The owner scans its live registry under a native futex lock before comparing
the node and nonce, and never dereferences an unrecognized caller node.
Objects and references carry the actual process identity. A reference copied
as three integers is not an additional owned reference. Drop consumes exactly
one node; the last node releases the immutable payload. There is no finite
reference counter. A create or retain allocation failure unwinds only its
unpublished allocations and leaves the existing owner unchanged.

## Calling convention

The export is hia_mv_background_payload(s, sN, o, oN, context, contextN).
All three views are disjoint. Output is at least 512 bytes and the context is
at least 256 bytes. Initialization is exclusive and requires context word 0
to be zero; it writes all live fields, so unused context memory need not
initially be zero. The enclosing owner retains its context for every active
call. Destruction is exclusive and refuses while any reference remains live.

HIABPY01 input is 128 bytes plus the optional create payload:

| Offset | Field |
| --- | --- |
| 0 | HIABPY01 |
| 8 | Operation |
| 16 | Zero |
| 24, 32, 40 | Owned reference node, nonce word 0, nonce word 1 |
| 48, 56 | Copy offset and count, only for operation 4 |
| 64 | Zero |
| 72 | Create payload size, only for operation 1 |
| 80 through 127 | Zero |
| 128 onward | Exact opaque create bytes |

Operations are 0 initialize, 1 create, 2 retain, 3 drop, 4 copy segment,
5 destroy, 6 borrow immutable view. Initialize/create/destroy require all
reference words to be zero. All otherwise unused fields must be zero.
Empty payloads and every possible byte value are accepted. There is no added
8 MiB or 64 MiB payload quota. Arithmetic overflow, address-space exhaustion
and actual allocator failure are refused before publishing an invalid object.

HIABPYR1 output header is 128 bytes:

| Offset | Field |
| --- | --- |
| 0 | HIABPYR1 |
| 8 | Status |
| 16, 24, 32 | Newly owned node and nonce, for create or retain |
| 40 | Complete payload size, for object operations |
| 48 | Segment bytes copied |
| 56 | Context process identity |
| 64 | Borrowed immutable pointer, only for successful operation 6 |
| 72 through 127 | Zero |
| 512 onward | Operation 4 segment bytes |

Statuses are 0 success, 1 unknown/stale/foreign reference, 3 invalid segment,
4 allocation failure, 5 lifecycle or process mismatch, 6 kernel failure,
7 insufficient segment output space, and 9 violated private invariant.
A valid framed operation returns native zero with this status. Invalid
private framing or short mandatory views return 0xfffffffd without mutating
the owner. The output continuation is private and may be written on refusal.

A borrowed pointer remains valid while at least one legitimate strong
reference to that object remains owned. Consumers must retain their reference
through parsing or copying, then drop it. Operation 4 supports arbitrary
in-range segments; a zero-byte copy at the exact end is valid. Short output
and invalid ranges do not partially write payload bytes. Neither reading
nor retrying a copy repeats the semantic action that produced the bytes.

## Construction and evidence

The HIA policy and HIA packer are compiled by the captured native source
compiler. The HIA packer creates the object and the HIA shared linker creates
the shared image. The readable mechanical adapter contains only syscall,
futex atomics, malloc/free and HIA-selected byte copies. Development GNU
assembly independently checks its complete fixed template; it is not a
production construction dependency.

HIA_BACKGROUND_OWNED_PAYLOAD.json records the exact source/build/image pins.
The current native image is 94,992 bytes with SHA-256
2f754946320efa6061cb29948f12c5ae4104617edb5e581a464bc6399ae961eb.

Qualification includes 13,022 native operations, 900 fresh random segment
comparisons, a complete 67,108,865-byte object compared both by segmentation
and borrowed view, 1,001 simultaneous references, 1,000 stale-node reuse
controls, and 1,600 retain/copy/drop cycles on 16 real threads. Empty and
arbitrary byte strings, process forks, malformed private requests, integer
range overflow and output atomicity are checked.

Actual malloc failure injection targets only instruction addresses in the
current native component. Five allocation failures cover empty/nonempty
create and retain; every existing object remains intact, and same-owner retry
succeeds. A sixth case verifies 1,002 actual allocations and exactly 1,002
frees for one object and 1,001 independent references. Twenty-four native
packer and mechanical provenance checks also pass. The external injector
is test instrumentation, not a product dependency.
