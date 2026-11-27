# Native Runtime terminal installed-resource custody

This is a private enclosing component profile. It keeps the previous 44-, 45-,
and 46-role products and their request domains intact. The new 47-role root
uses one Value implementation and arena, the existing installed resource owner,
and the existing Future/code sidecar. Its native text and every leaf remain
inside the original 16 MiB / 4 MiB limits.

## Actual ownership

A constructor that owns an unpublished, strong native Runtime capability calls
the fixed `hia_generation_runtime_borrow` entry before exposing its Runtime
Value. Registration verifies that capability through the same captured native
carrier. The caller must keep that strong native capability until the call
returns; this entry is not a public operation on a borrowed raw pointer.

Each successful registration owns a real installed-resource borrow plus one
root active guard and one sidecar active guard. Registration is not the
transfer of the caller's native Runtime capability. The new carrier invokes
retirement only after the Runtime effects owner has actually retired, after
all native capabilities and operation pins have gone, and before its Runtime
object is freed. The carrier mutex is released around this fixed call.

A Lease's original internal Runtime reference continues to retain the Runtime.
Consequently, closing and dropping the caller's Runtime while a Lease is alive
does not release the installed tools/source directory/threshold lifetime.
The last actual native holder triggers retirement. Old, unregistered Runtime
consumers follow their existing carrier path and receive an empty-ledger ACK.

## Stable layouts

The original root work extent is still exactly 2048 bytes. The global owner
already owns an actual 8 MiB mapping at root offsets 1088/1096. The following
nonoverlapping spans are reserved inside that mapping:

| Offset | Size | Owner |
| --- | ---: | --- |
| 7340032 | 512 | Original global control |
| 7340544 | 512 | BackgroundOptimizer binder |
| 7341056 | 512 | Runtime borrow ledger |

The Runtime anchor contains `HIARTLC1` at 0, actual PID at 8, root address at
16, fixed global entry at 24, linked-record head at 40, and record count at 48.
All anchor and list operations use the existing actual root mutex at root64.
No public request selects these addresses or initializes the prefix.

Each record has a real anonymous 4096-byte native mapping:

| Offset | Meaning |
| --- | --- |
| 0 / 8 / 16 | HIARTLN1 / actual PID / owning root |
| 24 | Actual native Runtime object address |
| 32 / 40 | Previous / next ledger record |
| 48 | State: registering1, live2, known pending3, unknown4, claimed5 |
| 56 / 64 / 72 | Actual installed-resource strong capability |
| 80 / 88 | Owned root72 / sidecar1208 guard |
| 96 | Consumed global-borrow cleanup still pending |
| 104 | Captured global resource nonce |
| 112 / 120 | Actual Runtime identity read by the native carrier |
| 128 / 136 | Last cleanup status / detail |
| 144 / 152 | Actual record address / extent4096 |

Updates made after an unlocked child call copy only record48..255. The native
policy reloads the current anchor and record links under the root mutex before
actual unmap and unlink, so concurrent insertions or retirements are preserved.

## Six-word entry and frames

All calls use input pointer/length, output pointer/length, root pointer/2048.
The fixed mechanical prefix captures the owner, global owner, and carrier
entry addresses. Runtime registration needs output at least 100696064 bytes;
retirement and query need output at least 262144 bytes.

Input is exactly 128 bytes with `HIARTLQ1` at 0 and operation at 8:

| Operation | Payload | Effect |
| --- | --- | --- |
| 0 | Actual Runtime capability at24/32/40 | Retain installed resources and both guards |
| 1 | Actual terminal Runtime object pointer at24 | Fixed carrier retirement hook |
| 2 | All remaining bytes zero | Observe actual linked-record count |

All unspecified words must be zero. Registration refuses duplicate bindings,
wrong kinds, forged or stale capabilities, nonready roots, and nonready
sidecars. Operation1 verifies the actual Runtime header, PID, kind1, retired
state, empty capability list, and zero operation pins before releasing a
matching record. Missing records preserve the original unregistered-carrier
behavior. Copied/forked root contexts are rejected without changing that root.

Reply is `HIARTLR1`, 128 bytes:

| Offset | Meaning |
| --- | --- |
| 8 | Status |
| 16 | Registration completed |
| 48 | Actual Runtime object |
| 80 / 88 | Pending / ownership known |
| 96 | Binding record actually removed |
| 104 | Terminal binding retirement complete |
| 112 | Detail |
| 120 | Actual record count |

Offset96 does not mean that the caller's Runtime capability was consumed.
It is set only after the ledger mapping was actually unmapped, the record
was unlinked, and both guards were released.

## Failure and retry

Registration allocation failure compensates both guards. A known failure
after obtaining a global borrow releases that actual capability before
unmapping its record. Unknown replies retain the record and guards in
quarantine.

At terminal retirement, global operation3 is used once while its capability
is still owned; only a real consumed ACK clears the three words. Subsequent
pending cleanup uses global operation4. The record remains linked if actual
`munmap` fails. The carrier retains its terminal Runtime object as pending,
and its original private HA1 operation7 runs the cleanup/destroy sequence
again. That retry cannot drop an already consumed Runtime capability or
global borrow. Only actual record unmap/unlink and guard release produce
the terminal ACK. Root/global/sidecar destruction remains blocked meanwhile.

The native bridge performs only fixed role calls, address calculation, memory
copy, atomic lock operations, and actual Linux syscalls. Decisions about
admission, state, lists, consumption and retirement are HIA policy.

## Qualification boundary

The component tests use the actual native root, installed tools, original
Runtime/Lease carrier, real kernel error injection at the ledger syscall IP,
and independent native packer/reference byte comparison. They cover both
Runtime/Lease closing orders, actual alias ownership, three concurrent Runtime
records, registration mmap failure, terminal munmap failure and native retry,
static/capability/fork/copy refusal, and preserved unregistered consumers.

The public constructor has not yet been wired to this private registration
entry. This component does not claim public constructor completion, immediate
GenerationInfo pruning, automatic subclass construction, or whole-runtime
qualification. The final enclosing product must retain this terminal hook
when combining the BackgroundOptimizer binding and newer Value components.
