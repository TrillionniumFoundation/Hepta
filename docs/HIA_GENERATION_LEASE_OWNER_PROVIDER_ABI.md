# Shared-arena native Runtime provider

The HIA role generation_lease_owner_provider borrows the enclosing owner's
actual Runtime/Lease carrier registry and Value arena. It owns only its common
immutable byte-payload registry and its operation-local cleanup records. The
older standalone provider is retained as a distinct protocol consumer.

## Fixed entry and construction

The six-argument mechanical export is hia_generation_lease_owner_provider.
It requires an exact 768-byte context and an output of at least 128 bytes.
Input, output and context must be non-null, non-overlapping, non-overflowing
ranges; the context must be aligned to eight bytes. Its HIA continuation uses
4096 bytes on the adapter's private stack.

The component pack frame is HIAGPP01, role count 2, two byte lengths, then
provider and payload policy flats. Both roles are compiled from their HIA
sources. The native packer emits an ordinary relocatable ELF object. Three
fixed imports must resolve to the enclosing owner's actual native adapters:

| Import | Actual target |
| --- | --- |
| hia_owner_carrier | Native owner handles adapter for registry at owner + 256 |
| hia_owner_effects | Native typed effects adapter, with r11 set to owner + 512 |
| hia_owner_values | The single actual Value image entry |

The provider component also imports the platform malloc and free allocator
bindings. Its current component qualification does not claim that these have
been replaced by a final standalone native allocator. No product request
contains an entry or context pointer.

The assembled mechanical source has policy hole 262, effects hole 469,
handles hole 479, payload hole 489 and Value hole 499. The qualification independently
checks the captured assembly bytes and its two allocator relocations. The
payload adapter is statically included before the two HIA policies.

## Trusted context

The final enclosing native owner captures the following prefix before control
initialization. The component fixture sets these private fields as an explicit
test seam; that fixture is not evidence for final enclosing initialization.

| Offset | Meaning |
| --- | --- |
| 0 | HIAGPCX1 |
| 8 | Actual PID |
| 16 | Lifecycle state |
| 24 | Provider mutex |
| 32 | Actual owned operation-record chain |
| 40 | Enclosing owner base |
| 48 | Actual provider context address, owner + 1280 |
| 56 | Fixed provider entry |
| 64, 72 | Actual carrier registry, owner + 256; extent 256 |
| 80, 88, 96 | Fixed Value entry; owner + 512; extent 256 |
| 104, 112, 120 | Fixed payload adapter; provider + 512; extent 256 |
| 128 | Nonzero Value binding nonce captured from Value context + 152 |
| 136–511 | Zero reserved prefix |
| 512–767 | Actual common payload registry |

The adapter supplies facts derived from its own address and fixed call holes.
HIA checks the actual context address, owner-relative offsets, PID, static role
bindings and the current Value binding nonce before using a shared owner role.
A copied context and a forked process do not acquire authority from copied
prefix bytes.

The provider holds no permanent Value context token. The enclosing BG/Future
borrower must retain its actual Value context token or an actual Runtime Value
for the duration of its use. The provider never initializes or destroys the
carrier registry.

## Requests and independent output custody

HIAMVBQ1 retains the original raw Runtime-carrier profile and HIAMVBO1
reply. HIAMVBQ2, operation 3, captures an actual Runtime Value: it first
retains that Value, calls private Value 49, verifies resource kind 1, and
clones the resulting actual Runtime carrier in the same registry. The original
public constructor must perform baseline verification and exact function
selection before issuing this capture.

HIAMVBQ3 supports the original carrier operations 1–5 and operation 6 for
known pending cleanup. Q2 and Q3 return HIAMVBO2:

| Offset | Meaning |
| --- | --- |
| 8 | Status, retaining original 0–3 domain |
| 16 | Original result kind |
| 24, 32 | Borrowed immutable payload pointer and length |
| 40, 48, 56 | Independently delivered output capability |
| 64 | Actual conditional-publication committed flag |
| 72 | Whether input consumption is known |
| 80 | Whether the input capability was consumed |
| 88 | Cleanup remains pending |

Consumption describes only the input capability. Capture, clone and snapshot
do not consume their input. A delivered output capability remains an actual
caller-owned result even when a later cleanup error changes status. Consumers
must harvest it before handling status; they must not hide it merely because
status is nonzero. A successful drop has known=1, consumed=1 and pending=0.
A stale capability refuses with known=1 and consumed=0.

## Control and enclosing close order

HIAGPCQ1 is exactly 128 bytes: operation at offset 8 and all remaining words
zero. Its reply is BO2.

| Operation | Action |
| --- | --- |
| 0 | Initialize only the common payload registry |
| 1 | Prepare close: under the provider mutex require no active/pending records and no payload references, then fence admission |
| 2 | Roll back an uncommitted fence |
| 3 | Commit close by actually retiring the payload registry |
| 4 | Retry known pending operation custody |

States are 0 uninitialized, 1 ready, 2 fenced, 3 closed, 4 initialization
pending, 5 retirement pending and 6 unknown quarantine. Initialization sets
state 4 before calling actual payload 0 and state 1 only after its success.
A valid failure with a still-zero payload context restores state 0; payload
initialization itself allocates no heap object or capability. Unknown
transport/reply facts preserve state 6. They do not manufacture a successful
compensation.

Commit moves state 2 to state 5 before the actual payload 5 call, and moves to
state 3 only after success. State 5 permits repeated commit, while rollback
accepts only state 2. A failed commit cannot reopen an owner whose carrier
registry may already have been destroyed.

The final enclosing sequence is actual Value 52 fence, provider prepare,
private carrier retry and registry destruction, provider commit, and actual
Value anchor consumption/retry. If a step before registry destruction refuses,
the enclosing owner must perform the real provider rollback and Value 53
unfence. The provider's prepare refusal never closes the payload registry.
Provider retry success does not replace prepare's no-active-operation check.

## Operation records and release

Each ordinary provider operation owns a 96 MiB child scratch allocation plus
4096 bytes of native cleanup custody. Its chain node lies exactly 96 MiB after
the allocation base. The provider mutex owns its insertion, claim and removal.

The 64-byte node header contains PID, captured Value nonce, previous and next
links, record state, actual allocation base, extent and provider address.
Record states are 0 active, 1 known pending, 2 claimed by cleanup and 3
unknown quarantine. Its saved continuation is in bytes 128–4095. Retry only
claims an actual linked known-pending node with matching extent and identity;
it does not dereference a caller-supplied cleanup pointer.

A consumed carrier cap is cleared only from actual HA2 known/consumed facts.
Pending carrier retirement invokes private HA operation 7. Value cap release
uses Q02 operation 29 and retries operation 31 after known consumption.
Descriptor slots are cleared only after successful close_range(fd,fd,0).
Allocation slots are cleared only after allocator completion. The final child
allocation is freed before unlinking the node, while holding the provider
mutex, so a failed release leaves actual owned custody available.

The current positive/native component gate includes real Runtime creation,
resource-class capture, old raw-carrier compatibility, an eight-thread
capture/drop race, immutable snapshot payloads, actual conditional publication,
stale/cancel ordering, prepare refusal, owner registry-busy rollback, actual
last-reference retirement, and empty FD/artifact results. It does not upgrade
whole BackgroundOptimizer, final allocator, final enclosing bootstrap or
unknown-corruption recovery to a whole-product claim.
