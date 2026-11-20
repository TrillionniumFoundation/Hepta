# Retained HIA generation references and lease closure

`examples/hia_bootstrap/generation_retention.hepta` owns the reference count,
retired state, lease closure and one-time retirement handoff for generations
registered in `ScalarMultiversionRuntime`. The original runtime calls this
owner through `hepta/hia_generation_retention_native.py`. Its state persists
between operations; Python does not reconstruct it from a hosted counter.

This component does not own the entire runtime lifecycle. Selection of the
current generation, publication compare-and-swap, cancellation, the epoch,
generation numbering, locks, proof admission and actual resource effects remain
in their existing implementations. Preparation that fails before registration
still uses the original `NativeRetirement` cleanup path without a generation
retention claim. No prepared-failure takeover or whole-stack completion is
claimed.

## Actual owner boundaries

| Original operation | Retained HIA responsibility | Original host responsibility |
| --- | --- | --- |
| `ScalarMultiversionRuntime.lease()` | Bind a fresh lease cell and increment the exact reference count together | Runtime lock, wrapper allocation, public selection epoch, delivery of the lease object |
| `GenerationLease.call()` / `__enter__()` | Query the bound cell's open/closed state | Per-lease lock, exact scalar ABI admission and the original native function call |
| `GenerationLease.close()` / `_release()` | Close the bound cell and decrement the count together; repeated close cannot decrement again | Per-lease and runtime locks, continuation of original retirement collection |
| Successful publication, rollback and runtime close | Mark the registered old generation retired | Original current-generation/epoch changes, writer lock, cancellation marker and event recording |
| `_collect()` / `_attempt_cleanup()` | Decide readiness and bind a one-time claim to the original retirement task | Register and retain the task first, verify its actual foreign resources, detach the original table row and call the original cleanup implementation |

The `.leases`, `.retired` and lease `._closed` observations keep the types and
meaning used by the original callers. Native observations decode verified state
bytes into exact Python values. Direct writes to private native counters or
closed flags are not a state-import interface. The default unselected runtime
continues to use its original hosted attributes and does not import this optional
adapter.

## Numeric and identity domain

The actual lifecycle starts with zero live leases and changes that count only
through successful acquisition and closure. The native owner supports every
nonnegative count representable by its allocated magnitude bytes. Increment and
decrement operate on arbitrary-length little-endian bytes; they do not truncate
at 64 or 128 bits. Host allocation exhaustion remains an ordinary resource
failure. No new fixed reference-count ceiling is introduced.

The unchanged maximum of 2 through 64 live artifacts limits simultaneous
generation resources. It does not limit total generation numbers, the selection
epoch, or references to one generation. Generation numbers and selection epochs
never enter the native packet. They remain their original Python values,
including the existing mutability of a delivered lease's `selection_epoch`.

Each retained owner, lease cell and original task claim has a nonzero random
128-bit identity, represented by two 64-bit words. HIA checks the owner and cell identity on every
cell operation. The same cell cannot be activated twice or closed through a
different generation's block. These private in-process buffers and the immutable
native image are trusted process state; the checksum is corruption detection,
not cryptographic protection against arbitrary memory modification in that
process. This component introduces no serialized state import, cross-process
publication, durable recovery or arbitrary-Python-object equivalence claim.

## State and wire

The unchanged three-buffer machine calling convention carries:

1. A 64-byte immutable request: magic, operation, owner identity, optional lease
   or task identity, and two zero reserved words.
2. A 64-byte retained lease cell. Generation-only operations leave it untouched.
3. A retained generation block with a 64-byte header and a growable magnitude.

The generation header holds its magic, owner identity, retired/claimed bits,
used magnitude length, checksum and task identity. The magnitude is canonical:
zero has zero used bytes, a positive value has a nonzero final used byte, and
all unused capacity is zero. The cell records its generation owner, lease
identity, open/closed status and checksum. Checksums cover the actual used
state; unused capacity is independently required to be zero.

Operations are initialization, acquire, close, retire, claim, generation query
and cell query. Protocol errors, malformed state, mismatched owner/cell,
retired acquisition and underflow refuse without mutation. A capacity refusal
is returned only after checking that the entire old magnitude is full. HIA
performs this decision before touching any generation or cell byte.

On a verified capacity refusal, Python allocates a larger zeroed block and
copies the original bytes. It retains previous allocations so existing private
memory aliases cannot dangle. Superseded allocations grant no adapter operation
authority; future calls use the one current retained block. The host never
computes or stores a replacement count.

## Allocation failures and uncertain native returns

A complete `NEED_CAPACITY` receipt establishes that no state or cell byte
changed. A subsequent pure allocation `MemoryError` removes the still-inactive
cell's custody registration and propagates the original exception object.
Failure of the initial cell-table insertion is also provably before HIA and
removes only that new registration, even if insertion occurred before the
exception. The public `Runtime.lease()` handler consumes this one-use transport
failure record instead of quarantining a healthy generation. Existing cells,
count, old allocations and resource ownership remain intact, and a later
acquisition can succeed. The record contains no lifecycle policy or count.
It belongs to one retained owner and binds the exact exception and cell objects.
Consumption checks all three identities under that owner's lock and clears the
record. Each subsequent acquire clears any earlier record before entering HIA.
An unmatched error, another owner or another cell cannot use it to suppress a
fence, and consuming it never removes a fence already established elsewhere.

All uncertain native return paths remain different. If a native invocation or
its attestation is interrupted, or a state/cell/receipt is invalid, the retained
owner is fenced and strongly rooted in process-local quarantine. ACQUIRE,
CLOSE and CLAIM are not replayed. The quarantine retains the original runtime,
generation, pending cells and task where one exists. Neither dropping user
references nor garbage collection grants a new resource-release right. A
read-only native query may recover diagnostic state, but never restores effect
authority. There is no production reset, forget or cleanup retry for a fenced
generation owner. This is a finite set of tested interruption sites, not a
proof of arbitrary Python asynchronous exception delivery or native crash
recovery.

## Retirement handoff

The original `NativeRetirement` object is strongly retained before insertion in
the pending-cleanup table. A registration failure before or after dictionary
insertion cannot manufacture a different cleanup holder on retry. HIA only
claims after that exact task is present in the original table. A claimed task
is checked by a read-only query when finishing an interrupted host handoff;
the claim mutation is not repeated to reconstruct state.

The original live row is detached before the actual cleanup attempt. Each
attempt also checks the retained claim, including retries after detachment.
Uncertain `close` or `dlclose` behavior remains owned by the existing retirement
implementation. Repeated lease closure after an already completed retirement
cannot recreate a task or close a reused descriptor. The new owner composes
with both the original retirement implementation and the existing retained HIA
retirement implementation; it does not replace their actual OS effects.

## Selection and qualification

An operator selects an explicit manifest through
`HEPTA_HIA_GENERATION_RETENTION_MANIFEST` before constructing a runtime. Empty,
missing or invalid selection fails before that runtime creates filesystem
resources. Admission checks the current package source even when an image is
cached. A runtime retains that admitted immutable image for its later
generations; ambient selector changes do not change an existing state owner.
Selection failure never falls back to hosted lifecycle policy.

`tools/build_hia_generation_retention.py` requires exactly one matching cold
report or explicit development mode. It binds construction inputs, compiler,
complete native compile output and produced image, then writes the manifest.
Development compiler reuse is component evidence only.

`tests/test_hia_generation_retention_native.py` checks generated-source fixed
point, independent HIA VM and native full-state traces, unbounded arithmetic,
capacity zero writes, owner/cell corruption, original locks, retained object
custody and actual descriptor reuse. Its explicitly labeled GNU as/ld identity
DSOs exercise the actual sealed loading and resource implementation. They are
resource fixtures and do not substitute for the original compiler gate.

`tools/qualify_hia_generation_retention_callers.py` loads all 99 tests in the six
unchanged original modules: multiversion (19), native retirement (19),
publication interruptions (15), scalar state (16), background optimizer (19)
and native profile convergence (11). Original Clang, Z3, Rust where required,
native loading, test time budgets and artifact limits remain in force. The
qualifier rejects skips, expected failures, unexpected successes, missing
starts/stops, source drift, hosted counter/closed-state reads, absent native
operations and mutations outside the original runtime lock. An executable
qualifier is not a passing result; matching-source execution must be recorded
separately for the exact integrated source tree.

CI selects the previously built matching-cold scalar-profile,
publication-measurement and native-mapping manifests during these same 99
original tests. `--require-companion-policies` binds their compiler identities,
records successful native-return counts and image identities for all three,
and forbids each corresponding hosted policy. It preserves the original test
modules and time limits. This combined caller qualification remains distinct
from a full-repository gate.

Whole-stack native closure, backend refinement, universal behavioral
equivalence and arbitrary asynchronous-unwind proofs remain unclaimed.
