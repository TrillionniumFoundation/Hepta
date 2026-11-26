# Managed Future resource owner

This checkpoint binds the HIA Future implementation to one native Value arena.
It proves the component behaviors in
`HIA_NATIVE_FUTURE_RESOURCE_OWNER_MANAGED.json`. It does not mark the whole
public Future, background optimizer, trusted production initializer, or native
callable dispatcher as complete.

## Source and construction

The reusable entry is `python3 -m tools.qualify_hia_future_managed_edges`.
It double-compiles all fourteen current HIA modules with the pinned native
compiler, builds each object and the public flat image using native HIA packers,
and compares the resulting bytes with independent layout calculations. It
checks the assembled adapter bridge against the captured bytes. The Value
dependency is one physically embedded image; the component uses its actual
entry and context.

The public packer is `generate_hia_background_optimizer_future_public_cleanup_packer`,
with `HIABFPP3`, nine roles, a 96-byte header, a per-role limit of 4 MiB, and a
16 MiB text limit. Role order is owner, carrier, timeout, log, cell, kernel,
Value, notify, cleanup. A fusion reuses the eight non-Value roles and points
every Value call at the single captured Value entry.

The component qualifier explicitly initializes trusted bindings as QA setup.
The final production sidecar must perform these captures in native code.
These QA writes are not a production initialization proof.

## Contexts and ownership

The Future global context is 256 bytes. The resource provider context is
512 bytes; its second 256 bytes hold the actual registry. The provider borrows
the Future context and the same Value context, and each live provider record
holds a real Value context token. It does not create a second arena.

| Provider byte offset | Captured fact |
| --- | --- |
| 0 | HIAFRCX2 magic; the original HIAFRCX1 domain remains separate |
| 8, 16, 24 | Actual PID, self address, fixed provider entry |
| 32, 40, 48 | Fixed Future entry, actual Future context, 256-byte extent |
| 56, 64, 72 | Fixed Value entry, same Value context, 256-byte extent |
| 80 | Provider nonce created by native initialization |
| 88, 96, 104 | Mutex, lifecycle state, active calls |
| 112, 120, 128 | Actual pending-record registry capability |
| 136, 144, 152 | Fixed registry entry, self + 256, 256-byte extent |
| 160, 168 | Captured Value binding nonce, actual registry initialization |
| 176 | X2 pending-retry exclusion bit; X1 reserves zero |
| 184 through 255 | Reserved zero bytes |

The native provider checks these facts against its fixed mechanical entry.
Requests cannot choose code or context pointers. Control requests use
`HIAFRCQ1`: 0 initialize, 1 prepare close, 2 roll back the fence, 3 commit
close, 4 retry retained custody. The provider closes only its own registry.
The enclosing owner closes the borrowed Future context after the provider has
really retired.

The component finalizer adapter has a separate 256-byte context because Value
requires that exact finalizer-context extent. Its prefix captures its own
entry/self/PID, the fixed provider entry and 512-byte context, the same Value
entry/context, the Value binding nonce and provider nonce. It validates these
against both native bindings, translates only the nonce domain, and forwards
the actual finalizer receipt. The final fused owner must use one fixed
dispatcher for all enabled resource kinds.

## Canonical construction

`HIAFRQ02` is a 128-byte private request. Operation 0 borrows the actual
factory identity at bytes 16–39 and its owned factory lease at bytes 64–87.
Bytes 40–63 and 88–127 must be zero.

The HIA producer creates the real registry record and context token, creates a
fresh raw Future, clones the factory lease, captures a true Value resource
(kind 7, canonical class 37), derives its weak identity, and binds the fresh
cell before making the canonical Value visible. The raw cell is not exported
during this sequence.

`HIAFRR02` carries status at 8, resource kind at 16, the actual owned Value
capability at 24–47, known at 96, published at 104, and pending at 112.
A true published bit means the caller owns the returned capability even when
independent cleanup reports a failure. The input factory lease remains with
its caller. Failure compensation retains uncertain custody in the actual
provider record and pending chain.

The original `HIAFRQ01` raw compound-capability domain remains available for
its original component callers. It refuses raw alias and query operations on
records that have a canonical weak identity.

## Worker acquisition

`HIAFRQ03` is a 128-byte private request: operation 0, a canonical Future
Value capability at bytes 16–39, and zero remaining fields. The HIA provider
checks the actual resource payload, actual registry membership and exact weak
identity, then creates a genuine strong Value reference.

`HIAFRR03` returns the owned strong Future Value capability at 24–47, a
borrowed factory identity at 48–71, and a borrowed raw Future capability at
72–95. Known, published and pending occupy 96, 104 and 112. The worker may use
that borrowed pair only while it holds the returned strong Value reference.
It releases the reference outside the Future mutexes through the same Value
owner. The request has no entry or context fields.

## Managed edges and deferred calls

The private Future profile is `HIABFP04`; the earlier public frame domains
retain their original behavior. Private operation 30 binds the fresh
canonical resource before its publication. Cell and callback-carrier state
retain a weak canonical identity, not an external Value root.

Actual result, exception and callback-environment capabilities enter the
resource object's GC edge list through Value operation 77 before native
ownership is committed. Operation 79 restores an external root if a failed
commit needs to retain it. Actual caller result copies use fresh external
capabilities. Workers and callback execution acquire a genuine external
Future Value reference while they can still access the cell.

Pure Value operations use the private per-entry `HIABVQ06` deferred domain.
Retain uses 91, ordinary drop 78, actual context-token drop 92, and mapping
retry 93. These operations never invoke a resource finalizer while a Future
mutex is held. Their receipts separate actual capability consumption, arena
mapping retirement, and the shared resource queue. A consumed capability is
cleared from its physical slot exactly once.

Operations 77 and 79 use the original R02 receipt: their consumed bit proves
the atomic ownership transfer even if the global pending bit is set; their
104/112/120 fields remain zero. Operations 78/91/92/93 report mapping pending
at 104, resource-queue pending at 112, and the deferred marker at 120. A
queued parent Future is not treated as an unconsumed child capability.
After all Future mutexes are released, the actual unique Value owner drains
the resource queue with operation 56.

The provider finalizer drives the actual typed Future/factory-lease
consumption and retries, clears only consumed slots, releases its context
token, and removes the true registry record before reporting consumed and
not pending. No Python finalizer decides this sequence.

## Proven behaviors and remaining work

The fourteen recorded groups cover self-result, self-exception, list and
mutual cycles; an independently returned result root; pending callback
environments; callback execution lifetime and native diagnostic cleanup;
canonical native construction, refusal compensation and shared factories;
native worker acquisition and stale/wrong-kind refusal; and eight threads
performing sixty-four real acquisitions without leaked capabilities.

The two callback-execution groups use an explicit QA callback oracle. They
prove the native carrier's ownership and cleanup behavior; they do not prove
the production native callable dispatcher.

The full 27-group Future campaign also passed against this exact runtime
snapshot, including private constructor binding operation 30. Its frozen
source, original assertions, 400-second per-group budgets, Value14 product
267d6ebf and public product 00a2951e are recorded in the qualification JSON.
The final merged Value15 fusion and any later runtime changes must run that
campaign again with the original assertions and budgets.

Remaining integration includes the actual trusted sidecar binder, fixed
native callable callbacks and custom truth protocols, complete background
worker/finalizer wiring, and the retained unknown-delivery recovery campaign.
The qualification flags deliberately keep those domains open.
