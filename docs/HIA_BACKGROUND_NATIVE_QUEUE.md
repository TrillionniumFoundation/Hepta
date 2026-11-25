# Native background queue component

This checkpoint qualifies the queue kernel. It does not claim that the complete
BackgroundOptimizer, native pthread worker, job/accounting owner or rank/runtime
integration is complete. The original semantic/test map remains in
HIA_BACKGROUND_NATIVE_PLAN.json.

The actual HIA component owns a capacity of one through eight pending jobs,
including the active job. Cancellation never releases that capacity itself.
The single bound Linux worker TID removes a job only when settling it. It
receives a borrowed job reference on take and the same owned reference on settle.
The callback/completion phase occurs after this removal and after releasing the
queue lock. The enclosing BG semantic owner must perform its accounting before
the matching removal, in the same original condition critical section.

A job reference is a node and two random tags from the native job owner.
The queue never dereferences caller-supplied node values. Its fixed provider
clones and drops strong references. Closing with cancellation copies all pending
references in submission order under the lock and returns these owned copies so
that cancellation callbacks run after the lock is released. An allocation
failure unwinds only newly cloned references; it does not lose queued jobs.
Failure-drain validates the complete bounded list before transferring references.

## Private ABI

The export is hia_mv_background_queue(source, source_extent, output,
output_extent, work, work_extent). The three views are disjoint. The request is
exactly 128 bytes, output and shared context are each at least 4096 bytes.
Initialization is exclusive. Context destruction requires no queued/active jobs
and the worker exited, or no worker was bound. Enclosing native owners retain
the context and provider for all active calls.

HIABGQ01 has opcode at 8, and all unused words must be zero. Operations are
0 initialize, 1 admit, 2 blocking worker take, 3 worker settle, 4 close,
5 snapshot, 6 worker failure-drain, 7 bind current worker TID, 8 mark exited,
and 9 destroy. Initialization fields are maximum pending at 16, fixed provider
function at 64 and provider context/extent at 80/88. Admit uses reference
node/tags at 24/32/40 and actual Future workspace/512 at 48/56. Settle has
slot at 16 and the identical reference triple at 24/32/40. Close has
cancel_pending (0 or 1) at 16.

HIABGQR1 is the 128-byte response header. Status is at 8, slot at 16,
closed/pending/queued/active at 24/32/40/48, reference count and owned flag
at 56/64, actual worker TID and exited at 72/80. Active/slot use UINT64_MAX
when absent. Reference entries begin at 512, stride 64: node/tags,
Future pointer/512, slot. Statuses are 0 success, 1 closed, 2 capacity,
3 wrong worker, 4 invalid lifecycle/private argument, 5 clone failure,
65 internal/PID/kernel refusal. Malformed private frames return 0xfffffffd
without changing the owner. Output contains a per-call continuation workspace.

The captured provider receives HIABJRF1, exactly 64 bytes: operation 1 clone
or 2 drop at 8, reference at 16/24/32, then zero. HIABJRO1 output is
128 bytes, status at 8, and a new owned reference at 16/24/32 for clone.
It is not a public injection surface. Product assembly binds it to the native
job owner. Component QA uses a wire-only translator into the already-qualified
HIA immutable-values owner to exercise actual native references.

## Evidence and construction

HIA is compiled by the captured complete native source compiler, then the HIA
packer constructs the ET_REL and the HIA shared linker constructs the SO.
The readable mechanical adapter implements syscall invocation, futex word
atomics and fixed provider calls; queue decisions stay in HIA. GNU assembly is
used solely by the external provenance check to compare the complete readable
adapter with the fixed template, never by the production pack/link path.

The JSON companion retains complete pins and results: nine groups including
all eight capacities, 560 FIFO wrap jobs, 120 blocked native worker wake cycles,
400 submissions from eight threads, clone rollback, ordered failure-drain,
actual Future reentrancy, PID/TID/duplicate-reference controls and private-frame
refusals. Twenty-four packer/provenance controls also pass. The worker threads
and protocol translator in this qualification are external fixtures; they do
not stand in for the still-required native BG worker or business logic.
