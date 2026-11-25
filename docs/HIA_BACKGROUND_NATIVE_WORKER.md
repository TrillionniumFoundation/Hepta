# Native background worker lifecycle component

This component creates a real native pthread. HIA controls its lifecycle,
queue consumption, fixed job-handler invocation, failure continuation and
serialized joining. It is a component qualification, not the complete
BackgroundOptimizer. The job handler used by these tests is an explicit
external fixture; it is not a substitute for the required HIA job, decision,
accounting and runtime/rank implementation.

The enclosing native BG owner captures and holds the queue, handler and their
contexts. It also holds this worker context and image through every active
method and until the actual pthread has been joined. BG shutdown will close
the logical queue and perform cancellations before optionally waiting. A
settled Future remains independently owned by the user's public capability.

## Fixed private ABI

hia_mv_background_worker uses the usual six words: source pointer/extent,
output pointer/extent and worker context pointer/extent. The views are
disjoint. Input is exactly 128 bytes, output at least 8192, context at least
512. HIABGW01 has the operation at 8. Initialize (0) captures queue function,
queue context and extent at 16/24/32, and job-handler function, context and
extent at 40/48/56. Every other input word is zero. Other operations require
all words after 8 to be zero.

Operations are 0 exclusive initialize, 1 start, 2 join, 3 snapshot,
4 internal pthread entry, and 5 exclusive destroy. The internal entry is
invoked only by the fixed mechanical pthread trampoline; it claims the
starting state exactly once and binds the actual Linux TID to the queue.
The public BG adapter must not expose operation 4 as a caller-controlled
authority.

HIABGWO1 output has status at 8, auxiliary value at 16, lifecycle at 24,
actual worker TID at 32, worker terminal status at 40 and join-in-progress
at 48. All later header words are zero. Lifecycle values are 0 initialized,
1 starting, 2 running, 3 ended but not joined, 4 joined, 5 start failed.
Status 0 is success, 4 is a lifecycle refusal, 6 is a pthread error whose
actual positive code is at 16, and 65 is an internal/kernel/PID refusal.
Malformed private frames return 0xfffffffd without modifying the context.

A join invoked by the worker itself returns success with auxiliary value 1
and does not call pthread_join. Concurrent other joiners serialize one real
join using the native mutex and predicate futex; after completion they all
observe the same joined state. An actual join failure releases that claim
and permits a same-context retry. Destroy requires never-started, start-failed,
or fully joined state and no join in progress.

The captured job handler receives HIABGWQ1, 128 bytes, with operation 1 run
or 2 kernel failure at 8; node/tags at 16/24/32; actual Future pointer/512
at 40/48; internal queue slot at 56; failure phase/code at 64/72.
It returns HIABGWR1 with status at 8: 0 continue or 1 stop. On continue,
the semantic handler has completed its original accounting/removal/completion
sequence; on stop, it has closed and settled the logical jobs. The kernel
does not forge a publication or successful accounting result on a malformed
handler response. An invalid response invokes the fixed failure continuation
once and records terminal kernel failure.

The BG semantic owner will maintain its original condition critical section
around logical start, accounting and pending removal. The queue's private
active marker is an implementation detail and is not the public BG snapshot.
Future callbacks execute after the original condition lock is released.

## Native construction and retained boundaries

The HIA packer produces the object and a dedicated HIA shared-link profile
accepts exactly pthread_create and pthread_join imports. The previous shared
linker still accepts only its previous libc import domain. Every layout,
symbol, relocation, size and workspace check is shared unchanged; no original
limit is increased. Objects with no imports produce byte-identical shared
images under the two profiles. Unexpected pthread or allocator symbols are
refused by this dedicated profile.

The mechanical source performs six-word dispatch, futex atomics, actual
pthread_create/join calls and the fixed thread trampoline. It has no BG
selection, accounting or publication decisions. C ABI u32 returns are
explicitly zero-extended after provider/pthread calls. The default construction
does not invoke as or ld; external assembly is solely a full readable-template
provenance test.

## Evidence

HIA_BACKGROUND_NATIVE_WORKER.json records exact source, object, image and test
pins. The 78,608-byte shared image has SHA-256
63ec27b119a0b9d8518c3e284123f310906f5b01434a4c75aa71ccf6bd8bbd83.

Six behavioral groups pass: 40 actual native create/join pairs, 400 FIFO jobs
with native Future completion and self-join controls, 12 simultaneous joiners,
cancelled queue settlement, failure continuation, and private-frame/PID
lifecycle controls. Six actual pthread failure cases cover create codes
11/12/22 and join codes 3/22/35 followed by same-owner retry. The fault shim
only intercepts calls whose instruction address belongs to this native image.
Twenty-four packer/provenance and 34 dedicated linker controls also pass.
The expected Python fork warning belongs to the external observer; the child
calls only the native PID-refusal path. All native worker threads were joined.
