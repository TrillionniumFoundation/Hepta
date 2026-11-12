# Native publication and background interruption contract

This document describes the finite Linux x86-64 scalar runtime. It does not
establish arbitrary asynchronous unwinding, crash recovery, a memory quota,
native refinement or a performance improvement. Fresh Core verification,
independent behavior proof, native compilation and image admission remain
required before either publication entrypoint may select a candidate.

## Ownership transfer has one commit marker

`ScalarMultiversionRuntime.publish` and `publish_if_current` share a private
prepared-image ownership transfer. Under the runtime and cancellation locks,
the generation is registered, the selected generation and epoch are updated,
and only then is the commit marker set. Before the marker, an interrupted
registration rolls back all selection fields and removes any partially
inserted generation. The caller retires that unselected image through the
existing release-debt mechanism. Unknown release results remain charged; this
change does not retry native close operations.

After the marker, a reporting, return or retirement interruption must preserve
runtime ownership of the selected image. It cannot unload that image as a
failed preparation. A committed cancellation token still returns false from
`cancel()`. An API exception after this point does not mean that no publication
occurred; conditional-publication callers retain the token and inspect runtime
state. Ordinary-publication callers inspect runtime state; its commit marker
is internal. No new
generation is inferred from an imported receipt or a caller's success flag.

Retirement transfers a generation out of the live table into its unique
retirement record before releasing native capabilities. An interruption after
successful release therefore cannot leave a stale table entry that creates a
second close owner for a reused descriptor. Close revisits still-owned images
after an earlier interrupted close, attempts independent retirements, and then
propagates the first interruption. Unknown native releases remain quarantined
and are never retried by numerical descriptor or loader identity.
If interruption occurs after registering the retirement owner but before
detaching its live row, `retry_cleanup` completes and checks that same transfer
before releasing it. An active/leased or differently bound row cannot be
released through the retry path.

## A failed worker cannot accept or abandon more work

The background coordinator still owns one worker and at most eight outstanding
jobs. An uncaught worker interruption closes admission, revokes uncommitted
publication tokens, drains the queued work without replay, and settles every
accepted future unless that future is already terminal. The host continues to
own the native runtime; stopping the optimizer does not close selected images
or outstanding native leases.

- An uncommitted job receives a rejected `worker_unavailable` result.
- An interrupted, already committed job receives `status: interrupted`,
  `publication_committed: true` and an unresolved `selected_id: null`. This is
  a diagnostic outcome, not a new admission authority or a claim of rollback.
- A future already completed before one of its callbacks fails retains its
  original result. Its callbacks are not replayed. Other queued futures still
  become terminal even if another completion callback raises a BaseException.
- If a cancelling thread is interrupted after cancelling the publication token
  but before cancelling its Future, the worker completes the Future transition
  without repeating token cancellation or optimizer execution.
- `snapshot().worker_failure` is a detached bounded diagnostic record. Ordinary
  prepublication errors remain per-job rejections; they do not automatically
  terminate a healthy worker. A failure after commit stops the coordinator
  instead of silently rebasing subsequent observations onto an untracked head.

Shutdown requests cancellation for every captured pending job even when one
callback raises. It joins when requested and then propagates the first such
exception to the calling thread. Callbacks run outside coordinator and runtime
locks. This does not promise that every user callback itself returns or that
Python can recover from process termination, repeated interruption during
recovery, or exhaustion that prevents diagnostic allocation.

## Executable evidence

`tests/test_hia_publication_interruptions.py` executes actual Clang compilation,
Z3 proofs, sealed loading, native calls and retirement. Faults are injected at
registration, the return from an actual commit, optimizer execution, completion
callbacks and shutdown cancellation callbacks. Synthetic cost observations only
make the lifecycle publication path reachable; these tests are not measured
optimization benefits.

The retained pre-fix counterexamples on source `2f49151` demonstrated an
unregistered live prepared image, a released image left in the generation
table with a prematurely committed token, and a stopped worker with two
unresolved futures. Explicit test-harness cleanup occurred only after recording
those observations and is not credited as runtime cleanup.
