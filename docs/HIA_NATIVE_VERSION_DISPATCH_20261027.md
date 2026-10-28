# Bounded native entry version dispatch

`hepta.hia_native_version_dispatch.NativeVersionDispatcher` extends the local
interpreter lifecycle experiment with actual Clang compilation and actual
isolated native calls. It provides one baseline, one reproduced candidate, one
background build at a time, explicit generation CAS, per-call image pinning,
retirement after drain, rollback, cancellation of build publication and close.

This is a finite P6 increment. It does not establish in-process instruction
patching, a persistent native worker, callback lifetime management, external
borrow migration, shared application state migration, distributed fencing or
crash durability. It does not complete the general P6 stage.

## Accepted program and native boundary

The caller supplies immutable Core bytes. The existing Core verifier remains
the semantic authority. Primitive v1-v6 is admitted; composite and v7 input is
refused by this lifecycle profile. A candidate must be the baseline itself or
the exact result of the existing registered byte-swap rewrite. Type validity
alone does not admit a different program.

The existing native observer supports one to 32 public exports, each with zero
to 16 homogeneous `i32` or `u32` parameters and one result of that same word
type. Public arguments are exact Python integers in that word's range; booleans,
incorrect arities, unknown exports and out-of-range values reject before a
native child starts. Internal Core functions may own byte buffers and borrow
them normally. Checked Core wrappers can convert an external `u32` parameter
to internal `usize` and an internal `u8` result back to `u32`.

The dispatcher does not accept arbitrary library paths, native callbacks,
executor hooks, caller-provided compilation receipts or model proof flags.
The host selects its trusted Clang command. The same compiler binary identity
and Core implementation identity must remain bound across baseline/candidate
builds. The compiler and host process remain in the trusted computing base;
content hashing is not independent compiler attestation.

## Build and image ownership

The constructor verifies and builds the baseline synchronously. Candidate
submission validates its exact transformation relationship before scheduling
one non-daemon background compiler thread. There is no unbounded build queue.
Only the most recent build-job record is retained, so clients must preserve a
completed receipt before submitting another job if they need an audit history.

Every build reuses `emit_program_llvm` and `compile_program_llvm`. Those functions
regenerate the verified Core lowering, check the native import/export inventory
and publish an identity-bound artifact. The dispatcher then uses the existing
native reader to copy those exact bytes into a sealed Linux memfd and checks
that Core, LLVM, ABI, artifact hash and byte count agree with the build receipt.
The temporary filesystem artifact is removed before the sealed descriptor is
transferred into dispatch ownership. Children later load that descriptor,
not a mutable artifact pathname.

At most two version images are retained. The shared native artifact reader
caps each image at 8 MiB. `max_in_flight` defaults to 4 and accepts 1..16. These
bounds are per dispatcher instance; they do not bound total compiler RSS,
all process RSS or all dispatcher instances in a host.

Two different Core versions may compile to identical native bytes. The build
receipt explicitly records `native_bytes_equal_baseline`. This dispatcher is
an explicit host lifecycle, not a performance-admission policy. Such a
lifecycle exercise establishes no speedup. NDU selection and performance
admission remain separate and do not automatically call `activate`.

## Actual native calls and switching

Each call validates its public signature, locks the current generation and
version, increments that version's in-flight reference, and executes the
existing native observer outside the dispatch lock. The observer starts a
fresh isolated Python/native child, installs its existing pre-dlopen Linux
seccomp policy and resource limits, loads the sealed image, then calls the
selected export. Its established process-group cleanup and bounded output
checks remain in effect. Native timeout is explicitly limited to `(0,10]`
seconds, with a 3-second default.

| Event | Effect |
| --- | --- |
| Submit a candidate | Start a real background build; current generation stays active |
| Wait for a completed build | Return a detached `staged`, `cancelled` or `failed` receipt |
| Activate a staged Core identity | CAS the expected generation; future calls use that version |
| Call already admitted | Keep its captured generation and sealed descriptor through native execution |
| Roll back | Route future calls to the retained baseline; existing candidate calls continue |
| Last inactive candidate call finishes | Close its descriptor and remove it from the version inventory |
| Native return, trap, timeout or observer rejection | Release the dispatch reference in `finally` |
| Close | Reject new submissions/calls/activation; cancel publication and drain admitted work |

A normal result is recorded as `status=returned`. A silent native SIGABRT is
recorded as `status=trapped`, with `native_trap_reason_proved=false`; it is not
labelled as a proven particular VM trap. Observer protocol, signal and timeout
failures retain the existing `HIADifferentialRejected` behavior. Unpinning does
not claim that a Core destructor ran after native abort. The child owns its
private resources, and operating-system process cleanup remains distinct from
language-level drop behavior.

No resource address, callback or task handle crosses this public native ABI.
Each call's internal private resources remain in its selected child process.
This restriction defines the admitted profile; it does not establish safety
for future shared-state, callback, external-borrow or persistent-worker paths.

## Cancellation and close

`cancel_candidate(job_id)` withdraws publication of an unfinished build. A
queued worker may stop before compilation. If compilation has started, the
existing compiler subprocess timeouts remain in force; cancellation does not
claim to interrupt or kill that compiler immediately. A completed cancelled
build has its sealed descriptor closed and is never staged or activated.
Compiler failure also leaves the previous native entry available.

`close(wait=False)` rejects new admission immediately and reports `closing`
while existing calls or a build still own resources. `close(wait=True,
timeout=...)` waits within the explicit bound, then reports whether everything
is drained. A timed-out close keeps that work tracked. `closed`/`drained` means
all owned version descriptors have been released and no admitted call or
compiler task remains; it is not a crash-recovery or distributed guarantee.
The class also provides a context manager for explicit host-owned lifetime.

Example, using a verified Core document with the supported external wrappers:

```python
from hepta.hia_native_version_dispatch import NativeVersionDispatcher
from hepta.hia_swap_opt import rewrite_byte_swap

candidate = rewrite_byte_swap(baseline_bytes).program.canonical_bytes
with NativeVersionDispatcher(baseline_bytes, clang="/usr/bin/clang-20") as host:
    queued = host.stage_candidate_async(candidate)
    finished = host.wait_candidate(queued["job_id"], timeout=30)
    if finished["status"] == "staged":
        generation = host.snapshot()["generation"]
        # An explicit host decision after its separate acceptance policy.
        host.activate(finished["candidate_sha256"], expected_generation=generation)
    observed = host.execute("native_swap", [5, 0, 4, 0])
```

## Executed controls and evidence limits

`tests/test_hia_native_version_dispatch.py` uses real Core lowering, real Clang
artifacts, sealed images and the existing restricted native child. Its finite
checks cover returned values versus the VM; bounds/overflow and allocation
refusal inputs; actual infinite-native-call timeout; incorrect Core relationships
and ABI arguments; generation mismatch; asynchronous build cancellation and
close; a controlled real compiler-command failure; descriptor release; and
concurrent-call admission limits.

The transition tests use Linux PID FDs to suspend and resume an actual spawned
child. While that child is held, activation or rollback changes the future
entry and the old sealed descriptor remains open. The child is then resumed
and its actual result is checked. This observes an in-flight child and version
ownership across the transition. It does not observe a particular loan event
inside the native function: there is no internal allocator/loan handshake in
that test. Build scheduling controls delay the real compiler call and then
allow it to finish; they do not substitute native results or forged receipts.

Finite lifecycle tests do not prove general backend refinement, native trap
causality, Rust safety equivalence, all-input semantic equivalence, real-time
scheduling, production hot updates or performance improvement. See also the
[interpreter lifecycle](HIA_LOCAL_VERSION_DISPATCH_20261027.md),
[Core consumer contract](HIA_PROGRAM.md) and
[NDU candidate contract](HIA_NDU_CANDIDATE_PIPELINE.md).
