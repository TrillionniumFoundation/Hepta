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
the exact result of its selected registered rewrite. `stage_candidate_async`
accepts `pass_id`, defaulting to `byte-swap.v1`; `full-view-fill-loop.v1` uses
the same public `make_plan`/`prepare_candidate` replay as the NDU candidate
boundary. The build receipt is now `hepta.hia.native-version-build.v2` and
binds the pass ID and canonical plan hash. Type validity alone does not admit
a different program, and the lifecycle does not confer NDU activation authority.

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
| Native return, trap, timeout or observer rejection with confirmed child reap | Release the dispatch reference |
| Child reap cannot be confirmed | Quarantine the call and retain its version/reference until a later confirmed reap |
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
all owned version descriptors have been released, no admitted call or compiler
task remains, and no known native child is awaiting reap confirmation. It is
not a crash-recovery or distributed guarantee.
The class also provides a context manager for explicit host-owned lifetime.

### Unconfirmed native cleanup

A bounded native-child wait can fail even after SIGKILL was sent. Both ordinary
and diagnostic observers now retain an explicit `NativeChildCleanup` owner and
raise `NativeChildCleanupPending` when the direct child cannot be confirmed
reaped. The dispatcher quarantines that actual call: its in-flight count and
sealed version descriptor remain held, rollback cannot retire its image, and
`close` keeps `drained=false`. This is a cleanup error, not a successful native
return, a successful trap observation, or evidence that kernel resources vanished.
Outermost observer cleanup checks the retained child state after file/channel
teardown, so a secondary close exception cannot conceal an unconfirmed reap
and release the image. Bounded secondary-error diagnostics remain attached to
the cleanup owner.

`retry_cleanup(timeout=...)` performs bounded reaps without executing another
native entry. `close(wait=True)` also retries within its own overall deadline;
`close(wait=False)` leaves unresolved ownership tracked. Once the original
Popen confirms a direct-child exit status, the reference is released exactly
once and the diagnostic handle reports recovery. Repeated retries and closes
are idempotent. Reaping does not retrospectively accept the earlier failed
native result or discard its diagnostic history.
Reap attempts use a separate serialization lock with a bounded acquisition and
recompute the remaining wait budget after acquiring it. Metadata snapshots do
not wait behind a process wait; a concurrent retry cannot indirectly hold the
dispatch admission lock through such a snapshot. These are bounded application
waits, not a hard real-time scheduling guarantee.

The original process group is signalled at most once before the first wait.
Retries do not send signals to a numeric PGID that could have been reused after
an interrupted wait. An uninterruptible kernel wait may therefore leave an
explicit quarantine that a caller must retain and recover; no bounded-time
kernel completion or crash-durable recovery is promised. Close/snapshot receipts
are now v2 and expose quarantined call identities and cleanup state. Historical
v1 receipts retain their original scope.

Direct callers of the lower-level native observer receive the same pending
exception and must retain its `cleanup` owner and retry `try_reap` until
confirmation. That helper does not create a dispatcher quarantine or a global
recovery service. The public differential runner can reject and close its
parent-side artifact descriptor while propagating the exception; the child
has its own inherited descriptor. Dispatcher image-lifetime and recovery
claims apply when the caller retains the dispatcher until it reports drained.

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

The original transition tests use Linux PID FDs to suspend and resume an actual
spawned child. They observe an in-flight child and version ownership, without
identifying a particular loan instruction. Build scheduling controls delay the
real compiler call and then allow it to finish; they do not substitute native
results or forged receipts. A separate explicitly instrumented profile now
observes a selected native loan interval, as described below.

## Diagnostic observation of an actual loan

`diagnostic_loan_site=(function, block, loan)` is an explicit constructor option.
It builds diagnostic images through `hia_native_loan_probe`, separately from
ordinary `emit_program_llvm` / `compile_program_llvm` publication. Ordinary
emission and its import whitelist remain unchanged. A diagnostic image cannot
enter `execute`; its caller must use `start_loan_probe`, wait for the real
native observation and explicitly acknowledge resumption.

The selected Core site must be one `borrow.read` or `borrow.mut` from a local
`buffer.new` / `buffer.try_new` in the same block, followed by one matching
`loan.end` in that block. The selected function may not call itself directly
or transitively: recursive re-entry would make a single first-occurrence state
ambiguous. Calls to other functions may occur while the loan is held, including
the registered fill-loop candidate's internal borrowed-view call. A loop may
execute the selected block again; only its first dynamic occurrence is observed.

The diagnostic emitter re-verifies Core, emits the ordinary LLVM, and replaces
exactly one uniquely matching function body with a deterministic re-emission.
After the selected borrow it calls a fixed internal helper. That helper samples
the actual view extent and first/last bytes (no dereference for an empty view),
writes one 40-byte event, and blocks on one acknowledgement byte. After the
selected `loan.end`, a second helper observes the now-available owner before
the next Core operation, including any drop. The normal result remains subject
to the existing exact scalar output protocol. A native abort or timeout retains
partial events and never invents a loan-end or a language-level destructor.

The added observations make previously unread bytes observable. The diagnostic
emitter therefore preserves Core's zero initialization for allocations in the
selected function, even when the ordinary emitter can omit that initialization.
This diagnostic difference is recorded in the site witness. These images do
not support a timing or performance comparison with ordinary native images.

The protocol has one fixed configure export, two internal Linux x86-64 syscall
helpers and no new ELF imports. The helpers can perform only the fixed read and
write calls emitted by the trusted diagnostic implementation; Core input cannot
provide inline assembly or a callback. The child inherits only the sealed image
and its two pipe endpoints, retains the exact ordinary observer's pre-dlopen
seccomp policy and limits, and receives no ambient loader environment. The
parent accepts at most two exact, ordered records, checks their magic, extent
and byte fields, and sends at most one acknowledgement. Kernel process-group
cleanup and bounded reap still apply on success, failure and timeout.

Build receipts retain the Core hash, ordinary and diagnostic LLVM hashes, full
diagnostic IR, exact function/block/instruction witness, compiler identity,
diagnostic implementation identity, ELF inventory and sealed artifact hash.
The same instrumented images are used by the dispatcher's actual version pins;
the tests do not observe a separate library while switching an unrelated image.

```python
with NativeVersionDispatcher(
    baseline_bytes,
    clang="/usr/bin/clang-20",
    diagnostic_loan_site=("swap_candidate", "entry", "loan"),
) as host:
    queued = host.stage_candidate_async(candidate_bytes)
    staged = host.wait_candidate(queued["job_id"], timeout=30)
    call = host.start_loan_probe("native_swap", [5, 0, 4, 0], timeout=8)
    observed = call.wait_active(timeout=5)
    # The actual old image is waiting inside its selected loan interval.
    host.activate(staged["candidate_sha256"], expected_generation=0)
    call.resume()
    result = call.wait(timeout=10)
```

`tests/test_hia_native_loan_probe.py` exercises actual borrowed storage while
activation, rollback and close occur, and checks the old descriptor remains
open until that call drains. It covers actual mutable/read loans, empty views,
initialized bytes, cross-call fill, trap before and during the loan, withheld
acknowledgement timeout, exact call budgets and malformed protocol negatives.
Synthetic parser negatives are labelled separately from actual native runs.

This evidence observes a selected loan and endpoint bytes. It does not observe
every byte or the full resource ledger, prove an uninstrumented instruction
schedule, or add support for external borrows, callbacks, shared state,
persistent workers, asynchronous tasks or in-process patching. Native borrow
instructions are normally aliases and `loan.end` normally emits no machine
instruction; the diagnostic witness makes their verified Core locations
observable under the trusted compiler. It is not a backend-refinement proof.

## Retained lifecycle qualification

`tools/qualify_hia_native_loans.py` runs seven fixed native child calls from
`examples/hia_native_lifecycle/swap.json`: a baseline call spanning activation,
a new candidate call, a candidate call spanning rollback, a trap during a loan,
an allocation-refusal input before the loan, a withheld-acknowledgement timeout,
and a candidate call spanning close. The expected finite denominator is four
returns, two traps and one timeout; six loan-begin events and four loan-end
events. The timeout and trap keep their partial observations.

The producer retains all three actual sealed images (baseline and two actual
candidate builds), complete build receipts, diagnostic LLVM, canonical Core,
raw loan observations, per-version dispatch snapshots and source identities.
It requires a new output directory outside the checkout and checkpoints failures.
`execution_passed` describes the seven actual controls; `ok` additionally requires
committed unchanged source and fully drained tracked work. A development run on
uncommitted source cannot become a frozen qualification through a success flag.

The producer and loan-observation receipts are now v2. Counts separate attempted
calls, positively observed child starts, confirmed direct-child reaps and
completed control observations. A successful Popen proves child creation, not
that the HIA entry was invoked: loader/setup failure is still possible. A loan
handshake or canonical returned value records an observed native entry. Failed
process creation without a returned PID retains an unavailable start outcome;
it is not silently counted as zero or as a successful spawn. Missing entry
evidence leaves `native_entry_invocations=null` with an explicit unavailable
denominator. For the seven passing fixed controls, all seven children are
observed/reaped, while the pre-loan SIGABRT still does not independently prove
entry invocation or trap cause.

`tests/test_hia_native_cleanup_quarantine.py` adds actual-child fault controls:
it observes real exit with WNOWAIT before deliberately refusing reap confirmation,
checks retained images and `drained=false`, and then uses the original wait to
reap that exact child. It also exercises repeated close/recovery, diagnostic
timeout, failed Popen, and a real child that stops before loading the HIA image.
Additional controls combine a real exited child with injected temporary-file
or pipe-close errors, and hold one actual reap while another thread requests
a zero-timeout retry, a snapshot and a short close. The close errors occur after
the real descriptor close, and test cleanup reaps every observed exited child
even when exercising a defective implementation.
No live orphan or synthetic successful native result is used by those controls.

```sh
/usr/bin/python3 tools/qualify_hia_native_loans.py \
  --clang /usr/bin/clang-20 \
  --output-directory /absolute/path/to/new-native-loan-evidence
```

This producer is an additional scoped gate; it does not silently replace any
gate in the unified qualification inventory or convert this diagnostic fixture
into a production hot-update or industrial workload result.

Finite lifecycle tests do not prove general backend refinement, native trap
causality, Rust safety equivalence, all-input semantic equivalence, real-time
scheduling, production hot updates or performance improvement. See also the
[interpreter lifecycle](HIA_LOCAL_VERSION_DISPATCH_20261027.md),
[Core consumer contract](HIA_PROGRAM.md) and
[NDU candidate contract](HIA_NDU_CANDIDATE_PIPELINE.md).
