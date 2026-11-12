# Explicit scalar state across native code generations

`hepta.hia_scalar_state.ScalarStateSession` extends the existing
`ScalarMultiversionRuntime` with one host-owned scalar state value. It uses the
same canonical verifier, fresh all-input translation validation, direct LLVM
backend, sealed native artifacts and generation leases. There is no alternate
admission path or imported proof receipt.

This closes a specific gap in the existing empty-state runtime: an application
can retain explicit state while equivalent code is published or rolled back.
It does not establish profitable optimization or general live-state migration.

## Admitted contract

The transition must be an actual exported function in the existing total,
acyclic, effect-free scalar profile. Its first argument and sole result have
the same scalar type. All other arguments are ordinary inputs. For example,
`accumulate(state: u64, delta: u64) -> u64` can return a wrapping sum.

Every candidate is proved equivalent for **all typed arguments, including the
state argument**, to the code runtime's original baseline. Equality on a set
of observed states is insufficient. The runtime still rejects allocation,
loans, resource operations, trapping instructions, external calls, cyclic
control flow, changed ABI, unknown proofs and unbound receipts.

```python
from hepta.hia_scalar_state import ScalarStateSession

# runtime is an actual ScalarMultiversionRuntime with an exported accumulate.
with ScalarStateSession(runtime, "accumulate", 0, max_native_calls=1000) as state:
    first = state.step([7], expected_revision=0)
    runtime.publish(equivalent_candidate)
    second = state.step([5], expected_revision=1)
    runtime.rollback()
    third = state.step([2], expected_revision=2)
    assert (first["state_after"], second["state_after"], third["state_after"]) == (7, 12, 14)
```

State publication is one assignment of an immutable record containing the
value, revision and last transition receipt. A session lock serializes state
transitions. Every request supplies its expected revision; two simultaneous
requests for the same revision can commit at most once. A stale revision is
rejected before native execution. Failed and cancelled native invocations
consume the finite native-call budget. No transition is automatically replayed.

The session owns its state and lock; its caller continues to own the shared
code runtime. Closing a session waits for its in-flight transition and prevents
future requests without closing other users' runtime. Sessions and cancellation
tokens cannot be copied into multiple owners. Snapshot objects are detached
copies, and diagnostic history retains at most 128 events.

## Cancellation and failures

`ScalarTransitionCancellation` is a one-use cooperative token. Its lock orders
an accepted cancellation against the state commit. If `cancel()` returns true,
that transition cannot later commit. A native invocation already accepted for
execution may finish; its result is discarded after cancellation. This is not
thread interruption or rollback of external effects; the admitted native
functions have no external effects.

Cancellation observed before invocation consumes no native call. Cancellation
after invocation and a host exception after native return preserve the previous
value/revision, retain the charged call and release the generation lease.
`cancel()` returns false after a successful commit or a completed failure.
A token cannot be reserved for a second request, including after cancellation.
If an actual native invocation fails while cancellation is also accepted, the
original exception is preserved and the failure is counted with a
`cancellation_requested` event field. It is not reported as a successfully
computed result discarded by cancellation.

If delivery of a successful response is uncertain, the caller can inspect
`snapshot()["last_transition"]` and the revision before retrying. Supplying the
old revision cannot repeat an already committed operation. This protocol has
no persistence, crash recovery, cross-process transaction or arbitrary
asynchronous-exception guarantee.

## Version changes and resource lifetime

Each transition obtains one existing generation lease. Its receipt records the
generation, selection epoch, canonical program hash and actual artifact hash.
Publication and code rollback can overlap that call. The old generation's
sealed mapping remains alive until its lease exits; the state transition can
finish using that exact code even after a new generation is selected.

Code rollback changes subsequent code selection and preserves committed
application state. It never rewinds the state value. If the underlying runtime
is closed during an invocation, its existing lease can still finish, but a
subsequent transition cannot acquire a lease or modify state.

The state schema is exactly one scalar, with no owned heap, outstanding loan,
stack continuation, pointer relocation or schema-conversion function. Those
cases remain outside this profile. The existing native compiler, solver,
dynamic loader, Python host and operating system remain trusted components;
finite native probes do not prove backend refinement.

## Executable checks

```sh
python -m unittest tests.test_hia_scalar_state -v
```

The tests compile and call real native code with the actual solver and sealed
generation loader. They cover publication and rollback with retained state;
unsigned wrapping, signed narrow and Boolean domains; exact ABI and revision
rejection; one-use cancellation before/during execution; charged failures after
actual native calls; concurrent updates; publication, rollback and shutdown
while the old code is leased; close ownership; detached receipts; bounded
history; and refusal of a behavior-changing candidate.

Deterministic thread barriers wrap actual native functions to exercise lifetime
races. Injected host exceptions and invalid return values are negative controls,
not claims that arbitrary native corruption is recoverable. Counts and source
identities belong to the generated test/qualification receipt for that run.
`automatic_profitability_established`, heap/loan migration and crash recovery
remain false in every session snapshot.
