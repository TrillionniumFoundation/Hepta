# Business continuation cleanup after worker exit

This is a source candidate. The original HIA author verifier accepts the
generated policies and packer, and development-source effect traces pass.
There is no claim of native execution, actual pthread exit qualification or
whole BackgroundOptimizer completion for this candidate.

## Why cleanup has a separate fixed entry

The business handler keeps its continuation in the last 1 MiB of its private
context. Its mechanical entry resets the phase before each invocation. The
generic worker can invoke the failure handler after a prior business error,
so the retained phase alone cannot authorize a cleanup continuation. Copying
or resetting this buffer from another thread while the worker still runs
would race its actual state.

The new fixed owner first calls the captured worker's `HIABGW03/op3` entry.
It requires successful state 4, which belongs to the actual serialized join
path. States 1 or 2 leave the business context untouched. It then reads the
worker's own immutable bindings and checks that the handler, context, extent
and queue are the same captured business instance. No public request can
provide an exit flag or substitute those bindings.

Only after this check does it acquire the business cleanup mutex at context
496, publish a temporary claim at 488, and call `HIABGWQ3/op3`. The claim and
mutex remain owned until that call returns. The enclosing native owner must
hold the worker, business instance, code images, factory lease and dependency
contexts through the call and retained cleanup. These private words are not
caller-writable authority fields.

## Closed owner ABI

Fixed six-word entry: `hia_background_business_cleanup(s, sN, o, oN, w, wN)`.
The request is exactly 128 bytes: `HIABGCQ1`, operation 0 at offset 8, and zero
at every other word. Output is at least 32,768 bytes. The 256-byte captured
context is immutable to this policy:

| Context offset | Actual captured binding |
| --- | --- |
| 0 | `HIABGCC1` |
| 8 / 16 / 24 | Business entry, context and extent, at least 1,064,960 bytes |
| 32 / 40 / 48 | Actual worker entry, context and extent, at least 512 bytes |
| 56 | Captured process ID |
| 64 through 255 | Zero |

The 128-byte output header is `HIABGCR1`: status at 8, detail at 16, observed
worker state at 24 and quarantine kind at 32. All other words are zero.
Status 0 means this business continuation has no retained cleanup; it says
nothing about unrelated queue, submission, Future or runtime owners. Status
6 is a lifecycle/binding refusal, 7 a dependency protocol error, 8 an observed
system/join error, and 9 retained quarantine. Quarantine kind 1 permits another
cleanup-only call; kind 2 forbids effect replay.

Different invocation output buffers can share the immutable context. The
actual business mutex serializes them. A repeated completed call observes the
worker and returns without reopening the business continuation.

The 508-byte mechanical bridge performs only system calls, 32-bit atomic
compare/exchange, byte copies and fixed captured six-word calls. It has no
allocator imports. The HIA packer `HIABGCP1` embeds one bounded policy with
the existing 4 MiB component and 16 MiB text limits.

## Business profile and ownership

`HIABGWQ3` accepts only operation 3, with all other request words zero. It
requires the fixed owner's actual claim and mutex, known retained cleanup,
no held queue condition and no active nested execution/account continuation.
The old `HIABGWQ2` domain remains unchanged, including rejection of operation 3.

The policy clears internal aliases for Job, metadata and Future when the
queue/submission records still own them. It never drops those aliases as
independent retains. It releases only owned current references and rows whose
complete queue-to-business ownership transfer was recorded before worker
exit. References are cleared at the explicit consumption point. Remaining
Job, Future/cell and value retirement uses separate retries and never reuses
a consumed nonce.

This operation performs no cancellation, accounting, publication, result
completion or user callback. If an error stopped the original fatal drain
before later jobs completed, cleanup does not invent those completions.
Remaining queue/submission records stay with their real owner. The shared
worker-failure value at business context 512 also remains owned by that
instance for snapshot and final teardown.

Unknown drop results, a condition not demonstrably released, an unfinished
nested owner, incomplete ownership transfer, or an inconsistent private reply
stay quarantined. A retry cannot turn them into an assumed successful cleanup.

## Evidence and remaining gates

`tools/probe_hia_background_business_cleanup.py` runs development-source
effect traces. It checks worker lifecycle states, mismatched bindings, no
write to a live worker's continuation, repeated completed calls, borrowed
references, nine transferred rows, consumed references with retained cleanup,
consumed dependency failures without a mapping, and malformed private replies.
It explicitly reports `native_execution=false` and
`real_pthread_exit_observed=false`.

Before product admission, rebuild the actual worker, value, Job, queue,
Future/cell and business images from coherent new sources. Run the original
business and failure-drain gates, the real pthread return/join window,
concurrent cleanup calls, actual pre/post-consumption allocation and unmap
faults, and final context lifetime checks. The public constructor and lifecycle
owner must also capture these bindings and retain their custody.
