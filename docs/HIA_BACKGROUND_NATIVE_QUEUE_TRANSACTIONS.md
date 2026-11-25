# Native background queue transactions and actual Job references

This component closes the original queue condition across native submit/account operations and binds the queue to the actual strongly owned Job implementation. It does not qualify the complete BackgroundOptimizer constructor, worker handler, public Future facade, runtime provider, or production installation.

## Actual Job reference provider

The six-word `hia_mv_background_job_refs` entry consumes exactly 64 bytes: `HIABJRF1`, operation 1 (retain) or 2 (drop) at byte 8, and the Job capability at bytes 16, 24, and 32. Bytes 40 through 63 are zero. Its output view is at least 128 bytes.

The immutable captured context is at least 64 bytes: `HIABJRC1`, the actual native Jobs entry at 8, its context at 16, and its extent at 24 (at least 256). Bytes 32 through 63 are zero. The composition owner captures this closure; an external caller does not choose the function pointer.

The provider invokes existing `HIABJO01` Job operations 2 or 3. A successful retain returns an independent nonce capability for the same Job; drop returns zero capability fields. The 128-byte reply is `HIABJRO1`, status at 8, capability at 16, 24, 32. A failed underlying operation retains its actual status. The mechanical adapter only supplies a private 4096-byte continuation view, translates fixed six-word calls, and copies the final public reply. Malformed views/envelopes leave the public output untouched.

## Condition transactions

The existing `HIABGQ01` operations 0 through 9 and their rejection domain remain unchanged. The separate private `HIABGQ02` envelope adds:

| Operation | Behavior |
| --- | --- |
| 10 | Acquire the existing queue mutex, capture the actual thread ID, and return with the condition held. |
| 11 | Verify the actual owning thread, clear its marker, and release the condition. |
| 1, 3, 4, 5, 6 | Execute the existing admit, settle, close, snapshot, or drain operation under this thread's already held condition. |

No caller-supplied thread identity is accepted. The queue context and output remain 4096 bytes. The pending limit remains 1 through 8 and still includes active and cancelled work until settlement. The owner marker at context byte 160 is published with an aligned word store. The original mutex is at byte 128.

A transaction is not recursively acquired. The controller must retain the held-state fact across internal accounting helpers and release it on every error path. Same-thread legacy calls during a transaction, a second begin, a missing begin, a wrong-thread release, and a repeated release are rejected without releasing the real owner's condition. Other threads remain blocked on the original condition. Future callbacks must run after release.

## Actual qualification

The combined fixture uses the native Job-reference provider, actual Jobs, actual Future cells, and the qualified mutable value owner. It passed seven groups covering legacy/external Job ownership, malformed/private views, eight queued Jobs and early input release, worker and shutdown blocking during the held transaction, original/private profile boundaries, and eight actual Job allocation failure positions. The rollback observations are exactly `[n, n-1, n-1]` for attempted allocation, successful allocations and matching frees.

The original queue suite also passed all nine groups: 4990 actual queue calls and 3132 value calls, including concurrent producers, FIFO wrapping, cancelled pending work, callback reentry, real worker identities, and all existing frame/view refusals. The original queue and new provider packers each passed 24 controls. Both policies were independently compiled twice by the actual native source compiler and compared byte for byte. Native HIA packers and the existing HIA shared linker produced the qualified images; assembly tools are used only in the external readable-source provenance check.

All exact source/image/report pins are in the companion qualification JSON. Earlier observer and construction failures remain in external QA records. The complete background service is still open.
