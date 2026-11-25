# Native worker exit observation

The private HIABGW03 profile accepts only operation 3. It preserves both
existing HIABGW01 and HIABGW02 request domains. The public reply remains
HIABGWO1; output is at least 8192 bytes and context at least 512 bytes.

States 1 and 2 report a live worker without waiting for an outstanding join.
Once the native business entry announces state 3, this query uses the same
serialized pthread join as operation 2. It returns state 4 only after that
actual join completes. Concurrent query and join callers share one join.
A real join error retains the same context and announced state for retry.
The entry rejects queries from a forked process.

This matches the relevant CPython 3.14.4 thread-handle behavior: is_done checks
the exit announcement and then executes the once-only join before reporting
completion. The captured reference source and its SHA are in the JSON report.
The native implementation does not execute CPython.

## Actual qualification

The four exit-observation groups made 84 actual native worker calls. An external
pthread wrapper held the real thread after the native entry had returned, so
the announced-but-not-returned interval was observable. Twelve query callers
and six join callers remained blocked until release, and made one actual join.
Other cases checked live-thread nonblocking observation, native self-query,
three actual join errors followed by successful retry, 23 private guards, and
fork isolation. The wrapper supplies only the scheduling window and native
pthread errors; it does not replace the worker policy.

The same image passed all six original worker behavior groups, all six original
pthread-fault groups, and all 24 packer controls. Every created thread was reaped.
The first combined qualification launcher stopped before the pthread-fault
suite because its new output directory had not been created. That failure is
preserved. A fresh tail run created the directory and ran only the two remaining
suites; the product source and bytes did not change.

This closes the worker exit-observation component. The whole BackgroundOptimizer
constructor, controller, and public lifecycle remain separate work.
