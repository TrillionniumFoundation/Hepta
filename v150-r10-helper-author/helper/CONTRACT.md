# R10 additional private-helper boundary gate

This separate gate compares the real R9 and R10 Core helpers in the unchanged
original `_Machine`. It is not a Native test, not the public checker entry,
and not a substitute for any of the eight retained groups. The actual R10
generation/size/pack and independent terminal-reader result are prerequisites.

The selected ABIs are f22/f24 writes, f23/f25 reads and f92 bounded two-byte
writes. f92 refusal calls the original f21 first-error policy, including its
real byte-40 read, eight-byte write at 40, four-byte read at 24, and eight-byte
write at 104. Neither HIA program is edited for these tests. Both complete
107-function programs are assembled and verified by the fixed source parser
inside the new 180 + 3 second owner, then invoked at their existing private
function names. Every call has 10,000,000 steps, 1 MiB heap, depth 128 and no
allocation-failure override. The top-level storage floor remains 3 GiB.

## Observations and oracle

The observer only subclasses `_Machine.operation` and delegates each actual
operation once. `invoke`, `tick`, allocation, scalar arithmetic, byte access,
permission checks and exception order remain the original implementation.
The observer logs the actual byte attempt and its actual returned byte or
exception. It does not call `_underlying` early, re-execute an access, or write
the HIA workspace. An observation failure stops the gate; it is never filled
from the oracle. This instrumentation is not a performance measurement.

The independent oracle uses direct `(offset + index) mod 2**64` addressing,
value shifts by `8 * index`, and `int.from_bytes`. It does not reuse the new
incremental-address SSA or generated Core. All successful/failed access
events, exact exception type/code/message, return values, resources, view
state and complete actual buffer bytes must agree between R9, R10 and the
oracle. Charged step counts and source identities are retained but deliberately
not required to match. No address-add operation may follow the final actual
byte access in the R10 trace.

The private ABI has one borrowed byte buffer and scalar arguments. The gate
saves that real buffer before and after every call. It does not invent three
F/O/W buffers for this one-buffer ABI. The original eight groups retain all
their full F/O/W requirements. Owner/view expiry and non-mutable arguments
are explicitly private invariant controls; they do not broaden the accepted
public entry ABI.

Cases cover dirty unaligned full-width values, every short extent, large
offsets through 2**64-1 without giant allocations, all two-byte boundaries,
and partial first-error/cursor writes. Both zero and nonzero byte-40 states
are tested. A nonzero byte 40 must still leave the entire buffer unchanged;
a zero byte 40 allows the original complete ordered first-error writes.

All requests, actual before/after buffers, observations, exceptions, complete
VM resources and case comparisons are written before an assertion. A failed
R9 oracle comparison stops before the R10 call for that case. The first
failed pair stops all later cases. Exact original prefix controls and the
full 6,777-file fresh domain are read before and after both parent and child;
no digest cache or skipped source scan is introduced.

The result only claims the finite added helper cases. The original Native162,
logical VM6 and aggregate groups still require their own real runs and
independent full evidence. Prior R9 fuel failure remains unchanged.
