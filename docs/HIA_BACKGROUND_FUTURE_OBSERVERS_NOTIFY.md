# Native public Future observer notification

This is the allocation-free completion notification component. It does not
claim a complete public wait, as_completed, iterable adapter, or background
controller.

The fixed six-word entry takes a 64-byte HIABFN01 request: the actual retained
kernel identity is the little-endian word at offset 8; bytes 16 through 63 are
zero. Its output view is at least 8192 bytes and its global context is the
existing 256-byte HIABFPS1 context. It returns zero with a 128-byte HIABFNR1
record: status at 8, matching subscriptions at 16, newly queued events at 24.
A malformed request or invalid/aliased/overflowing six-word view returns
0xfffffffd; an invalid context or registry records status 107.

The global mutex at 32 protects registry head 48 and all registered queues.
Each observer owns its Future vector, identity hash table and N-slot queue
before publication. The notification never allocates, appends a particular
Future at most once, and uses actual lock acquisition order. The observer's
word at offset 248 is a sticky readiness flag. Notification sets it to one
and calls FUTEX_WAKE_PRIVATE while still holding the registry mutex. The
consumer may clear it only under that mutex after confirming an empty queue.
The global 32-bit sequence at 40 is additional diagnostics/wakeup state and
is never sufficient evidence to sleep. An observer cannot be freed until it
has been unlinked under the same mutex.

The policy uses only fixed syscall, compare/exchange, address translation and
byte-copy effects. The checked mechanical bridge contains no event or
lifetime policy. The HIA packer actually produces bridge plus policy from
HIABFNPK + policy_length + zero16 + policy with an independent output extent
check. Development assembly is an exact mechanical-prefix verification.

The companion JSON records source pins, two equal source-bound native builds,
actual HIA packing, 36 component controls and 4620 actual native calls,
including eight concurrent producers, 2051 distinct events seen in identical
order by four subscribers, duplicate suppression, and a real sleeping futex
woken while the diagnostic global counter wraps. These tests use opaque
fixture kernel identities; integration with actual public Future objects
remains a separate required gate.
