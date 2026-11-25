# Native public Future core

This component supplies independently owned Future factories, typed result and
exception methods, typed callback closures, timeout conversion and caught-error
diagnostics. Its fixed native composition has no undefined imports and no host
semantic dispatch loop. Public wait/as_completed, native iterable capture and
the inherited executor setter/running surface remain separate integration
obligations; this document does not claim whole-Future or whole-BG closure.

## Current native construction

The HIA packer composes eight source-built roles: owner, carrier, timeout, log,
Future cell, Future kernel, mutable value owner and actual observer notification.
The final flat image is 1779472 bytes,
`8d0e3366502578eace019e4e6ac5b803d022974fb0a8d27ef3349c51c1556d4e`.
The object is 1780160 bytes,
`bfd5c63769534dd5f151c6c8004f17b45817ab3c9bd03b85874d37ad0110d090`.
Each object and flat was produced twice by the actual HIA packer and matched its
independent development reference byte for byte.

The readable 2412-byte mechanical prefix is
`d0529de50d49c1451b2d7b64d6b5fc2066026bca7ca2e13a1921987777ecfa5d`.
It binds product roles, performs fixed copies, atomics, futexes and system calls,
and supplies the closed mmap allocator. It contains no BG policy. User callbacks
are an explicit typed six-word native callable surface, distinct from product
role substitution. The caller must keep its native callable code mapped through
the closure lifetime. The native runtime owns every captured environment value.

All HIA sources remain within the captured compiler's original bounds:
128 functions, 1536 blocks, 8192 operations, 16 block parameters, and 256 blocks
per native function. The compiler is the captured 494833… native source builder.
Exact source and product hashes, profiles and complete gate results are in the
adjacent qualification JSON.

## Independent ownership

A runtime-owned 256-byte value context record outlives all dependent factories.
The public 256-byte global record owns an independent context token; each
factory and Future cell owns further independent tokens. Dropping a BG factory
lease does not invalidate public Futures, and a retained mutable result can
outlive every Future and factory.

Factory identities and Future references are nonce-checked records. Every
retain creates a distinct reference. Ordinary methods pin their actual cell
before releasing the factory mutex. Completion callbacks execute outside the
factory, Future condition and publication token locks. Per-thread, per-factory
invocation frames preserve the original typed exception through nested calls,
including callbacks that complete another Future or drop the last external
reference.

A failed final release keeps its ResultBox, cell, closure or factory in the
appropriate registry. Retry claims a quarantined cell under its registry mutex
before unlocking; parallel callers cannot finalize it twice. Closure retry uses
the same claim discipline and reads intrusive neighbours again under lock.

## Public core ABI

Entry: `hia_background_optimizer_future_public(s,sN,o,oN,w,wN)`.
Input is exactly 192 bytes with magic `HIABFP01`; output is at least 65536 bytes;
global work record is at least 256 bytes. Null, overflowing or overlapping views
are rejected before writes. All unused request words must be zero.

| Offset | Input |
| --- | --- |
| 8 | Operation |
| 16/24/32 | Factory identity |
| 40/48/56 | Factory lease or Future reference |
| 64/72/80 | Result or closure environment value reference |
| 88 | Native user callback entry |
| 96 | Private completion kind: result 1, Exception 2, BaseException 3 |
| 104/112/120 | Timeout value reference; all zero means None |

| Operation | Action |
| --- | --- |
| 0 | Initialize; words 16/24 contain the actual value context and extent |
| 1 | Create an independent factory and its first lease |
| 2/3 | Retain/drop a factory lease |
| 4 | Create a Future under a held factory lease |
| 5/6 | Retain/drop a Future |
| 7 | Token-aware cancel |
| 8 | Settle already accepted token cancellation |
| 9/19 | Actual accounting state observation |
| 10/11 | Result / exception |
| 12 | Private completion with the indicated value kind |
| 13 | Add a typed native completion callback |
| 14/15/16 | done / cancelled / running in the normal BG lifecycle |
| 17 | Private actual cell borrow under a held factory lease |
| 18 | Destroy the empty global record; live observers also block this |
| 20 | Retry quarantined cleanup |
| 21 | Stable actual identity under a temporary Future retain |

Reply `HIABFRP1` is 128 bytes. Status at 8 is 0 normal, 1 raised Exception,
2 raised BaseException, or 3 invalid capability. Kind at 16 is 0 None, 1 boolean,
2 Future, 3 factory lease, 4 owned mutable value, 5 accounting state, 6 private
borrow, 7 identity, or 200 an owned actual typed exception record. Factory
identity is at 24/32/40, reference at 48/56/64, owned value at 72/80/88, and
scalar at 96. Callback seen/caught counters are 104/112; 120 carries token state
or cleanup-failure detail. Accounting state is 0 pending, 1 cancelled, 2 finished.

Built-in error classes are 100 CancelledError, 101 TimeoutError,
102 InvalidStateError, 103 MemoryError, 104 TypeError, 105 ValueError,
106 OverflowError and 107 RuntimeError. Kind 200 preserves the same owned
native exception dictionary, including its class/message values.

## Typed callbacks and timeouts

The callback receives a 192-byte `HIAFCBQ1` request with factory identity
at 16/24/32, borrowed Future reference at 40/48/56, and borrowed captured
environment at 64/72/80. It may retain these values independently. Its output
view is 8192 bytes; `HIAFCBR1` has kind at 8 (normal 0, Exception 1,
BaseException 2) and an owned return or exception value at 24/32/40.
Other words in the first 128 bytes are zero. A borrowed environment token
cannot be returned as if it were an owned reference.

Ordinary callback Exceptions log their actual class/message and permit later
callbacks. BaseExceptions preserve their owned value identity, stop the current
callback sequence and propagate from the completing call. A Future result
already committed before the callback error remains available.

Terminal Futures are observed before timeout conversion. Pending result and
exception calls implement the original Condition timeout domain, including
bool/int, NaN, infinities, negative zero, subnormals and arbitrary integers.
Positive binary64 seconds are multiplied by 1e9 with nearest-even binary64
rounding, then rounded upward for the native wait. The as_completed deadline
addition/subtraction contract is a separate observer component.

Caught diagnostics stream under a dedicated native log mutex. The test surface
preserves complete Unicode class/message content, including NUL and newlines;
unpaired surrogates use backslash replacement. UTF-8 chunk boundaries and long
messages do not introduce a new aggregate public size limit. This is a native
typed exception protocol, not an interpreter for foreign Python objects.

## Actual final gates

- Core smoke: 5 groups, 85 calls, including result identity and independent lifetime.
- Private requests: 5 groups, 52 calls, 363 reserved-field controls and 11 invalid views.
- Concurrency: 5 groups, 227 calls; 8 simultaneous callback frames, nested same/cross
  factory calls, blocking waits across last external drops, immediate callbacks,
  and 94688 diagnostic bytes with Unicode boundary cases.
- Closed allocator: 20 real kernel ENOMEM cases across construction, retain,
  completion and callbacks. Retry succeeds and every owned mmap is released.
- Shared value arena: 6 groups with 12 real kernel ENOMEM results. Failed growth
  preserves capabilities and the original mapping; retry and final cleanup succeed.
- Packaging: 53 exact construction, rejection and fixed-role checks.
- Cleanup: 2 groups, 108 calls; actual dependency rejection retains custody,
  then 8 threads retry 9 quarantined closures across 3 factories without double release.
- Timeout conversion: 12224 original/native cases, with the same final timeout role.

Two rejected candidates are retained only as failure provenance in the gate
record: a live-factory retry tail that did not terminate, and an unclaimed
concurrent cell retry whose original image actually exited with SIGSEGV.
The final image passes the corresponding controls. No canonical installation,
tool registration, cold-chain release or cleanup authorization is inferred from
these component results.
