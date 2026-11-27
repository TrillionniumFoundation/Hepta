# Explicitly deferred native equality and hashing

HIABVQ13 is a new private Value request domain. It accepts only operations 62
and 63. Their entire original Q05 request shape, default comparison/hash
algorithm, primary response, and error domain are unchanged. No earlier Q01
through Q12 domain is enlarged.

A request is 128 bytes. Operation 62 has A at 24/32/40 and B at 48/56/64.
Operation 63 has only A. Offsets 16, 72 through 120 and the unused B fields for
operation 63 must be zero. These are actual Value capabilities in the same arena.

The response is HIABVR01. Successful operation 62 returns kind 1 at 16 and the
boolean result at 48. Successful operation 63 returns kind 2 at 16 and its
signed 64-bit hash bits at 48. Neither publishes a capability at 24/32/40.
All original error statuses, including unhashable values, recursive comparison,
invalid capabilities and genuine allocation failure, retain their original meaning.

The fixed extra trailer is:

| Offset | Fact |
| --- | --- |
| 128 | HIABVD01 |
| 136 | Whether the pending snapshot was captured while holding the Value mutex |
| 144 | Actual arena mapping pending |
| 152 | Actual native-resource or invocation queue pending |
| 160 | Exactly 1: this entry deferred automatic finalizer draining |

This applies to one entry only and does not modify an arena-wide flag. The
original Q05 operations continue to run their normal epilogue. A failed
pre-lock syscall leaves the private snapshot unknown. Existing queued native
retirement survives either Q13 operation and is retired by a later real native
drain.

Native callable bodies reject Q13. The coupled owner used for this component's
checks has an older frozen public routing policy; this receipt does not certify
final enclosing public owners' whole-Q13 refusal. Those owners must reject the
entire private domain at their actual public boundary.

The original ten equality/hash/key groups execute through Q13 with all original
oracle assertions unchanged, including numeric cross-kind behavior, exact
dataclass type identity, NaN identity, unhashable fields, cycles, deep structures,
and actual kernel mremap ENOMEM. Additional checks prove exact primary bytes,
real code-munmap EIO queue preservation, actual getpid EIO before the arena lock,
all old-domain refusals, and actual native-body refusal. The complete original
six component gates, twenty-two prior protocol gates, and all six full campaigns
also pass on the exact new image with their original timeouts and assertions.

This private domain supplies the existing default native comparison/hash
operations. It does not claim arbitrary user-defined __eq__ or __hash__ dispatch,
nor completion of the public LLVM origin or output APIs.
