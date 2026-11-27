# Canonical heap-bound exception and private deferred lookup

The fixed Value image appends canonical class **75**, `HIAHeapBoundRejected(ValueError)`.
Existing `HIAStaticBudgetRejected` is class **47** and remains available through operation 99.
No earlier class ID, MRO, operation boundary, or namespace is repurposed.

## Ordinary operation 116

The existing six-word Value ABI accepts a 128-byte `HIABVQ05` request with
operation 116 at offset 8 and class ID 75 at offset 104. All other fields are zero.
It returns the actual canonical class capability at offsets 24, 32 and 40 in the
existing `HIABVR01` response. The capability is a fresh strong token for the same
canonical node; separate lookups do not return identical token bytes.

The class has actual MRO 75, 24, 22, 21, 1. Operation 75 constructs its real
exception object with the original one-element message tuple and actual
namespace `code` attribute. The original class has `args=(code + ": " + detail,)`;
the caller supplies the real values and retains the normal strong graph edges.
Operation 116 is a class query and does not implement or grant resource-budget admission.

## Private HIABVQ12

The new, separately versioned private domain accepts **only operation 116** with
the exact same 128-byte request shape and ID 75. It performs the real class
lookup and token publication while deferring automatic resource finalizer
draining for this one entry. It does not set a process-wide or arena-wide
deferred flag. Ordinary Q05/116 retains its normal behavior.

The old Q01–Q11 domains are unchanged. In particular Q11 does not acquire 116,
and the previous catalog operations do not accept ID 75. Native callable bodies
cannot issue Q12 or operation 116.

The private response retains the complete original R01 result and adds the
existing fixed deferred trailer:

| Offset | Meaning |
| --- | --- |
| 128 | Eight-byte `HIABVD01` marker |
| 136 | Whether the lock-protected pending snapshot is known |
| 144 | Actual arena mapping pending fact |
| 152 | Actual resource or invocation queue pending fact |
| 160 | Deferred-entry fact, exactly 1 |

Original primary delivery and cleanup facts remain independent. A failed
pre-lock getpid leaves the snapshot unknown; it must not be interpreted as an
empty queue. Actual queued code retirement survives a successful Q12 query and
a deferred token drop. A later native drain performs the real retry.

## Qualification scope

The exact frozen image is built twice for every native module with the fixed
494833 compiler and packaged by the original native HIABVP09 packer. The result
remains below the existing 4 MiB Value limit. The original six component gates,
all twenty-one prior protocol gates, and all six complete campaigns run against
this image with their original assertions and timeouts.

Six new native groups cover class identity/MRO, original exception args and
code, actual code-munmap EIO pending, pre-lock getpid EIO, token getrandom EIO,
all prior-domain refusals, and actual native callable-body refusals. No
production callback, prefix, lock word, syscall return, or cleanup ACK is
fabricated.

The coupled owner used for these component checks has the old frozen public
routing profile. This qualification does **not** claim that final public
enclosing owners have adopted their new whole-Q12 refusal, and does not claim
public LLVM origin, output, or bounded resource analysis closure.
