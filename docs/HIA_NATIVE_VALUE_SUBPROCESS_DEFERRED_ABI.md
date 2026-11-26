# Native subprocess exceptions and private exception operations

The sixteen-role HIABVP09 format and its sole Value entry remain unchanged.
The image retains all earlier request domains and adds the operations below.
Every resource, argument, field and exception remains in the same actual arena.

## Canonical exception types

HIABVQ05 operation 110 returns only canonical SubprocessError (71) or
TimeoutExpired (72), selected at request offset 104. Their actual MRO bases
are Exception (22) and SubprocessError (71). Operation 112 returns only
BackgroundOptimizationRejected (73), whose actual base is ValueError (24).
The original operation 101 still rejects every ID above 70. Operation 110
rejects ID 73; operation 112 rejects all other IDs.

These requests are 128 bytes, with A/B/C, tail length, selector 112 and all
reserved fields zero. The returned HIABVR01 contains an owned capability
at 24, known at 88, delivered at 96 and independent cleanup status at 104.
A delivered capability remains the caller's responsibility even when real
subsequent cleanup reports a failure.

Operation 75 builds actual exception instances from the canonical class,
actual args tuple and actual namespace. It retains the original operation
75 semantics. The enclosing public constructor must perform its argument
binding; a wire capture is not presented as Python constructor dispatch.

## TimeoutExpired fields

HIABVQ05 operation 111 accepts an actual TimeoutExpired or real subclass
as A at offset 24. Selector 104 is 0 cmd, 1 timeout, 2 output, 3 stderr, or
4 stdout. Mode 112 is 0 to read or 1 to set. B at offset 48 is the actual
borrowed new value only for a setter; C is zero.

A getter publishes a strong reference to the actual namespace field.
The stdout selector reads the output key. A stdout setter changes that
same output key and publishes None; it does not add a separate stdout
dictionary entry. Direct mutation of the actual output dictionary entry
is immediately visible through stdout. Setters reserve all needed storage
and publish their return capability before committing the field mutation.
A real getrandom EIO before publication leaves the old field untouched.

Fields accept arbitrary actual Values, including mutable containers and
self references. The normal collector traces these real edges and reclaims
cycles. Existing cause/context/suppression operations preserve the fields.
A missing field returns status 3 and a wrong or same-named unrelated type
returns status 2. Original args are retained independently.

## HIABVQ11: one-entry deferred exception and record operations

The new private magic permits exactly these existing operation numbers:

| Operations | Original operation family |
|---|---|
| 32 | Original builtin class lookup |
| 40, 43 | Actual tuple capture and immutable record field |
| 57, 87, 98, 99, 100 | Existing class catalogs and LLVM record |
| 101 through 112 | Platform, chains, Unicode and new exception operations |

Each operation preserves its original request length, arguments, validation
order, output header, allocation behavior and ownership facts. An old
header field is never repurposed: for example, older object-producing
operations keep their actual object identity at 104/112, while platform
operations keep their independent cleanup status at 104.

After the existing 128-byte reply header, the private profile adds:

| Offset | Meaning |
|---:|---|
| 128 | HIABVD01 |
| 136 | Whether a locked native snapshot is known |
| 144 | Actual arena mapping retirement pending |
| 152 | Actual resource or callable-continuation queue pending |
| 160 | 1: this single entry deferred finalizer execution |

The private entry still acquires the real Value mutex, checks all real
capabilities and types, performs allocations and runs the original native
collector. Before releasing that mutex, it reads the resource queue count
from the actual arena, then captures mapping and callable-ledger facts.
It does not claim or execute a native finalizer, change a global defer flag,
discard a queued object, or substitute a cached count for the locked read.

An admission failure before acquiring the mutex reports snapshot_known=0.
Its zero pending fields do not establish that the queue is empty. The
caller must preserve existing custody until a later actual known receipt.
A known queue-only pending result permits the enclosing locked operation
to continue; an ordinary native call after its locks are released can drain
the retained queue. Existing 78/91/92/93 keep their own original deferred
reply contracts.

An actual compiled native function is forbidden from issuing HIABVQ11
through the generic invocation request protocol. Public owner rejection is
a separate enclosing-profile obligation and remains unqualified here.

## Actual validation

This frozen image passed the original six component groups and six complete
campaigns with unchanged 300/660-second campaign budgets and CPython 3.14.4.
All seventeen prior protocol/platform/Unicode/GC/call/custody gates were
rerun against the same image. Seven new exception groups cover canonical
types, actual bases, arbitrary field values, stdout aliasing, subclasses,
cause retention, native raised identity, getrandom failure and real cycles.

Six new deferred groups cover every allowed operation, original error
semantics, actual code-munmap EIO pending through every operation,
getrandom and pre-lock getpid failures, actual cycle collection during
4097 deferred calls, all excluded operations and malformed frames, and an
actual compiled HIA body attempting the private profile.

The first new paired-test run incorrectly equated the identity of two
separately allocated tuples. Its failure is retained. The corrected test
validates each returned identity against that result's actual native query,
while preserving all type, field, publication and cleanup assertions.
Production bytes were unchanged by this test correction.

The Value remains below 4 MiB. The platform catalog now inherits the actual
parent's native MRO through one fixed HIA implementation instead of repeated
literal writer blocks, retaining the original compiler budgets.

Public constructor binding, generic exception string formatting and custom
attribute overrides, trusted resource subclass capture, the real
_OptimizationFuture subclass, and public LLVM logging/origin/output/budget
integration remain unfinished independent scopes.
