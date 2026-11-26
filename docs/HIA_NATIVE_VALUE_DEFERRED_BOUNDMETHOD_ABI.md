# Trusted deferred native bound-method capture

This independent operation preserves the sixteen-role HIABVP09 format,
the sole Value entry, existing operation 69 and the fixed HIABVQ11 domain.
Operations 70 and 97 retain their original actual user-code semantics.

## HIABVQ05 operation 115

The request is exactly 128 bytes. A at offset 24 is a borrowed actual
source-bound native callable; B at 48 is the borrowed actual receiver.
C, tail length, arguments 104/112 and reserved words are zero.

Preparation acquires the real Value mutex, performs operation 69's
original actual callable and receiver checks, and creates the same native
invocation custody record with strong function, environment and self
references. It releases that mutex before entering the fixed actual code
owner. The code owner clones the registered real code capability. A
request cannot provide an entry pointer, signature flag or replacement
function handler.

The nested resource capture uses the already defined HIABVQ08 operation
48 rather than the ordinary capture entry. Its returned mapping, queue,
deferred and actual consumption facts are validated. Temporary strong
references are retired through actual operation 78. Neither nested step
claims or runs a resource finalizer. A single outer-only defer check would
not establish this property; the whole native binding path is deferred.

After the actual invocation record has retired or entered its real pending
ledger, the owner reacquires the actual Value mutex and recaptures the
actual queue facts. There is no global defer flag, fake lock word or host
production polling.

The original method construction semantics remain: strong self and
function lifetime, actual method type, inherited environment and nested
bound-method argument order. No user callable body executes during the
binding operation itself.

## Reply and ownership

The original HIABVR01 header contract remains intact:

| Offset | Meaning |
|---:|---|
| 24 | Actual delivered method capability, when delivered |
| 64 | Primary disposition, 1 for a method return |
| 80 | Actual mapping/resource/continuation pending |
| 88 | Ownership facts known |
| 96 | Primary capability delivered |
| 104 | Independent cleanup status |
| 120 | Original reserved value 0 |

An actual delivered method remains owned by the caller if subsequent
call-record munmap fails. The pending native record remains in its real
ledger and an ordinary later native entry performs the actual retry and
retirement ACK. A pre-publication allocation or random failure leaves
the original borrowed function and self unconsumed.

This new private operation adds:

| Offset | Meaning |
|---:|---|
| 128 | HIABVD01 |
| 136 | Actual locked snapshot known |
| 144 | Arena mapping retirement pending |
| 152 | Resource or callable-continuation queue pending |
| 160 | 1: this single entry defers resource finalizer execution |

A pre-lock failure reports snapshot_known=0. Its zero queue field does
not prove the existing queue empty. Queue-only pending does not turn a
successfully delivered method into a failed binding. Existing cleanup
status is retained independently.

Other request magic domains continue rejecting operation 115. It is not
added to Q11 or to the set of requests allowed from compiled HIA callable
bodies. Final enclosing public-owner refusal is a separate required gate.

## Actual native qualification

Eight new groups prove ordinary and nested method semantics against
CPython, strong self/function survival, real code-munmap EIO queue
preservation through nested Q08/78 operations, caller capability drops
while the actual code owner is stopped by a kernel notification, original
type/error order and unknown pre-lock failures, actual nested capture
getrandom EIO, actual code-clone getrandom EIO, and post-delivery
call-record munmap EIO followed by one native retry. Malformed and other
domain requests remain rejected, and actual compiled HIA code is unable
to issue this private operation.

The same source-frozen image passed the original six component groups,
all six complete 300/660-second campaigns with CPython 3.14.4, and twenty
earlier protocol, platform, Unicode, invocation, custody, subprocess,
deferred-operation and actual resource subclass gates. Every native role
was double compiled with the pinned original compiler and the complete
Value remains below 4 MiB.

The enclosing Clang/GEN user-call reentrancy and queue lock-order gate,
public private-operation refusal, public LLVM log/origin/output/budget,
and the whole public runtime remain separate unfinished scopes.
