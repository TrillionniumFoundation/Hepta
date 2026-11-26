# Trusted native resource subclasses

The sixteen-role HIABVP09 format and unique Value entry are unchanged.
This profile adds two private operations without changing operations 48,
57, 101, 110, 112 or any existing Q01 through Q11 request domain.

## Actual subclass capture: HIABVQ05 operation 113

A request is exactly 152 bytes. A at 24 is the borrowed environment or zero;
B at 48 retains the existing borrowed base/cache meaning; C at 72 is a
required actual class capability. Tail length at 96 is 24. The kind at
104 is 1 Runtime, 2 Lease, 6 BackgroundOptimizer or 7 Future; offset 112
is zero. The tail at 128 is the actual native provider's strong capability.

The real class MRO must contain canonical Runtime 20, Lease 31,
BackgroundOptimizer 35 or Future 37 for the selected kind. The actual
native provider binding, mask, nonce, ownership and capability checks
remain required. A same-named unrelated class does not pass. This profile
currently supports actual plain layout 0; nonempty builtin multiple
inheritance layouts return 18 before consuming native custody.

The resource stores the actual class as a strong GC edge and preserves
the existing environment and base edges. It does not store the class in
the bound-function field. The provider capability is consumed only after
the actual Value capability has been published. A failure before that
point reports known=1/consumed=0 so the enclosing native owner still owns
its provider capability. A published capability remains delivered even
when an independent real cleanup failure occurs.

The original HIABVR01 cap is at 24, pending at 80, known at 88, and actual
provider-capability consumption at 96. For this new capture operation,
104 is actual mapping retirement pending, 112 is actual resource or
callable-ledger queue pending, and 120 is 1 for this deferred entry.

## Actual _OptimizationFuture class: HIABVQ05 operation 114

A 128-byte request has only its magic, operation 114 and argument 104=74
set. It returns the canonical _OptimizationFuture class, with actual
Future 37 as its base and the actual native MRO matching the source
Python class. This uses plain instance layout 0. The original class
catalogs continue rejecting ID 74. Operation 114 rejects other IDs.

Its normal platform reply retains cleanup status at 104. It does not
reuse that field for a different meaning.

## Deferred receipt and lock behavior

Both new operations add this explicit trailer after the original header:

| Offset | Meaning |
|---:|---|
| 128 | HIABVD01 |
| 136 | Actual locked snapshot known |
| 144 | Arena mapping retirement pending |
| 152 | Resource or callable-continuation queue pending |
| 160 | 1: finalizer execution deferred for this single entry |

Both retain actual type checking, allocation, capability validation,
arena locking and native GC. The locked queue snapshot reads the actual
arena. Neither entry claims or executes a native finalizer or changes a
global defer flag. A failure before the snapshot is known is not proof
of an empty queue.

Native callable bodies cannot issue 113 or 114 through the generic
request protocol. The final enclosing public owner must reject both
private operations separately; this component does not claim that gate.

## Native evidence and limits

Nine new groups cover canonical class identity against original CPython,
actual Runtime and Lease subclasses in both ownership orders, strong
class and environment retention, real scalar execution through the
underlying Lease, wrong MRO and stale capabilities, unsupported layouts
and provider masks before consumption, real getrandom EIO before
publication, real code-munmap EIO queue preservation, a class-namespace
and Runtime reference cycle, and eight native calling threads creating
and retiring 64 resources through one later native drain. An actual HIA
body attempting the private operations is rejected.

The same frozen image passed the original six component groups, all six
complete campaigns with the unchanged 300/660-second budgets and
CPython 3.14.4, and all nineteen earlier protocol, platform, Unicode,
call, custody, deferred-operation and subprocess gates.

The new concurrency QA originally assumed the global pending bit had to
be zero while other threads were legitimately retiring resources. The
retained failure was corrected to validate actual pending facts and use
the private deferred drop contract. A following QA-only error incorrectly
expected a HIABVR01 reply from operation 78; the corrected test checks
its original HIABVR02 ownership facts. Production bytes did not change
during either QA correction.

The initial uncompiled author exceeded the unchanged operation budget.
The frozen author reads the actual parent's MRO using fixed HIA logic,
with the original multiple-base construction preserved. The final Value
is below 4 MiB and no compiler profile was enlarged.

Public Runtime subclass constructor dispatch, nonempty builtin multiple
inheritance layouts, actual BG/Future subclass provider integration,
public private-domain refusal, public LLVM logging/origin/output/budget,
and the whole public runtime remain separate unfinished scopes.
