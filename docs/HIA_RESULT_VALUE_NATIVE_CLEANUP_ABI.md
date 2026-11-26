# Explicit mutable-value cleanup facts

This is the fixed candidate integration contract. Source generation and local
language verification do not constitute native qualification. The old
`HIABVQ01` domain and replies remain unchanged.

## Request domain

`HIABVQ02` accepts exactly operations 25 through 31. It rejects every operation
0 through 24 and every operation above 31. Operations 25 through 28 retain the
ordinary `HIABVR01` reply. Only operations 29 through 31 use `HIABVR02`.

All requests use the existing 128-byte layout, followed by an empty tail for
these three cleanup operations:

| Offset | Field |
| --- | --- |
| 0 | Eight bytes `HIABVQ02` |
| 8 | Operation |
| 16 | Zero |
| 24, 32, 40 | Capability A: independent node and two actual nonce words |
| 48 through 88 | Capabilities B and C, all zero |
| 96 | Tail length, zero |
| 104, 112, 120 | Both operation arguments and reserved word, all zero |

Operation 29 drops the actual value capability A. Operation 30 drops an actual
context-token capability A. An all-zero A on operation 30 consumes the initial
context anchor instead. Operation 31 requires an all-zero A and retries only
the already recorded mapping cleanup; it never consumes a value, context token
or anchor.

The exact source and output envelopes and original output/workspace minimums
remain in force. Invalid private framing returns `0xfffffffd` and does not
produce a structured cleanup completion. No consumer may infer consumption
from a malformed or incomplete reply.

## Structured completion

A complete native entry returns zero and emits the following 128-byte header:

| Offset | Field |
| --- | --- |
| 0 | Eight bytes `HIABVR02` |
| 8 | Original value status |
| 16 through 79 | Zero |
| 80 | `pending`: actual retained mapping cleanup recorded under the context lock |
| 88 | `known`: the requested operation's consumption outcome is known |
| 96 | `consumed`: this invocation consumed A or the initial anchor |
| 104 through 127 | Zero |

The three flags are Boolean words. `consumed` is zero whenever `known` is zero.
An unexpected role completion makes the consumption result unknown and requires
quarantine; callers must not retry the same capability on that basis.

The actual producer status domain is closed: operations 29/30 produce only
0, 1, 6 or 11; operation 31 produces only 0, 6 or 11. A different status, such
as 5 or 999, is a bad private reply and must be rejected before any owned slot
is changed. An arbitrary nonzero word is not an accepted dependency status.
The following associations are also required before trusting `consumed`:

- Status 0 has known=1 and pending=0; consumed is one for 29/30 and zero for 31.
- Status 1 has known=1, consumed=0 and pending=0.
- Status 6 has known=1 and consumed=0; pending may be zero or one.
- A known consumed reference can occur only with status 0 or 11.
- The current 29/30 unknown-action path produces only status 11, known=0,
  consumed=0 and pending=0. No other flag combination is a valid unknown reply.
- The current operation-31 producer always has known=1 and consumed=0. A
  different result is quarantined as a bad/unknown private completion.

These checks precede clearing any caller-owned capability. In particular,
contradictory success (status 0 with pending=1) cannot be trusted merely because
its consumed bit is set.

The `known` flag concerns consumption, not a claim that every unrelated context
fact was observed. In particular, an error before acquisition of the context
lock can have `known=1, consumed=0, pending=0`: this invocation did not consume
anything, but it did not establish that another invocation has no cleanup
pending. Only a successful operation 31 establishes that this retained mapping
cleanup is complete. A nonzero status must not be reinterpreted as successful
context destruction.

| Actual outcome | Status | known | consumed | pending |
| --- | ---: | ---: | ---: | ---: |
| 29/30 successfully consumes the reference; other references may remain | 0 | 1 | 1 | 0 |
| Last reference consumed and mapping successfully unmapped | 0 | 1 | 1 | 0 |
| Last reference consumed, actual `munmap` fails | 11 | 1 | 1 | 1 |
| 31 successfully completes the recorded cleanup | 0 | 1 | 0 | 0 |
| 31 is called again on a fully retired context | 0 | 1 | 0 | 0 |
| 31 retries the mapping, and actual `munmap` fails again | 11 | 1 | 0 | 1 |
| 29/30 targets an already closed context with retained mapping, observed under lock | 6 | 1 | 0 | 1 |
| 29/30 targets a fully retired context, observed under lock | 6 | 1 | 0 | 0 |
| Invalid or stale capability in an otherwise active context | 1 | 1 | 0 | 0 |
| 31 targets an active context | 6 | 1 | 0 | 0 |

The pending column does not classify every dependency failure. After an
actual capability was consumed, an unexpected failure of the empty-registry
check can produce status 11 with `known=1, consumed=1, pending=0`. The reference
must still be cleared from its caller's owned slot. There is no recorded mapping
to retry using operation 31, so the context remains quarantined for the actual
dependency failure. Do not require every post-consumption error to have
`pending=1`.

## Persistent context and retry

The external 256-byte context remains alive through cleanup and retains its
state magic, captured PID and original mutex. Successful reference consumption
is recorded at the actual `cap_drop` completion or initial-anchor transition.
It is not inferred from a status code.

Only after the original locked registry check establishes that no reference
remains does the owner record:

| Context offset | Actual retained value |
| --- | --- |
| 80 | Pending flag, one |
| 88 | Mapping address |
| 96 | Mapping byte length |
| 104 | Last failing kernel return, when available |

The existing mapping address and length at context 16 and 40 remain unchanged
until `munmap` actually succeeds. Operation 31 acquires the same mutex, checks
the same captured PID, requires the retired state and consumed anchor, and
checks that 88/96 equal 16/40 before issuing the retry. A successful retry
clears both mapping fields and all four retained-cleanup fields. Concurrent
retries serialize; subsequent ones return the idempotent completed result.

A legacy `HIABVQ01` cleanup failure has no newly attested pending record. The
new operation does not silently adopt such a mapping. Cross-process calls and
inconsistent state fail closed under the original lifecycle policy.

## Consumer ownership rule

On `known=1, consumed=1`, clear the original owned capability immediately, even
when status is nonzero. Preserve the actual context strongly while pending is
one, and use only operation 31 for its mapping retry. On `known=0`, isolate the
object without assuming either consumption outcome. Callback/worker code must
not turn a nonzero drop status into an instruction to drop the same node again.

The actual native qualifier must cover initial-anchor, token and value last
release, actual kernel unmap failure, retry failure, retry success, concurrent
retry, wrong-process use, stale references and the unchanged old request domain.
Those executions remain pending while the native build host is unavailable.
