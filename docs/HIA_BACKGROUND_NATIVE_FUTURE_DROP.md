# Explicit Future drop consumption

## Status and scope

This is an isolated source candidate based on
`d118f47c189b3047b0457e7fca212e084ea1b93a`. The original source verifier accepts
both generated HIA policies within all existing compilation limits. Native
construction, live retirement faults, and final consumer regression remain
pending while the original ROG endpoint is unreachable. No native qualification
or whole-runtime completion is claimed by this document.

The existing cell `HIABFQ01`, `HIABFQ02`, and `HIABFQ03` profiles retain their
request domains and `HIABFR01` replies. The existing public `HIABFP01` and
`HIABFP02` profiles retain their request domains and `HIABFRP1` replies. This
change does not infer consumption from an old error code.

## Why the new result is necessary

Cell drop unlinks the nonce from the global capability list and the object's
capability list, then frees that nonce. Its following retirement may fail while
destroying the kernel, releasing the result Box, or releasing the value context
token. A failure at this later point cannot restore the nonce. Retrying the old
drop request with that consumed nonce is invalid.

The new consumption bit is set at cell continuation 405, after both unlink
sequences and the nonce deallocation effect have returned. It remains set
through later retirement failure and through public factory cleanup. Before
this commit point it is zero.

## Cell profile 04

The six-word calling convention and existing continuation/effect bridge remain
unchanged. The input is exactly 128 bytes, the output is at least 16,384 bytes,
and the context is at least 256 bytes. Framing errors retain return
`0xfffffffd` and do not produce an admitted reply.

| Input offset | `HIABFQ04`, op 20 | `HIABFQ04`, op 21 |
| --- | --- | --- |
| 0 | Eight-byte magic | Eight-byte magic |
| 8 | 20: drop one nonce | 21: observe retirement list |
| 24/32/40 | Actual nonce capability | Zero |
| All remaining words | Zero | Zero |

No other operation is admitted under profile 04. New operations are rejected
under all older request magics.

The new reply magic is `HIABFR02`. Offsets 8 through 120 keep the cell reply's
existing status and diagnostic interpretation. The following extension is
defined only for this profile:

| Offset | Meaning |
| --- | --- |
| 128 | `consumed`: 0 or 1; op 20 only |
| 136 | `retiring_pending`: 0 or 1; op 21 only |
| 144 | `retiring_known`: 0 or 1; op 21 only |
| 152 | Reserved zero |

Op 20 writes zeros at 136, 144, and 152. Successful op 20 returns status 0 and
consumed 1. A pre-consumption failure returns consumed 0. A post-consumption
retirement failure returns status 9 and consumed 1; the original final-failure
diagnostic at 120 remains available. The nonce must not be dropped again.

Op 21 writes consumed 0. After admission and process/context checks, it acquires
the actual cell mutex and reads whether context offset 40, the retirement-list
head, is nonzero. Only this locked observation sets `retiring_known` to 1.
Entry, process, or lifecycle failure leaves it zero. The result is an observation
at the locked read, not a promise that unrelated concurrent calls will never
create another retiring object.

### The exact meaning of retry

Existing cell op 13 scans the retirement list for the first state-3 object with
no nonce references and no active calls. It claims that object by changing state
3 to state 2 while locked, then releases the mutex and retries retirement. After
one successful retirement it returns. It may also reach the end after skipping
objects another thread has already claimed as state 2. Therefore status 0 from
op 13 means neither that all retiring objects were retried nor that the list is
empty.

A caller that owns a cleanup obligation performs an ordinary op 13 attempt,
then profile-04 op 21. It retains its enclosing factory lease whenever the
query is unknown or reports pending 1. It can complete that cleanup obligation
after status 0 / known 1 / pending 0. A single cleanup attempt does not spin
waiting for another thread's state-2 retirement. Existing cell op 5 remains a
destructive context close and is not repurposed as a query.

## Public profile 03

The public six-word entry keeps its existing output/context extents. Input is
exactly 192 bytes:

| Offset | Meaning |
| --- | --- |
| 0 | `HIABFP03` |
| 8 | 26: drop a Future nonce and report consumption |
| 16/24/32 | Actual factory identity |
| 40/48/56 | Actual Future nonce capability |
| All other words | Zero |

Only op 26 is admitted under profile 03. The reply is `HIABFRP2`, with status
at 8, kind at 16, and the existing diagnostics at 112 and 120. This operation
does not return a result capability or an owned exception value.

| Offset | Meaning |
| --- | --- |
| 96 | `consumed`, 0 or 1 |
| 104 | `consumption_known`, 0 or 1 |

Before the cell effect is issued, a failure is known not to have consumed the
Future nonce. Immediately before issuing that effect, the owner clears known.
It restores known only after validating the actual `HIABFR02` reply, its
status, consumption bit, and reserved claims. A callee protocol failure remains
unknown; it does not infer consumption from status 107 or from a later lookup.

| Result | Required caller ownership action |
| --- | --- |
| known 1, consumed 0 | Keep the original Future capability |
| known 1, consumed 1 | Clear that capability exactly once; retain the factory lease while retirement remains pending |
| known 0 | Keep the original call/cleanup record quarantined; do not replay the effect |

A normal drop is status 0 / kind 0. Invalid capability remains status 3 / kind
107. Lifecycle, syscall, protocol, and retirement errors remain status 1 /
kind 107, the existing built-in RuntimeError classification. In particular,
post-consumption retirement failure is status 1 / kind 107 with known 1 and
consumed 1, not an owned typed exception. Value fields 72/80/88 are zero.
The existing public op 20 retry and actual factory lifetime checks remain in
place; callers must not equate an old retry's status alone with total retirement
completion.

## Required live qualification before admission

The native qualification must construct both policies and the fixed public
capsule from actual HIA, then cover:

- Original request rejection domains, old replies, and inherited Future gates.
- New exact lengths, reserved words, unsupported profile/op combinations,
  process mismatch, stale nonce, foreign factory, and destroyed lifecycle.
- Successful non-last and last drops with known consumption and stale-nonce
  refusal after the actual commit.
- Actual kernel retirement refusal after consumption, followed by genuine
  retirement retry, without double drop or early factory destruction.
- Actual result-Box/value retirement failures, preserving the result object's
  owner and the factory lease until cleanup succeeds.
- Concurrent state-2 retirement while op 13 returns status 0; op 21 must still
  report pending 1. After real completion it must report pending 0.
- Malformed callee feedback or contradictory consumption claims producing
  public known 0, without replay.
- Same-source construction and final BG/Jobs consumer integration using these
  exact new response profiles.

Development source verification is recorded separately in
`offline-verification.json`; it is not any of the live gates above.
