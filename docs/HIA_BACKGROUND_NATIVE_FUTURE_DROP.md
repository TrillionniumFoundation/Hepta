# Explicit Future, factory, and global cleanup consumption

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
| 8 | Operation 26 through 29 |
| 16/24/32 | Actual factory identity for 26/27/28; zero for 29 |
| 40/48/56 | Future nonce for 26; factory lease for 27; zero for 28/29 |
| All other words | Zero |

Only operations 26 through 29 are admitted under profile 03. The reply is
`HIABFRP2`, with status at 8, kind at 16, and the existing cleanup diagnostic at
120. None of these operations returns a result capability or an owned exception
value. Older profile replies, including their different use of offset 112,
remain unchanged.

| Operation | Requested action |
| --- | --- |
| 26 | Drop one actual Future nonce and attest its consumption |
| 27 | Drop one actual factory lease and retain any unfinished retirement |
| 28 | Retry an actual retained factory retirement record, identified by FID |
| 29 | Close the global owner, or retry its actual recorded mapping retirement |

| Offset | Meaning |
| --- | --- |
| 96 | `consumed`, 0 or 1 |
| 104 | `consumption_known`, 0 or 1 |
| 112 | `pending`, 0 or 1; zero for op 26 |
| 24/32/40 | Actual FID for an op-27/28 pending retirement; otherwise zero |

These flags describe the current invocation. A nonzero status is not evidence
that every unrelated context resource was inspected. A failure before acquiring
a lock may know that this invocation did not consume a reference without having
observed another thread's pending retirement. A caller must not treat
`pending=0` on an error as proof of successful overall destruction.

### Future nonce: operation 26

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

### Factory lease and registry custody: operations 27 and 28

Operation 27 sets consumption at continuation 183, after the actual lease has
been removed from the linked lease registry and the deallocation effect has
returned. If other independent factory leases remain, it completes normally.
If it removed the last lease, the existing factory registry takes explicit
retirement custody of the actual factory storage. The consumed nonce is no
longer a lease and is never used as a retry token.

The factory's unused private header words now hold this limited state:

| Factory offset | Internal fact |
| --- | --- |
| 128 | 0 ordinary lifetime; 1 retained retirement; 2 retirement claimed by an active call |
| 136 | An actual value-context mapping remains pending after the factory token was consumed |
| 144 | Unknown dependency completion, or a consumed token with an unrecorded cleanup failure; quarantine |

These words are written from actual owner effects while holding the original
factory registry mutex. They are not supplied in the request. Existing checks
still require no independent lease, active call, callback frame, callback
carrier, or cell object before freeing the factory. The cell and token are
retired in their original order.

If retirement cannot finish, operation 27 returns consumed 1, known 1, pending
1 and the actual FID at 24/32/40. The caller clears the consumed lease and keeps
this separate retirement record and its enclosing global storage. It invokes
operation 28 using only that FID. A successful drop with other factory leases
still present has pending 0; it is not a claim that the entire factory is dead.

Operation 28 validates the FID against the real registry. Under the registry
mutex it claims state 1 as state 2, and performs one bounded cleanup attempt.
Another call finding state 2 returns pending 1 without issuing another
retirement effect. The active claimant returns the record to state 1 if work
remains; only actual terminal cleanup unlinks and frees it. An unknown
dependency leaves the record quarantined and cannot be replayed. Operation 28
never consumes the already invalid lease: consumed is always zero. After the
record has actually been freed, a repeated stale FID is rejected; this protocol
does not invent a new completion cache.

Operation 28 is not a substitute for profile-04 cell op 21 while an ordinary
factory lease is still alive. A Future-drop consumer retains its ordinary lease,
performs public op 20 or the appropriate actual cell retry, and observes the
cell's retirement list. Only the last-lease operation transfers ownership into
the factory registry retirement record.

### Value dependency and the global owner: operation 29

The new retirement paths require the separately qualified mutable-value
`HIABVQ02` operations 29, 30, and 31. Its candidate source checkpoint is
`62c0dd36549595c2a98f08e910f1d752bdfb1d0c`, with the precise status-domain
contract at `c41703ff0b2ec662eec8f5fa2d06f581604284e2`, documented in
`HIA_RESULT_VALUE_NATIVE_CLEANUP_ABI.md`. No old value image is silently
interpreted as implementing this candidate contract.
The original value profile remains available to the unchanged legacy paths.

The new value reply is `HIABVR02`, with status at 8 and Boolean pending, known,
consumed at 80/88/96. All other reply words after status are zero. A success
from value op 29 or 30 must be known 1, consumed 1, pending 0; op 31 must be
known 1, consumed 0, pending 0. Unknown or malformed replies are quarantined.
The actual producer's fixed status domain is 0/1/6/11 for operations 29/30,
and 0/6/11 for operation 31. A known consumed reference can accompany only
status 0 or 11. Status 1 additionally requires pending 0. These checks precede
any local capability clearing. Status 999,
or status 1/6 accompanied by consumed 1, is a malformed completion rather than
evidence of reference consumption. In particular, status 11 / known 1 /
consumed 1 / pending 0 is valid and must follow the quarantine rule below;
post-consumption errors do not all have pending 1.

When a new cell drop has touched an object, its actual result Box and context
token use the new value cleanup operations. A consumed Box capability or token
is cleared in the actual retained object before any retry. Actual mapping
pending is recorded separately. Value op 31 retries that captured mapping and
never drops the original capability. A nonzero op-31 result retains the previous
pending record even if the failed invocation could not acquire the lock and
therefore returned pending 0. Only successful op 31 clears that record.

A consumed value/token followed by a nonzero error with no recorded mapping is
different: the capability is cleared, but the object remains quarantined for
the dependency failure. It is not legal to manufacture an op-31 obligation from
this error. Unknown consumption retains the complete original call record and
does not repeat the original effect.

Operation 29 applies the same rule to the global owner's actual context token.
It first checks that the real factory registry and observer registry are empty.
If either remains, it retains the token and returns a nonzero result with known
1, consumed 0, pending 1. Otherwise it invokes value op 30. Consumption clears
the held token exactly once. The existing lifecycle word at global offset 24
now distinguishes live 0, closed 1, actual mapping retirement 2, and unknown
quarantine 3. Only state 2 may invoke value op 31. State 3 retains the global
storage and refuses replay. A successful retry closes the owner; a later call
on the same closed, process-matching context is an idempotent no-consumption
success. Older public operations still reject every non-live lifecycle state.

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
- Actual factory last-lease consumption before retirement failure; retain the
  registry record, reject reuse of the consumed nonce, and complete with op 28.
- Actual value token/anchor last-release `munmap` failure, repeated failure,
  successful op-31 recovery, and the public op-29 global-close path.
- A claimed factory retirement observed by another thread; no duplicate cell
  destruction, token drop, unlink, or free. Keep actual storage until the
  claimant has finished.
- Actual pre-lock retry failures after a mapping was recorded; a returned zero
  pending bit on an error must not erase the previous retirement record.
- Post-consumption dependency errors without a mapping record and malformed
  completion frames; retain quarantined storage without repeating the drop.
- Concurrent state-2 retirement while op 13 returns status 0; op 21 must still
  report pending 1. After real completion it must report pending 0.
- Malformed callee feedback or contradictory consumption claims producing
  public known 0, without replay.
- Same-source construction and final BG/Jobs consumer integration using these
  exact new response profiles.

Development source verification is recorded separately in
`HIA_BACKGROUND_NATIVE_FUTURE_DROP_OFFLINE.json`; it is not any of the live
gates above. The offline author-transition matrix checks the new wire and
continuation facts without executing allocation, memory effects, syscalls,
callee policies, or native code. It does not establish actual concurrency or
kernel-fault coverage.

The development author matrix is retained as
`tools/qualify_hia_future_drop_author_protocol.py`. It takes explicit
`--source-root`, `--baseline-root`, `--dependency-root`, and `--output` paths.
The baseline must be a checkout or exact author capture from the baseline
commit above; the dependency root supplies the original author helpers. Its
output remains offline development evidence, never a runtime authority input.
