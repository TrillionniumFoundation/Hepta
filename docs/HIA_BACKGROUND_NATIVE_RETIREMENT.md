# Background Job retirement and queue rollback (offline candidate)

This checkpoint contains source changes prepared during the ROG connection outage. The original authoring verifier accepted the generated HIA. Native compilation, native execution, fault controls, and the complete background optimizer are **not qualified** by this checkpoint.

## Why the change is required

The existing Job release removes and frees the caller's nonce before retiring the Future and immutable payload fields. A later dependency failure therefore does not mean the nonce remains live. The old response cannot distinguish this case. Retrying the same nonce is unsafe.

The new private profiles expose the actual consumption point and retain unfinished retirement in the Job owner's registry. Successful payload releases clear their slots before another attempt. Retirement workers claim an object under the registry mutex and read its current neighbours again before unlinking.

## Job profile

Requests retain the 128-byte envelope and 2,048-byte output / 256-byte context minima.

| Magic and operation | Meaning |
| --- | --- |
| HIABJO03 / 13 | Initialise an external-Future Job owner using the same captured role fields as HIABJO02 / 9, with the new cell retirement profiles available. |
| HIABJO03 / 11 | Drop the actual Job capability at offsets 24, 32, and 40. |
| HIABJO03 / 12 | Retry unfinished retirement. All request fields after operation are zero. |

The new response is HIABJOR2. Existing fields through byte 119 retain their meaning. The added words are:

| Offset | Meaning |
| --- | --- |
| 128 | Actual caller nonce consumed: 0 or 1. |
| 136 | Consumption known: 1 for a valid response produced by this owner. A private transport failure without a valid response is unknown. |
| 144 | Cleanup still pending for the operation or the inspected retirement registry: 0 or 1. |

Bad capabilities are not consumed. A capability removed by the actual release remains consumed even when retirement returns an error. A caller clears a consumed capability, retains its enclosing contexts and factory lease, and uses operation 12 for the remaining retirement. It never repeats operation 11 on that consumed nonce.

The source uses private object states for available, claimed, and quarantined retirement. Unknown dependency outcomes are quarantined instead of replayed. Concurrent retry does not claim an already active object.

The captured cell dependency uses HIABFQ04 / 20 for drop, with HIABFR02 consumption at byte 128. After a failed consumed drop, retry invokes the original one-object cell cleanup operation 13 and then HIABFQ04 / 21. The latter reports the actual retirement-list observation at byte 136, with its validity at byte 144. A successful operation 13 alone does not prove the list is empty.

The existing HIABJO01 and HIABJO02 request domains and response formats remain unchanged.

## Reference adapter

HIABJRF2 accepts the existing 64-byte clone/drop requests (operations 1 and 2). Its HIABJRO2 reply keeps the original status and capability fields and adds consumption at 40, validity at 48, and retirement pending at 56. The drop path invokes Job operation 11. Malformed child output produces validity zero.

HIABJRF1 remains unchanged.

## Queue profile

HIABGQ04 permits only operations 4 (close and optionally capture pending references), 5 (capture active reference), 10 (enter condition), and 11 (leave condition). Its response magic is HIABGQR2. Queue state, reference count, ownership, and 64-byte rows retain their existing positions.

If capture fails and rollback cannot release every cloned reference, the reply preserves the remaining rows instead of discarding them. For each remaining row, byte 48 is zero when ownership is known, or one when a child outcome was not interpretable. Such an unknown row must not be blindly dropped again.

The new reply word at 120 is a bit set:

| Bit value | Meaning |
| --- | --- |
| 1 | The reply contains references still owned by the caller. |
| 2 | At least one row has an unknown consumption outcome. |
| 4 | Job retirement cleanup remains pending after a consumed reference. |

A successful ordinary response has this word zero. Existing HIABGQ01, HIABGQ02, and HIABGQ03 domains and response bytes are unchanged.

## Required completion gates

The final native qualification must include the existing Job, reference-adapter, queue, allocation, and packer suites; actual new cell dependencies; pre-consumption and post-consumption failures; one-object cell cleanup followed by an actual empty-list observation; concurrent retirement claims; head and neighbour changes during a lock-free finalizer; payload failures after earlier slots were consumed; queue rollback with retained references; wrong capability, cross-process, and private-frame refusals.

The background business worker, shutdown, snapshot, submission failure paths, and public constructor must consume the new receipts consistently. Their existing successful reports do not qualify these new paths.
