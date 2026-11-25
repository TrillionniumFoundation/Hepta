# Future temporary-reference custody: source candidate

This checkpoint adds a real private cleanup-record owner and connects the public
Future and callback carrier policies to it. It is based on the qualified inherited
Future source `d118f47c189b3047b0457e7fca212e084ea1b93a` and the explicit drop
candidate documented in `HIA_BACKGROUND_NATIVE_FUTURE_DROP.md`.

The original source verifier and the development policy models pass. The new HIA
roles have **not** been constructed by the qualified native compiler, and actual
allocation faults, concurrent cleanup and downstream consumers have not been
qualified. No installed pin or whole-runtime claim follows from this checkpoint.

## Persistent ownership

The public owner reserves a cleanup record before obtaining its first temporary
owned reference. Invalid original Future capabilities are checked before this
allocation. Callback registration first observes the actual environment capability
before reserving its record. The record is linked under the existing global mutex
into the actual factory at offset 152, or the global context at offset 208. Its
lifetime therefore survives the caller output buffer.

A record contains a 128-byte header and 96 bytes for each requested slot. All of
the payload is explicitly zeroed by HIA before it is linked, including both the
64-byte active rows and the 32-byte shadow rows. Correctness does not depend on
fresh anonymous memory or the allocator returning zeros. The development
transport fills each allocation with `0xa5` before the policy initializes it.

An active row is written before a temporary reference is passed to an actual
cell/value drop. The row retains the original capability, the unconsumed
capability when applicable, and the exact known/consumed/pending result. A known
consumed reference is cleared exactly once. Pending cell retirement uses the
existing retry followed by the new locked query. Pending value mapping retirement
uses only value operation 31. Unknown replies and known post-consumption errors
without a retryable mapping remain quarantined; neither replays the original
drop. Repeated adoption of the same original nonce within that record returns
its stored fate without issuing another effect.

The public owner reserves sixteen slots. This is a fixed number of its own
simultaneously live temporaries, not a limit on Future collection size. The first
half of its shadow area captures the complete original call site before a drop;
the second half preserves subsequent moves if a completion is malformed. A
failure must not replace the first half after an old continuation clears its
local slot. Records containing any shadow claim are not automatically replayed
or freed. The actual factory and global destruction checks include these chains.

The carrier uses the same record mechanism for its retained environment during
registration, the temporary Future passed to a callback, and the callback's owned
return or exception value. A failed value observation is not treated as evidence
that the owned return was consumed. The callback environment itself follows the
separate consumed-aware retirement path already recorded by the prior checkpoint.

## Private record protocol

The pure policy has the fixed six-word ABI, exactly 192 input bytes, at least
32,768 output bytes and the existing 256-byte global context. The closed
mechanical wrapper exposes a 128-byte result by allocating a private 32,768-byte
stack frame for that policy. It checks the three caller views before mutation and
copies the result only after a successful policy completion. It does not contain
ownership decisions.

The request magic is `HIABFC01`:

| Offset | Meaning |
| --- | --- |
| 8 | 0 reserve; 1 adopt and drop; 2 release active record; 3 retry one released record |
| 16/24/32 | Actual factory identity, or all zero for the global chain |
| 40/48/56 | Actual record capability for operations 1 and 2 |
| 64 | Operation-1 kind: 1 Future, 2 value |
| 72/80/88 | Operation-1 original owned capability |
| 96 | Operation-0 slot count |
| Other fields | Zero |

The 128-byte response magic is `HIABFCR1`:

| Offset | Meaning |
| --- | --- |
| 8 | Status 0, 1, 4, 5 or 9 |
| 16/24/32 | Reserved record capability on successful reservation; otherwise zero |
| 40/48/56 | Pending, known, transferred Boolean facts |
| 64 | Actual dependency status when relevant |
| 72/80 | Reserved allocation extent and slot count on successful reservation |
| 88 through 127 | Zero |

`transferred` records whether this call's reference entered persistent custody.
It is distinct from the dependency's consumption fact. A transferred reference
whose callee completion is unknown remains owned by the record. Claiming and
releasing a record uses the original global mutex; effects run outside it. Final
unlinking refreshes the actual adjacent list links after the unlocked effect.

## Closed nine-role construction

The old eight-role packer and its request domain remain unchanged. The new
`background_optimizer_future_public_cleanup_packer.hepta` consumes `HIABFPP3`,
count 9, nine actual lengths and a mode word in a 96-byte header. The role order
is owner, carrier, timeout, log, cell, kernel, value, notify, cleanup. Mode 0 emits
the closed relocatable object and mode 1 emits its complete flat image. Each
input retains the existing 4 MiB bound and the combined text retains the existing
16 MiB bound. The standalone readable mechanical source is
`tools/hia_background_optimizer_future_public_cleanup_bridge.S`.

The original source budgets remain 128 functions, 1,536 blocks, 8,192 operations,
256 blocks per function and 16 block parameters. The owner, carrier, cleanup and
packer fit those budgets. Exact source identities and model evidence are in
`HIA_BACKGROUND_NATIVE_FUTURE_TEMPORARIES_SOURCE.json`.

## Remaining qualification and consumers

This checkpoint does not yet close unpublished-factory construction failure,
array observer cleanup or Iterable cleanup. Those paths must preserve actual
storage and capabilities through the same explicit consumption rules. Native
construction, original inherited/public regression, real pre/post-consumption
faults and concurrent cleanup must run on the resulting same-source capsule.
The source models are development evidence, not substitutes for those gates.

The portable development qualifiers write only to
`HEPTA_FUTURE_SOURCE_QA_OUTPUT` (default `build/future-source-qa`) and are not
default production roots. The carrier model also exercises the public and record
models on which its scripted transport depends.
