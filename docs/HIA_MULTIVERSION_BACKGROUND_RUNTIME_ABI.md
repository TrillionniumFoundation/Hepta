# Private background-to-runtime provider contract

This fixes the composition interface; complete runtime qualification is pending.
Provider hia_mv_background_runtime uses the ordinary six borrowed-view words:
(input,input_bytes,output,output_bytes,runtime_context,runtime_context_bytes).
The fixed HIA owner supplies results; applications cannot acknowledge its effects.
Output must be at least 128 bytes. Input/output are disjoint.

A runtime or reply reference is (node,tag0,tag1), validated against the owner's
live reference registry before dereference. Clone creates a separate ownership
node; drop consumes exactly that node. There is no finite integer reference
counter. BG holds its runtime reference until worker and callbacks have ended.
An in-flight publication also holds the exact Future/token workspace alive.

## Request: HIAMVBQ1

128-byte little-endian header, then spans.

| Offset | Field |
|---|---|
|0|HIAMVBQ1|
|8|1 snapshot, 2 publish-if-current, 3 clone-runtime, 4 drop-runtime, 5 drop-reply|
|16,24,32|Runtime reference node,tag0,tag1|
|40,48|For publication, actual Future/token workspace pointer and extent512|
|56,64|Expected generation and epoch decimal lengths|
|72,80|Candidate raw Core length and optional measurement JSON length|
|88|Original max_prepare_ns, exact integer below 2^63|
|96|Original monotonic preparation handoff or UINT64_MAX for absent|
|104|Bit0 measurement present; other bits zero|
|112,120|Zero|

Publication tails: canonical nonnegative decimal generation, decimal epoch,
candidate raw Core, measurement JSON. No fixed numeric width. Decimal equality
uses the actual immutable selected values under the selection lock. Core and
measurement are freshly captured by native owners.

Snapshot/clone/drop-runtime require 40..127 zero and no tails. Drop-reply uses
40,48,56 for reply node,tag0,tag1, with 64..127 zero and no tails.

Preserve original ordering: clock and input checks, writer lock, closed and
generation/epoch checks, cancellation/time, capacity, generation reservation,
fresh admission/proof/build/load/mapping/probes, final locked comparison/commit.
A reserved generation remains consumed when later preparation fails.

## Completion: HIAMVBO1

Complete structured results return u32 zero and a 128-byte header:

| Offset | Field |
|---|---|
|0|HIAMVBO1|
|8|0 success, 1 original exception, 2 allocation failure, 3 internal owner failure|
|16|1 snapshot payload, 2 publication payload, 3 runtime reference, 4 acknowledgement|
|24,32|Borrowed immutable payload pointer and length, or zero|
|40,48,56|New owned reply/runtime reference node,tag0,tag1, or zero|
|64|Actual publication committed marker, otherwise zero|
|72..127|Zero|

Payload lifetime ends only at drop-reply. BG copies or finishes consuming it
before drop. Publication is never rerun merely because its report was large.
Post-commit allocation failure preserves the committed marker. Private framing
returns 0xfffffffd before an action; short output returns 0xfffffffe before an
action. A failed payload allocation can be represented inline without allocating
another exception. Allocation failure maps to the original MemoryError category.

Publication payload is the original complete publication result as JSON,
including GenerationInfo, epoch, prepare_ns, max_prepare_ns, and optional
measurement admission. Integers remain JSON integers. An original exception
payload is an object with its exact type name and message. The HIA implementation
must not claim that a report grants execution authority.

## Snapshot payload: HIAMVBS1

256-byte little-endian header, then generation and epoch decimal tails:

|Offset|Field|
|---|---|
|0|HIAMVBS1|
|8|Zero|
|16|Bit0 closed, bit1 baseline present, bit2 current present|
|24,32|Current generation decimal length, epoch decimal length|
|40|Total payload bytes|
|48,56|Zero|
|64..95|Baseline canonical Core SHA256|
|96..127|Baseline original input SHA256|
|128..159|Current canonical Core SHA256|
|160..191|Current original input SHA256|
|192..223|Current actual artifact SHA256|
|224..255|Zero|

An absent current has zero-length generation and zero current hashes. This is
the original BG-required private projection, captured in one selection-lock
interval. It does not replace the full public runtime snapshot. Epoch is always
a complete canonical decimal value. BG verifies its supplied baseline against
the actual baseline and uses the current hashes to identify tracked source.

## Same-token commit

Future workspace512: PID8, token state64, token mutex132. Runtime holds writer,
selection and token locks in the original order. It installs the complete
generation and epoch before setting token state2 as the final committed marker.
A pre-marker interruption rolls back selection; a post-marker interruption must
not retire the selected image. Do not call Future operation7 while already
holding its token mutex; the enclosing HIA runtime performs this protected
transition directly on the same strongly retained token workspace. BG only
cancels or observes and never commits.
