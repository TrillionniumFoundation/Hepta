# Explicit native service context owner

This component owns the existing context creation, identity checks, attempt and
wall-budget decisions, ordinary remaining-time calculation, and evaluation's
single captured deadline. It is explicitly selected by
`HEPTA_HIA_SERVICE_CONTEXT_MANIFEST`. It does not change the default service path,
replace the request journal, replace execution-budget accounting, or authorize
execution from a context record. The original four methods remain as retained
references, guarded against the frozen v74 fixture.

## Held image identity in Agent proof receipts

An Agent service captures its context image once, before its first state or
artifact effect. Its proof producer and ordinary retained-receipt consumer
explicitly pass the same in-process `HeldNativeOwner` capability to the checker.
That capability retains the exact admitted manifest and HIA source bytes and a
strong reference to the immutable executable mapping. Each identity observation
rehashes that actual mapping and checks it against the retained source and
manifest identities. It does not read a later environment selector or pathname
to identify an already-running service.

Two admissions may share a cached immutable mapping while retaining distinct
manifest bytes. A new admission still performs all complete fresh file reads and
readbacks. An old service can continue with its held image after selector or
path changes; a newly selected different mapping cannot consume its proof. A
serialized evidence dictionary cannot become a held executable capability.
Current source changes still encounter the original installation-staleness
checks; holding an image does not waive those checks.

`HELD_NATIVE_OWNERS` is separate from the ambient `NATIVE_OWNERS` inventory.
`checker_native_selection()` and `proof_result()` keep their default empty held
scope for ordinary Core consumers. The Agent explicitly supplies its service
owner when present. The four original reference policies remain unchanged.

The r6 development CI found that appending `NATIVE_SOURCE_FILES += (...)` was
visible to module imports but invisible to the actual wheel build hook, which
reads one literal assignment per resource role. The successor development
harness edits that original literal tuple and preserves all five resource
roles. It does not weaken the build hook, installed-wheel assertions, source
admission, or test deadlines. The original r3 component result remains 45/46
with its installed-wheel failure; its separate original Agent result remains
48/48. Neither result qualifies this revised identity binding.

## Policy and foreign ports

The generated HIA program chooses every continuation action, branch, loop and
rejection. It retains its nonce, sequence, native claim, exact-result permission,
live temporary slots and error-delivery state in a private 128-byte buffer.
Before each object, SQLite or provider operation, HIA consumes a claim. Only the
exact issued result object, exact typed header and matching retained buffer may
authorize that operation. An unconfirmed call or ACK cannot be replayed by
resetting a hosted diagnostic flag. Unknown states retain their buffer and real
object custody; no retry or forget operation is exposed.

For exact Python integers, HIA performs addition, subtraction, multiplication,
comparison, floor division by one million and max with zero. Python provides
only exact-type observation and integer byte representation. Workspace and
result bounds derive from actual operand bytes, with no decimal or bit-width
quota. The shared HIA bigint bodies are preserved mechanically apart from
byte-address helper names. Foreign numbers and rich comparison objects use
separately issued fixed interpreter primitives, preserving their actual
operator, truth, exception and destructor behavior. This explicit foreign
protocol is a hosted dependency, not a whole-HIA numeric implementation for
arbitrary Python objects.

Operand byte lengths A and B determine `capacity=(A+B)//4+4`; four bigint
regions each have `stride=24+8*capacity`, and output has `33+4*capacity` bytes.
The successful ABI returns the fixed 32-byte header length, whose u64 field
carries the actual integer payload length. Inputs wider than the original test
corpus use this same algorithm. Physical address/extent overflow and allocator
failure remain possible, and the HIA representation uses more memory than a
single CPython integer operation. Finite differential tests do not prove
all-input equivalence or equal allocation-failure thresholds.

Schema/profile validation, artifact publication/JSON, SQLite, clocks and the
existing execution-budget provider remain fixed dependencies. Context creation
keeps the original order: publish the artifact, insert the contexts row, then
call `execution_budgets.create` once. A partial effect is not silently rolled
back or retried. `_remaining_ms` re-queries the row on each call. Evaluation
captures its row/deadline once and subsequently samples the clock without new
SQL reads. The original budget limits, SQL/schema, request transaction and
execution authority are unchanged.

## Exception and object custody

A fixed catcher returns the actual error object before the HIA-selected
temporary cleanup begins. Cleanup therefore observes the original outer handled
exception. HIA consumes cleanup claims and then a distinct physical delivery
permission. The shared HIA emitter produces the fixed exception-delivery
mechanism, which calls the actual public CPython `Py_IncRef` and
`PyErr_SetRaisedException` APIs with the GIL held. It preserves the exception
instance, `StopIteration`, cause, context and notes without Python chain repair.
This is a hosted CPython 3.12+ mechanism on Linux x86-64 LP64.

The original error remains strongly owned until the public run handler observes
that same physically delivered instance. An interruption after native delivery
permission is consumed is still unknown. Ordinary errors retain the original
function locals through the delivered traceback; only HIA-authorized temporary
slots are retired. `BaseException` and an actual foreign `ContextUnknown` remain
explicit conservative nonterminal boundaries. They are never formatted as
ordinary terminal service rejections or retried automatically.

Business, integer and exception-emission requests have different exact magic
values. The business and shared-emitter requests are both 64 bytes; length alone
does not dispatch the mechanism. Malformed and neighboring-magic requests are
covered by actual complete-buffer controls.

## Build and selection

Production build:

```sh
python -m tools.build_hia_service_context --compiler /absolute/B3.image.bin \
  --cold-report /absolute/current-cold.json --output /absolute/new-output
```

The builder requires the current complete source contract and original 180+3
cold limits before creating its output. It checks every component input,
strictly typed native compiler receipt, disk receipt and produced image. It
rechecks all consumed source/compiler/cold and publication bytes before returning
the read-back manifest. It never falls back to development selection.

The separate `--development` entry requires an explicitly supplied compiler,
records the actual component input hashes, and grants no source-cold authority.
Build reports retain `production_activated`, `all_input_equivalence_proved` and
`whole_stack_rewritten_in_hia` as false. The selection manifest itself is an
operator-owned executable-code choice, not an equivalence proof or a promotion.

New selections read the manifest, HIA source and actual image bytes afresh,
including cache hits, then repeat those reads after mapping. Duplicate JSON
fields, non-file inputs, non-sibling image paths and drift refuse. A returned
service keeps its immutable image even if the environment or disk later changes.
An active pinned worker bundle remains authoritative; registration of this new
family is a separate parent integration step, not an ambient fallback.

## Tests and qualification boundary

The native tests support one explicit selection among
`HEPTA_HIA_SERVICE_CONTEXT_COLD_REPORT`,
`HEPTA_HIA_SERVICE_CONTEXT_DEVELOPMENT_COMPILER`, or
`HEPTA_HIA_SERVICE_CONTEXT_DEVELOPMENT_MANIFEST`. Dual selections refuse before
output creation. `HEPTA_HIA_SERVICE_CONTEXT_EVIDENCE` holds an exclusive directory
per test class. Cold selection uses the same strict production builder; it does
not relabel a retained development compiler as current-source cold.

Controls retain the original method bodies, real SQLite write order and partial
effects, exact identity/error/temporary lifetimes, actual native preclaim and ACK
interruption, no replay, complete ordinary-VM/native state and canaries, 1,380
integer boundary comparisons, and arbitrary foreign numeric protocol witnesses.
The installed test copies the full five declared resource roles, disables
authoring imports and all four hosted reference methods, and exercises the real
service with its actual installed HIA asset. A development export that adds the
pending resource registration is labeled separately from a production wheel.

The earlier r4 and r5 development checkpoints remain immutable, including all
original failed observations. New builder, installed, source-cold, full Agent and
Python-version results apply only to their actual input hashes. No legacy files
are retired and no all-input or whole-stack closure is asserted here.
