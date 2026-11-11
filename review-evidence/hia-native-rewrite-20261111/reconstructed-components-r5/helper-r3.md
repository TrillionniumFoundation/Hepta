# Native helper transport — reconstructed r3 development handoff

## Identity and status

This is a new, source-bound development revision after replacement of the
execution environment. It implements the complete helper request transport and
helper response/continuation owner in HIA. The reference owners remain present.
It does not activate a new default, remove hosted code, or claim cold
qualification, a complete native composite driver, or whole-stack closure.

The earlier helper r1 raw archive was lost before a durable checkpoint. Its
historical observations are not counted here. Two authoring files were recovered
byte-for-byte: the top-level generator and reply authoring. The shared common
and request authoring were reconstructed under a new identity; both generated
images were compiled again and independently exercised.

The six production files are frozen in
`checkpoints/source-reconstructed-r3/source.json`
(SHA-256 `09a776716e07b6d1a47cf22cc858fe45da591ee0f6d2f88023c1c265565feb27`).
That original source snapshot says UNCOMPILED because it was made before
compilation. The subsequent compile bundle and all five execution summaries are
separate evidence of the actual compilation and execution of those same bytes.

| Component | Functions | Blocks | Instructions | HIA source SHA-256 | Image SHA-256 |
| --- | ---: | ---: | ---: | --- | --- |
| Request | 59 | 946 | 3221 | `8eaafadb953c5f2bf81094800e3fb93773ec9b07a79a785ff3b4fc6c526eaec3` | `67db83d79a0b8d721842cbf85166e92bca66b46226f6b1691e21762b01a0eae4` |
| Reply | 44 | 854 | 3109 | `511b0f053edfe29bccc508ac691c2678a1ad1072196ac7662536354024e4de57` | `fe972083aab6e1e6160a532e07ae28c41e596636e73bc8a7c049fbd3bd706e49` |

Use `development/compile-reconstructed-r3/bundle.json`, not the earlier r2
bundle. The compiler was the exact recovered f50 B3, 668608 bytes, SHA-256
`0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8`.
The actual subprocess receipts retain 10 CPU seconds, 20 wall seconds, 256 MiB
address space, and the existing compiler limits. The language limits were not
raised. Both HIA modules fit within the original 128-function, 1536-block and
8192-instruction limits.

## Ownership

The request kernel consumes complete seven-item helper metadata from the
existing native ObjectToken-to-IR owner:

```
[6, taskID, stepID, operation, serial, pollEffects, cancelEffects]
```

It binds the IR and source-index lease to the caller request, task session and
last completed type command. It issues real QUERY requests to the frozen type
transport owner, copies the complete returned descriptors into its own arena,
and constructs the complete original eleven-item helper input packet:

```
[serial, operation, task.flat, task.state.flat, task.result.flat,
 step.flat,
 [[variant, [field.flat for each field]] for each step variant],
 task.poll, task.cancel, pollEffects, cancelEffects]
```

The sixteen primitive identifiers are converted to their exact primitive names
by HIA. All names, list ordering, effects, empty lists and zero-width layouts are
preserved. No hosted helper plan, descriptor selection, flat-list conversion,
packet construction or helper JSON interpretation occurs in the forwarding
loop.

The reply kernel validates the actual helper header and workspace association,
parses the complete helper JSON envelope using the preserved private JSON
grammar, validates the original helper envelope, emits the entire typed helper
value, and constructs the exact function continuation. Errors 1, 2 and 3 remain
numeric values; they are not collapsed to boolean failure.

Full thirteen-field descriptor semantics, DAG validation, issued identifiers and
cross-command registry ownership remain with the frozen native type-transport
r2 owner. The helper kernel retains its own copies of the descriptors it needs;
no descriptor string or graph refers into a reusable type output buffer.

## Fixed ABI

Both images share one private, one-shot GROW workspace. The external ABI has two
input buffers plus the mutable workspace; internally both inputs are borrowed
read-only. A complete workspace is at least 4096 bytes.

At workspace offset 256, the initial configuration is sixteen little-endian
u64 words:

```
[HIAHRI01, helperLease, irLease, irStream,
 functionRequest, functionSerial, functionSlots,
 typeLease, lastCompletedTypeCommand, firstQuerySeq,
 0, 0, 0, 0, 0, 0]
```

The request image first receives the actual metadata IR as its first input and
its exact source-index lease as its second input. When waiting for a descriptor,
it receives the actual 128-byte HIATRE01 QUERY event and the corresponding
current type-transport workspace. The reply image receives the complete actual
HIATHP01 frame and its actual helper workspace.

A successful ABI call returns 256 and publishes this 32-word HIAHRE01 event at
workspace offset zero:

| Words | Meaning |
| --- | --- |
| 0–3 | Magic, action, helper lease, function request |
| 4–7 | IR lease, IR stream, type lease, last completed type command |
| 8–11 | Query sequence, query identifier, starting serial, final serial |
| 12–15 | Numeric helper error, helper name ID, wire offset, wire bytes |
| 16–19 | Helper-value offset/bytes, continuation offset/bytes |
| 20–23 | Name offset/bytes, required GROW size, refusal reason |
| 24–26 | Actual header copy offset/bytes, actual helper frame extent |
| 27–31 | Zero |

| Action | Value | Executor operation |
| --- | ---: | --- |
| QUERY | 1 | Forward the complete query wire to the actual type command image |
| GROW | 2 | Grow this workspace and replay the same immutable local inputs |
| CALL_HELPER | 3 | Call the actual helper image with the complete packet view |
| DONE | 4 | Consume the complete helper and continuation views |
| REFUSAL | 5 | Dispose of the failed lease |

The ABI failure return is `0xfffffffd`. It takes precedence over any old event
bytes. Once the workspace is large enough to hold the state, a protocol failure
permanently refuses both entry points. A shorter buffer cannot physically carry
a poison state; the fixed driver must dispose of the lease on every ABI failure.

DONE word 8 is the last consumed QUERY sequence. A subsequent helper uses that
value plus one; a session that has not queried starts at one. GROW never asks the
driver to issue another QUERY or invoke the helper again. It replays the same
local input bytes after copying the existing workspace to a larger allocation.
All references within this component are offsets.

The normal function continuation is:

```
[HIAFLR01, functionRequest, 6, numericError, 0, finalSerial, nameBytes, 0]
+ complete generated name
```

The zero-length name at serial 8192 has nameOffset equal to continuationOffset
plus 64. Consumers need not assume a canonical offset for an empty view; bounds
remain mandatory. On an error the helper-value view has offset and size zero.
The wire view is meaningful for QUERY and CALL_HELPER; inactive views must not
be interpreted as a second output after the reply parser has reused arena space.

## Ordering and private lease boundary

The request kernel queries the task and step identifiers before rejecting an
out-of-range fresh counter. This preserves the old issued-type-before-counter
transport order. The actual query owner refuses unissued identifiers and its
lease is then discarded; the driver must not fabricate a helper result.

A query is committed to the helper cache only after the complete descriptor
copy has capacity and succeeds. A GROW retry validates the remembered sequence,
identifier, event extent and stable type counters. The first query establishes
the counter snapshot; a self-consistent arbitrary header is not independent
proof that a session is authentic.

The IR, its source/index buffer, the type event/workspace, and helper
frame/workspace are private native-issued leases. Their owner retains the same
immutable input across a retry. Session numbers are correlation values, not
cryptographic authentication for arbitrary external buffers. The generic type
registry is not reconstructed in the host.

The full coordinator retains the existing outer-owner order:

1. Call the actual helper image.
2. Present the actual helper workspace and complete 64-byte header/extent to
   the existing outer HIAOTH gate.
3. Run the helper reply parser on that same actual helper result.
4. Convert the complete successful typed helper through the native packet-JSON
   and final-summary owners, register the opaque value, and receive the outer ACK.
5. Forward the exact function continuation.

The complete function/outer coordinator is a separate work item. These tests
exercise actual kernels and actual helper/type owners with test-constructed
metadata delivered through the real IR issuer; they do not claim that a complete
function controller already drove this component.

## Fresh verification

All five execution groups returned PASS after their source readbacks. No case
was skipped, and no language, image, response, compiler or timeout limit was
raised. Complete raw inputs, views, continuations, native events, original
stdout/stderr, and source pins are retained alongside each summary.

| Group under development/ | Cases | Request entries | Reply entries | Scope |
| --- | ---: | ---: | ---: | --- |
| pipeline-reconstructed-r3-attempt1 | 15 | 95 | 15 | Three retained public task fixtures × five operations, serial 0 |
| pipeline-reconstructed-r3-serial8191 | 15 | 95 | 15 | Same fixtures and operations at serial 8191 |
| pipeline-reconstructed-r3-serial8192 | 15 | 95 | 15 | Same fixtures and operations at serial 8192 |
| boundaries-reconstructed-r3-attempt1 | 122 | 405 | 165 | Layouts, complete wire bounds, encoding and protocol controls |
| query-boundaries-reconstructed-r3 | 9 | 30 | 7 | Large QUERY GROW, issued-ID and first-refusal ordering |
| Total | 176 | 720 | 217 | New reconstructed r3 only |

Across these groups there were 396 actual IR entries, 76 packet-issuer entries,
531 native type-transport entries, 90 semantic type-owner entries, and 70 actual
helper executions. Seventy separate helper executions through the original
adapter supplied the reference results. Twenty-five layout cases also compare
the complete old hosted helper result or error and partial fresh-counter state.

The 45 public fixture pipelines compare the entire eleven-item packet, complete
helper result, continuation, name, numeric error and counter. The forwarding
loop disables the hosted type materializer and command method, ObjectToken
decoder, hosted helper packet builder, old helper dispatcher and helper adapter
generation methods. Reference execution and fixture setup occur outside that
loop.

The 122 boundary cases include five complete layouts across all five operations:
zero width, a read loan in state, a mutable loan in result, all sixteen primitive
flat types, and the existing maximum 512-slot task. They cover actual helper
errors 0, 2 and 3, reordered variants, packet extent 131072 minus one/exact/plus
one, helper response extent 4 MiB minus one/exact/plus one, malformed header and
workspace association, repeated replies, and permanent refusal through both
images.

The response grammar controls include UTF-8, BOM variants, UTF-16/32 in both
byte orders, escaped and raw lone surrogates as admitted by the original private
JSON parser, NUL, maximum Unicode, and malformed encoding. Complete values and
canonical byte comparisons keep bool/int and floating-point distinctions
visible. Private response floats retain their typed transport tag; the public
integer parser and later Core gate are separate unchanged boundaries. These
wire mutations and directly constructed descriptor graphs are explicitly
private ABI controls, not claims of additional accepted public HIA programs.

The final nine cases force a real type QUERY containing a descriptor name over
300 KiB through helper GROW. The descriptor is copied into owned storage and the
QUERY is not reissued. Six mismatched local replay headers permanently refuse
both images. A valid task and step are queried before serial 8193 is rejected;
an unissued task instead makes the actual type owner refuse first, with no
helper execution or fabricated completion.

## Earlier attempts preserved

The first reconstructed r2 generator exceeded the existing per-function block
limit (281 blocks in its fixed literal selector) and was rejected. The original
log is retained. Splitting the fixed selector preserved the original limit.
The next r2 draft was actually compiled, then static review found that flat
primitive identifiers needed conversion to the original primitive names.
That draft and its compile receipts remain separate. The r3 common authoring
implements the conversion; all 176 new semantic/protocol cases use r3.

No old missing r1 logs, lost archive members or prior test counts have been
reconstructed or relabelled as original evidence.

## Reuse and custody

The integration entry is the fixed r3 bundle and the six production files.
`development/helper_harness.py` is only a test executor; it does not implement
the production semantics. Its manifest admission freezes source and image bytes
before mapping, checks them against the current sources, and rereads them after
execution.

The final delivery manifest names each source, compile product, run summary,
reference snapshot and historical attempt. The sibling archive custody report
records the complete member list, lengths, SHA-256 and mode, and verifies every
archived member against the live bytes. Original absolute paths remain intact
inside execution receipts; the additional dependency snapshots make those
observed bytes recoverable without rewriting receipts.

All installed resource registration, release contract/profile changes, final
driver integration, complete public qualification and eventual old-owner
deletion remain explicit integration work. This handoff authorizes none of those
claims by itself.
