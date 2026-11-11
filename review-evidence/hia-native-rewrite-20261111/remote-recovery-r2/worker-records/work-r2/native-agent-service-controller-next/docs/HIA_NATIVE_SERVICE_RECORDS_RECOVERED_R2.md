# Native service records — recovered development r2

This component is a complete native owner of the successful service record and
the data-level HIAAgentService._error record, including deferred slot-snapshot
publication continuation. It is not a complete Worker, namespace service,
installed ordinary route, or cold qualification.

## Provenance

The two authoring texts were saved in Git recovery commit
a3c61136b79fdb7a4b6d6428fb4bdf31cd5ed270 before this new ROG execution.
The earlier cloud-generated HIA/image/receipt originals are not recovered by this
stage. This stage generated and compiled new bytes, which happen to match the
earlier observed HIA/image hashes:

- HIA: 103588 bytes, ca8c522d9986ef77ebab7047ae01c142820f55c4200147e402e0e219a1c64a9e.
- Image: 154906 bytes, 9c3fd57c3914a1d2775a16a5369c21b96802656c28c966bde727575afe53cacb.
- Historical f50 B3 used for this new development compilation:
  0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8.
- Authoring: 25 functions, 370 blocks, 1690 instructions; maximum 124 blocks in
  one function and 16 parameters in one block. All original compiler limits
  remain unchanged (10 CPU seconds, 20 wall seconds, 256 MiB).
- The actual new receipt is records-compile-recovered-r2/service-records.receipt.json.

R13 worker-report, R14 worker-request, and R6 GraphWire original archives were
recovered and all 7986 file members were read back against their original
bytes/mode/SHA manifests. GraphWire uses a new path-relocation manifest; its HIA,
images, and original compilation receipts are byte-identical to the published
versions. No source or qualification from the old ROG job was modified.

## Actual results

| Group | Cases | Records entries | Graph scan | Graph emit |
|---|---:|---:|---:|---:|
| Ordered semantic records and publication fixtures | 110 | 233 | 220 | 324 |
| Private frame, growth and permanent-refusal controls | 108 | 213 | 0 | 0 |
| Late wire scalar/tuple/key/cycle controls | 8 | 16 | 16 | 18 |
| Exact 8 MiB final wire | 1 | 2 | 2 | 3 |
| Final wire 8 MiB + 1 | 1 | 2 | 2 | 3 |
| Total | 228 | 466 | 240 | 348 |

All groups completed with exit 0. The 110 semantic cases compare the complete
ordered records and original wire bytes/errors to the retained reference. They
cover missing versus explicit null/false/zero/empty attributes, complete aliases,
all UTF-8 widths around the 128/4096 code-point truncation boundaries, preserved
and discarded lone surrogates, actual type-name fallback, and both publication
success and publication failure. During actual forwarding, retained _error,
_reference_call, store wire/decode, bounded_json_wire and json.loads are disabled.

The publication inputs and replies in these tests are explicitly private
fixtures. The native component requests publication for every non-null pending
snapshot, including false/zero/empty values. On a publication failure it returns
the complete failure observation and does not turn it into a rejected record.
These tests do not claim an actual namespace effect.

The 8 MiB exact and +1 cases each complete the full native record first. The
original GraphWire policy then accepts the exact boundary and rejects +1 with
the same full error as the original store wire. The native record component
therefore adds no early 8 MiB quota. Each child retains 90 CPU seconds and 1 GiB
address space. Measured user CPU was 3.679515 and 3.585340 seconds respectively;
these are development observations, not a cold or performance qualification.

All recorded input buffers, read-only second inputs and canaries remained
unchanged, and every declared source/image/receipt pin was read back. Compressed
content-addressed originals are retained and independently decompressed during
sealing.

## ABI and finite scope

See HIA_NATIVE_SERVICE_RECORDS_R1.md for the fixed 96-byte HIASRC01 command,
HIASRR01 publication reply, and 128-byte HIASRE01 event at workspace offset 256.
Return 384 indicates an event. BAD is 0xfffffffd and the fixed caller must discard
the lease immediately.

Full-workspace malformed commands, mismatched growth/reply correlation, replay,
completed reuse, and event-sequence overflow are permanently refused. A borrowed
workspace shorter than 1024 bytes cannot necessarily hold poison state; the
caller must still discard it. Event-sequence overflow may leave an older event
in memory; BAD takes precedence over event fields.

Source Graph and publication Graph are issued private immutable leases. The
header comparisons are correlation checks, not authentication of an arbitrary
same-shape replacement. An explicit private replacement control documents this
limit. The initial error-field lookup relies on the issuer's valid Graph; this
stage does not claim arbitrary malicious Graph-body admission.

The record boundary consumes already-observed exception attributes, message and
actual type-name strings. It does not emulate arbitrary Python descriptor or
__str__ side effects. Actual fixed native error producers and the whole service
controller must provide these observations at the original exception boundary.

The outer controller must unwind an actual effect transaction before requesting
snapshot publication. It must also suppress final cost/journal writes if record
construction or snapshot publication itself fails. Those orchestration rules
remain the next implementation stage; this component cannot claim them merely
from a fixture reply.

## Preserved development history

The remote recovery had two recovery-only failures: the importlib.util probe,
and a version of the archive recovery script that expected path instead of the
R14 manifest's name field. Both original durable job records and scripts remain.
The uppercase host alias was rejected before launch. MCP read timeouts are
transport observations, never semantic failures.

The unexecuted protocol-r1 script remains as a draft. Its status-word error
expectation was corrected before the separate protocol-r2 script was executed;
no failed native run is rewritten as a pass. The six original interruption
texts remain separately classified as exact authoring readback versus new
unexecuted design/test drafts.
