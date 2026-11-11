# Final Core visitor — fresh reconstructed development revision r1

## Scope and identity

This owner executes the complete bounded-snapshot structural traversal and final
byte-budget decision in HIA. It consumes the original complete ObjectToken
producer frames, exact private native-issued SourceIndexLease values, and opaque
function/helper summaries produced by another invocation of the same visitor.
It does not serialize Core, authenticate external registries, decide function
semantics, or make the surrounding driver fully native.

The old pre-environment-switch Core proof result was not recoverable. The source
here is a new, explicitly reconstructed identity. All results below were freshly
executed on this identity. The old lost helper r1 archive is not evidence for it.

- HIA source: 140,616 bytes, SHA256
  34f0d66c4ffe19b286dab5ad5c07d3b11e69bf8cd6c9e27d4bd3ddb53cf87e66.
- Actual image: 212,690 bytes, SHA256
  b210b6e1f8347c783273baf860e76a1e2462a7be4d38529c122dc722252e508e.
- 42 functions, 673 blocks, 2,358 instructions. Original compiler ceilings remain
  128 functions, 1,536 blocks, 8,192 instructions, 256 blocks per function,
  16 parameters per block.
- Exact recovered f50 B3 compiler: 668,608 bytes, SHA256
  0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8.
- Compilation used the original 10 CPU second / 20 wall second / 256 MiB gate.
  This is source-bound DEVELOPMENT, not qualification for the current repository.
- Source, image and dependency bytes were checked before and after actual calls.

The authoring host only combines fixed source text and lowers it through the
existing HIA assembly builder. Traversal, map key membership, summary composition,
continuation state and final error choice run in the HIA image.

## Original-order composition

For a finite, acyclic detached value, after visiting a preorder prefix:

    visited + queued = 1 + sum(arities of visited containers)

Map keys are validated and deduplicated but are not structural nodes. Every
occurrence of a repeated source or opaque alias is visited and counted.

A queued-node failure occurs when the arity prefix exceeds 262143. The first
too-deep node is checked before adding its own arity. The visitor records the
arity prefix D immediately before that node. A normal full-tree summary N uses
saturation only at 262145; no subsequent tokens are discarded after saturation.

A function/helper summary is evaluated at relative depth 0 with limit 62, since
its opaque root is inserted at absolute depth 2 in the final program. At opaque
composition, N nodes add N-1 arity, and the first depth prefix is shifted by the
already accumulated arity prefix. The enclosing depth-2 edge ensures the capped
N/D information retains exactly the thresholds needed by the final gate.

Only after the complete outer stream:

1. If a first depth prefix exists and is at most 262143, preserve the original
   depth failure.
2. Otherwise, if N exceeds 262144, preserve the original queued-node failure.
3. Otherwise, ADMIT compares the complete actual serialized byte count against
   8388608.

ADMIT does not replace an earlier structural failure. Object mode reports its
summary without prematurely rejecting a later enclosing program. The full
independent proof and retained-reference checks are in
development/proof_controls_reconstructed_r1.py and its raw JSON report.

## Fixed driver duties and public boundary

Header correlation is not arbitrary external source authentication. The driver
must hold the exact immutable native-issued source packet and index for the
whole session. A private test intentionally replaces the entire source with a
different same-shaped source and shows why header/extent equality alone cannot
establish its identity. The driver must never permit that replacement.

Likewise, opaque handles resolve only to the exact completed object summary,
serialized bytes and digest held by the private native issuer. The visitor does
not implement the hash owner. This component's tests label their digest as a
reference SHA256 while the JSON byte count is produced by the actual native
packet-to-JSON image.

Every BAD return discards the driver's visitor lease, regardless of a stale
event header. With a valid full workspace, the first protocol error permanently
poisons every dispatch family. If the advertised workspace is shorter than
131328 bytes, the raw borrow ABI returns BAD before writable session state is
available; it cannot physically promise a poison write. That explicit negative
control requires driver disposal.

GROW resumes through HIACSC01, using already copied producer bytes and the same
immutable source lease. It does not fetch the producer frame again. A retry
without enough capacity emits the same needed extent without consuming a
producer sequence. All persistent references are offsets, so copying the old
workspace into the larger allocation is sufficient.

The caller performs the original envelope checks at their original time:
function map kind 6 with unknown-key bit 0 and mask 63 or 127, after the complete
stream and state mirror; outer map kind 6 with unknown-key bit 0 and mask 1920,
after the complete stream and before final snapshot admission. The visitor only
reports key inventory. It does not decide field-value semantics.

The public preservation claim concerns already detached, admitted source values
and actual native producer scalars. It does not extend public syntax to arbitrary
cyclic Python graphs, custom objects, malformed source bitmaps, or substituted
private payloads.

## Fresh actual verification

| Group | Complete cases | Visitor entries | Native packet issuer entries |
|---|---:|---:|---:|
| Smoke | 13 | 72 | 3 |
| Limits, composition and deterministic differential | 248 | 2025 | 365 |
| Protocol and explicit private-boundary controls | 130 | 1027 | 3 |
| Total | 391 | 3124 | 371 |

The independent reference proof also ran 429 structure/composition cases and
3 byte-boundary cases. No original language limit, native compiler limit,
test timeout or old error-order requirement was increased.

The boundary group includes real 262144-node cases, dictionary keys excluded
from that count, depths around 64/62, both depth-versus-queue orders, 8192 active
keys across chunks/GROW, repeated aliases, and actual native ordered JSON byte
counts at 8388607, 8388608 and 8388609. It compares the old exception code/text
and complete structural summary. Its wall time was 52.010450553 seconds;
that is a development observation, not a cold performance claim.

The protocol group includes 119 permanent-refusal cases. After each first BAD,
all six dispatch families returned BAD and the entire workspace remained byte
identical. Eleven additional controls cover valid resumptions and explicit
private ABI limits. Every actual call checked command/source immutability and
buffer canaries. The group completed with process exit 0.

Forwarding disables the hosted snapshot, structure and old token-decoder owners.
Reference computation and initial generic test-packet serialization occur outside
that forwarding scope. No hosted structural decision feeds the native results.

These are direct component and composition controls. They do not claim that the
new full function/outer controller has already been executed with this visitor,
nor that every ordinary CLI/public entry selects the new driver. Those remain
integration gates owned by the coordinator.

## Raw evidence and handoff

Stage 1 is immutable:
hia-composite-core-final-reconstructed-stage1-development.tar.xz,
722432 bytes, SHA256
0f6d044b158c647592418784022a4b0450cb65cc0ec54dcc71884ee97a51e407.
Its 2981 members total 218379198 uncompressed bytes; each member was compared
byte-for-byte, by SHA256 and mode, against its original live file.

The separate stage 2 increment contains this report and the complete protocol
source/log/raw calls. It does not rewrite the stage 1 archive or relabel an
unexecuted test as executed. See the sibling custody manifests for exact paths.

No reference owner was removed, no ordinary selector was changed, and no global
contract/profile/CI qualification was regenerated by this isolated component.
