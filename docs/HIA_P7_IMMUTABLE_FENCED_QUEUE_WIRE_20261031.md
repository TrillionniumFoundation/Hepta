# HIA P7 — immutable canonical owner queue wire and exact live fences

## Exact provenance

Stacked on #474 at `2c52fb4578a434320ebc355e644b1815093f12d4`.
The existing `OwnedAdaptiveRuntime.submit_queue(items)` remains supported,
but its caller-owned Python dictionaries do not offer an atomic multi-key
snapshot while another producer is actively mutating them. The prior #470
repair detaches each item before subsequent budget and execution checks; it
does not make a full concurrent request atomic.

## New bounded independent admission

`submit_queue_wire(wire: bytes)` accepts only an **exact built-in immutable
bytes object** no larger than 32 KiB. Prior to JSON object construction it runs
the existing bounded HIA JSON grammar scanner (1,024 nodes, depth 4), rejects
duplicate keys, and requires byte-for-byte canonical sorted compact JSON.
The exact envelope has `schema`, `owner_id`, `generation`, `revision`
and `items`. The currently alive owner, generation and revision are checked
**under the same runtime RLock** that registers the queue. Parsed items cannot
be mutated by an external producer and continue through the original finite
128-item/1e9-step resource checker.

The successful return contains the SHA256 of the immutable request, bound
queue digest, owner/generation/revision and explicit `DENY_ALL` / no durable
recovery. The parse/identity time is charged to unamortized preparation ahead
of the original queue-registration accounting. The legacy queue token
generator additionally refuses an existing token rather than overwriting
a previously retained completion receipt.

## Adversarial and real-native evidence

- Invalid bytes/UTF-8, noncanonical whitespace, duplicate keys, unknown
  schema/fields, unsupported subclasses and over-budget JSON all refuse.
- Stale owner/generation/revision, bool-as-integer and invalid scalar/total
  resource limits refuse before queue registration.
- Deterministically forced 128-bit token collisions cannot erase old queue
  evidence.
- Real Clang20/Z3 native owner test executes the same immutable queue and
  reads native committed steps, final owned values, unchanged queue hash,
  and original queue status.
- The inherited mutable Python queue tests and full independent P0/P1/P5
  source-native gate must continue passing on this exact SHA.

## Limitations / unclosed gates

This closes **one scoped P7 input/provenance defect**, not P7. The new wire
does not provide a cryptographic authorization signature, external identity
attestation, crash journal, power-loss recovery, task side-effect exactly-once
semantics, long-lived hardware qualification, or a new runtime authority.
The original native NDU net benefit and all P0–P7 production gates remain
OPEN / `DENY_ALL`. No merge or production activation without independent
source + native + lifetime qualification.
