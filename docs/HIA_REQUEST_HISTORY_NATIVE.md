# Native request history component

## Public behavior

The native stdio MCP service now exposes `request_history` beside its existing
eleven Worker tools. The Worker tool catalog and its ordinals remain unchanged.
The service maps the new SDK tool ordinal 12 to private service role 13; role 12
continues to mean HIA resource reading.

`after_id` is an optional nullable string and `limit` an optional nullable
`u16`. Omitted or null arguments select the empty parameter object. The public
page accepts limits 1 through 32, defaults to 32, and requires lower-case
64-character hexadecimal cursors. A foreign or expired cursor is refused
after filtering records to the trusted session owner.

Records retain the original ordering by full `u128` accepted time and request
identifier. The page contains only request identity, canonical tool name,
observed state, accepted time and optional elapsed milliseconds. Its retention
metadata remains 512 global records and 128 per session. The encoded original
`CallToolResult`, including its complete-result marker, is bounded by 64 KiB.
The selected protocol's existing response adaptation remains in force.

History does not admit an audit ticket, audit itself, seed an archive, or close
an archive epoch. It reuses the held root, private-inode checks, store lock and
bounded hot-store scan. The original verified staging cleanup and missing-hot
directory recreation still occur when required by the original read semantics.

A live kernel-backed dispatch ticket yields `accepted`; a retained read pin
alone does not. Completed and failed records retain their original meanings.
The result explicitly states that these observations do not establish effect
delivery or business success and do not authorize automatic operation retries.

The original pinned Rust implementation cannot insert a selected `u128`
timestamp above `u64::MAX` into its JSON value. This native implementation
preserves the resulting short public failure and subsequent process store-lock
poison, rather than narrowing the timestamp or reporting success. Unselected
and other-owner large timestamps still participate in full-width sorting.

The observed rmcp 3.9.0 parameter errors are reproduced, including sorted
Value-map field order, duplicate-key last-wins behavior, finite number
formatting, and Rust string Debug escaping. A decoded erroneous string or
unknown field above 1 MiB receives the existing bounded `-32602 Invalid params`
response. Diagnostic text parity above that explicit native bound is not
claimed. The query page and retained-record limits are unchanged.

## Versioned audit protocol

The composition changes from `HIARAU01` to **`HIARAU02`** and contains 17 policy
roles. The new history role precedes the JSON decoder. The existing begin,
finish and fixed 512-byte response protocols retain their layouts.

History uses a distinct request magic **`HIAAHQ01`**, version 1. Integers are
unsigned little-endian 64-bit values. The request is 512 bytes plus the exact
held root path bytes.

| Offset | Field |
| --- | --- |
| 0 | Eight-byte request magic |
| 8 | Version 1 |
| 16 | Operation 3 |
| 24 | Complete packet byte count |
| 32 | Prepared held-state descriptor |
| 40 | Prepared shared audit descriptor |
| 48 | Worker slot, below 32 |
| 56 | Live worker PID |
| 64 | Nonzero worker generation |
| 72 | Prepared controller PID |
| 80 | Held root path byte count, 1 through 4096 |
| 88 | Page limit, 1 through 32 |
| 96 | Cursor byte count, 0 or 64 |
| 104 | 24 zero bytes |
| 128 | Trusted owner, 64 lower-case hexadecimal bytes |
| 192 | Cursor or 64 zero bytes |
| 256 | 256 zero bytes |
| 512 | Exact held root path |

The public caller cannot choose the owner, descriptor identities, worker lease
or root. The service constructs them from its authenticated native session and
prepared state. The daemon checks the shared header, held root and live
slot/generation lease before acquiring or using the store.

The response magic is **`HIAAHO01`**, version 1. Its header is 64 bytes followed
by 1 through 65536 body bytes.

| Offset | Field |
| --- | --- |
| 0 | Eight-byte response magic |
| 8 | Version 1 |
| 16 | Complete response byte count |
| 24 | Status, 0 success or 1 failure |
| 32 | Reason, zero on success |
| 40 | Worker slot |
| 48 | Worker generation |
| 56 | Reserved zero word |
| 64 | JSON text on success, redacted error text on failure |

Reasons 33 through 36 represent unavailable cursor, wire-page bound, the
original selected-time serialization failure, and poisoned store lock.
Existing reasons remain intact. The service rejects malformed or oversized
responses and drains a cancelled predecessor's correctly framed stale
slot/generation response before accepting its own response.

## Construction and evidence

This checkpoint is an independently constructed **component** on Hepta base
`6728cc419d88e56f8b802a0e258ce4848a4e28e9`. It does not qualify a complete cold
release, installed Worker or HTTP credential-history product.

The construction invokes the four pinned checked-in native seed roots. A
separately named `div-word` profile combines the already supported unsigned
division/remainder and bounded little-endian word stores through the shared
`add_word_store` authoring helper. Original div and word HIA bytes remain
unchanged. The profile's B1, B2 and B3 bytes agree; these are profile fixed-point
controls, not the final complete cold compiler identity.

The actual audit executable contains all 17 native roles and the native packer.
The actual public bundle contains every one of the controller manifest's
19 required members, with real native service and bridge composition. The
Worker configuration is an explicit fixture. No valid Worker job is requested;
a locally rejected HIA call observes a real service-owned audit identity.
All native compilation and packing calls, source hashes and product hashes
are retained in the evidence.

The final component controls cover:

- 328 native div/word profile cases, including original profile identity,
  malformed admission, CPU traps and real addresses above 4 GiB.
- 16 history process cases plus the unchanged 16 retention and 24 v12 controls.
- 35 public cases against the exact original Rust history oracle; the original
  oracle ran 37 cases twice in fresh processes with identical observations.
  Its live-ticket and caller-unselectable-owner cases are covered by native
  daemon controls instead of fabricating public ownership inputs.
- Two public discovery/default-argument and stdio reconnection-isolation cases.
- 36 additional exact typed-parameter cases and one explicit diagnostic-bound
  refusal. The eight typed cases in the main history corpus also compare the
  complete original rmcp error object.
- Native Unicode classification across all 1,114,112 code points, including
  all 1,112,064 valid scalars, plus four output-capacity refusals. The table
  comes from actual Rust 1.96.1 Unicode 17 string Debug observations.
- 21 audit-composition and 60 controller-product malformed-packet refusals.

The reference source is
`TrillionniumFoundation/hepta-runtime@ae1c7ea593da45f7299c692a2acd44605c35be09`,
`src/mcp/runtime/request_audit.rs`, SHA-256
`b5189f2923153ffa83d0b45a7cdf89873b0f17ebbe6ec1b174c05bab291d73da`.
The 27 original production blocks are copied without edits into the
qualification-only projection. Its 103 registry dependencies match the
original lock checksums. The reference project, complete inputs and observations
are retained under `tests/fixtures/hia_request_history_oracle`; they are not
installed native runtime components.

See `HIA_REQUEST_HISTORY_NATIVE_QUALIFICATION.json` and
`evidence/hia-request-history/` for actual product pins and per-scope results.

## Integration boundary

Merge this source checkpoint normally into the current canonical head. Register
these new HIA source paths through the existing native authority mechanism:

- `examples/hia_bootstrap/mcp_request_audit_history.hepta`
- `examples/hia_bootstrap/seed_div_word_backend.hepta`

Regenerate the current-head native source authority, controller source list,
Worker manifest/identity/install recipes and controller release stage together.
The release author now consumes the versioned audit composition magic and role
list. Shared authority and release-derived files were deliberately left to that
current-head integration, so this older-base component cannot overwrite newer
canonical changes.

The same resulting source/distribution tuple must then pass the unchanged
complete cold, release, installation and installed-rebuild gates. No
component receipt in this checkpoint substitutes for those gates.
