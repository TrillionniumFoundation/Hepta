# Native Worker Store wire/digest peer — development ABI r2

This component owns the complete existing Store.wire(value) → SHA-256 → lower-case hexadecimal value calculation. It invokes the unchanged GraphWire scan/emit and SHA stream images, and consumes an actual registry IMPORTED event before producing the initializer's peer-8 reply. It does not own Store publication, any SQL effect, namespace capabilities, the complete Worker request loop, or a public syscall executor.

The local source-r2 kernel was compiled with the original f50 B3 image (668608 bytes, SHA-256 0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8). Its first actual six-image smoke completed 12 cases / 314 entries before the environment became unavailable. The authoring, original smoke source and exact compilation summary were copied to Git before interruption. The local entry buffers/CAS and compiled image bytes were not yet uploaded; their original locations currently have no availability proof. This document does not upgrade that observation into a complete archived qualification.

The new independent CI regenerates eight unchanged initializer/registry peers, then SHA and this controller: ten actual original-limit compilations. Its target and complete-initializer tests are new, unexecuted source at this handoff. Previously passed registry, pure-join and local-smoke counts are not inherited.

## Private input ownership

The outer retained entry is RWW, borrowing its second buffer read-only. Semantically the inputs are (sourceGraph R, commandAndActualPeerPayload R, workspace W).

The fixed caller must own an actual immutable Graph issued by the existing registry, the actual same GraphWire state/output allocation, actual SHA output plus state, and the actual registry reply plus resulting Graph. Lengths, IDs and headers provide correlation; they do not authenticate an arbitrary externally supplied arena with the same shape. In particular, own GROW reuses the same immutable completed GraphWire lease. A replaced payload with the same header is outside this private issuer contract.

Native integer, Unicode, arbitrary magnitude, cycle, key-collision and error ordering decisions remain in the original GraphWire owner. It receives the original Store configuration: maximum 8388608 bytes, flags 2 (ensure_ascii=False, sort_keys=True), and the registry's exact integer digit limit. No new maximum is imposed on the complete registry Graph or on total registry commands. The selected-value serializer retains its existing node/depth/queued-container/byte decisions.

The new CI assumes the existing default Store serializer path. It does not independently qualify an optional separately selected binary64-format manifest.

## Command: 16 little-endian u64 words

Magic HIAWDC01; total extent is 128 + payloadBytes.

| Word | Meaning |
| --- | --- |
| 0 | command magic |
| 1 | operation: 1 BEGIN, 2 WIRE, 3 SHA, 4 CONT after own GROW, 5 BIND |
| 2–3 | invocation and call IDs |
| 4 | this digest service lease |
| 5 | last controller event sequence; zero for BEGIN |
| 6–7 | current actual Graph lease and exact byte extent |
| 8 | exact payload byte count |
| 9 | actual producer native return |
| 10 | actual producer role: 1 scan, 2 emit, 3 SHA, 4 registry |
| 11 | actual producer allocation or frame extent |
| 12 | BEGIN kind: 0 generic private digest, 1 actual initializer pending; zero later |
| 13 | original initializer source lease, which registry carries independently of current Graph generations |
| 14 | expected issued action ID; zero for BEGIN |
| 15 | reserved zero |

All calls after BEGIN bind invocation, call, service, event sequence, source identity and pending action. A malformed frame, wrong phase, failed correlation or replay returns BAD (0xfffffffd). A full valid workspace is permanently poisoned. An advertised workspace shorter than 131072 bytes cannot safely write its state: it returns BAD without an in-buffer poison guarantee. The caller must discard every BAD lease immediately, including sequence overflow where the event area can remain stale.

BEGIN has a 576-byte payload: the actual registry BORROW event (256), its exact HIAGWC01 configuration (64), then the immediately following actual RESERVE event (256). With kind 1, append the actual initializer HIAWIE01 event (256), for total commands 704 or 960 bytes. Native return words are 768/registry/768. The controller checks the complete relevant headers, source extent, live value handle, selected root, registry command/sequence continuity, reserved fresh foreign/output leases and original source lease.

Kind 1 additionally requires the actual initializer's pending peer 8 at phase 14. The pending ID, handle, source lease, digit limit, no-input-view shape, snapshot extent and actual open-Store authority presence are checked. This uses a real pending event; it does not synthesize initializer progress.

## Event: 32 u64 words at workspace offset 512

The native return is 768 (end of the event). Magic HIAWDE01.

| Words | Meaning |
| --- | --- |
| 0–7 | magic, action, invocation, call, service lease, new event sequence, phase, refusal reason |
| 8–11 | original Graph lease, original extent, borrowed value handle, selected root |
| 12–15 | own workspace need, issued producer role, producer allocation need, action ID |
| 16–17 | next actual producer request view offset/bytes |
| 18–19 | complete wire view offset/bytes |
| 20–21 | raw SHA view offset/bytes (32) |
| 22–23 | complete one-string HIAGRF01 result offset/bytes (192) |
| 24–27 | reserved foreign Graph lease, output Graph lease, registry command, last registry sequence |
| 28–29 | exact initializer reply offset/bytes |
| 30–31 | unchanged GraphWire semantic error ID and cause kind |

Actions are 1 CALL_WIRE, 2 GROW this workspace, 3 CALL_SHA, 4 DIGEST_READY, 5 BOUND, 6 semantic error, 7 protocol refusal. A numeric BAD always overrides any event bytes. Every issued producer call gets the next action ID; own GROW does not reissue a producer call.

Views borrow this workspace and expire on the next controller call or GROW. Copy/consume them before mutation. DIGEST_READY exposes wire, digest and Graph. BOUND exposes those same values plus the final initializer reply, now backed by an actual registry-issued value handle.

Phases are 10 GraphWire, 20 own GROW, 30 SHA initialization, 31 SHA updates, 32 SHA finish, 50 awaiting actual registry import, 90 complete and 99 refused. A terminal lease cannot be reopened.

## Actual GraphWire continuation

WIRE forwards the complete actual shared scan/emit workspace, with the actual 128 return and exact allocation size. The controller checks both the HIAGWE01 event and the native state: config identity, source nodes/extent, error/cause, phase, required capacity and output extent. A scan GROW re-enters scan with the unchanged inputs; scan's actual emit request switches to emit. Emit GROW re-enters emit. A semantic error yields the complete original text without calling SHA.

The completed output is checked against its native output-base/output-length fields. Only then does the digest arena request 131072 + wireBytes if necessary. CONT forwards the same completed actual producer lease, without a second scan or emit entry. It verifies saved event/extent/correlation, and copies the completed wire into the owned arena. A still-small replacement asks for GROW again.

## Actual incremental SHA

The controller emits complete SHA requests: byte 0 initializes; byte 1 followed by at most 65536 bytes updates; byte 2 finishes. Chunk planning and offsets are HIA decisions. The caller forwards the exact emitted request to the frozen sha256_stream image using an independent 32-byte output and 1184-byte state.

SHA operation 3 returns payload [actual output32][actual state1184], total command size 1344. The native return must be 0 for initialization/update and 32 for finalization. The controller checks the real state tag, phase, total byte count, partial-block count, retained 512-byte round constant prefix and final chaining-word/output equality. The accumulated count must equal the complete wire length before result publication.

The controller emits a complete 192-byte HIAGRF01 arena: one string containing 64 lower-case hexadecimal bytes, using the actual reserved foreign lease. The string's character-count auxiliary field is 64. The source-r1 compiled prototype omitted that field; it was corrected statically before the first semantic entry. Original r1 authoring and compile observation remain separate history.

## Registry binding and initializer reply

The caller passes the complete HIA-produced Graph to the existing registry IMPORT → original Graph merge → actual MERGE reply flow. It must not parse hexadecimal bytes to build a replacement Graph or choose a root. After actual import, BIND supplies the actual 256-byte IMPORTED event and the actual resulting Graph as first input.

The controller checks current output lease, exact extent, original invocation/call, reserved command, advanced registry sequence, merge child sequence/extent, issued-count increment, selected imported root, handle, source-node/edge/scalar deltas and all 64 hexadecimal bytes in the native Graph. It then produces the precise 256-byte HIAWIR01 peer-8 success reply with kind 7, the actual issued value handle and raw digest words. Kind 0 has pending ID 0 and is not a usable ordinary initializer continuation.

A GraphWire semantic rejection yields HIAWIR01 status 1 with an opaque error payload at 256. The payload header is eight words:
[HIAWDX01,1,1,errorID,causeKind,textBytes,64+textBytes,0].
Type value 1 denotes the existing HIAEditRejected domain; all sixteen original messages, including E_HIA_EDIT prefix, are rendered by HIA. The initializer preserves the actual issued exception payload; the eventual ordinary Worker exception renderer remains a separate required owner. There is no host reason-code-to-text fallback.

## Workspace bounds and evidence

The owned arena minimum is 131072 bytes; the only variable retained region is complete wire starting at 131072, at most the original 8 MiB. Thus this owner needs at most 8519680 bytes. Source Graph, GraphWire workspace, SHA state/output, registry and initializer workspaces are separate issued allocations; this arithmetic does not claim total-process RSS or namespace bounds.

Control regions are disjoint: event 512, saved source/header views 768–1791, SHA constant snapshot 1792–2303, reply 2304–3327, SHA request 4096–69632, raw digest 69760–69791, hex Graph 69824–70015 and wire at 131072. Whole-wire and integer operations are u64 with source/extent gates preceding access.

New CI groups preserve 90 CPU / 180 wall / 1 GiB each. Compiler invocations preserve 10 CPU / 20 wall / 256 MiB. Target groups cover original twelve semantic cases; five real initializer-pending cases; actual-producer-derived malformed frames, replay, permanent refusal and GROW controls; 65535/65536/65537/131073-byte wires; independent 1 MiB, 8 MiB and +1 groups. A separate complete initializer test uses all ten images and compares the original full state, first error and ordered call trace for eight cases, while retaining fourteen explicitly foreign business/effect peers. All those CI executions are pending at source handoff.

The production digest sources are frozen independently of these development tests. No ordinary selector, Worker install entry, SQLite replacement, complete Store service or whole-product qualification is activated here.
