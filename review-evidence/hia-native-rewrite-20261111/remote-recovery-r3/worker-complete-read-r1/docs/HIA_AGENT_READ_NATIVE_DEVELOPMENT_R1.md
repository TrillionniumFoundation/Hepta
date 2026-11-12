# Complete HIA read business owner — development protocol r1

This source-only candidate implements the whole retained
`HIAAgentService._hia_read` algorithm for the ordinary, already input-schema-
validated tool call. It has not yet been parsed, generated, compiled, or executed.
It is not an ordinary Worker selector, a finished namespace service, or a whole
product qualification. Old code and all prior evidence remain unchanged.

## Exact retained sources and boundaries

The reference is commit `0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5`.
The service source is Git blob `2f56a5b4b02c54b9e56e53882db5cbd5687e4b4e`,
100742 bytes, SHA256
`684caf496de7e3e7c8db1fd80ef616139cf13717aa5879bbd2d6ebf834df9330`.
The complete method, rather than a simplified page API, is the oracle.

Before this owner, the complete ordinary call must perform its original request,
catalog and argument-schema gates. The artifact reference has its exact three
fields; cursor is optional; max_bytes is an integer in [512,65536], including the
finite integral binary64 values accepted by the original schema. The private
controller does not claim compatibility for arbitrary replacement Python objects,
subclasses, mutable alias races, or calls that bypass those public gates.

The namespace ABI file must be the published 51264-byte original with SHA256
`c15222c99cb04ef8bc6a7f13108a7e90adb0bc908876d663eb4329fd14563c04`.
Its original 31 operations and 10 tables are not reduced to a key/value store.
At authoring time the exact SQL strings uniquely bind OP_CURSOR_SELECT and
OP_CURSOR_INSERT. No numeric operation is guessed or selected by Python at
runtime. The original rows are (id, artifact_id, sha256, offset); the SELECT has
one bind, the INSERT OR IGNORE has four. The final generator's ABI-layout checks
still require execution against that original JSON, whose full text was pending
recovery when this candidate was written.

## Original semantic order

1. Resolve args.artifact, then await complete Store.get(ref). Success means the
   exact-reference check, artifact read/hash and **metadata decode** have all
   completed. Metadata failure precedes any cursor lookup, although its value
   is discarded by the method.
2. If cursor is present, await the complete materialized SQLite row. Its entire
   four-column conversion occurs before reading the fields used here. Missing
   row or unequal artifact_id/sha256 gives the original E_HIA_CURSOR text.
   No column is coerced from its declared SQLite type.
3. Convert max_bytes using the original validated integer domain; preserve
   INTEGER signed-64 offsets and the original NULL/REAL/TEXT/BLOB failure
   behavior. Python's unbounded addition is represented by sign+magnitude, so
   positive signed-64 maximum plus 65536 cannot wrap.
4. Compute the ordinary Python slice. Negative indices clamp separately for
   start and stop. Keep the original offset for the later next-cursor sum.
5. Decide UTF-8 versus binary using the **complete artifact**. A bad byte outside
   the page still selects base64. If the whole artifact is valid, obtain exactly
   the same page that repeated chunk[:-1] decoding returns: the longest valid
   prefix of the selected slice. A cursor inside a continuation sequence can
   therefore yield an empty page.
6. For each page-budget condition issue three distinct complete wire services in
   source order: wire(content), inner wire(content), and wire(inner_bytes.decode
   UTF-8). The first and third lengths are summed and compared with 230000.
   If too large, apply chunk[:max(1,len(chunk)//2)] and rebuild utf8/base64 content,
   then repeat all three calls. No wire/admission witness is cached or elided.
7. Compare original_offset + len(final_chunk) with artifact length. If more
   remains, build the full {"artifact":ref,"offset":sum} Graph, call complete
   wire once, feed those exact bytes to native SHA-256, and generate all 69
   bytes of the page-<hex> cursor in HIA.
8. Await the real INSERT OR IGNORE statement result. Only then return the
   complete ordered four-field result Graph.

The complete wire service retains max 8 MiB, ensure_ascii=False, sort_keys=True
(flags 2), and the actual digit setting. If an installed binary64-format selector
requires fresh source/image admission, that is part of every wire service call,
including strings with no floating values. The component must not substitute
its own byte-count estimate for any of those calls.

The native UTF-8 prefix scan is equivalent to repeated tail trimming: after the
first invalid sequence starts at p, every longer prefix still fails, while the
prefix ending at p succeeds. It rejects overlong encodings, surrogates, invalid
continuations, truncation and codepoints above U+10FFFF. Base64 includes the
original padding and no line breaks. Output artifact key order is copied from
the input Graph; top-level result order is artifact, encoding, content,
next_cursor. This is a public value/byte contract, not a claim to preserve a
private Python object's identity.

## Images and buffers

Two HIA kernels share one private growable workspace:

| Role | Kernel | Owned phases |
|---|---|---|
| 1 | agent_read_flow | Store/SQL/wire/hash order, peer correlation, cursor and result |
| 2 | agent_read_values | Exact limit/slice arithmetic, full UTF-8, page trimming, base64 |

Both retain the established external RWW entry. The wrapper borrows the second
buffer read-only; the internal ABI is (args Graph R, actual peer view R, state W).
The fixed executor must declare both kernels in its two-read mask.

The first buffer always remains the same immutable input Graph lease. The
second buffer is either empty at initialization or the exact actual view
associated with the last issued peer. Matching header/lease integers are
correlation checks, not external authentication. A future fixed coordinator
must own those mappings and prohibit substitution.

Minimum workspace is 8192 bytes. Config is [128,256), ACK [256,384), immutable
copies [1280,1472), internal error text [1536,2048), event [2048,2304), actual
Graph-wire command [2304,2368), saved ACK [2432,2560), saved view prefix
[2560,2624), and complete cursor [3072,3141). Page bytes occupy [8192,73728).
The complete generated Graph starts at 73728 and grows as required.
There is no new cumulative command, descriptor, artifact or output quota.

The private artifact view remains owned and immutable from completed Store.get
until this invocation terminates. Reborrowing it after the cursor query is a
mechanical mapping action, never another namespace get, read, hash, or decoder.
No full 64 MiB artifact copy is needed. Only the selected page, at most 65536
bytes, is copied to the controller workspace.

## Initialization

Write this 16Q little-endian config at offset 128 of a zeroed workspace:

[HIARDC01, invocationLease, call, argsGraphLease, argsRoot, resultGraphLease,
 digits, 0,0,0,0,0,0,0,0,0]

All five identifiers are nonzero. digits is 0 or at least 640. The ordinary
Worker owns their issuance. The first call uses role 1 and an empty second
buffer. No host precomputes artifact offset, encoding, page length, cursor or
returned value.

## Event: 32Q at offset 2048, native return 2304

| Word | Meaning |
|---|---|
| 0 | HIARDE01 |
| 1 | action: 0 complete, 1 GROW, 2 peer, 3 semantic/peer exception, 4 next role, 5 ABI refusal |
| 2,3,4 | invocationLease, call, monotonically increasing eventSeq |
| 5,6,7 | argsGraphLease, phase, allowed role |
| 8 | exact required workspace extent on GROW |
| 9,10 | peer kind, outstanding peer request sequence |
| 11,12,13 | source owner, offset, exact byte extent |
| 14,15,16 | source root, source lease, fixed namespace operation (SQL only) |
| 17,18,19 | completed result Graph offset, bytes, lease |
| 20 | generated Graph generation |
| 21,22,23,24,25 | error class, owner, lease, offset, bytes |
| 26 | first private refusal reason |
| 27,28 | held actual artifact lease and extent |
| 29,30 | command/config offset and bytes, 64 for complete wire |
| 31 | zero |

Source owner 1 means the original args Graph, 2 the current actual peer view,
3 this workspace, and 4 the held immutable artifact view. These enums do not
grant authority over arbitrary buffers. Result and command views must be
consumed before the next state mutation or GROW. The exact generated Graph is
frozen for the whole actual wire call.

Action 3 with owner 3 is an HIA-produced full error string, class 1
AgentRejected or 2 TypeError. With owner 2 it forwards the exact opaque issued
exception view from a peer; its class/lifecycle belongs to that peer and the
outer complete call owner. A namespace or wire failure is never recategorized
by this business component.

## Peer ACK: 16Q at offset 256

[HIARDA01, invocationLease, call, issuedEventSeq, peerKind, status,
 actualNativeReturn, viewLease, viewBytes, payloadOffset, payloadBytes,
 0,0,0,0,0]

status 0 is a completed successful peer; status 1 is its complete issued
exception view. The complete read owner will forward a status-1 view unchanged.
The fixed coordinator must only form ACKs from actual completions. In
particular, a row Graph or arbitrary integer is not a namespace capability.

| Kind | Complete operation | Required successful view |
|---|---|---|
| 1 | Store.get(ref), including metadata decode | Exact artifact bytes, offset 0, existing maximum 64 MiB |
| 2 | Reborrow held artifact mapping | Same actual artifact lease, extent and bytes; no I/O |
| 3 | SELECT * FROM cursors WHERE id=? | Fully materialized 4-column row Graph, or null Graph |
| 4 | Complete ordinary wire | Actual HIAGWE01 workspace, return 128, payload spans equal its fields |
| 5 | Native SHA-256 over exact issued wire span | Actual 32-byte digest result, return 32 |
| 6 | INSERT OR IGNORE INTO cursors VALUES (?,?,?,?) | Actual statement success; returned value is unused |

The wire header is checked against all six source command correlation fields,
zero error/cause/next-role/private-refusal, and its exact payload extent.
The command is HIAGWC01 with actual output Graph lease, current request
sequence, root 1, maximum 8388608, flags 2, digits and zero reserved field.

Kind 3's successful private projection is explicitly downstream of full SQLite
row materialization. NULL, INTEGER, REAL, TEXT and BLOB remain distinct. This is
a proposed high-level join boundary, not a claim that the unfinished ordinary
namespace adapter already emits this ACK format. Namespace schema/transaction
authority stays with its existing owner.

The SHA peer can mechanically chain the exact already-native sha256_stream
INIT(0), UPDATE(1+wire), FINAL(2), with 1184-byte state and 32-byte output.
Its current intended source is the exact 0ef 30784-byte sha256_stream.hiaasm,
SHA256 7fdc436867514b3d1dd741e3c3d86c0b95cc19d5b69907d5df9febf29639cb68.
The final return must be the actual 32 from that final entry.

## Growth, refusal and lifetime

GROW never reissues Store.get, SELECT, wire, SHA or INSERT. A completed actual
peer view stays immutable across controller GROW; the owner repeats only its
local construction stage. Event sequence advances on every valid owner entry.
Pending request sequence remains unchanged while consuming a response through
GROW. The fixed coordinator must not confuse those two counters.

With a full workspace, malformed initial config, correlation, unknown role,
unexpected phase, late ACK, altered retained header, or use after terminal
permanently refuses the invocation. Advertised workspace shorter than 8192
cannot safely record poison: every BAD return, including that case or event
sequence overflow, requires immediate outer lease disposal. Do not inspect a
stale event as though BAD guaranteed a newly written frame.

The ordinary outer call's native_failed, transaction unwind, cost record and
cached return semantics stay with the separate complete call controller.
This owner does not start an implicit transaction, retry a statement, or commit
a namespace view. On success or any exception the fixed outer owner must
release all temporary Graph/wire/hash mappings and this read workspace while
retaining only the issued complete result/exception view.

## Required evidence before integration

No execution result is claimed by this document. The next stage must:

- Read and bind the exact namespace ABI, generate both kernels under the
  original 128-function/1536-block/8192-instruction limits, and compile with the
  pinned historical f50 B3 under 10 CPU seconds/20 wall seconds/256 MiB.
- Compare complete values, full error texts, SQL binds, all three wire calls per
  condition, hash input, returned cursor and input immutability against the
  complete original method. Include negative extrema, wrong SQLite classes,
  multibyte start/end splits, all control characters, empty and binary data.
- Exercise actual Graph-wire and native SHA peers, not host encoders or hashes,
  while keeping namespace fixture evidence clearly separate from namespace
  qualification.
- Verify complete buffers/canaries and wrong ACK, duplicate response, GROW,
  unknown phase, permanent refusal and held-lease cleanup.
- Bind the high-level namespace adapter and the fixed Worker coordinator before
  claiming any ordinary tool execution or installed scan closure.
