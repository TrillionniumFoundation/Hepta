# Complete ordinary default DataJSON prefix — development r1

Status: NEW SOURCE, not yet AST-generated, compiled, executed, installed or
activated. The six initial authoring blobs are preserved. The only pre-execution
follow-up uses an ASCII run in complete Unicode validation; the full bytes are
still read, and the last successful codepoint observations remain identical.

This component migrates the complete **ordinary default** path of
`hepta.hia_agent_store.decode_data` in exact reference
`0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5`. It does not silently select the
operator-selected Agent-data profile, whose error order is a separate contract.

## Ordered owners

1. HIA checks the input kind. Bytes undergo complete strict UTF-8 decoding;
   strings arrive as the caller's private surrogatepass representation and
   undergo complete strict UTF-8 encoding validation. A Unicode failure is
   emitted before the 8 MiB test, including a failure after 8 MiB of valid text.
2. HIA performs the exact outside-string number regex scan. Only a successfully
   matched fractional/exponent lexeme becomes the single ASCII byte `0`.
   Quoted strings and integer lexemes retain their original bytes.
3. The exact native integer-JSON preflight is invoked with 262144 nodes and
   depth 128. Its original status and diagnostic reason produce the original
   full ValueError or OverflowError. Its complete work buffer is the reply.
4. The exact native Agent raw decoder parses the original source to its private
   value arena. It neither evaluates Python integers nor invokes float callbacks.
5. For a syntactically valid source, the previously frozen HIA DataGraph owner
   handles all value production and the actual binary64 peer. It preserves
   source-order numeric callbacks, arbitrary integers, negative zero, object
   insertion order and the exact interpreter digit policy.
6. If masked preflight passed but the original decoder reports syntax failure,
   a third HIA controller walks the original prefix in source order. It invokes
   the real binary64 peer for each reached float and performs the original
   integer digit check before moving to the following delimiter. Thus
   `[1e9999,1-2.5]` reports the first nonfinite conversion, whereas
   `[1,1-2.5,1e9999]` reports the earlier separator error without evaluating the
   last float. It renders complete JSONDecodeError text, line/column and
   codepoint position. It never materializes another value tree.

No prior admission, VerifiedProgram, object graph or qualification result is
cached. The same raw decoder is not retried after a failed syntax result. The
late parser is not a reduced public grammar: it is a private continuation after
the complete masked JSON admission and actual original decoder. Reaching an
otherwise accepted terminal there contradicts the actual decoder return and
retires the invocation.

## Private transport ABI

Each of the three controller images exposes the retained RWW executable ABI;
the second buffer is borrowed as read-only by HIA. The first is the caller's
original immutable source lease. The third is one private growable workspace,
minimum 8192 bytes. There are no host-selected schema branches.

The initial configuration is 16 little-endian u64 fields at workspace 128:

| Word | Meaning |
| --- | --- |
| 0 | `HIAGDC01` |
| 1–2 | invocation lease, call |
| 3–4 | raw wire lease, output Graph lease |
| 5 | ordinary input kind: 9 bytes, 4 text; other kinds are the ordinary type rejection |
| 6 | current interpreter integer digit policy: 0 or at least 640 |
| 7–8 | private decoder arena lease, DataGraph invocation lease |
| 9 | exact original source byte extent |
| 10–15 | zero |

All required leases and the call are nonzero. The original 128 bytes, extent and
kind remain bound on every continuation. Strings are represented by exact UTF-8
surrogatepass bytes only as transport; no replacement character or silent
Unicode repair is allowed.

The ACK at workspace 256 has 16 words:

`[HIAGDA01, invocation, call, pendingEventSeq, peerKind, actualU32Return,
actualBorrowedExtent, actualWorkspaceExtent, outputLease, workspaceLease,
rawLease, actualOutputCapacity, actualInputExtent, 0, 0, 0]`.

The fixed coordinator must forward the actual return and exact immutable peer
buffers from that same request. A matching integer header is only correlation.
It does not authenticate any arbitrary replacement arena or output.

Peer kinds are 1 integer preflight, 2 original raw decoder, 3 complete DataGraph
service, 4 late binary64. For kind 3 the service consumes its own real GROW and
binary64 continuations and hands back its actual terminal workspace; it does
not hand back a host-interpreted value. Its invocation, call, arena, wire,
Graph lease, digit policy, terminal phase, result extent and error shape are
all checked by the controller.

Every event is 32 words at workspace 2048; the actual function return is 2304:

| Words | Meaning |
| --- | --- |
| 0–4 | `HIAGDE01`, action, invocation, call, event sequence |
| 5–9 | raw lease, Graph lease, input kind, digits, phase |
| 10–13 | next controller role, GROW required extent, peer kind, pending sequence |
| 14–20 | peer input owner / offset / bytes, output capacity, work capacity, config offset / bytes |
| 21–23 | terminal result owner / offset / bytes |
| 24–30 | error domain / reason / start / end / auxiliary / line / column |
| 31 | zero |

Actions: 0 DONE, 1 GROW, 2 invoke the fixed peer, 3 ordinary semantic error,
4 private refusal, 5 next controller. Input owner 0 is original raw, 1 is this
workspace's masked bytes, 2 is the actual held decoder arena. Terminal owner 1
is the controller's exact UTF-8 error; owner 2 is the actual completed DataGraph
workspace and its complete Graph subview. The latter lease must stay alive and
immutable until the caller consumes it.

Error domains preserve complete exception class and text: 1 AgentRejected with
code E_HIA_JSON, 2 ValueError, 3 OverflowError, 4 UnicodeDecodeError,
5 UnicodeEncodeError, 6 JSONDecodeError, 7 RuntimeError. AgentRejected's native
text is the actual `str(exc)`, without inventing a code prefix. Unicode
decoding positions are raw byte indices; Unicode encoding / JSON syntax
positions are original Unicode codepoint indices.

Return `0xfffffffd` always retires the invocation. A too-short advertised
workspace and event-sequence overflow may be unable to issue a fresh refusal
event. The fixed coordinator must not inspect an old event and resume after
BAD. Other full-workspace protocol errors persist phase 99; semantic terminals
persist phase 90/91 and cannot be reused.

## Growth and bounds

Only the raw-mask workspace can request controller growth: 8192 plus original
source bytes, after complete Unicode validation and the original 8 MiB gate.
The mask cannot expand its source. Its event points into the same private
workspace. Moving the buffer preserves every previous byte and the issued
configuration; no already completed peer is invoked again.

Integer preflight uses its original key-table and 4256-byte stack formulas.
Raw decoder uses the original `arena_sizes` formulas: at most
`max(4256,64+56*min(262144,(N+1)//2+1)+N)` output bytes, with
`max(keyBytes,6320)` work. These are allocation bounds derived from admitted
input size; neither changes node or depth admission.

The late prefix parser needs only 129 active containers, each 16 bytes. This
capacity follows the already completed depth-128 gate and adds no language
quota. The original decoded value Graph remains entirely in the growable
DataGraph peer. No raw/Graph node limit is introduced here beyond the existing
default `decode_data` admission.

Every dynamic error is composed from fixed literals, u64 decimal positions,
one byte or one surrogate, or the already bounded native numeric message.
1024 bytes covers these forms conservatively; no user label or whole JSON
document is embedded in an error message. The original source lease remains
available for a future mechanical exception/report bridge.

## Planned new validation

All 7 images compile afresh under the original f50 B3 identity
`0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8`,
10 CPU seconds / 20 wall seconds / 256 MiB for each compile. No old image is
substituted for a failed newly generated image.

Independent groups preserve the original 90 CPU seconds / 1 GiB per process:
semantic full values and diagnostics, exhaustive byte/Unicode controls, digit
and callback ordering, depth, four oversized Unicode-priority cases, two exact
8 MiB strings, 262144/+1 node controls, a 100000-digit unrestricted integer,
and malformed private protocol/terminal controls. The group identities and
budgets are fixed before the first execution. Failures are retained independently.

The unchanged Python default `decode_data` is the oracle outside the actual
interval. It records exact masked preflight input and every reached float
lexeme. Each HIA result is compared by complete error class/text/position or
complete Graph value, including integer magnitude, binary64 bits and dict order.
Former Python parsing and materialization entrypoints are poisoned in every
actual interval. Whole source/images and input/read-only buffers are pinned
before and after; per-entry complete input/workspace bytes have compressed CAS
records and canaries.

The executor here remains a mechanical Python development harness. This stage
does not close fixed Worker dispatch, the operator-selected profile, installation,
namespace storage, runtime-free execution, or whole-stack qualification.
