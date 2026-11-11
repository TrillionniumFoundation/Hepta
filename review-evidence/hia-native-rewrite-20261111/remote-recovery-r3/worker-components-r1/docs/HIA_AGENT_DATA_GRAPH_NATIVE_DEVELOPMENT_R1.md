# Agent DataJSON value materialization: new development owner

This is a new, unexecuted revision, not restored R15 evidence. It replaces the
value-producing part of the explicitly selected Agent-data decoder path with
HIA. The HIA source consumes an actual HIADATA1 arena and the same original
wire, and emits the existing HIAGRF01 value graph. It never asks a foreign host
to interpret a semantic plan or box a value.

The full ordinary decode_data entry is not yet closed: its original bytes/text
admission, default fractional-token masking/preflight behavior, image-selection
failure ordering and diagnostic publication still need a fixed coordinator.
The complete tool schema, namespace peers, business owners, eleven-tool Worker,
default routes and installed Worker also remain open.

## Authority and immutable inputs

The first read buffer is the exact complete arena returned by the independently
source-bound Agent-data decoder image. The second read buffer is the exact wire
that the same invocation decoded. The fixed caller must retain these two private
immutable leases and their actual identity throughout every GROW and binary64
continuation. Matching headers and lease numbers are correlation, not an
authenticator for a replaceable arena or wire.

The component checks the whole arena header, all kinds and fractional-tag
consistency, then the complete parent/sibling/container/string/numeric/key
extents and one-parent ownership before any numeric callback. It does not
promise the old Python materializer's arbitrary forged-arena exception text.
Malformed private transports return BAD and must retire the lease.

## RWW executable ABI, with two semantic read buffers

The executable wrapper receives arena R, wire W borrowed as R, and workspace W.
The wire is never modified. Minimum workspace is 4096 bytes; short workspace
returns 0xfffffffd without a promise that poison could be stored. Any BAD return
requires the fixed caller to abandon the lease, irrespective of event contents.

The initial 128-byte config is at workspace offset 128. Other bytes in the first
4096 bytes must initially be zero.

| Word | Config field |
| --- | --- |
| 0 | HIADGC01 |
| 1–2 | Invocation lease, call |
| 3–5 | Arena lease, wire lease, new Graph lease |
| 6 | Original integer digit limit, including zero for unlimited |
| 7–8 | Exact arena extent, exact original-wire extent |
| 9–15 | Zero |

Mutable state begins at 512. Immutable config and arena-header copies are at
1024 and 1152. Full error text is at 1536; decimal text scratch at 1920.
**The event is at 2048..2239 and every normal invocation returns 2240.**
The event cannot overlap config. An earlier unexecuted authoring draft placed
it at zero and was superseded before any execution.

The 24 event words are:

| Word | Event field |
| --- | --- |
| 0–4 | HIADGE01, action, invocation lease, call, increasing event sequence |
| 5–7 | Graph, arena and wire leases |
| 8 | Needed workspace bytes for GROW; otherwise zero |
| 9–10 | Complete Graph offset/extent on DONE; otherwise zero |
| 11–12 | Original-wire numeric span on CALL_BINARY64; otherwise zero |
| 13 | Current source node plus one |
| 14 | Error kind; zero on success |
| 15–16 | Full error UTF-8 offset/extent for semantic failure |
| 17–19 | Configured digits, most recently visited integer digit count, actual binary64 status |
| 20–21 | Private refusal reason, state phase |
| 22–23 | Zero |

Actions: 0 DONE, 1 GROW, 2 CALL_BINARY64, 3 semantic failure, 4 private refusal
(event advisory; the BAD return remains decisive). Phases 10 and 20 are the
structure-scratch and complete derived-workspace allocation continuations;
30 walks values, 31 waits for the actual binary64 response, and 90/91/99 are
terminal. All terminal invocations refuse reuse.

GROW copies the complete previous workspace into a strictly larger buffer.
The caller repeats this component with the same arena/wire leases. No decoder
or completed binary64 invocation is replayed. The component does not publish a
partial Graph. Events and payloads are borrowed until the next invocation.

## Actual binary64 continuation

The floating lexeme is borrowed directly from the original wire span in the
event. The fixed caller invokes the source-bound agent_binary64 image using
that span, a fresh 8-byte output and its original 4096-byte workspace. It
performs no decimal parsing, float conversion or schema decision.

The actual reply header is eight words at workspace offset 256:
HIADGR01, invocation lease, call, issued event sequence, actual u32 status,
actual extent (8 only for status 8, otherwise zero), pending source-node-plus-one,
zero. The actual eight result bytes are copied to offset 320.

Successful finite IEEE bits are copied directly into Graph kind 3. Negative
zero and all finite subnormal/normal rounding results remain bit exact. Actual
nonfinite and syntax statuses preserve the selected store floating callback's
AgentRejected E_HIA_JSON messages; other actual private statuses preserve the
existing RuntimeError message. The fixed caller must bind this response to the
real invocation, not construct a plausible header from an arbitrary peer.

## Complete values and original order

Traversal is iterative source-order, children-before-parent DFS, matching the
existing materializer. Integer digit refusal occurs when that integer is
visited, not during initial structural validation. Floating conversion occurs
at the same position. Thus an earlier oversized integer still precedes a later
nonfinite float, and a preceding nonfinite float precedes a later integer error.

Integers use 32-bit limbs and nine-digit decimal chunks, with exact u64 products
and carries. The output is the existing little-endian absolute magnitude plus
sign, including zero-length magnitude and positive sign for both 0 and -0.
The configured zero limit remains unlimited: there is no new total-digit quota.
The algorithm has quadratic large-integer work; the development panel must not
be called a performance proof for every possible 8 MiB unlimited integer.

Strings and object keys are checked as strict UTF-8 and record Unicode codepoint
counts. Arrays retain source order. All values under an object are completed
before its keys are decoded, and all of that object's keys are decoded before
duplicate-key testing, preserving the original list-comprehension then set
ordering. Hash collisions use exact complete key-byte equality. Containers and
key nodes are issued solely by HIA; the caller never translates a descriptor
table into values.

Graph records use exactly the established 64-byte HIAGRF01 node layout:
null 0, bool 1, magnitude integer 2, IEEE binary64 3, string 4, array 5, object 6.
Object edges alternate issued string-key and value IDs. No new Graph language
or integer-only substitute is introduced.

Semantic failure payload kinds are: 1 original integer ValueError full text;
2 AgentRejected E_HIA_JSON nonfinite message; 3 AgentRejected E_HIA_JSON syntax
message; 4 RuntimeError original converter-profile message. Production error
classification/publication belongs to the fixed coordinator; a test oracle's
Python exception object is not a production fallback.

## Capacity proof and remaining execution scope

The original decoder bounds values N at 262144 and nesting at 128. Map key
occurrences K are at most N-1, and total Graph edges are N-1+K. Additional key
nodes do not create a language-node quota. Structure scratch is first bounded
by N; full allocation is derived only after all tree extents pass.

The private implementation uses N linked bytes, two N-word maps, N frames of
24 bytes, a power-of-two full-byte-equality table with fewer than 4K slots of
32 bytes, and the complete Graph. Metadata needs at most 144N bytes, apart
from a fixed small header. Scalar pool reservations include UTF-8 bytes,
8 bytes per float, and ceil(integer-span/2)+3 bytes per integer. The three
trailing bytes permit a final 32-bit limb; unused scratch is removed from the
published exact Graph extent. All additions that can depend on arbitrary
payload extents check u64 overflow.

For an actual issued decoder arena, string/key spans and numeric source
occurrences derive from the bounded original wire. A conservative total is
under 321N + original-wire-bytes + 8192, well below 1 GiB for the original
8 MiB input and N bound. This is a workspace derivation, not a claim about
arbitrary external arenas with overlapping forged spans, whole-process RSS,
or qualification of all possible runtime durations.

The planned new CI compiles this owner plus exact original decoder, binary64,
Graph scan and Graph emit sources with the same historical B3 and original
10 CPU / 20 wall / 256 MiB gates. Separate child panels retain 90 CPU / 1 GiB.
Semantic values, full error text/order, actual binary64 calls, actual native
Graph-wire interoperability, source/canary custody, protocol negatives,
262144 nodes, exact 8 MiB string and a 100000-digit unlimited value are recorded
independently. No old test result is inherited. A future fixed native executor,
raw prefix, caller lifecycle, schema and entire Worker still need their own
actual evidence.
