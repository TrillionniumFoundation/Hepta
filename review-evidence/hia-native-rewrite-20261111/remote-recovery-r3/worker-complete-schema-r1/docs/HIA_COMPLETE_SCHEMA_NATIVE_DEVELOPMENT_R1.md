# Complete fixed-catalog schema owner — new development revision

## Current status

This revision contains new authoring and a new independent CI harness. It has
not yet been generated, executed in CoreVM, compiled by B3, or executed as native
code. Earlier fixed-pattern and DataGraph component passes do not qualify these
four new images. This revision does not activate an ordinary Worker selector,
remove Python, close namespace storage, or claim whole-stack completion.

The reference is the exact restored hia_agent_contract.py from the selected
reference snapshot: SHA256
5878c0b188cb4a31f486e4a2b6f261a30fb20c06da810cd5f079746956abb2f7.
The complete vocabulary used by all eleven tool input/output schemas and the
ten internal workload/objective/cost/machine-plan schemas is covered. The
existing contract is a fixed-catalog validator, not general JSON Schema. No
new regex language, foreign catalog extension, or arbitrary malformed Python
schema-object compatibility is promised.

## Semantic ownership

All validation, vocabulary traversal, child ordering, branching, catch scope,
numeric comparisons, wire requests, pattern requests and full diagnostic text
are owned by HIA. The host may forward an issued event, grow a workspace while
copying its complete old bytes, or invoke the exact requested image. It may not
walk a schema, select a branch, compare values, translate a semantic plan, or
supply a cached wire/regex admission.

The four images share one private workspace:

| Role | Image | Work |
| --- | --- | --- |
| 1 | schema_scalar | Strict types; const/enum; string bounds and patterns; exact numeric bounds |
| 2 | schema_logic | Complete oneOf/anyOf/tagged diagnostics; allOf/not/if; vocabulary |
| 3 | schema_containers | Required/properties/additional fields; array bounds/unique/items/contains |
| 4 | schema_errors | Full diagnostic text and exact schema-only catch unwinding |

The independent Graph-wire scan/emit pair executes every original wire()
invocation with max_bytes=8388608, flags=2 (ensure_ascii=false, sort_keys=true),
and the caller's exact integer digit setting. The independently compiled
pattern image implements the five exact published patterns, including Python
re.search dollar-anchor behavior with a single trailing LF.

This split is a fixed image-dispatch mechanism. HIA decides the next role. It
does not give the host a semantic plan. Each image retains the original
128-function, 1536-block, 8192-instruction, 256-block-per-function and 16-parameter
authoring limits. Each actual compiler child retains 10 CPU seconds,
20 wall seconds and 256 MiB address space.

## Preserved order and failure behavior

Validation starts with boolean schema behavior and strict Python-kind rules.
Only finite integral binary64 values count as integer; bool is distinct.
Const compares two fresh full wire admissions. Enum rewires the value before
every visited choice and stops at the first complete equality.

Both oneOf and anyOf evaluate every matches() branch. Only AgentRejected is
caught. A foreign HIAEditRejected raised by a wire admission is propagated even
after a previous branch matched. On zero matches, dictionary discriminator
checks use properties order and actual wire calls; exactly one tagged branch
is replayed for its original diagnostic. The final union rejection remains
after that replay.

allOf is ordered. not and if use the original schema-only catch scope.
Missing dictionary fields are deduplicated and sorted by Unicode code point
before children. Present fields are visited in source order; property counts
are checked afterward. List length is checked before unique/items/contains.
uniqueItems independently wires every element, including those after a known
duplicate; an exact-byte hash table is only a comparison index, never an
admission cache. contains short-circuits and uses the separate default
"arguments" label. String lengths count Unicode code points.

Numbers retain arbitrary little-endian integer magnitudes and full binary64
bits. Comparisons are exact dyadic comparisons, not floating conversion of a
large integer. NaN, infinities, signed zero, subnormal values and default
infinite bounds preserve the original branches.

An uncaught schema error exposes complete label + ": " + reason with
E_HIA_SCHEMA as a separate code. A foreign wire error exposes its complete
E_HIA_EDIT text. Vocabulary failure exposes the original ValueError text.
The diagnostic has no new arbitrary byte limit. Workspace GROW occurs before
the corresponding allocation; it does not repeat a completed peer invocation.

## Private inputs and authority

Every image has the retained three-buffer entry shape. The first read buffer
is the private immutable issued HIAGRF01. The second buffer is borrowed as a
read buffer from the command or the actual source-bound peer result. The third
buffer is the shared mutable workspace.

The Graph contains both value and trusted catalog schema. Its existing node
kinds preserve null, bool, arbitrary integer, binary64, string, list, map,
tuple, opaque Python-kind witness and bytes. The new owner checks header,
extent, node/edge ranges and UTF-8/code-point counts before traversing. This is
not an external authentication protocol. Equal headers or integers do not
authenticate a replacement arena. The fixed coordinator must retain the same
private immutable issuer lease and exact actual peer buffer throughout a
continuation.

The initial workspace is zeroed and at least 4096 bytes. The complete 128-byte
command is sixteen little-endian u64 words:

| Word | Meaning |
| --- | --- |
| 0 | HIASVC01 |
| 1 | Invocation lease, nonzero |
| 2 | Call identity, nonzero |
| 3 | Exact Graph lease |
| 4 | Value root; required for validation |
| 5 | Schema root |
| 6 | Label string root; zero selects arguments |
| 7 | Exact integer digit setting |
| 8 | 0 validate; 1 check_vocabulary |
| 9–15 | Zero |

All workspace references are offsets. State begins at 512; saved command and
association records are below 1536. The event occupies [2048,2304). Dynamic
frames, paths, comparison bytes and diagnostics begin at 4096. A frame is
192 bytes; a label component is 32 bytes. Parent pop/catch releases child
temporary memory at the exact frame mark. There is no new total command,
total node, recursion-depth or output quota beyond the existing peer language
gates and representable u64 allocation arithmetic.

## Actual peer acknowledgement

Before resuming a pending peer, the coordinator writes this complete 64-byte
ACK at workspace offset 256:

HIASVA01, invocationLease, call, requestSequence, peerKind,
actualNativeReturn, actualBorrowedExtent, zero

peerKind=1 is Graph wire; peerKind=2 is fixed pattern. The owner binds all
fields to its outstanding request, then validates the complete actual peer
header, output view, error domain and response extent.

Graph wire must have its actual 128-byte terminal event. GROW and scan-to-emit
events are consumed by the fixed wire peer before replying to this owner.
Pattern must have its complete 64-byte terminal response with exact pattern
identity, string-byte count and match bit.

A response-copy GROW preserves the copied ACK and peer-header association.
The same immutable actual peer buffer is supplied again, without re-invoking
the peer. Association checks are not permission to substitute another buffer
with equal-looking metadata.

## Event

The returned extent is 2304, and the 256-byte event is at offset 2048. Its
32 little-endian words are:

0 magic HIASVE01; 1 action; 2 invocationLease; 3 call; 4 eventSequence;
5 graphLease; 6 requestSequence; 7 peerKind; 8 peerRoot; 9 nextRole;
10 growNeeded; 11 commandOffset; 12 commandBytes; 13 frameOffset;
14 frameStage; 15 responseActive; 16 responseExtent; 17 errorDomain;
18 errorReason; 19 errorTextOffset; 20 errorTextBytes; 21 valueID;
22 schemaID; 23 digits; 24 privateBadReason; 25 flow; 26 mode;
27 status; 28 observedPeakHeap; 29–31 zero.

Actions are 0 success, 1 GROW, 2 semantic rejection, 3 peer request, 4 next
fixed role, and 5 private refusal. The scalar entry is the only initial role.
A role transition is bound to the emitted nextRole; replaying a completed
invocation is rejected.

The direct return BAD=0xfffffffd takes precedence over any event. The fixed
caller must discard the invocation and all pending borrowed views immediately.
For a workspace shorter than 4096 bytes, native code cannot safely persist
poison; no claim is made that such a raw ABI call writes a refusal event.
Sequence overflow likewise must not be interpreted through an old event.
These are private coordinator obligations, not public schema errors.

## Independent execution plan and evidence

The new job restores exact original dependencies and the historical f50 B3
668608-byte compiler with SHA256
0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8.
It does not substitute a different current compiler or inherit cold status.

Generation and B3 attempts for every independent role are preserved. Tests
start only if all four new images and all three peer images have compiled.
Five separate original-limit groups cover:

- Strict kinds, all keyword paths, source/diagnostic ordering, complete text,
  exact wire invocation order and pattern invocation order.
- Arbitrary integer/binary64 and length-bound comparisons, including random
  finite/nonfinite bit patterns and limits around 2^53, 2^64 and 2^1024.
- Every actual tool input/output schema and all ten internal schemas, plus
  vocabulary refusals and empty-tool input/output diagnostics.
- An exact 8 MiB value, complete long Unicode diagnostics, sorted missing keys
  and a full 1024-element uniqueItems wire sequence.
- Wrong command/Graph/role/ACK/peer fields, repeated GROW, response correlation,
  terminal replay, sequence overflow and the short-workspace discard boundary.

The retained Python validator is used only before native execution as an
independent oracle. The Graph capture is an explicit test fixture, not a public
issuer. During actual forwarding, old validate/check_vocabulary/wire,
bounded_json_wire, json.loads and re.search paths are disabled. Every actual
entry records source, complete second buffer and complete workspace before and
after, return value, immutable input and canaries. Raw bytes are compressed
content-addressed objects with fresh decompression checks. Source and compiled
image bytes are checked before and after.

A successful development job would close this component under its stated
private issued-input contract. It would not close the public raw DataJSON
prefix, full fixed Worker coordinator, installed scan, eleven business tools,
or physical namespace service.
