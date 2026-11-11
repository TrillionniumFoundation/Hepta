# Native ObjectToken renderer

This component implements streamed ObjectToken-to-canonical-JSON conversion in
HIA. It is an explicit native candidate, with no public default switch and no
whole-stack qualification claim. Its source is developed in a separate v68
worktree; the v67 qualification checkout is immutable.

The component accepts an exact typed source packet and complete ObjectToken
frames. It keeps a HIA-owned typed graph, source-node index, streamed container
stack and retained-object registry. Source references address actual wire node
headers, including dictionary keys. A reference is never interpreted as an
address into scalar payload bytes. Native records distinguish null, booleans,
arbitrary-precision decimal integers, UTF-8 strings, lists and dictionaries.
References to a previously sealed dictionary retain that typed graph. JSON is
produced only by the final native serializer.

## Byte API

`NativeNominalTokens(image).session()` creates an independent retained session.
`begin(source_wire, stream_magic, action, serial=0, slots=0, request=0)` admits
the source packet and starts its first stream. `feed(frame)` accepts a complete
64-byte identity header followed by its declared payload and returns whether
that stream is final. `canonical()` returns HIA-produced UTF-8 JSON with sorted
keys and compact separators. `restart(stream_magic, action, serial=0, slots=0,
request=0)` starts another stream over the same admitted source. A successful
`seal(handle)` retains a final dictionary under a unique handle at least 2**63.
Closing a session releases its private mappings.

Use the session as a context manager. `restart` requires a completed final
stream. It keeps the admitted source and all sealed dictionaries, reclaims
unsealed graph allocations, clears the active stream, and starts sequence zero
under the new complete identity. `seal` accepts a dictionary root only; repeated
or low-namespace handles poison the session. A reference can target the same
source subtree repeatedly without cloning that subtree into host objects.

Every stream frame is `<8Q>(magic, action, sequence, final, serial, slots,
request, payload_bytes)`. Sequence starts at zero; final must be zero or one.
Token payload is a sequence of `<2Q>(kind, value)` headers. Kind 0 references a
source node or retained handle; 1 has `value` following string bytes; 2 is an
unsigned 64-bit integer; 3 is a boolean 0 or 1; 4 is null with value zero; 5 is
a list child count; 6 is a dictionary pair count. Token headers and string
bytes are complete within a frame; containers may span frames. A final stream
contains exactly one complete root. Dictionary keys must be unique strings.

This native path accepts valid Unicode scalar strings. The older foreign
`surrogatepass` transport route is outside its input contract. Source integer
lexemes are canonical decimals and do not pass through a host integer parser.
Any public JSON digit policy is enforced before this typed transport boundary.
The component introduces no 8 MiB expanded-result limit. Workspace and output
requests are calculated in HIA, checked for address-space overflow, and grown
by the fixed buffer bridge before native publication. A malformed protocol
permanently poisons the session. Capacity retries must not consume a frame.

## Native ownership and publication

The checked HIA program owns source admission, a sorted index of every actual
source node offset, typed graph nodes, dictionary key hashing and collision
comparison, container completion, references, and the retained handle chain.
Node records distinguish source integer lexemes from token u64 integers. Key
references are resolved to their real string type before duplicate checking;
referencing a dictionary or number as a key is refused.

The fixed Python bridge creates private mappings, transports immutable byte
requests, checks the complete 64-bit native return and eight fixed reply words,
grows a mapping only in response to a larger native requirement, and returns
the completed byte slice. It contains no JSON payload parser or serializer,
`ObjectTokenDecoder`, source wire encoder, nominal classifier, or foreign type
materializer. Request bytes are compared after each native invocation. Code is
loaded through the existing source/image-bound native resource loader. Session
calls and close are serialized by a lock; mapping exports are temporary so
exception tracebacks do not retain exported mmap views.

The image first counts actual source nodes or complete frame tokens, checks
arithmetic, and reserves enough graph and key-table space before admitting the
operation. Strings and node headers cannot split across frames. A capacity
reply changes neither the expected sequence nor the admitted token count.
Protocol refusals publish only a fixed refusal header; canonical payload is
available only after one complete final root. The canonical serializer uses a
native traversal stack and cached complete sizes over a typed acyclic graph.
It reuses the existing HIA JSON escaping functions, and sorts string keys by
UTF-8 byte order, which agrees with Unicode scalar order in this input domain.

The native request is `<8Q>(HIANTK01, operation, identity0, identity1, identity2,
identity3, identity4, payload_bytes)`. Operations are begin 1, feed 2,
canonical 3, restart 4, and seal 5. Begin and restart carry the five stream
identity words; seal carries only its handle. Other reserved fields are zero.
The reply is `<8Q>(HIANTR01, status, final, next_sequence, required_workspace,
required_output, token_count, root_kind)`. Status 0 succeeds, 1 requests more
workspace, 2 requests more canonical output, and 3 permanently refuses. The
Core return is always exactly 64 for a framed response. Canonical output
follows that header; its complete extent is the u64 required-output word,
not a truncated Core return. Sizes are checked against the addressable buffer
range. Progress counters use their separate u64 overflow rule.

## Building and evidence scope

`tools/build_hia_nominal_tokens.py` requires a matching-source cold compiler
and complete cold source map. It checks the actual native compiler receipt:
compiler and input identities, successful return, exact integer sizes, full
zero-extended return encoding, unchanged input, produced image identity, and
an empty forbidden-module list. It rechecks source, compiler, cold report,
source map, image and receipt before writing the manifest and build report.
The builder does not activate a route or claim equivalence for untested inputs.

`tests.test_hia_nominal_tokens_native` has independent checked-interpreter
controls before native execution. Its native fixture either constructs fresh
B0/B1/B2 development generations or, when
`HEPTA_HIA_NOMINAL_TOKENS_COLD_REPORT` is set, actually runs the strict builder
into a new independent directory using the nested cold compiler. A development
manifest is never substituted for that branch. Set
`HEPTA_HIA_NOMINAL_TOKENS_EVIDENCE` to a new directory to retain compile inputs,
receipts and observations; the observation file by itself is not a PASS report.

Controls cover exact typed values and source node/key offsets, rejected payload
offsets, canonical arbitrary-precision decimals, valid and invalid Unicode,
cross-frame containers, three owner identity layouts, duplicate reference
keys, retained dictionaries, one thousand deterministic random trees, expanded
output above 8 MiB, capacity retries, permanent refusal, full-return and input
custody, concurrent independent sessions, mapping cleanup, and native compile
receipt identities. Linked-image controls compile the actual constructor owner,
constructor renderer and raw JSON codec using the same compiler, then pass their
real frames through this renderer with host payload parsers and encoders blocked.
They compare completed bytes with the retained decoder only in the test oracle.
They cover first type requests and early final refusal states; they do not count
as complete constructor initialization.

The constructor integration supplies already checked canonical input
and uses this renderer for commands and final state bytes. This file does not
claim complete constructor initialization, function lowering, outer lowering,
or retirement of the existing Python semantic stack.

The current output API is canonical JSON only. It does not yet export the typed
transport needed for direct function/outer startup composition. That follow-up
must preserve typed reference semantics and dictionary insertion order, and
must not route expanded results through the public 8 MiB raw JSON codec.
