# Native ObjectToken renderer

This component is a candidate under construction. No qualification result or
public default is implied by this file. Its source is kept in a separate v68
worktree; the v67 qualification checkout is immutable.

The component accepts an exact typed source packet and complete ObjectToken
frames. It keeps a HIA-owned typed graph, source-node index, streamed container
stack and retained-object registry. Source references address actual wire node
headers, including dictionary keys. A reference is never interpreted as an
address into scalar payload bytes. Native records distinguish null, booleans,
arbitrary-precision decimal integers, UTF-8 strings, lists and dictionaries.
References to a previously sealed dictionary retain that typed graph. JSON is
produced only by the final native serializer.

## Proposed byte API

`NativeNominalTokens(image).session()` creates an independent retained session.
`begin(source_wire, stream_magic, action, serial=0, slots=0, request=0)` admits
the source packet and starts its first stream. `feed(frame)` accepts a complete
64-byte identity header followed by its declared payload and returns whether
that stream is final. `canonical()` returns HIA-produced UTF-8 JSON with sorted
keys and compact separators. `restart(stream_magic, action, serial=0, slots=0,
request=0)` starts another stream over the same admitted source. A successful
`seal(handle)` retains a final dictionary under a unique handle at least 2**63.
Closing a session releases its private mappings.

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

The intended constructor integration supplies already checked canonical input
and uses this renderer for commands and final state bytes. This file does not
claim complete constructor initialization, function lowering, outer lowering,
or retirement of the existing Python semantic stack.
