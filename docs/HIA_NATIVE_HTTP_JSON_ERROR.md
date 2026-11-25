# Native HTTP JSON syntax diagnostics

The `mcp_http_json_error` HIA module implements the raw JSON syntax error
behavior used by the Streamable HTTP MCP boundary. It emits the original
serde error text, including byte-based line and column positions, without
the transport's `fail to deserialize request body ` prefix.

## Pure-call contract

The six-word span ABI receives the raw body as its input view. The input
limit is 4 MiB, the output view is exactly 8 MiB, and the work view is
exactly 44 MiB. Output word 0 selects the operation:

| Mode | Operation |
| --- | --- |
| 0 | Parse the first Value, then require only whitespace through end of input. |
| 1 | Parse the first Value and leave trailing input for the typed MCP decision. |

Return zero means this syntax operation succeeded. A positive byte count
below the output extent identifies the exact error bytes at output offset
zero. Invalid modes, invalid view extents and bodies above the limit return
4294967293. Work word 0 records the actual first Value's consumed prefix
offset; trailing whitespace is not included in that offset.

The module streams values without imposing the retained JSON arena's node
limit. It preserves the original 127-container recursion boundary, UTF-8
and escape checks, number overflow behavior, duplicate-key syntax behavior
and first-error position. It does not classify a Value as a valid MCP message.

## Transport ordering

The transport first invokes mode 1. A syntax failure is returned immediately.
Otherwise it passes exactly that consumed Value to the existing typed
ClientJsonRpcMessage classifier. An unrecognized typed message keeps the
original generic untagged-enum error. Only a recognized message proceeds
to mode 0's trailing-input check.

This ordering was compared with the frozen original HTTP server over actual
loopback sockets. A whole-document syntax check before the typed decision
would change errors for a syntactically valid but unrecognized message
followed by trailing bytes.

## Qualification

The qualification record pins the source, actual native flat image,
qualified full native source compiler and external evidence. There are
2970 full-Value comparisons against the original serde oracle and 120
prefix controls, plus five private mode/body-size refusal controls.
Coverage includes all 256 byte values in strings and keys, malformed UTF-8,
Unicode surrogate edges, numeric overflow and underflow, every selected
truncation/mutation position, recursion boundaries, more than 524288 value
nodes, and inputs up to exactly 4 MiB.

380 actual original HTTP requests also matched the native syntax and
typed-before-trailing decision order, including valid requests,
notifications and responses, invalid typed fields, malformed input,
recursion and body-size boundaries.

The component was constructed by the qualified full native HIA source
compiler with an empty PATH. The smaller independent word seed correctly
refused this recursive source; that development attempt is retained and
is not reported as a successful construction. The existing 1 MiB Jobctl
diagnostic facet is unchanged.

This record qualifies the JSON error component. Listener, authentication,
session state, cancellation, work-directory behavior and complete HTTP
service qualification remain owned by the transport integration.
