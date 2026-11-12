# Native Agent JSON wire owner

The entry in `examples/hia_bootstrap/agent_json_wire.hepta` writes compact UTF-8 JSON from the actual native Agent-data decoder's private `HIADATA1` arena. It owns traversal, decoded string-key sorting, string escaping, decimal-to-binary64 conversion, shortest finite binary64 formatting, integer lexical output, and the final 8 MiB output budget.

This is an explicit private codec. The ordinary `wire(data)` Python-object API and default `decode_data` admission remain separate owners. The adapter allocates/copies buffers and maps immutable code; it does not parse JSON, create an object graph, convert decimal numbers, or reconstruct successful wire bytes. A raw arena supplied without its admitted native producer is not an authentication or semantic admission token.

## Exact boundary

`f0(raw:readbuf, output:mutbuf, state:mutbuf) -> u32` consumes the original bytes and an owned copy of the decoder arena. Node layout is unchanged: 64-byte header and 56-byte records; tag 7 stores the original fractional/exponent number span. The entry checks header, extents, parent/child/sibling ownership, complete node coverage, UTF-8 strings, integer lexemes and depth. It records actual float bits beside the arena, then sorts each object's child chain and writes the complete result.

The JSON profile is fixed to 8 MiB, 262,144 nodes, depth 128, string keys, `ensure_ascii=False`, sorted keys, and comma/colon separators without spaces. Numeric conversion runs in original node order. Integer output conversion limits run in sorted serialization order. Zero for the observed interpreter integer-digit setting means unlimited; it is not replaced by the default 4,300. Integer negative zero becomes `0`, while binary64 negative zero remains `-0.0`.

The earlier default Agent decode path checks whole-input UTF-8, its byte bound, preflight, and source-order numeric conversion. This writer does not claim that earlier error ordering. A caller composing the complete metadata owner must preserve that admission separately before using this private codec.

## Reused native algorithms

The source generator incorporates the existing HIA decimal converter and finite binary64 formatter. Its inverse AST audit restores every original numeric function after removing only workspace addresses, span transport, entry capacity and function namespace rebasing. Shared arithmetic helpers are required to be exactly identical. The canonical UTF-8 string encoder and linked merge sort are copied as exact source ASTs.

That source audit is mechanical custody evidence. It does not replace executing the composed program in the independent Core VM and as a native image. Component controls compare complete bytes, boundaries, actual native refusal status, canaries, input immutability and concurrent private workspaces.

## Relation to the existing bounded object writer

The current Python writer also preflights foreign-object cycles, queued nodes, arbitrary object types, numeric keys and key-coercion collisions. Those cases remain outside this decoded-JSON tree ABI.

For a well-formed admitted tree, every non-root node has exactly one parent and is visited once. At any point, visited plus queued nodes is bounded by the complete node count; therefore the old queued-node check adds no rejection when that count is at most 262,144. This implication relies on the complete ownership and coverage checks, not merely the count word.

Every valid decimal integer span contains at most 8 MiB digits. An integer with D decimal digits has bit length at most 4D, so the original `maximum * 4` integer-bit guard cannot add a rejection in this fixed raw-input domain. The actual decimal repr digit limit remains a separate check during sorted output. Decoded string escaping is checked independently; native UTF-8 byte order gives the same order as Unicode scalar values for valid keys.

## Publication and custody

The adapter never returns partial bytes on refusal. The raw input and producer arena remain immutable: sorting and numeric scratch operate on a private copy. A new copy is required on every call.

The standard five-field manifest binds source, image and compiler. The production builder requires the original matching-source cold gate, including 180-second qualification and 3-second cleanup limits, and rechecks all source/compiler/cold/image bytes before publication. Explicit loader use does not activate the ordinary Agent provider.

`whole_native_delivery_qualified`, `default_changed`, `native_Agent_persistence` and `python_object_graph_owner_replaced` remain false. See `HIA_AGENT_JSON_WIRE_ABI.json` for exact offsets and status values.
