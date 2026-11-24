# Native MCP input-contract diagnostics

The checked-in HIA program replaces the original Rust input-schema diagnostic operation for the eleven HIA tools. The native process service calls it after durable audit begin, before typed provider admission. The service's raw JSON admission, SDK request deserialization, authentication and resource route remain separate operations.

The semantic reference is the unchanged `check` and `validate_input` implementation in `runtime-v26-source/src/mcp/hia_contract.rs` at runtime commit `d022649c64b48fb2a43263faf90103a9a8957b94`. Its RPC prefix comes from `server.rs::dispatch_hia`. In the original call path, `call_tool` begins the durable audit before invoking the router and input validation.

## Flat ABI

The ordinary six-machine-argument HIA flat ABI takes a read buffer, output buffer and workspace buffer. Input is a compact, key-sorted, serde-compatible JSON Value serialization of the tool's arguments. The parent owns normalization of duplicate object keys and number representations before this operation. This precondition is material to structural equality and first failing object-field order.

Before entry, the caller writes the tool ordinal (1–11 in the frozen catalog's order) as little-endian u64 at workspace byte 0, and the exact 64-byte lowercase catalog SHA-256 at bytes 8–71. The catalog digest is `b6b8054ce46ae9ceac260e99a3d1beaf5d6c9343bc4c6e5d96281eedd3c3edfd`.

The maximum input is 8 MiB. Output capacity is at least 8 MiB + 512 bytes, and workspace capacity is at least 32 MiB. A long unknown key can legitimately produce an error larger than 1 MiB; the full path is retained.

Return 0 means validation succeeded and output bytes are unspecified. A positive ordinary byte count is the complete UTF-8 RPC error object containing code -32602 and the original message prefix, path and diagnostic suffix. Existing parser statuses `0xfffffffc`–`0xffffffff` are invocation or parsing refusals, not output lengths. The caller must distinguish those statuses before consuming the output buffer.

The workspace and output scratch are private to the call. No path, descriptor, process, environment or network authority is used by this component.

## Original check order

HIA preserves the original ordering: depth and boolean schema; type; constant and enum; oneOf, anyOf and allOf; not; if/then; required object fields in schema order; present properties in Value order; array length, uniqueness, items and contains; Unicode scalar string lengths and patterns; numeric bounds. Alternative failures collapse to their original parent-path diagnostic. Decimal generation strings have a separate u64 overflow diagnostic after pattern acceptance.

The Rust regex end anchor requires the actual string end. A final LF is rejected by the RPC schema check. Numeric values distinguish a non-integral float's type error from an integral out-of-range float's bound error. Structural uniqueness compares the original Value number variants, including equal positive and negative floating zero.

Only after schema success is the original 512 KiB serialized-arguments limit applied. Moving this check ahead of the schema would replace a specific advertised-contract diagnostic with a different error.

## Reproduction and evidence

`tools/build_hia_mcp_input_diagnostic.py native` checks the rendered authoring source against the checked-in HIA, captures component sources and the chosen compiler, invokes the selected native `hia-source-build compile` with an empty PATH, and records the actual flat. It reports component source custody, not whole-source cold admission.

The native checkpoint has 77 functions, 889 blocks and 7,884 operations. The existing compiler limits of 128 functions, 1,536 blocks and 8,192 operations are unchanged. The selected matching compiler emits a 417,014-byte flat, SHA-256 `335c117fdfd60bdfeb46bab95c4c356d24c3ef6d9c47453a4b95f9a54ae0789c`.

`tools/build_hia_mcp_input_diagnostic.py oracle` links the original Rust module directly, without modifying its functions. It uses the original release dependencies, including rmcp 3.9.0 and the serde_json artifact with float_roundtrip/raw_value. The original release compiler is Rust 1.95.0 with panic=abort. Its manifest records source, driver, executable and dependency hashes.

`tools/qualify_hia_mcp_input_diagnostic.py` executes the actual native flat through its buffer ABI and compares it with that independent original Rust executable. The source campaign covers 5,906 inputs across all tools, schema fields, alternatives, conditional combinations, required-field priority, floating/integer cases, u64 strings, Unicode and control characters, structural repeated values and 90 nested array levels. Every returned RPC object and its exact encoded bytes match. Twelve separate ABI/parser controls refuse wrong pins, invalid roles, insufficient capacities, an over-bound input and malformed JSON.

The largest admitted test is exactly 8,388,608 input bytes and produces the full 8,388,686-byte original error. An earlier fixture accidentally constructed an 8 MiB + 1 input and stopped in the observer's domain assertion; that failed input remains in external QA evidence. The fixture was corrected to derive its exact key length from the JSON envelope, without changing the product boundary.

These are component gates. The final native service must still prove its own raw admission, audit ordering, completion mapping and reply integration on the assembled executable.
