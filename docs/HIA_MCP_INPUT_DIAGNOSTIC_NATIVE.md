# Native MCP input-contract diagnostics

The checked-in HIA program replaces the original Rust input-schema diagnostic operation for the eleven HIA tools. The native process service calls it after durable audit begin, before typed provider admission. The service's raw JSON admission, SDK request deserialization, authentication and resource route remain separate operations.

The semantic reference is the unchanged `check` and `validate_input` implementation in `runtime-v26-source/src/mcp/hia_contract.rs` at runtime commit `d022649c64b48fb2a43263faf90103a9a8957b94`. Its RPC prefix comes from `server.rs::dispatch_hia`. In the original call path, `call_tool` begins the durable audit before invoking the router and input validation.

## Flat ABI

The ordinary six-machine-argument HIA flat ABI takes a read buffer, output buffer and workspace buffer. The original canonical selector remains unchanged: workspace byte 0 holds the tool ordinal (1–11), and input is compact, key-sorted, serde-compatible arguments Value JSON. This mode checks both the schema and the following serialized-arguments bound.

The explicit raw selector is `(1 << 32) | tool_ordinal`, stored as the same little-endian u64 at workspace byte 0. The parent first admits the complete message through its original 8 MiB, 262,144-node, depth-128 route gate, rejects duplicate keys, and validates finite serde-compatible numbers. It then begins durable audit and passes the original arguments span to the diagnostic. The HIA program sorts each decoded object's linked member list by UTF-8 key bytes using a bounded iterative merge sort. It also classifies negative zero and integers outside serde's i64/u64 variants as floating numbers before structural equality. Escaped keys are compared by their decoded bytes. It does not construct an expanded canonical JSON document.

Raw return 0 establishes schema success only. The parent must then canonicalize the Value and apply the original 512 KiB serialized bound before provider admission. This order preserves the original specific field diagnostic even when a raw input below 8 MiB would expand past 8 MiB during canonicalization. The two modes use the same exact 64-byte lowercase catalog SHA-256 at workspace bytes 8–71: `b6b8054ce46ae9ceac260e99a3d1beaf5d6c9343bc4c6e5d96281eedd3c3edfd`. Other mode bits or tool ordinals refuse. Callers of the original selector do not need to initialize any new workspace bytes.

The maximum input is 8 MiB. Output capacity is at least 8 MiB + 512 bytes, and workspace capacity is at least 32 MiB. A long unknown key can legitimately produce an error larger than 1 MiB; the full path is retained.

Return 0 has the mode-specific meaning above and output bytes are unspecified. A positive ordinary byte count is the complete UTF-8 RPC error object containing code -32602 and the original message prefix, path and diagnostic suffix. Existing parser statuses `0xfffffffc`–`0xffffffff` are invocation or parsing refusals, not output lengths. The caller must distinguish those statuses before consuming the output buffer.

The workspace and output scratch are private to the call. No path, descriptor, process, environment or network authority is used by this component.

## Original check order

HIA preserves the original ordering: depth and boolean schema; type; constant and enum; oneOf, anyOf and allOf; not; if/then; required object fields in schema order; present properties in Value order; array length, uniqueness, items and contains; Unicode scalar string lengths and patterns; numeric bounds. Alternative failures collapse to their original parent-path diagnostic. Decimal generation strings have a separate u64 overflow diagnostic after pattern acceptance.

The Rust regex end anchor requires the actual string end. A final LF is rejected by the RPC schema check. Numeric values distinguish a non-integral float's type error from an integral out-of-range float's bound error. Structural uniqueness compares the original Value number variants, including equal positive and negative floating zero.

Only after schema success is the original 512 KiB serialized-arguments limit applied. Moving this check ahead of the schema would replace a specific advertised-contract diagnostic with a different error.

## Reproduction and evidence

`tools/build_hia_mcp_input_diagnostic.py native` checks the rendered authoring source against the checked-in HIA, captures component sources and the chosen compiler, invokes the selected native `hia-source-build compile` with an empty PATH, and records the actual flat. It reports component source custody, not whole-source cold admission.

The native checkpoint has 68 functions, 925 blocks and 7,852 operations. The immutable schema table uses larger bounded banks to share repeated literal values and strides; this reduces total operations while adding raw normalization. The existing compiler limits of 128 functions, 1,536 blocks and 8,192 operations are unchanged. The selected matching compiler emits a 433,898-byte flat, SHA-256 `a3fa8ab237efbef5c9db100097b3f900fdaf09f4f604d60e7febf6aa894e587e`.

`tools/build_hia_mcp_input_diagnostic.py oracle` links the original Rust module directly, without modifying its functions. It uses the original release dependencies, including rmcp 3.9.0 and the serde_json artifact with float_roundtrip/raw_value. The original release compiler is Rust 1.95.0 with panic=abort. Its manifest records source, driver, executable and dependency hashes.

`tools/qualify_hia_mcp_input_diagnostic.py` executes the actual native flat through its buffer ABI and compares it with that independent original Rust executable. The source campaign covers 5,906 inputs across all tools, schema fields, alternatives, conditional combinations, required-field priority, floating/integer cases, u64 strings, Unicode and control characters, structural repeated values and 90 nested array levels. Every returned RPC object and its exact encoded bytes match. Thirteen separate ABI/parser controls refuse wrong pins, invalid roles, insufficient capacities, an over-bound input and malformed JSON.

The largest admitted test is exactly 8,388,608 input bytes and produces the full 8,388,686-byte original error. An earlier fixture accidentally constructed an 8 MiB + 1 input and stopped in the observer's domain assertion; that failed input remains in external QA evidence. The fixture was corrected to derive its exact key length from the JSON envelope, without changing the product boundary.

The `--raw` campaign retains those 5,906 semantic cases with reversed object fields, escaped keys, negative-zero lexical variants and whitespace, then adds ordering, numeric equality, overflow and expansion cases: 5,944 observations match the original Rust schema phase and exact RPC bytes. It explicitly identifies any original post-schema serialized-bound result as the following parent phase rather than claiming the raw component checked it. The raw campaign includes a 7,291,490-byte arguments span whose original serde serialization is 10,091,490 bytes; the exact 6,291,564-byte field diagnostic matches the original. The original canonical 5,906-case campaign also passes on the new flat.

A raw counterexample against the preceding flat is retained in external QA: unsorted `section`, `z`, `a` fields incorrectly selected `arguments.z` before normalization. The repaired HIA selects `arguments.a`, matching the original sorted Value. No failed field or original assertion was removed.

These are component gates. The final native service must still prove its own raw admission, audit ordering, completion mapping, serialized bound and reply integration on the assembled executable.
