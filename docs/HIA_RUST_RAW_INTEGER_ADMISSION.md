# Raw integer admission in the Rust shadow

The standalone Rust checker and execution entry points consume the original
bounded JSON bytes. They independently admit the JSON integer spelling `-0`
as integer zero, matching the canonical Python decoder. This applies to both
primitive Core constants and scalar CLI arguments. Canonical identities, values,
step counts and resource ledgers are unchanged from the spelling `0`.

`serde_json` dispatches `-0` through its floating visitor. The decoder therefore
masks only the minus sign of a complete `-0` token outside JSON strings before
running the existing bounded, duplicate-key-safe decoder. It preserves the input
length and offsets. A token must start at a JSON value boundary and end at a JSON
delimiter or end of input; the normal JSON parser still validates its grammar.
The float visitor continues to reject every floating value. Spellings `-0.0`,
`0e0`, `-0e0`, malformed numbers, quoted numeric text, duplicate keys and excessive
nesting remain refused. No Python receipt or canonicalized Python input grants
Rust admission.

The Rust integration tests exercise primitive schemas v1–v8, both shadow paths
where declared, execution and argument decoding. The Python differential tests
pass the *same original raw bytes* to each implementation and compare identity,
values, steps and the complete resource ledger. Negative inputs are also sent
directly to the Rust checker and its zero-step execution entry point.

This correction does not switch production authority, expand the memory model,
admit new scalar types or claim diagnostic-category equivalence for arbitrary
malformed Core. The canonical Python verifier remains the production authority.
