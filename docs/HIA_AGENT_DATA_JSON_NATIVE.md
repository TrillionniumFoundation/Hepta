# Agent ordinary-data JSON

`HEPTA_HIA_AGENT_DATA_JSON_MANIFEST` explicitly selects a source-bound trusted
HIA image for `hia_agent_store.decode_data`. Without it, the existing decoder is
unchanged. Invalid selected artifacts fail closed, with no fallback. Inputs do
not select executable code. This changes no production service or default.

The image handles the complete ordinary JSON grammar, UTF-8 and escaped Unicode,
duplicate decoded keys in each object, structural node/depth admission, and a
one-parent value arena. Number grammar includes fractions and signed exponents;
raw numeric lexemes are preserved, without changing an integer to a float.
The Agent profile remains 8 MiB, 262144 nodes and root-at-zero depth 128.

The arena has a distinct `HIADATA1` magic. Tags 0–6 retain the existing value
layout, and tag 7 records a fractional/exponent lexeme. Core's integer-only
decoder does not accept this protocol. The shared foreign bridge still checks
tree ownership, ranges and object-key uniqueness before returning objects.

Python **still performs** foreign object construction and arbitrary-precision
integer conversion. This grammar image does not itself implement decimal
conversion: it preserves numeric lexemes. The separate explicit
`HEPTA_HIA_AGENT_BINARY64_MANIFEST` image can produce finite IEEE-754 bits with
native integer rounding; without that selector, conversion remains hosted.
Neither image implements native shortest floating printing or canonical digest
serialization. Negative zero, subnormals and finite overflow rejection retain
their value semantics. SQLite transactions, durable request identity,
publication, recovery, authorization and installed code custody remain hosted.
No whole-native Agent or whole-stack closure is asserted.

Build only with an actual completed current-source cold replay:

```sh
python -B -m tools.build_hia_agent_data_json --compiler B3.image.bin \
  --cold-report cold.json --output native-agent-data-json
```

The builder requires all original cold checks, the exact current profile/source
manifest, and three matching compiler generations before creating output.
Qualification includes complete independent VM/native arena byte equality,
numeric type and binary64-bit parity, malformed grammar/Unicode/duplicate-key
refusals, budgets and the full byte ceiling, private concurrent arenas, selected
Agent callers with hosted JSON parsing/tokenization forbidden, and real wheel
resources. Passing these components does not close floating conversion or state.
