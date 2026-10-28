# Parameter contract identity across C declarations

Compatible C declarations may rename parameters. A caller-supplied migration
contract must still denote the same ABI argument positions in every captured
declaration of a function. Argument names alone do not establish this identity.

After the existing contract checks, both the ordinary C profile and record-view
profile compare a shared normalized signature:

- A slice extent is identified as `("fixed", 1)` or
  `("parameter", zero_based_parameter_position)`.
- Each record initializer field is paired with its source parameter position.
- Return and parameter types, pointer/value classification, access modes and
  existing C qualifier information remain part of the comparison.

For example, a declaration `probe(p, n, other)` and definition
`probe(data, other, n)` assign different argument positions to `length: "n"`.
Likewise, `bind(ctx, a, b, n)` and `bind(state, b, a, n)` assign different sources
to `initialize: {"data": "a"}`. Such declaration sets now reject with
`E_C_FUNCTION` before a migration bundle is published, even when their C ABI
types match. Both declaration-first and definition-first collection check the
same identity.

The original names and contract remain available for emission, reports and
diagnostics. Existing ordinal selectors still allow pointer/record parameter
renaming that preserves every binding. This does not extend the accepted
contract syntax or infer a replacement for a missing length/source name.
The fixed extent `1` is distinct from scalar argument position `1`.

The discovered gap concerned consistent contract admission. The preserved
original-language probes use defined inputs, but they do not demonstrate a
target runtime memory failure or source-equivalence failure. Caller provenance,
actual allocation size, initialization and foreign aliasing remain the explicit
obligations of the existing unsafe ABI boundary.
