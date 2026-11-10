# Native whole primitive Core declaration admission

This component implements the complete `_primitive_structure` policy for
primitive Core v1-v8: exact program fields, schema/module/function inventory,
the embedded full native function declaration/SSA/CFG policy, duplicate
function detection and explicit export name/uniqueness/existence/scalar-ABI
checks. It is **not** the complete Core body/type/resource verifier. Unknown
operation names can satisfy declaration shape but are still rejected by the
mandatory body verifier. Composite normalization remains a separate host path.

The HIA image decodes the complete raw JSON once. Global function/export names
and separate function-local parameter/SSA/block identities share a native table
with disjoint context tags; identical local names in distinct functions are
legal. The table is initialized once for the whole input, not once per function.
It stores exact decoded text, not host-computed name indexes or declarations.
Diagnostic ordering follows the full policy, including checking a repeated
function's complete shape before duplicate-name refusal and checking all export
identifiers and duplicates before resolving their signatures.

The full existing Core ceilings remain: 8 MiB, 262,144 value nodes, depth 64,
1,024 functions and 4,096 blocks per function. No 128-function/compiler-emitter
limit or 128-export limit is substituted. Empty explicit exports remain legal.
Both mutable buffers are per-call private scratch; the public result is a u32
status. Native export-descriptor refusal has its own reason status and preserves
the existing diagnostic wording. Other shape categories do not claim exact
foreign diagnostic prose or an all-input refinement proof.

`tools.build_hia_program_shape` requires a completed compiler cold report bound
to the **current whole source manifest**, not just an identical compiler image.
`HEPTA_HIA_PROGRAM_SHAPE_MANIFEST` explicitly selects it. Source/image custody is
rechecked; missing/invalid selection or native refusal has no foreign-policy
fallback. A selected program-shape image embeds the function policy and does
not depend on the separately selected function-shape image.

Host boundaries remain explicit: exact bounded caller snapshot and JSON
serialization, allocation, image custody/build, function/block-map object
materialization, composite lowering and complete body/loan/resource-flow
verification. The unselected default is unchanged. This component does not
authorize production activation, deletion of required reference implementations
or claims of whole-product native-only delivery.

Independent ordinary Core VM witnesses precede native image compilation.
Qualification includes schema/type/loan/chain combinations, name scopes,
malformed JSON and declaration positions, export permissions/error precedence,
deterministic multi-fault cases, full function/export/block/byte/node/depth
profiles and one-past refusals. Actual Core calls forbid both old declaration
and old function-shape policies while retaining mandatory body safety checks.
