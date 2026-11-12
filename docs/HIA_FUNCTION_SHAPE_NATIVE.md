# Native primitive Core function-shape policy

`function_shape.hepta` implements the full production `_function_shape`
declaration/SSA/CFG policy, not the smaller selfhost compiler's input grammar.
It decodes raw JSON using the HIA arena decoder, validates exact fields,
ASCII/reserved names, every primitive type and effect, v8 parameter-bound loan
origins and permissions, SSA uniqueness, entry signature, edge targets and
arity, graph reachability and versioned chain declarations.

The existing Core limits remain 8 MiB input, 262,144 nodes, depth 64 and
4,096 blocks. The compiler's smaller function/block/emitter limits are not
substituted for these limits. Neither operation typing nor resource flow can
be admitted merely because declaration shape passed. Original block order,
arbitrary JSON field order and escaped keys/identifiers are supported.

The status is the only public result. Both borrowed mutable buffers are
private per-invocation scratch, including on refusal. A namespaced native hash
table indexes exact decoded identifiers; no host graph/identifier resolver is
called. The native image is trusted executable code, not a security sandbox.

`tools.build_hia_function_shape` builds an operator-selected manifest using the
existing completed-cold compiler custody path. Setting
`HEPTA_HIA_FUNCTION_SHAPE_MANIFEST` selects it; malformed/missing manifests,
source drift and native rejection do not fall back to the old policy. The
unselected default is unchanged. Host snapshotting/JSON serialization,
allocation, source/image custody and block-map object materialization remain
explicit host bridges. Native rejection preserves diagnostic categories; it
does not claim byte-identical foreign diagnostic prose.

Independent ordinary Core VM fixtures precede native compilation. Native
tests cover malformed positions, diagnostic precedence, all primitive types
and schema feature combinations, deterministic multi-fault mutations, full
4,096-block/262,144-node/64-depth/8-MiB inputs and one-past refusals. Actual
selected Core execution prohibits the foreign shape checker while retaining
the complete body/type/resource verifier. Passing these finite observations
does not establish an all-input refinement proof.

General Core body admission, full program structure/exports, complete native
Agent/persistence/runtime/build/install and whole-product closure remain open.
No default activation or legacy implementation retirement is authorized by
this component alone.
