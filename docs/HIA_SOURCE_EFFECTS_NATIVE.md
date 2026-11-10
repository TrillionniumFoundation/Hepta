# Selected HIA source effect/resource phase

This is a staged migration of `_Checker.finish_effects`, **not a complete
semantic checker or whole-stack rewrite**. The default reference path is
unchanged. `HEPTA_HIA_SOURCE_EFFECTS_MANIFEST` selects a trusted local native
image bound to `source_effects.hiaasm`; an invalid selected in-profile image
refuses instead of silently invoking the reference phase. Out-of-profile graphs
continue to use the reference phase.

The HIA implementation computes the monotonic call-effect fixed point, including
cycles, local effects and the existing eight declared known effect upper bounds.
It decides worker restrictions, missing effect declarations, and the three
existing resource/effect conflicts in their original diagnostic order. Unknown
local effects propagate; unknown declared effects do not become call upper
bounds. Duplicate worker sites retain their original spans and order. Resource
clause values are not interpreted as new proofs or permissions.

The host transports the resolved graph and symbol identities, allocates private
buffers, materializes result sets and diagnostic objects, and retains the other
checker phases. Declaration, expression/type, lifetime, ownership, control-flow,
module, runtime, optimizer, build and delivery implementation are still foreign.

The input ABI is a 112-byte header, 48-byte function rows, 8-byte call/resource/
worker rows, 16-byte UTF-8 symbol ranges and their payload. Its declared profile
is at most 1 MiB input, 2,048 functions, 64 effect symbols, 16,384 call edges,
8,192 resource keys, 4,096 worker sites and 8,256 symbols in total. Scratch is
`64 + 8 * function_count` bytes. All input tables are validated before scratch
mutation. The output contains a 32-byte header, inferred masks and ordered
24-byte diagnostic records. A counting pass checks output capacity before any
output publication. Invalid input/scratch returns `0xfffffffd`; short output
returns `0xfffffffe`. Source and trailing guards are preserved. These are bounded
application limits, not new limits or relaxations in the native compiler.

Tests execute a literal graph/result in the independent Core VM **before** any
seed build, then build real B0/B1/B2 successors and require their fixed point.
The candidate is compiled by B2; tests compare the original final checker phase
on cyclic/random/boundary graphs, verify exact diagnostics and spans, disable the
foreign final phase in actual source checker callers, and exercise buffer
refusals and concurrent private scratch. These finite observations are not an
all-input refinement proof. Cold/source-bound/full-suite acceptance must be
reported separately; earlier-stage acceptance does not qualify this phase.

`tools/build_hia_source_effects.py` requires a completed matching cold compiler
receipt. No default/release lock, production service or deployment is changed.
The Python authoring generator is development tooling, not a HIA compiler
replacement. The audited foreign-source inventory includes that generator and
its host build/transport code.
