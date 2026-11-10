# HIA semantic type-validity controller — qualified phase, whole stack still open

This successor of the type-graph dependency implements the existing complete
`_Checker.valid_type`, `generic_arguments`, and `valid_owned_payload_shapes`
phases in executable HIA. It does **not** implement the complete semantic
checker. Declaration checking, expression typing, flow/ownership, host AST and
transport objects, module/package resolution, optimizer, general runtime,
agent tools, build and delivery retain foreign authority. No default, main,
release lock, production configuration, or service is changed.

## Implementation and selection

The combined kernel `examples/hia_bootstrap/type_graph.hiaasm` has 61 functions,
854 blocks and 216,060 source bytes. Its authoring modules are
`tools/generate_hia_type_graph.py` and `tools/generate_hia_type_validation.py`.
All compiler limits are unchanged (including 16 block arguments, 128 functions
and 1,536 blocks). The largest generated block has 12 arguments.

`HEPTA_HIA_TYPE_GRAPH_MANIFEST` selects the trusted-local image with schema
`hepta.hia.type-graph-native.v3`. The default reference remains. Explicit
transport/context/continuation/output profile exhaustion uses the documented
reference; a broken selected artifact, changed source or malformed result
raises and never silently falls back. All native diagnostic types, messages
and mappings materialize before host diagnostics are appended.

HIA makes the decisions: lifetime arity/scope, reference restrictions and child
flags, primitive/owner/parameter/container forms, exact `Task<u64>` and
`Sender<u64>` identities, nonnegative *integer* array lengths (not booleans),
nominal generic checks, Copy/Owned bounds, scoped/cancellation/sender rejection,
ordered diagnostics and the reference's deliberately asymmetric Boolean return
values. A native explicit continuation stack replaces recursive host validity
calls. Native mapping records choose missing-argument error sentinels and
ordered duplicate parameter bindings; the host merely constructs the map.

Owned-payload traversal uses exact `(nominal name, argument count, ordered
linear-bit-vector)` visited keys, not a 64-argument mask or name-only shortcut.
It preserves contextual substitutions, raw storage-query semantics, reference
opacity and payload diagnostic order. Native iterative postorder cloning
instantiates each diagnostic type; the bridge does not interpret environments
or perform generic substitution.

## Explicit bounded ABI

All modes use a maximum 1 MiB input, 8,192 physical type nodes/symbols,
32,768 argument/lifetime edges, 512 nominal declarations, 4,096 declaration
parameters and 8,192 declaration members. Header/table bounds are checked.

| Mode | Purpose | Private scratch | Maximum result |
| --- | --- | ---: | ---: |
| 1 / 2 | Capability / raw stored-borrow query | 680,256 B | 32 B |
| 3 | Instantiated owned-payload shapes | 4,932,240 B | 1,376,288 B |
| 4 / 5 | Complete validity / generic arguments | 6,374,032 B | 2,424,896 B |

Extended profiles bind 8,192 contexts, 65,536 bindings, 4,096 owned mask states,
262,144 mask bytes, 8,192 owned diagnostics, 32,768 postorder diagnostic nodes,
65,536 cloned edges, 8,192 type continuations and 32,768 type diagnostics.
Explicit generic parameters are capped at 4,096 and the configuration at
8,192 words. Scratch and outputs are private per invocation. Failed input,
short buffers, or exhausted diagnostic cloning publish no partial output.

The native validity output has a 64-byte header, ordered 32-byte tagged
diagnostic records, optional 16-byte mapping records, 24-byte postorder type
records and 8-byte edges. Host checks cover sizes, tags, indices, complete edge
coverage, postorder and reachability before materialization; messages render
native-selected tags and auxiliary values, not host semantic predicates.

## Development evidence, not whole-repository qualification

The retained `type-validation-development-03.log` reports **19 tests PASS**,
37.663s: independent VM literals before B0; real B0/B1/B2 fixed point and
native application compilation; branch/return/order witnesses; 400 random
complete-type and generic checks, 400 random graph queries, and 400 random
owned-shape graphs; exact capacities, real exhaustion and canaries; private
concurrent calls; and 81+ actual parsed source callers with the original
capability, storage, owned-shape, validity and generic phases disabled.

The first development run found a scope-transport variable-shadowing error;
it remains retained as FAIL. The source transport was repaired and regression
coverage includes nonempty declaration parameters versus caller scope. Earlier
owned-shape fuzzing also exposed malformed container `Type.__str__` crashes;
the real formatter now preserves malformed arities instead of indexing a
missing argument or hiding extra arguments. Valid spellings are unchanged.

Shared identity v19 explicitly adds only the new authoring module: 391 paths,
223 root package modules, commitment
`b7fcd093ea305b86c4e39e56a9a79c65c0f0bc8b04921b5349058cfd31083dc6`.
All 390 v18 paths and older projections remain independently pinned. The new
134 identity bytes move from logs to metadata within the unchanged aggregate
evidence envelope; no process/time/resource cap is raised. Shared closure
and acceptance development tests: **15 PASS**.

Clean-commit source CI, new-source cold replay, language, full selected/default
callers, strict composition, release checks and repository-wide regression
must be recorded separately on exact source. The old type-graph cold receipt
can build a development candidate; it does not qualify this newer source.
Finite tests are not proofs for all accepted inputs. Whole-stack closure is
still open.

## Exact clean-source phase acceptance

Qualified implementation: `01c4460bf5c23777e96713360af4f5077b53be1f`. Clean source CI109PASS; cold11/11+5049PASS, 122.626s under unchanged180+3-second limits; language1242+10PASS; combined native120PASS; shared15PASS; release18PASS. Selected/default semantic168, parser/modules63, JSON83, incremental55eachPASS. Additional231strict composition PASS with eight original foreign paths disabled simultaneously. All prior5049witness names/successes preserved. Exact counts/clocks, verified archive and lossless full-tree inventory are in `type-validation-summary.json`. Whole-repository and remote CI remain unqualified at capture; no branch-specific result qualifies a future combined-source merge.
