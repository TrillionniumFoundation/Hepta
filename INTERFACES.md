# Hepta 0.2 compiler interfaces

This file describes the current internal pass boundary. The implemented language
contract is [docs/SPEC.md](docs/SPEC.md); named JSON schemas are described in
[docs/AGENT_PROTOCOL.md](docs/AGENT_PROTOCOL.md). The frontend uses the Python
standard library. Native outputs do not depend on Python. Internal Python APIs
and AST shapes are not a stable public compatibility promise.

## Source and graph

`parse(source, path) -> Program` consumes a closed syntax model from `hepta.ast`.
No source fragment is spliced into native output. `Program` contains structures,
functions, enums and imports. Generic declaration parameters and expression type
arguments are explicit AST fields. Match patterns/arms are dataclasses; visitors
must traverse their bodies and type positions, not just dictionaries/lists.

`hepta.modules` resolves standalone or package imports, validates public access,
reserves generated identifiers, flattens declared names mechanically and retains
per-file spans. `LoadedProject` carries source bytes, lexical path bindings,
module/import-edge mappings, package state and project identity. Project identity
includes resolved edges as well as bytes; revalidation checks symlink bindings.
`hepta.packages` handles local-only manifests and exact content locks. C import
metadata and visible in-package original headers participate in validation.

## Frontend checks

`check(program) -> CheckResult` reports diagnostics, inferred expression types,
transitive effects, external assumptions and resource contracts. It checks all
function bodies, including unused generic functions. Generics and ADT payloads
are constrained to the implemented Copy profile. C boundaries accept only the
explicit ABI-compatible type set. No undeclared native namespace is reachable.

Effects are `alloc`, `panic`, `io`, `block`, `spawn`, `ffi`, `unsafe`, `write`.
Mutation of borrowed inputs/raw memory requires `write`; local assignment does
not. Unsafe operations and calls to unsafe/foreign functions require an explicit
unsafe block. Deallocation is allocator interaction and carries `alloc`.
Static resource clauses support `heap_allocations=0` and
`may_block/may_suspend/may_spawn=false`. Task-group numeric admission contracts
are a separate runtime facility, not a process-wide heap bound.

Linear Buffer/Task/TaskGroup values must be consumed on modeled normal paths.
Match, branching, loops and early returns participate in resource flow. The
runtime uses aborting panic; process failure and nontermination do not receive
an eventual-cleanup theorem.

## Native paths

`analyze_project` accepts a directory, manifest or source, loads the graph and
runs the selected path. The Rust path checks declarations/effects/linear flow in
Hepta and submits generated Rust to the pinned real rustc for final type/borrow
validation. Successful native validation requires toolchain identity and a
nonempty output. `frontend_only` is a distinct incomplete state.

`emit_c` and `compile_c` implement direct AST-to-C11/GCC for the documented
64-bit scalar/array/structure/borrowed-slice subset. Its conservative borrow
analysis is independent of rustc. Unsupported ADTs/generic declarations/hosted
task runtime reject. Reports do not label C validation as Rust borrow checking.
Both paths retain their toolchain, flags, target and output identities.

C header import probes actual types/layouts/integer constants, emits public C
structures and external declarations, and writes paired metadata. Recorded ABI
facts do not prove the foreign implementation's ownership, effects or lifetime
contracts. Arbitrary FFI and raw pointers retain explicit caller obligations.

## Agent changes and evidence

`apply_project_patch` implements one-body `hepta.patch.v2` changes bound to a
loaded project and source/interface identities. Full graph validation precedes
application; original content, lexical bindings, edges and package state must
still match. All participating Hepta sources use sorted cooperative locks shared
with v1, followed by recheck and atomic target replacement. Non-cooperating
editors are outside this lock protocol. Contracts are preserved, but functional
equivalence and external side-effect rollback are not established.

`tools/release_check.py` binds all gates to an unchanged source snapshot and
hashes generated evidence separately. Formal proofs describe explicit abstract
models, not an unproved correspondence with these Python passes. Agent evaluator
fixtures and real provider runs are distinct evidence classes. Unknown,
unsupported, environment-blocked and not-run qualifications never become passed
because some other backend or fixture succeeded.
