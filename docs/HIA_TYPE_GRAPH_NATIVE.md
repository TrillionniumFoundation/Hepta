# Native nominal/generic type graph dependency

For the newer, not-yet-qualified complete validity/generic/owned-shape candidate,
see [HIA_TYPE_VALIDATION_NATIVE.md](HIA_TYPE_VALIDATION_NATIVE.md). The receipt
below belongs only to its pinned type-graph dependency source.

This is a dependency of the still-incomplete source semantic checker rewrite,
not a complete type checker or whole-stack selfhost claim. The default paths
remain unchanged; no release or production service is switched.

`HEPTA_HIA_TYPE_GRAPH_MANIFEST` selects a trusted-local HIA application for the
existing capability and stored-borrow queries. The HIA program performs the
whole traversal, nominal declaration lookup, generic contextual substitution,
cycle/name tracking and reference boundary decisions. Python packs AST tables,
loads a source/image-hash-bound ELF image, allocates private buffers and reads
one Boolean result. It does not precompute the query's answer.

## Preserved semantics

- Capability queries inspect arguments even after a nominal name is visited.
- Declaration fields/variant payloads substitute zero-argument, length-free
  parameters. Duplicate parameter bindings use the last argument, matching
  `dict(zip(...))`; a placeholder lifetime does not prevent substitution.
- A `ref_mut` query makes both reference kinds opaque after direct membership
  testing. Other queries still inspect referents.
- Stored-borrow classification checks references, type lifetimes and declared
  lifetimes, then **raw** nominal payloads, without generic substitution.
- Registry keys determine lookup; struct entries precede enum entries.

## Wire and scratch profile

The version-one packet has a 128-byte header; 64-byte topologically ordered
type records; 48-byte declaration records; flat argument/lifetime, parameter,
member, query and prior-seen index vectors; and an interned UTF-8 symbol table.
Limits: 1 MiB input, 8,192 type nodes/symbols/query names/prior-seen names,
512 declarations, 32,768 argument/lifetime edges, 4,096 declaration parameters
and 8,192 declaration members. Each call owns 680,256 scratch bytes and a
32-byte result. Packed contextual references preserve substitutions without
host-side instantiated types. No recursive native function calls are used.

Unsupported transport/profile inputs and explicit contextual scratch exhaustion
retain the reference implementation. A malformed selected artifact, hash
mismatch or invalid native result **does not** silently fall back. Invalid
native packets and short buffers publish no result.

## Development evidence and remaining work

Tests execute literal decisions in the independent Core VM before any native
seed, build real B0/B1/B2 successors and require the B1/B2 image fixed point,
then compile and execute this application. They compare 400 randomized nominal
generic graphs in both modes, exercise declared profile boundaries and buffer
guards, and run actual source fixtures with both foreign graph queries disabled.
These are finite tests, not all-input equivalence or soundness proofs.

Clean-source CI, current-source cold export, composed callers, language and
repository-wide regressions must be recorded separately. Older phase receipts
do not qualify this source snapshot. `valid_type`, generic argument validation,
instantiated owned-payload shape checking, expression/ownership/control-flow,
the complete runtime, modules, optimizer, agent tools and delivery remain open.
