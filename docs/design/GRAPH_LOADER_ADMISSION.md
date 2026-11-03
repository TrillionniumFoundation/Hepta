# Experimental graph-work admission on normal loader algorithms

Status: isolated graph profile stacked on #624 at
`0ec8b881b1e93cda6c25e5723cf315d7074d3f15`. Production entry points remain
legacy and unbounded. No default switch, new production consumer, merge or
publication mechanism is included. This is a finite work-admission gate, not a
complete bounded production loader, sandbox or hard CPU/heap/time ceiling.

## Implementation and ownership

`experiments.graph_loader.Owner` subclasses the reviewed read-owner, selects a
private graph-aware operations object and retains the same handle identity,
private disk-revalidation authority, explicit read-role provenance, terminal
rejection and finite hook contract. The older `experiments.owned_loader.Owner`
continues to reject unsupported graph-limit overrides; its previous gate is
preserved unchanged.

Real production algorithms contain the work events. No loader algorithm is
copied or rewritten at runtime, and production imports no experiment.
`LegacyLoaderOps.edge` and `node` do nothing; `path` invokes the same original
Path method. Public APIs, types and eleven-field LoadedProject remain unchanged.
Manifest discovery becomes a normal private algorithm called by its public
legacy wrapper; internal calls use the existing identity-aware dispatch so
module/package namespaces and replacement hooks retain their legacy behavior.
The experimental owner rejects such replacements rather than resetting budgets.

One context counts the entire owner lifetime: initial construction, initial
snapshot, locked snapshot verification, final loader revalidation, later owner
revalidation, and subsequent loads. Private authority copies do not reset it.
Public `handle.project.unchanged()` is still legacy, never budget authority.

## Exact counters and event placement

Root depth is **1** in each traversal. An edge event first checks depth, then
charges the edge counter; refusal does not increment the rejected counter. It
runs before path resolution inside that invocation/visit, cycle diagnostics,
cache hits or seen-set returns. A dependency caller may already have resolved
its target through a separately charged path operation before entering the
recursive load.
Consequently a deeper route to an already cached node still requires depth and
edge admission. An experimental low quota can precede a legacy cycle diagnostic;
with sufficient budget the existing diagnostic remains unchanged.

- `module_edges`: each module visit attempt, including root and cached imports.
- `modules`: each uncached, non-cycle module attempt, charged before source reads
  or parsing. It counts work attempts, not only successfully returned nodes.
- `module_depth`: current import traversal depth, including cached-edge attempts.
- `package_edges`: each package-load invocation and each package-snapshot visit,
  including roots, cached package references and already-seen snapshot nodes.
- `packages`: each uncached, non-cycle package-load attempt before manifest
  existence/read checks, plus each previously unseen snapshot node before
  retaining it. Missing/invalid package attempts consume admission too. This is
  cumulative construction **and snapshot work**, not unique packages over time.
- `package_depth`: current dependency-load or snapshot traversal depth, including
  cached/seen edges.
- `path_checks`: each explicit `absolute`, `resolve`, `is_file`, `is_dir` or
  `is_symlink` call in the normal graph/package/discovery/revalidation algorithms.
  Charge occurs before invoking that Path method. Short-circuited operations
  are not charged. The wrapper preserves the original receiver and method.

A standalone diamond imports root→left/right→shared: four module node attempts,
five edges, maximum depth three. A package diamond with four packages and five
visits per traversal consumes 16 package node attempts and 20 edges over initial
load+snapshot and final reload+snapshot. A one-package load consumes four package
node attempts/four edges; each successful owner revalidation adds two of each.
These examples are asserted in the gate, not estimates.

## Path and broader limits

`path_checks` bounds only the explicitly instrumented normal algorithm calls.
It does not count every filesystem syscall or Path operation in the process.
Read-owner role canonicalization, descriptor-reader checks, directory inventory
internals and Path's internal symlink resolution retain their separate reader,
inventory and checkpoint protections. The existing eager manifest ancestor-list
allocation is unchanged and occurs before per-candidate stat admission. Pure
path comparisons/construction are not separately charged. The tests and name do
not imply all path work or resolver CPU is bounded.

Metadata byte/decode admission and two separately charged lexing passes remain
as before. AST assembly, metadata allocations, graph authority-copy retention,
digest/serialization, arbitrary Python mutation and native processing remain
outside a complete bound. Large configured depth limits do not establish safety
against Python recursion limits. No admitted-token transfer/single-pass parsing
or owner-preserving native consumer interface is added.

## Safety and compatibility gates

Graph/path admission calls the same context check as reader admission, preserving
checkpoint cancellation, thread/reentrancy rejection and finite namespace-hook
checks. Rejected graph/path quotas are RuntimeError-derived admission errors,
not HeptaError/OSError; legacy stale-state catches cannot turn them into False.
Quota/cancellation failure through the owner closes the context permanently.
Private lower-level seams are test surfaces, not a public lifecycle API.

The profile still rejects all non-None source overrides before reads or graph/path
work. Locks still authenticate disk state only at the original verification
point. Owner revalidation does not reread Hepta.lock, so corrupting only the lock
can leave it true while fresh verification fails. A quota failure does not write
or replace a lock. Hook/descriptor rejection and private graph authority remain
as documented in OWNED_LOADER_INTEGRATION.md; no additional sandbox claim.

## Validation

32 new controls cover exact and one-over limits, cached/seen edges, depth on
cached routes, repeated loads/revalidation, path admission before each operation,
manifest discovery, a direct-path-fallback source audit, cycle diagnostics, cancellation, hook/descriptor rejection,
lock preservation and all 80 example outcomes (68 matching graphs and 12 matching
diagnostics, not 80 compilation successes).

The focused aggregate requires 191 unique tests: these 32 plus all prior 159.
The hosted aggregate requires 323: these 32 plus the prior 291, on exact HEAD,
Ubuntu 24.04/Python 3.11 and 3.12 with Rust 1.90/GCC, zero skips or expected
failures. Run `python -m experiments.graph_loader.gate --include-consumers`.
Local Rust is unavailable, so focused passes are not a hosted/native aggregate
pass. Verify the final hosted commit separately. Source pins and consumer
inventory were refreshed only after independent review of the production seams.
Compiler identity changes; old qualified artifacts must not be relabelled.
