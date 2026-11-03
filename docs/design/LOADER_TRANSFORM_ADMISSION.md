# Experimental loader transform-entry admission

Stacked on draft #629 at b627dfeb353bb44a0ed8483b8dfb8e520f0265fa.
Independent audit and design review selected transform admission before attempting
broader private authority/package-copy coverage. No production default/caller
migration, merge, deployment or native qualification.

## Exact boundary

The normal loader's local transform function has a private depth argument, root
1, passed as depth+1 along its six recursive call sites. Its first body statement
is ops.transform_visit(depth). LegacyLoaderOps implements that method as a no-op.
The seam receives only the depth integer, not the value, constructor or result.
It therefore introduces no wrapper retaining those objects in exception frames.
The existing Type constructor expression, field traversal and mutation order,
container expressions, name resolution and per-occurrence alias processing stay
unchanged. Original captured-constructor and finalizer behavior is tested against
the frozen historical direct loader, including held exceptions.

The isolated experiments.loader_transform.Owner adds positive-integer limits:
transform_visits defaults to 200,000 and transform_depth to 128. Each successful
entry admission consumes one cumulative attempted transform invocation. Scalars,
sets and unchanged values count too. Root depth is 1; every recursive transform
call increases it, including calls that return their value unchanged. Depth is
not AST grammar nesting or canonical deepcopy graph depth.

One checkpoint runs before each entry admission. Finite pins reject changed or
deleted admission hooks and changed modules.Type, Expr, Span, fields and
is_dataclass aliases after callbacks. Unknown depth values reject without custom
comparison. Swallowed reentrant rejection cannot reopen terminal state. Trusted
ordinary private/runtime/class integrity remains required; these finite checks
are not a sandbox against arbitrary monkeypatching or concurrent mutation.

A denied visit does not increment the counter and does not execute that body's
branch, constructor or collection reconstruction. A failed admitted body does
not refund its attempt. Owner load failures are terminal and never return a
partially transformed graph. Counts accumulate across declarations, modules and
reloads. Unchanged revalidation adds no transform work. Prior profiles keep their
old policies and do not acquire the new counter.

## What has already happened and what is not covered

The Python call frame and argument evaluation exist before this body guard.
The root declaration deepcopy, declaration.name assignment and construction of
frozenset(type_params) occur before root transform admission. Child getattr/item
retrieval and depth arithmetic precede each child entry. Parent reconstruction
may already have started before a later child refuses. This is not transaction
rollback or a claim to precede every allocation.

The metric counts invocation attempts, not completed transformations, reconstructed
objects, constructor calls, bytes or allocations. Type reconstruction also builds
argument tuples and often a Span; empty immutable values may retain identity.
Resolution separately splits strings and sometimes copies whole type/function
namespace dictionaries. Its cost depends on namespace width and is not bounded
by a transform invocation count alone. Those maps, strings, reports, hashes,
private authority/package copying, native work and OS isolation are excluded.
See AUTHORITY_COPY_AUDIT.md for the separately measured remaining copy shapes.
No hard heap, CPU, time or Python recursion-stack ceiling follows.

## Measured boundaries and falsifiable controls

- Empty module: zero transform entries.
- One empty function: 14 entries, maximum depth 2. Quota 13 or depth 1 refuses.
- Two empty-function modules: 28 entries, maximum depth 2.
- One hundred empty functions: 1,400 entries, maximum depth 2.
- Forty-operand left-associated return: 333 entries, depth 84. Quota 332 or
  depth 83 refuses. Its separate canonical copy graph depth is 131, not 84.
- Shared Type values are transformed once per occurrence and produce separate
  new Type values as before; the new profile does not introduce memoization.

38 new controls plus all prior 337 give 375 unique focused controls; adding the
prior 132 consumer controls gives 507. The gate rejects duplicates, skips and
expected/unexpected failure shortcuts. Independent review adds retained-exception
constructor/finalizer parity, actual body-line tracing on refusal, aliases,
callback swaps, hook deletion and swallowed reentrancy controls.

All 80 examples retain full outcomes: 68 graph/AST matches and 12 diagnostics,
not 80 compilation successes. Separate isolated subprocess differentials compare
the old/new normal loaders against the same frozen example paths, including full
reports, ASTs, source bytes and unchanged results, plus the prior 99-case direct
Lexer/Parser differential. Graph evidence digests depend on input paths; each
old/new pair must match within its run.

The hosted workflow requires Python 3.11 and 3.12 to verify exact candidate and
frozen #629 checkout identities, both direct differentials, then all 507 controls
with zero skips. See the PR for exact-head results. Local Rust is absent; focused
local testing is not a native aggregate qualification. Reviewed source pins and
consumer inventory change; compiler identity changes and old qualified artifacts
must not be relabelled.

Run python -m experiments.loader_transform.gate --include-consumers.
