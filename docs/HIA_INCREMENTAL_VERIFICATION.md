# HIA local incremental verification

`hepta.hia_incremental.IncrementalVerifier` adds an in-memory Agent editing
session for the existing closed primitive v1–v8 profiles. It reuses completed
function-body checks under an explicit dependency contract. The ordinary
`verify_program`, `apply_program_patch`, batch editor, interpreter, native
backend and publication paths retain their full verification behavior.

This is static admission of a candidate Core. It does not establish behavior
equivalence, backend refinement, a faster native program, whole-language
soundness, or a real-model productivity benefit.

## API

```python
from hepta.hia_incremental import IncrementalVerifier

session = IncrementalVerifier(program)  # performs full verification
candidate, verification = session.verify(changed_program)

# The existing bounded patch.v1 / patch.v2 request grammar is also accepted.
# Its expected_sha256 must match the current session baseline.
candidate, patch_receipt = session.apply_patch(patch_request)

assert session.base_sha256 == candidate.sha256
last_attempt = session.last_report  # detached report, including rejections
session.close()
```

A failed candidate, stale patch or forbidden interface migration does not
replace the saved baseline. All replacements in a patch are simultaneous;
intermediate candidates are not admitted. A session serializes its operations,
so two patches for one expected baseline cannot both commit different results:
the later attempt observes a stale digest. Multiple sessions are independent.

Existing patch v1 preserves interfaces. Patch v2 requires an explicit
`interface_policy` of `preserve` or `migrate`. Allowing a migration does not
certify external callers. The ordinary editor and the incremental session use
the same request validation, candidate construction and interface-policy
helpers. The old editor's receipt schema and full checks are unchanged.

## What is checked every time

Every candidate is independently, strictly decoded into detached immutable
canonical bytes. Size, node, nesting, duplicate-key, exact-value and JSON rules
remain the ordinary Core rules. The complete global/shape pass still checks:

- the program schema, exact envelope fields and module identity;
- every function's declaration, signature, effects, name and uniqueness;
- every block, operation shape, output type and function-wide SSA definition;
- every CFG edge's target and arity, entry restrictions and reachability;
- all explicit scalar exports, including resource-descriptor exclusion.

The incremental path only skips the subsequent semantic function-body pass.
It never skips parsing, the global pass or the shapes of unchanged functions.
Consequently an unchanged source hash or matching function name alone cannot
authorize a candidate.

## Dependency contract

The explicit contract identifier is
`closed-body-and-direct-callee-interface.v2`.

For a function body, the shared checker receives:

1. the exact primitive schema;
2. that function's own complete declaration/body and checked block map;
3. immutable callee interfaces containing original parameter names and types,
   return types, parameter-bound `return_loans` entries and declared effects.

The checker no longer receives callee bodies through its function table.
The existing primitive grammar has statically named calls, explicit block
parameters and no global storage or foreign/indirect calls. All cross-function
checks read those interface fields: call arity and type compatibility, owner
transfer, loan permissions/alias restrictions, returned owner and loan origins,
and required effects. Each function verifies its own declared effects against its
body. V8 borrowed results name original formal parameters. Parameter names and
`return_loans` therefore participate in interface identity; a change invalidates
every unchanged direct caller, even if types/effects stay equal or actuals
alias the same owner. Parameter renames conservatively invalidate callers in
all admitted primitive versions. The patch protocol continues to require an
explicit migration policy for such interface changes.

A body is reusable only if its exact canonical bytes equal the locally cached
bytes and every directly called function still has the same immutable
interface. A changed or added function is checked. Deleting a referenced
callee invalidates its callers and the ordinary call checker rejects them.
Deleted unreferenced functions leave no retained cache entry. Function order
does not create an implicit dependency.

No transitive callee-body dependency is invented for static admission. A callee
body can change behavior while its interface stays fixed, so a cached caller's
observable result can also change. `hia_patch_impact` remains a separate
conservative transitive call-graph observer for behavioral test selection.
Neither observer proves equivalence. Recursive call cycles require no extra
body-summary fixpoint under this finite interface-only contract; they also do
not prove termination or stack bounds.

If a future verifier adds global storage, effect inference, body-derived
summaries, indirect targets or another dependency, this contract must be
extended and independently qualified before such inputs can reuse checks.
The new primitive-schema allowlist is deliberately closed at v1–v8; extending
the registry alone does not enable incremental verification for a new schema.

## Cache origin and invalidation

The constructor always performs ordinary full verification, including when
given a manually constructed `VerifiedProgram`. A cache exists only in a
module-private weak-reference table populated by that completed call or a
subsequent fully accepted session attempt. Public hashes, reports, JSON cache
documents and `VerifiedProgram` values cannot seed it. Instances created with
`object.__new__` are unregistered; copying, pickling and subclassing sessions
are rejected. The instance exposes no assignable cache attributes.

Only the latest accepted snapshot is retained per session. Caller dictionaries,
returned documents and returned receipts do not back the stored state. Closing
or releasing a session discards its cache. The implementation assumes trusted
in-process compiler code; arbitrary Python code that modifies private module
state is already inside that trust boundary. Public native/interpreter
consumers continue to reverify bytes rather than trusting this class.

The session binds reuse to the actual checker function and method identities,
verification constants, relevant limits and shared registry descriptor. A live
checker reload, changed capability/registry policy, changed schema or changed
module envelope triggers full verification. A policy change observed during
checking triggers one full recheck of the same immutable candidate bytes;
continuous changes reject. A changed nominal input or structured-input/Core
binding always takes the full path. Composite inputs are not independently
incrementalized by this feature, including newer nominal schema versions.

## Work reports

`hepta.hia.incremental-verification.v1` records:

- before/after Core identities, status, mode and full-fallback reason;
- whether global structure completed, all function/operation shapes checked;
- function bodies attempted, completed or reused;
- direct-interface invalidations;
- block and operation counts in completed body checks;
- the ordinary controlled rejection code/message for rejected attempts.

Counts describe the primitive Core. Parsing and nominal normalization are not
included. An interrupted/failed function is not counted as a completed body.
If a full fallback rejects, its internal progress is unknown to the session;
the corresponding counts are `null`, rather than fabricated zeros or passes.

The patch API returns `hepta.hia.incremental-patch-result.v1`, with its work
report nested under `verification`. It distinguishes complete candidate
admission from `all_candidate_bodies_rechecked`. It does not reuse the old
whole-module-body-recheck claim when function bodies were actually cached.
The receipt digest identifies report bytes; it never authorizes another
verification or a native compilation.

## Validation scope

`tests/test_hia_incremental.py` compares candidate acceptance, exact canonical
bytes and rejection diagnostics with ordinary full verification. Its finite
cases cover all eight admitted primitive schemas, added/removed/recursive
functions, changed effects and return interfaces, Owner/Loan failures, global
shape errors, nominal fallback, strict JSON, fabricated cache attempts,
live-policy changes, atomic multi-site edits and concurrent stale patches.

`tests/test_hia_incremental_v8.py` additionally changes a valid callee from
returning a loan rooted in owner A to owner B. One unchanged caller releases B
while A’s child is still live: it is legal before the edit and illegal after it.
The cached caller must be invalidated and rejected. Other controls preserve
original formal identity through renames, aliases, CFG edges, direct-child
returns and recursion; verify atomic failure rollback; and distinguish a
permitted simultaneous origin/cleanup edit from its illegal intermediate.

One instrumented work-count case uses a 36-function module. A single leaf-body
edit must invoke the shared body checker once while checking all 36 function
shapes and 70 operation shapes. The test separately executes the edited
program and observes a changed result in a reused transitive caller. This
guards both actual check reuse and the absence of an equivalence claim.

These fixtures are not representative maintenance tasks, elapsed-time
benchmarks or model experiments. They support only the declared finite
incremental static-verification contract. Full diagnostics, further semantic
profiles and measured Agent task/cost benefit remain separate work.
