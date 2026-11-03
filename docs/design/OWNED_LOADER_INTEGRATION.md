# Experimental owner over normal production loader algorithms

Status: narrow integration gate stacked on #623 at
`a702290adc660f872a9e5425bf86effdc09b1fdc`. No production entry point selects the
experimental owner. This is finite read admission and ownership evidence, not a
complete bounded loader, sandbox, filesystem snapshot, or native qualification.

## Boundary and small production change

The real `hepta.modules._load_project` and private package implementations run
without copied algorithms, runtime rewriting, module substitution, or global
owner state. Three existing production files gain only admission seams:
`LegacyLoaderOps.hook` and `revalidation_hook` are no-ops; dispatch checks the
hook before it could invoke a replacement; final revalidation checks before
accessing a descriptor; manifest discovery checks its canonical function identity.
Legacy public wrappers, namespaces, replacement-hook evaluation, graph fields,
signatures and public `unchanged` behavior remain unchanged. Production imports
no experiment. Compiler source identity changes and old qualified artifacts must
not be relabelled.

The experiment's `Owner` returns a separate `_OwnedGraph` containing the original
eleven-field `LoadedProject`. Its owner revalidation uses private copies of the
initial source bytes, bindings, package state and package graph. Mutating the
public graph/report dictionaries cannot erase this disk-revalidation authority.
The public AST remains mutable: this is not proof that consumer-modified programs
are qualified. Handles are accepted by object identity only within their owner;
constructing a lookalike or passing another owner's handle is rejected.

## Explicit budget and role ownership

One context and reader account for initial reads, final loader revalidation,
owner revalidation and subsequent loads. Rejection/cancellation is terminal.
Cross-thread use and checkpoint reentrancy are rejected. Public
`handle.project.unchanged()` intentionally still uses legacy operations and is
not the budget authority; consumers must keep and use the owner handle.

Roles come from explicit production read call sites, not filename guesses.
Revalidation requires a previously admitted lexical path. Both lexical-path and
resolved-target records retain the strictest observed role cap, including header
files whose extension looks like source and multiple aliases of one target.
Retargeted admitted lexical bindings are rejected before/after reads. Even a
checkpoint retarget during reading cannot inherit a weaker target's role cap.
The descriptor reader's per-read cap remains explicit. This does not make
filesystem name resolution and reads atomic.

The adapter reuses the isolated request context's regular-file reader, bounded
inventory, metadata byte/invocation admission, JSON structural-depth checking,
and lexer/parser admission. It preserves two separately charged lexing passes.
There is no token reuse, token-transfer API, or admitted-token provenance claim.

## Finite hook rejection contract

The adapter rejects the listed package helper aliases in both original namespaces,
manifest finder, parser/tokenizer entry aliases, JSON/TOML namespace objects and
load callables, and class/instance `unchanged` replacement. Context checks validate
the namespace identities after every checkpoint, including before a live decoder
call. A custom revalidation descriptor is rejected with static lookup before its
`__get__` is executed. Tests include a public-wrapper forwarder that would otherwise
reset the owner to fresh legacy operations and dynamic decoder/helper swaps.

Bootstrap assumes trusted parser/lexer and standard-library modules. This is not
security against arbitrary Python code, pre-bootstrap corruption of canonical
functions, private-field/function mutation, bytecode/default edits, class method
replacement throughout the AST/parser, or another thread changing namespaces
between checks. Digest, serialization, native/compiler callbacks and every Python
runtime callback are not covered by the finite hook allowlist. No whole-program
hook-safety claim is made.

## Lock and override limits

This profile rejects every non-None override mapping, including an empty one,
before filesystem reads. Existing legacy override semantics are unchanged.
A disk lock does not authenticate overlaid text. Owner revalidation preserves
legacy snapshot semantics and does not reread `Hepta.lock`: corrupting only the
lock after load can leave it true while fresh lock verification fails. No lock
writing or publication API is exposed by the owner. Native publication and
compiler-bound receipt gates remain separate.

## Deferred work before a production bounded profile

This gate does not add package/module node, dependency/import edge, path-check or
recursion-depth admission to normal algorithms. The reused Limits structure has
those fields for the older isolated fork, but those fields are **not enforced**
by this integration. Non-default values for these unsupported fields are rejected
at owner construction, rather than silently accepted as enforced quotas. Manifest ancestor discovery/path resolution, AST assembly,
metadata allocations, digest/serialization work and handle/authority retention
are not completely bounded. Inventory and input limits do not imply hard heap,
wall-clock or CPU ceilings. Token provenance with single-pass parsing, complete
role inventory across other consumers, and owner-preserving native/pipeline
integration remain separate gates. Do not switch a production default based on
this finite experiment.

## Validation

32 new no-skip tests cover owner lifetime, identity and type preservation, private
disk authority, hooks, descriptors, roles and symlink-retarget cases, source
refusal before parsing, real generated C header/sidecar inputs and all 80 example
outcomes (68 graph loads, 12 matching diagnostics, not 80 compilation successes).
The focused aggregate requires these plus the existing 127 tests: 159 unique
controls, no skips or expected failures. The hosted aggregate adds the existing
132 consumer regressions: 291 unique tests per Python 3.11/3.12 Ubuntu 24.04 job,
with exact HEAD verification and Rust 1.90/GCC. Use:

`python -m experiments.owned_loader.gate --include-consumers`

The local computer has GCC but no Rust compiler. Local focused results cannot
claim the full native-dependent 291-test gate; hosted exact-head results must be
checked separately. This is not all-platform/full-project/native ABI approval.
