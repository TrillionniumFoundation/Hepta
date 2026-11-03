# Experimental parser append-attempt admission

Stacked on draft #627 at c6895fecd5db295eb32c7dae62d74b3c603a7941.
No production default/caller change, merge, deployment or native qualification.
This is an incremental work-admission policy, not complete container or memory
accounting. The existing grammar-depth guard is inherited unchanged, not new.

## Why this metric exists

Parsing 1 or 100 generic type names or lifetimes makes the same three semantic
AST constructor attempts. Module path segments similarly do not grow AST count;
match payload bindings have the same issue. Existing source/token limits already
make that work finite. This policy permits a stricter cumulative grammar append
quota independent of token/node quotas, and rejects before recursive append
arguments. It does not repair an otherwise unbounded owner or prove a hard heap
bound.

## Exact seam and semantics

Normal Parser._admit_append(operation) returns its exact supplied callable. All
25 grammar list.append call sites use the curried form
self._admit_append(container.append)(original_argument). Receiver/method lookup
and bound callable capture still precede argument evaluation. The original
callable and argument are used, with no legacy wrapper, collection replacement,
retained argument, copied parser algorithm or production experiment import.

The separate experiments.parser_appends.Owner extends the AST constructor
profile. Limits.parser_appends is a positive integer, default 20,000. An attempt
is charged before the append argument is evaluated, not after successful
insertion. Nested parsing may therefore charge parent before child append sites.
Later argument or append failure does not refund admission. A refused attempt
neither evaluates the argument nor invokes append, and owner parsing failures
are terminal. Counters accumulate across all modules and reloads of the owner;
unchanged revalidation with no parsing adds no append charge.

The empty function charges one functions-list append. An empty module charges
zero. Previously constructed literal seeds are not charged. The experimental
hook accepts only exact built-in list.append bound methods; unknown objects are
rejected without invoking custom attribute/equality/hash behavior. The normal
hook remains identity-preserving for arbitrary legacy callables. Finite hook
checks pin the normal seam after callbacks. This is not arbitrary Python runtime
mutation security or cross-thread race isolation.

## Exclusions and compatibility

The post-hoc tree validator's one append and three extends are unchanged and
excluded. Initial list literals/seeds, empty collections, tuple conversion,
dictionary and set operations, namespace comprehensions/unions, AST field
literals/defaults, token splitting, path string joining, metadata, loader
copies/assembly, retained authority and downstream/native work are excluded.
No peak-live, byte-allocation, hard CPU/time, OS memory or complete container
claim follows. Inherited source/token/AST/depth/read/graph bounds remain separate.
Previous owner profiles do not acquire the new quota. Legacy double lexing,
source overrides, locks and existing diagnostics retain their prior contracts.
Source identity changes; old qualified artifacts must not be relabelled.

## Validation

Static inspection requires exactly 25 curried grammar append sites and one
unchanged direct append only in the validator. Independent design and code
review checks original callable/finalizer ordering, pre-argument refusal,
conservative failed attempts, generic names/lifetimes/path segments/match
bindings, independent AST budgets, reload/revalidation and terminal hooks.
25 new controls plus the prior 267 give 292 focused controls. Full example
parity matches 68 graphs/ASTs and 12 diagnostics, not 80 compilations. Consumer controls add
132 more. The gate rejects skips, duplicate identities, expected failures and
unexpected successes. Local Rust is unavailable, so local focused testing is
not a native aggregate pass.

The separate 99-case direct normal Lexer/Parser differential against frozen #627
matches full source hashes, tokens, ASTs and diagnostics. The evidence hash is
54497ceff2a8fc163fef5953fa9de7bb1c8c1a5b616bdea79cf4c1d8022f096b.
Hosted Ubuntu 24.04 / Python 3.11 and 3.12 verifies candidate/base identities,
runs that differential, and then runs the complete no-skip aggregate with Rust
1.90 and GCC. See the PR for exact-head hosted results, not assumed here.

Run python -m experiments.parser_appends.gate --include-consumers.
