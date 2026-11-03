# Experimental parser AST-constructor admission

Status: isolated structure-count profile stacked on #626 at
`dd456b531e1e08cf320dc3cd1b904d7a3c995222`. Production defaults and legacy double
lexing are unchanged. No production caller, merge, deployment or new native
qualification mechanism is included. This is a finite constructor-attempt budget,
not a complete bounded parser, AST memory bound, process sandbox or hard CPU limit.

## Reviewed design and genuine pre-construction seam

The normal Parser contains one private `_admit_node(constructor)` method, which
returns its exact argument in legacy mode. Each of its 36 semantic AST-constructor
call sites now uses `_admit_node(Expr)(...)` and the corresponding constructor.
The curried form preserves constructor resolution before arguments, passes the
original positional/keyword arguments, and introduces no legacy wrapper retaining
those arguments. Unlike a post-hoc traversal, the experimental override charges
before evaluating that call's arguments and before invoking its constructor.

The twelve covered classes are Type, Expr, Stmt, Param, Struct, EnumVariant, Enum,
Pattern, MatchArm, Import, Function and Program. A static source audit rejects a
new direct call to these constructor names and requires the reviewed 36 sites.
The AST dataclasses, fields, signatures and the parsing algorithm are unchanged.
No parser source rewriting, copied parser implementation, production experiment
import or global budget is added.

The separate `experiments.ast_structure.Owner` extends the owner-bound single-lex
profile. A private parser-factory method in that earlier experiment lets the new
profile select its subclass without copying token provenance or parsing code.
All original legacy/read/graph/token profiles keep their prior policies. Legacy
still tokenizes twice; this experimental profile retains the prior single lex.

## Exact quota meaning

`Limits.ast_nodes` is a positive-integer cumulative admission limit, default
20,000. It counts attempted calls at the covered parser sites over the whole
owner lifetime, not successful nodes or unique returned objects. Admission is
not refunded when later arguments, construction or parsing fail. Such failures
through owner.load are terminal. The next denied attempt does not increment the
counter or invoke its arguments/constructor.

A parent call may be admitted before recursively constructed inline arguments.
Other argument lists, maps, source text, tokens and children may already have
been built by earlier statements. They are not retroactively bounded by this
quota. Count ordering follows each actual constructor site, not a postorder walk.

An empty `fn main()->Unit effects {} {}` admits three nodes: its return Type,
Function and Program. Repeated modules and reloads share one cumulative counter.
Successful disk revalidation with no parsing does not add AST-node charges.
Package snapshots and graph authority copies retain their separate semantics.
This is not a new syntax-tree depth guarantee: grammar nesting and the legacy
post-construction tree-depth check remain distinct and unchanged. A small node
quota can refuse a wide or long-left-associated source before the legacy depth
check would run; with sufficient quota the existing diagnostic is retained.

## Hooks, identities and terminal behavior

Experimental constructor selection uses identity, never hashing or equality of
untrusted callable objects. The profile checks the selected constructor aliases
in the parser and AST namespaces, plus the private admission seam, after each
checkpoint. A namespace replacement or deletion is rejected before invocation.
Trusted canonical bootstrap and ordinary private runtime integrity are assumed;
this does not protect against arbitrary class method/bytecode/private-registry
mutation or another thread racing namespace checks.

The inherited source/path/token identity, single-use batches, private parser
snapshot, finite hook checks, cancellation and reentrancy rejection remain.
Swallowing a nested terminal error cannot allow outer success. Source overrides
remain rejected, public graph.unchanged remains legacy rather than budget
authority, and lock revalidation does not freshly authenticate Hepta.lock.
A node quota failure neither writes nor replaces a lock.

## Explicit exclusions

Span, Token, Diagnostic and exception construction are not counted by ast_nodes.
Separate token/read quotas still apply. Standalone list/map/set allocation,
metadata, parser auxiliary records, the loader's deepcopy/assembly/rewrites,
retained graph authority, downstream analysis and native work are not counted.
The parser's post-hoc depth scan remains post-hoc; this PR does not relabel it as
pre-allocation admission. OS resolution, Python recursion limits and allocator
behavior are not isolated by this profile. No hard heap, CPU or wall-clock bound
follows from the count.

## Validation

32 new controls cover exact/one-over quotas, refusal before arguments and actual
constructors, conservative failed attempts, wide declarations/fields/arrays,
left-associated malicious input, multiple modules, repeated loads/revalidation,
constructor aliases, cancellation, swallowed reentrancy, source/token ownership,
locks/overrides, legacy hooks/double lexing and all 80 example graph outcomes
(68 matching loads and 12 diagnostics, not 80 compilation successes).

The aggregate retains all prior 235 focused controls: 267 unique no-skip tests.
Hosted Python 3.11/3.12 on Ubuntu 24.04 adds the existing consumer regressions for
399 controls per job with Rust 1.90/GCC. Before that aggregate, an isolated
99-case direct Lexer/Parser differential compares source hashes, full tokens,
ASTs and diagnostics against exact #626, verifying both checkout identities.

Run `python -m experiments.ast_structure.gate --include-consumers`.
Local Rust is absent; local focused passes are not a native aggregate result.
Source pins and inventory were refreshed after independent seam review.
Compiler identity changes; old qualified artifacts cannot be relabelled.
