# Experimental canonical assembly-copy preflight

Stacked on draft #628 at 1c87a3f9f7fd5637a8d95b1db215d31bd6e7ee00.
Independent design and adversarial implementation review precede publication.
No production default/caller migration, merge, deployment or native qualification.

## Scope and preserved legacy behavior

Normal loader assembly calls a private ops.deepcopy(captured_callable, value)
seam at two existing sites: copying the main Program and copying each original
declaration. Legacy invokes the exact callable with the original single argument.
Callable lookup remains before value evaluation. A finally block clears callable
then value so failure tracebacks do not newly retain temporary callable/argument
objects. Their finalizer order is tested against the original direct call,
including retained exceptions. The initial Program copy is not optimized away
although its declaration lists are subsequently cleared.

The separate experiments.assembly_copy.Owner extends the append profile. Old
profiles and legacy retain their policies. The new profile admits canonical graph
work before invoking the standard captured deepcopy with its original one-argument
signature and fresh memo. No parser/loader/copy algorithm is duplicated or rewritten.

## Exact logical metric

Limits.copy_visits defaults to 1,000,000 cumulative positive-integer visits across
all assembly copy attempts, modules and owner reloads. Limits.copy_depth defaults
to 256 and is a positive integer. Root depth is 1. One visit is charged for each
root or recursively reached reference occurrence:

- Dataclass to its actual instance dictionary is one edge.
- Dictionary keys and values are separate edges.
- List, tuple and set elements each supply one edge.
- Scalars and empty containers each cost one visit.

Aliases are expanded every time, not skipped after first encounter. Current-path
identity repeats are rejected as cycles. Traversal state resets for each copy;
counters do not. Depth is checked for every occurrence, including scalars and
aliases. Denied depth/visit attempts do not increment visits. Admissions already
consumed are never refunded on subsequent shape/cycle/copy/cancellation failure.
Errors through the copy entrypoint are terminal.

This conservatively overcounts mutable aliases that deepcopy memoizes. It also
handles a genuine counterexample to unique-identity counting: unchanged immutable
tuples are not memoized by Python deepcopy and an aliased tuple DAG can require
exponentially many traversals. Ten doubled tuple levels have only eleven unique
tuples but 3,071 unfolded canonical visits and 2,047 tuple-copy dispatches.

The metric is not the exact number of deepcopy calls or allocation events.
Dataclass reduction also processes constructor arguments, and set reduction
creates synthetic argument containers. It is not unique-object, byte, peak-live,
hard heap, Python recursion-stack, CPU or wall-clock accounting. Scalars such as
strings are single visits regardless of byte size; prior byte/token bounds remain
independent. Standard deepcopy still may raise RecursionError, terminally.

## Bounded traversal and callback boundary

The root is admitted before traversal bookkeeping. Each child is admitted before
its pending frame. An explicit stack retains one constant-sized iterator/frame
per active compound plus one active identity. No eager child list, copied vars
map or complete key set is constructed. Traversal work is finite in admitted
visits; the stack is bounded by admitted depth. Fixed class-schema/hook tables and
constant setup overhead are not described as allocator-byte admission.

The external checkpoint runs before inspection, and after copying. There are no
user checkpoints during the finite preflight or between its completion and copy.
This prevents a checkpoint from modifying an already validated subtree before
copying. Cancellation latency includes the whole admitted preflight/copy phase;
there is no hard timing guarantee or claim of checking every copy operation.

This phase assumes ordinary trusted execution with no concurrent, signal, tracing,
GC/finalizer or private graph/class mutation during preflight and copy. Callback-
free does not mean atomic against those mechanisms. The policy is not a Python
sandbox. Post-copy cancellation may occur after allocation and prevents success.

## Canonical shapes and finite hook checks

Allowed exact types are the thirteen AST dataclasses Span, Type, Expr, Stmt,
Param, Struct, EnumVariant, Enum, Pattern, MatchArm, Import, Function and Program;
list/tuple/dict/set; and None/bool/int/float/str. Unknown classes are compared by
identity, never hashed or equality-compared. Unknown subclasses and descriptors
are rejected without invoking their custom behavior. Dictionaries require exact
string keys and sets exact string members. AST __dict__ must have exactly the
reviewed field names, checked incrementally without a copied key set.

Supported copy protocols are pinned using static inspection: __deepcopy__,
__reduce__, __reduce_ex__, __getstate__, __setstate__, __getnewargs__,
__getnewargs_ex__, __new__, __getattribute__, __getattr__, __dict__ and __setattr__.
Slots must remain absent. The lazy __slotnames__ cache may be absent, None or an
exact empty list only. Finite copy helper identities, canonical-type dispatch and
reduction entries, and the builtin type dispatch used for reduction constructor
arguments are also checked. No claim covers arbitrary unlisted runtime mutation.
The real deepcopy memo and alias identity behavior are preserved unchanged.

Independent adversarial review found and fixed dynamic __getattr__ synthesizing
__deepcopy__, class-object copy dispatch, and slot metadata invoking a property.
It also found the legacy exception-frame retention difference; explicit cleanup
now preserves the original temporary-finalizer order. All have regressions.

## Exclusions and evidence

The transform stage's Type/list/tuple/dict reconstruction, retained private
owner authority/package copies, parse/token snapshots, resolver/metadata/native
work and OS resource isolation remain outside this profile. Revalidation with
no new graph assembly adds no visits. Existing lock/override/read/token/append/
AST and namespace policies remain independently enforced.

Measured empty Program: 16 visits/depth 3. One empty function: 83 Program-copy visits
plus 67 declaration-copy visits, total 150. A valid forty-operand left-associated
return expression has canonical depth 131 although existing parser admission
accepts it. This demonstrates an independent early-refusal condition.

All eighty real examples fit the canonical shape: 68 full graph/AST outcomes and
12 exact diagnostics, not 80 compilation successes. Direct isolated subprocesses
compare old/new normal loaders against the same frozen example paths, including
full reports, ASTs, source bytes and unchanged outcomes. Its raw digest is path-
dependent; equality within each run is required. The independent 99-case normal
Lexer/Parser differential remains available too.

45 new controls plus every prior 292 give 337 focused controls. Adding the prior
132 consumer controls gives 469 total. Exact
unique counts are declared by the gate, with skips/expected failures/duplicates
rejected. The hosted workflow requires Python 3.11 and 3.12 to verify the frozen #628 and
candidate checkout identities, both direct differentials, and the complete aggregate. See the PR for
exact-head results. Local Rust is absent, so local focused evidence is not a
native aggregate pass. Source pins/inventory change after review, and compiler
identity changes; old qualified artifacts must not be relabelled.

Run python -m experiments.assembly_copy.gate --include-consumers.
