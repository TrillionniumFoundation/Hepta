# Experimental authority-map copy admission

This profile extends `experiments.loader_transform.Owner`. No production caller or default selects it. The previous transform profile and all earlier profiles keep their existing accounting.

## Three operations, not all authority construction

The experimental owned loader already creates private disk-revalidation authority with one shallow `LoadedProject` copy and four independent one-argument `copy.deepcopy` calls. This adds a private virtual seam at those four calls. Its legacy implementation invokes the captured copier exactly once, without a memo argument, and deletes its captured callable then value in `finally`. Capturing the copier still precedes evaluating `getattr(graph, name)`. The final `setattr` remains after copy return. Exceptions retain their original type and message; the outer loader remains terminal on failure. Independent tests compare successful calls, argument failure, copier failure, setter failure and temporary-reference finalization with retained exception tracebacks.

Only `source_bytes`, `bindings` and `package_state` receive new admission. The fourth `package` copy still uses the original copier and its own fresh memo. `Package` dataclasses, concrete `Path` reduction/reconstruction, and the initial shallow copy remain **excluded**. A terminal context refuses even direct private seam calls; this is not a general private API or sandbox. An unknown map name is refused rather than falling through to arbitrary copy work.

Canonical shapes:

- `source_bytes`: exact `dict`, exact `str` keys, exact `bytes` values.
- `bindings`: exact `dict`, exact `str` keys and values.
- `package_state`: `None`, or exact dictionaries with exact string keys and values that are exact strings or exact dictionaries. Nested `None` is not admitted. Actual generated and verified locked snapshots fit this shape; this preflight is not a substitute for their schema/hash validation.

Subclasses and all other values are refused by identity-based type inspection without calling their copy, reduction, attribute, comparison, hashing or iteration overrides. Dictionary key validation occurs before yielding its key; source/binding value-shape validation occurs before yielding its value. Consequently invalid edges may be refused without being charged, rather than providing a universal count of all rejected-input examinations.

## Units and boundaries

`authority_visits` defaults to 200,000 cumulative admitted occurrences per owner; `authority_depth` defaults to 64. Both must be positive exact integers. A map root or root `None` costs one. Each dictionary key and value costs one plus any expanded descendants. Root depth is one, and every key/value edge increases depth. Empty dictionaries cost one. Depth and remaining quota are checked before charging/retaining a child traversal frame. Charged work is never refunded, including when later copy/checkpoint operations fail.

Traversal is iterative and streaming. It maintains active-path identities, not a permanent visited set. Cycles reject; acyclic aliases expand again. Thus shared mutable dictionaries may be conservatively charged multiple times even though real `deepcopy` memoizes them. The actual copy is unchanged: it preserves aliases inside each copied map and uses a fresh independent memo for each call. A mutable dictionary shared across different input maps receives separate copies. Immutable strings, bytes and `None` may retain their original identities across all calls.

Falsifiable formulas, with root included:

- source map with N entries: `1 + 2N`.
- bindings with M entries: `1 + 2M`.
- absent package state: one. A standalone one-source project therefore costs seven across the three calls.
- package snapshot: `9 + 12P + 2E + 2F`, where P is package-record count, E is dependency-entry count and F is file-record count. The one-package fixture snapshot costs 25; its three-map total is 31.
- `{'a': shared, 'b': shared}`, where `shared = {'x': 'y'}`, costs nine, not the identity-unique object count or actual allocation count. Its output still has one shared copied child.

These units are **not bytes, allocations, actual deepcopy invocations, a heap ceiling, a CPU budget or a hard time bound**. One bytes object of length one and one of length one million each cost one; normal deepcopy preserves the immutable bytes identity. String length, hashing, dictionary capacity, temporary interpreter objects, memo bookkeeping, actual recursion stack and native/OS resources are not measured. Structural depth admission does not guarantee that Python deepcopy cannot raise `RecursionError`, especially with unusual ambient stack depth or a caller-relaxed depth limit. Earlier parser/copy/transform quotas retain distinct units.

## Callback and protocol policy

The new profile checks the inherited context and invokes its cancellation checkpoint before preflight. It pins the original captured deepcopy, owned-loader copy module alias and legacy seam, inherited finite assembly copy dispatch/helper/AST protocol policy, plus the previously uncovered exact-bytes dispatch and reducer entries. Canonical dict/str/None dispatch is already covered by the inherited policy. It does not invoke unknown objects' reducers to discover a graph.

No checkpoint runs during graph traversal or between traversal and actual deepcopy. A checkpoint can mutate the input before traversal; that resulting graph is the one inspected. A checkpoint after copy may cancel, with no handle returned and no quota refund. Finite pin checks catch covered namespace changes made by the entry checkpoint. They do not secure arbitrary mutation of private functions, globals, types or code objects.

The inspected graph and runtime must remain stable during callback-free traversal and copy. Concurrent threads, signal/tracing hooks, garbage-collection finalizers and private graph/class mutations during this phase are outside this trusted-runtime model. This is not a sandbox or atomic snapshot guarantee.

## Failure and remaining work

A failed preflight does not invoke the selected map's copier. Prior map copies, public graph assembly, transform work and the shallow authority copy may already have completed. A later package-copy failure also prevents the final handle append. Public `load` and `unchanged` remain terminal after failures; an earlier returned handle does not reopen its owner.

Namespace-resolution dictionary merges, string operations, report/hashing work, Package/Path and shallow copies, synthetic reduction overhead and downstream compiler/native/OS activity remain separate work. See `AUTHORITY_COPY_AUDIT.md` for Package DAG and runtime/path-dependent Path measurements. No complete-loader or memory-safety claim follows from this gate.

Validation includes exact quota/depth boundaries, generated and locked package states, alias/memo behavior, rejected hooks/cycles/deep graphs, cancellation, legacy finalization, all 80 repository loader outcomes (68 graphs and 12 diagnostics), and the entire previous focused/consumer test gates with zero skips. Hosted Python 3.11 and 3.12 bind the exact candidate and frozen #630 baseline before direct 99-case parser and 80-case loader differentials.

The final gate contains 57 new tests (30 core and 27 independent review regressions), 432 unique focused tests, and 564 including consumer controls. Every skipped, duplicate, expected-failure or unexpected-success result fails the gate.
