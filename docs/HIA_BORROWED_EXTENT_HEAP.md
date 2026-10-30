# Finite v8 heap admission with caller-derived borrowed extents

This is a separate **opt-in v3 admission contract** over existing primitive v8
Core. It extends finite invocation analysis to helper allocations whose sizes
come from incoming borrowed-buffer lengths. It introduces no Core opcode,
source annotation, execution rule, Rust Machine behavior or native ABI.

```python
from hepta.hia_heap_bound import (
    qualify_finite_entry_live_heap_budget_v8_with_borrowed_extents,
)

report = qualify_finite_entry_live_heap_budget_v8_with_borrowed_extents(
    core, "entry", [False], max_live_heap_bytes=36,
)
```

The result uses schema `hepta.hia.finite-entry-live-heap-admission.v3` and
profile `acyclic-byte-owner-transfer-caller-borrowed-extents-v8`. Its meaning is
the maximum live **requested HIA payload bytes** for the specified exact
scalar invocation, including allocation-failure and stopped-execution
prefixes. It does not bound allocator metadata, native stack, process RSS,
foreign memory or runtime view objects. It does not authorize a production
optimization, resource migration, native execution policy or imported receipt.

The previous
`qualify_finite_entry_live_heap_budget_v8` contract remains v2, with its
original incoming-loan length boundary. The primitive v7 finite-invocation
contract remains v1. Their schemas, reports and admission behavior are not
silently widened. See [the v2 contract](HIA_FINITE_V8_HEAP.md).

## Concrete missing boundary

A scalar entry allocates a 9-byte retained owner and a 4-byte owner transferred
to a helper. Two shared formals refer to the same retained owner. The helper
reads the first borrowed buffer's length, allocates a temporary buffer of
that length, drops the temporary, and returns the transferred owner.

The existing canonical verifier and runtimes accept this resource lifecycle.
Actual execution reaches `9 + 4 + 9 = 22` live bytes and returns with no live
resource. The v2 analyzer nevertheless refuses the temporary allocation with
`E_HIA_BUDGET_UNBOUNDED`: incoming borrowed roots intentionally carry unknown
lengths in that profile. The v3 API admits this invocation with a 22-byte
bound and refuses a policy below that bound. It derives the length from the
actual caller owner; the user supplies no borrowed-resource size promise.

## Two independent facts about an incoming loan

An incoming borrowed root has a payload ownership location and an optional
length upper bound. These facts must remain separate:

| Fact | Representation | Meaning |
| --- | --- | --- |
| Payload location | Existing external root with owner extent `None` | The caller or an ancestor retains this storage; the callee must not count a new owner. |
| Length information | Separate external-root upper-bound map | `buffer.len` may produce an interval bounded by the actual caller root. |
| Call specialization | Frozen internal `_BorrowedExtent(upper)` argument | Distinct borrowed extents produce distinct memo contexts; the value does not create ownership. |
| Returned view | Existing canonical `return_loans` formal-to-actual mapping | Reconnect the result to the original caller root, including non-first and reordered results. |

At a call, the analyzer resolves each actual loan through its verified loan
graph. A local owner supplies its already established upper extent. A root
borrowed from an ancestor can supply the separate propagated upper extent.
An unknown extent stays unknown. The public entry must remain scalar, so
there is no public argument position accepting `_BorrowedExtent`, a borrowed
handle or an external size assertion.

An owned actual is removed from the caller's local sum before adding the
callee's peak. A borrowed actual leaves its root in the caller. Callee
external roots contribute no local payload, even when their upper extents
are known. Thus a nested helper can size a temporary buffer from a loan
without charging the retained storage at every call level. Shared actuals
that refer to one caller root also do not duplicate its payload charge.

## Lengths remain intervals

The upper extent of an owner is not necessarily its actual length. In
particular, `buffer.try_new(8)` may return an empty logical owner on allocator
failure. A borrowed `buffer.len` therefore yields `[0, 8]`, not the constant
`8`. The same conservative rule applies to infallible owners in this profile.
An upper extent of zero yields `[0, 0]`; it does not remove the logical owner
or loan lifecycle.

The regression `interval_program` returns this borrowed length from a helper,
ends the loan, drops the original owner, and requests `100 - length` bytes.
Normal allocation produces a later 92-byte request; a failed first allocation
produces a 100-byte request. The admitted bound is 100 bytes. Treating the
upper extent as an exact length would produce an unsound 92-byte bound.

All syntactic CFG branches remain included. This extension establishes no
new reachability or exact-value premise. Arithmetic uses the existing
reviewed interval transfer and checked machine-width rules. Other unknown
values, including presently unmodeled data-dependent allocation sizes,
cannot acquire a length proof merely because the function has a bounded
borrowed parameter.

## Calls, CFG joins and origins

The call-context key includes the callee name and all abstract arguments,
including each borrowed upper extent. A helper invoked with 3-byte,
11-byte, then 3-byte actual roots uses two helper contexts and one entry
context. Reusing the first context for the larger root would underestimate
the peak; the dedicated regression has an actual and admitted peak of
29 bytes.

CFG edges rename external root identities using the same verified
block-parameter mapping as owners and loans. The separate extent map follows
that mapping. At joins, shared known upper bounds take their maximum. If a
root lacks an established extent on an incoming edge, the joined extent
stays unknown. This permits a helper to locally select between two incoming
read loans and use the maximum extent for a temporary allocation.

This join rule grants no returned-loan provenance authority. Returning a
loan from incompatible original formals is still rejected by canonical Core,
even if both paths have finite sizes. A declared returned-loan origin must
still match the original borrowed formal on every return path. Mutable
aliasing, early parent termination and malformed or hidden invalid helpers
are rejected before estimating resource usage.

## Composite partial state, failure and cancellation

The tests use actual composite v4 elaboration to primitive v8. In the nested
record fixture, the first field owns 3 bytes and the second owns 11 bytes.
A helper traverses a renamed composite argument, returns the two field views
in reverse order and allocates an 11-byte temporary from the second field's
borrowed length. The two retained fields plus temporary have a 25-byte peak.
Failures during either field initialization clean only the initialized
logical state. Read and mutable versions use the same existing contract.

The task fixture borrows an initialized partial-record field during `poll`,
calls a helper that allocates from its length, and ends the returned and
parent loans before the next task state is carried. With a 3-byte field the
admitted peak is 6 bytes, including the helper temporary. Pending cancel,
running cancel and completed join follow the existing explicit cleanup
paths. No loan crosses a task suspension boundary, and no asynchronous
unwind behavior is introduced.

For the owner-replacement fixture, an unrelated 3-byte caller owner remains
live beside an 11-byte borrowed owner and a transferred 4-byte owner. The
helper follows two nested returned-loan calls, then uses that borrowed length
for a fallible replacement. Success drops the old owner; allocation failure
or explicit cancellation returns the original owner. The caller allocates
another temporary from the returned loan before ending loans and dropping
owners. The conservative peak is 36 bytes, which the normal run reaches.
Cancellation and replacement-failure runs have lower peaks but use the same
conservative all-branches bound.

An infallible allocation failure, VM step stop, heap stop or call-depth stop
can leave live owners and loans in the observation ledger. The bound covers
those prefixes; it does not invent destructor execution after a stop.

## Qualification boundary and evidence

The entire canonical module must pass the existing audited primitive v8
byte-resource profile, acyclic call graph and acyclic CFG checks. Unsupported
chains, recursion and cycles remain refused, including in uncalled helpers.
The finite analysis limits remain 1,024 distinct contexts, 32,768 abstract
transfer steps and 64 active analysis frames. Exhausting a limit produces
`E_HIA_BUDGET_LIMIT`, never a guessed bound.

The receipt binds the input and canonical Core digests, exact scalar entry
arguments, payload policy and bound, the static VM tick/allocator/frame
report, and actual analysis work. Its digest is binding information, not
authority to import someone else's resource assertions. Core is reverified
before analysis on every public call.

`tests/test_hia_borrowed_extent_heap.py` provides three distinct checks:

1. Canonical admission tests cover the former refusal, exact policy boundary,
   context separation, shared aliases, reordered origins, CFG extent joins,
   zero/failed owners, partial records and tasks. Negative tests retain stable
   refusals for invalid resources, unproved sizes, graphs and exhausted work.
2. The existing independently implemented Rust parser and Machine execute
   the real normalized Core bytes. Value, status, ticks and the complete
   resource ledger are compared against Python under allocation-failure
   injection, cancellation and every step cut in the targeted resource/task
   fixtures. Existing bound-v2 execution transport also checks call-depth
   stops. Rust does not consume the Python admission receipt as proof, and
   these tests do not claim that Rust independently elaborates nominal input.
3. Linux native builds use the existing LLVM backend and a linked allocator
   observer. The observer compares actual allocation attempts, allocations,
   frees, peak/live bytes and returned values for the corresponding cases.
   These are finite host observations, with no new native VM-budget promise.

Run the focused closure with Cargo and Clang available:

```sh
HEPTA_BORROWED_EXTENT_EVIDENCE_DIR=/absolute/evidence/directory \
  python -m unittest -v tests.test_hia_borrowed_extent_heap
```

Without those toolchains the respective unittest classes are explicitly
skipped and cannot be counted as independent/native qualification. Evidence
produced against a dirty development source is development evidence. Final
source qualification must bind a frozen source revision and its corresponding
test inventory; this document does not convert development observations into
such a qualification.
