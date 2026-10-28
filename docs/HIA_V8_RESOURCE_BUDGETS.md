# Returned-loan resource analyses on primitive v8

These profiles analyze the already executable `hepta.hia.program.v8`. Every
entry re-runs canonical `verify_program`; no displayed contract, producer
claim, prior receipt or successful sample can grant Core admission. They
reuse the existing call-graph and interval/CFG analyses. They do not introduce
another ownership verifier or a new language version.

## Distinct quantities and receipts

| API | New v8 receipt | Qualified quantity |
| --- | --- | --- |
| `qualify_vm_call_depth` | `hepta.hia.vm-call-depth-budget.v2`, profile `parameter-loan-synchronous-frames-v8` | Maximum root-inclusive synchronous HIA invocation frames |
| `analyze_static_budget` | `hepta.hia.static-budget.v2`, profile `acyclic-byte-owner-parameter-loans-v8` | Conservative VM tick, allocator-interaction and invocation-frame counts for an acyclic byte-owner module |
| `qualify_entry_live_heap_budget` | `hepta.hia.entry-live-heap-admission.v1`, profile `borrowed-call-local-peaks-v8` | Total requested live byte payload for one public scalar entry; private summaries count additional local payload only |

Existing v1–v6 static-budget and v1–v7 frame receipts retain their original
shape and meaning. The legacy all-function `analyze_constant_live_heap` and
`qualify_live_heap_budget` still refuse v8. In particular, adding
`max_live_heap_bytes` to the old combined static-budget API does not silently
select the new public-entry meaning. The old source-facing native receipt
consumer still refuses the new v2 event receipt; it has not gained a source
or native refinement qualification.

## Frame and event rules

Canonical v8's only synchronous function invocation is the explicitly named
`call` operation. Returning an input loan constructs one child view; returning
an existing direct child transfers it. Neither action invokes another HIA
function or adds a VM tick. The existing return terminator still contributes
one tick. For an acyclic direct call graph:

```
frames(f) = 1 + max(frames(callee)), with max(empty) = 0
```

Every defined function contributes to the checked graph, including private
uncalled definitions. A recursive call edge remains unqualified even if an
input depth happens to terminate in an execution. CFG loops do not themselves
increase nested synchronous frames, so they can receive the narrow frame
receipt while the total-tick analysis refuses them.

The event profile audits all declared input/output/block types and opcodes
against a closed byte-owner inventory. It excludes `chain`, including a
chain parameter consumed only by the syntactically ordinary `owner.drop`:
one such instruction can perform an input-dependent number of destructor
ticks and frees. The frame profile separately permits reviewed chain
operations because their iterative destruction does not invoke HIA functions.
An unknown opcode or terminator cannot inherit either profile merely because
a future verifier accepts it.

Within the byte-owner event profile, each block's local cost includes its
operations and terminator, with each callee's cost added at every call site.
The CFG join takes a conservative maximum over successor costs; invocation
entry adds one tick. The bound counts each `buffer.new`, `buffer.try_new` and
byte-owner drop as a potential allocator interaction, including paths where a
zero-sized or failed allocation actually performs fewer interactions.

## Borrowed-call heap summaries

The new heap entry API reuses the existing typed scalar interval transfers,
owner/loan root mapping and CFG maximum joins. The additional abstract state
distinguishes:

- A local owner root with a finite requested-size upper bound.
- A borrowed external root whose extent is **unknown**, represented internally
  by `None`; this is never a zero-byte owner or an assumed length.

A private function's summary is its peak **additional local payload**. At a
call site, the existing owners remain live, and the bound is:

```
peak at call <= live local payload in caller + additional local peak of callee
```

The induction is over the acyclic call graph. Storage borrowed from an
ancestor remains charged at the ancestor's allocation. It is not double
counted in every callee and is not removed from the eventual public-entry
total. A scalar public entry has no external resource parameters, so its
additional-local summary is a total live-payload bound for that invocation.
The report labels private summaries explicitly and does not claim their total
entry payload is bounded independently of their callers.

Returned loan roots are reconstructed from the verified callee's
`return_loans` and actual caller arguments. A later `buffer.len` on such a
returned view retains the caller's known owner-size upper bound. CFG edges
rename external roots along with their borrowed parameters. A join cannot
replace a local owner bound with an unknown external root or vice versa.

By contrast, `buffer.len` of a private external parameter remains unknown.
Allocating directly from that unknown length rejects, even if this particular
caller passes a small constant-sized owner. A separately checked cast to a
small machine type can establish a finite intrinsic bound, using the existing
trap-aware interval transfer. No caller value promises or sample-derived
extents are trusted.

The finite profile rejects owner-valued call inputs/results, recursive call
graphs, chains and unknown allocation extents. Existing independently
reviewed zero-local-heap scalar cycles can still have a finite heap bound;
arbitrary resource-carrying loops with calls remain unqualified. A payload
bound is not a termination, allocation-count, cumulative-byte, view-object,
RSS, native-stack, native-refinement or unwind-cleanup proof. Explicit traps
and evaluator budget stops retain the actual stopped resource ledger.

## Replay and evidence

`tests/test_hia_returned_loan_budgets.py` exercises actual Core admission and
VM execution for forward/direct-child/CFG returns, multiple shared results,
swapped mutable origins, nested temporary allocations, returned-view lengths,
branch maxima, allocation failures and every tick cut of a nested-call case.
It also checks recursive/chain/owned-boundary refusal, malformed origins,
exclusive aliases, uncalled future operations, exact-byte receipt replay and
the unchanged old native consumer boundary.

Run `tools/qualify_hia_returned_loan_budgets.py --expected-head <clean-commit>
--output <external-path>` to retain the actual tests, positive analysis
receipts, diagnostics, executed VM ledgers and canonical program bytes under
an unchanged complete source inventory. These observations are a separately
identified replay and must not be added to a combined full-suite denominator.
No whole-language soundness or general P1/P2/P7 closure is claimed.
