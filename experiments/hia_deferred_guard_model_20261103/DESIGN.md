# Deferred selection of versioned CFGs: applicability model, not an optimizer

This document records the model milestone at `beceb193`. The subsequent
experimental implementation and its still-restricted status are described in
[IMPLEMENTATION.md](IMPLEMENTATION.md); statements below about an unimplemented
candidate describe that earlier design milestone.

This branch is based on #564 source `23af1df3eed65230137aa54ab8b10eac3520abd3`.
It contains a read-only frontier planner, a conditional symbolic model and
counterexample tests. It **does not produce transformed Core, change the
production lowering/admission path, compile a candidate, or measure speed**.
The intended reference semantics are the already guard-selected slow/fast CFG,
not an unproved assertion that arbitrary fast and slow programs are equivalent.

## Motivation from actual code

The canonical composition in `hia_guarded_optimization._compose` selects two
complete CFG clones at function entry. Actual Clang20 MIR retains callee-saved
parameter copies before that split. Forcing shrink-wrap had no object effect;
disabling common-code sinking changed linear fallback code by three bytes but
left the targeted entry saves and empty return path unchanged.

A possible generic change is to share the **identical CFG prefix** and defer
version selection until the first different block. This does not identify
n=0, synthesize a constant answer, or add a thin wrapper. Allocation refusals
and other early returns may also finish in the shared prefix.

For both current workloads, comparing the actual narrowed slow and fast Core
finds differences in b5 and b8. The shared set is b1/b2/b3/b4/b6/b7/b9. The full
frontier is b4→b5 **and** b7→b8; using b5 alone would be unsound as a structural
rule. The selected suffix must include b4/b5/b6/b7/b8/b9, including backedges.
The tentative composition has 21 blocks instead of 19, so neither smaller code
nor faster code should be presumed. LLVM could still canonicalize it back.

## Restricted first applicability envelope

1. Match verified slow/fast function interface, block inventory, block parameter
   order/types and terminators. A block is shared only if its **entire body,
   effect operations and terminator** match. Do not trust a proposal's changed
   operation list as the sole difference oracle.
2. Initially support only one total unsigned `usize <= constant` guard on an
   original immutable function input. No heap loads, foreign/global state,
   effectful calls, trapping division, or checks with side effects in a guard.
3. Limit the first graph model to 128 blocks. Calls/recursion in the selected
   function are outside this initial model; they require a whole-call-graph
   simulation, not an inferred local guarantee.
4. Find all blocks reachable from entry while stopping at every different
   block. Every edge from this shared set to a different block is a frontier
   edge, including multiple successor edges and different first-divergence
   sites. An already-different entry requires immediate dispatch.
5. At every frontier, execute the original guard on the **original input
   snapshot**, then enter the corresponding version clone with exactly the
   original edge operands. Both cloned suffixes must be successor-closed.
   After selection, all backedges stay in the selected clone, not the shared
   prefix or a newly evaluated selection.

This planner's exact-envelope comparison only checks a design description.
It is NOT an independent checker of generated Core or of alpha-renaming.
No generated candidate exists in this work.

## Proposed SSA lowering, still to implement and independently check

Carry an immutable hidden **scalar** snapshot across every shared block edge.
The externally visible function signature stays unchanged. At entry the snapshot
is the actual function parameter; downstream block parameters receive that same
value, including every phi predecessor. Compute the comparison only at frontier
nodes. Do not copy an owner/loan descriptor as a hidden snapshot.

For each frontier node, transport the target's original ordered block operands
into the chosen suffix clone. Use fresh bijective names, not potentially colliding
prefix concatenation. All successor edges in a selected suffix must use that
suffix's namespace, even when they revisit blocks also present in the shared
prefix. Prune unreachable clone blocks without omitting reachable loop headers.

A future independent checker must reconstruct the name/value bijections from
the actual candidate, validate every phi incoming edge and operand position,
check original guard-input provenance, and re-run the real Core verifier. It
must bind the proposed structure and all source/proof identities. An old receipt
with `guard_before_effects=true` cannot authorize this new composition.

## Conditional simulation argument

Let G be the total immutable guard. In the reference, G selects a version before
execution. In the proposed graph, a state is either shared or selected-fast/slow.
Relate states by original block identity, equal scalar/resource state modulo
verified renaming, equal ordered event history and the same original guard input.

- In a shared state, both versions have exactly the same block transition.
  Couple the same external/resource result (for example the same allocation
  refusal event). Both execute the same operations, branch, trap or return.
- On a frontier, the added pure comparison emits no resource event. Snapshot
  preservation makes its result G, so the candidate joins precisely the version
  already selected by the reference, with equal ordered block arguments.
- In a selected state, the cloned block and all its successors remain that
  reference version. Loop backedges therefore preserve the relation.
- A path that stays in the shared prefix forever has the same infinite event
  trace under these assumptions. Early returns and traps agree without ever
  reaching a different block. Guard computation is finite and nontrapping.

This is a **conditional, human-readable stuttering-simulation argument**, not
an all-program theorem checked by Lean. The Z3 shared-step obligation encodes
congruence under the explicit equal-transition/equal-state assumption. It does
not prove that an implementation has satisfied that assumption. Guard/snapshot
bitvector obligations and negative models are separate, narrower checks.

## Resource, trap, quota and dominance risks

- Merging a prefix that merely returns the same scalar but allocates, borrows,
  writes, frees, traps or calls differently is invalid. Complete ordered
  operations and actual arguments must match. Do not move or delete effects.
- A changed scalar can also control resource behavior. Treat any differing
  operation in a block as divergence before executing that block.
- Original input identity is not the current loop-carried variable with a
  similar name. Copying the wrong phi operand or reevaluating a mutable value
  can switch versions after overflow/refusal conditions have changed.
- No single frontier block necessarily dominates all changed operations. The
  proof requirement is a complete **cut set** plus selected-suffix closure,
  not an informal “the usual loop header dominates” claim.
- Ordinary shared-prefix traps preserve their order. A trapping/effectful guard
  does not: postponing division by zero past an early return changes behavior.
- Instruction counts, VM quotas, timeout/fuel boundaries, code size, compilation
  cost and native latency are NOT preserved by this equivalence claim. Even a
  zero early return avoids guard instructions that the old composition counts.
  Any VM-facing deployment needs a separate policy decision/proof for that cost
  model; this experiment grants none.
- LLVM poison/undef, allocator/FFI conventions, register allocation and machine
  code remain outside this model. A compiler flag is not a refinement proof.

## Executable checks and counterexamples

With the existing pinned solver environment:

```sh
python -B -m unittest tests.test_deferred_guard_model -v
python -B tools/research_deferred_guard_model.py
```

The tests cover real workload frontier extraction, missing cuts, missing loop
backedges, wrong phi order, changed resource operations, mutable snapshots,
non-total guard shapes, entry divergence and unsupported calls. Differential
finite-state examples include prefix/suffix loops, modeled allocation refusal,
modeled borrow/write/end/drop event order, early return and prefix traps.
They are abstract models, not execution of transformed HIA.

Z3 4.15.4 proves snapshot selection equality and an explicitly conditional
common-step congruence obligation. It produces concrete countermodels for a
mutated loop/phi argument, wrong phi operand and signed/unsigned guard mismatch.
The differential model also finds omitted-cut and mutable-reselection trace
counterexamples. A 40-block-step prefix bound is not a termination theorem or
proof of arbitrary-length execution.

## Next decision

Review these applicability conditions and counterexamples first. Only then
implement an untrusted experimental proposer and a separately written checker
bound to actual Core, with HIA resource-trace differential controls. Only a
verified candidate should enter a bounded compile-only comparison. A useful
machine-code change and further correctness checks would precede a distinct
preregistered timing campaign using the complete original gate. None of those
later stages is completed or authorized by this model output.

`authority=DENY_ALL`, `production_admission=false`, `performance_qualified=false`.
