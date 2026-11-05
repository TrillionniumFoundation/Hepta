# Proposed connection obligations: actual Core to the existing Lean prefix model

Design only, based on research PR #594 source
46e17ddc03fc5abb4200c150f555731d5cb80d28. No new prefix-memory model, production
checker change, zero-initialization bypass, compiler run or target execution is
introduced. This document does not establish a universal Core/Lean/LLVM bridge.
The first proposed conclusion is deliberately narrow: every successful load
in the admitted fragment reads an index previously explicitly stored in that
same live dynamic allocation instance. Even that conclusion is not established
by this design; it needs the connection obligations below.

Every proposed connection result must remain DENY_ALL and
initialization_elision_authorized=false until separately justified and reviewed.

## Reuse rather than duplicate

The existing `formal/HiaInitializationPrefix.lean` already defines Memory,
write, fillPrefix, PrefixValues and FullyInitialized. Its named theorems cover:

- write_at_index / write_at_other: byte update and its frame;
- write_extends_prefix / prefix_invariant: contiguous zero-based unit steps;
- completed_fill_initialized / completed_fill_independent_of_initial /
  completed_fill_matches_zeroed: completed schedules and initial-byte independence;
- increment_within_limit / completed_exit_is_exact_bound /
  completed_exit_establishes_initialized: bound and normal exit;
- incomplete_prefix_is_not_full / skipped_zero_stays_uninitialized /
  stride_two_leaves_a_hole: rejecting schedule cases.

`tools/qualify_hia_initialization_prefix.py` already checks that model with the
locked Lean 4.19.0 binary/support identity, named theorem inventory and targeted
negative mutations. `tests/test_hia_initialization_prefix_formal.py` protects
that qualification boundary. This design does not claim to rerun Lean or upgrade
that model-only receipt into program authority. The new #594 Z3 conditions are
supplementary scalar diagnostics, not a replacement or a new foundational model.

Existing production coverage and its native poison-malloc tests are documented
in `docs/HIA_INITIALIZATION_ELISION.md` and `tests/test_hia_initialization.py`.
They do not currently recognize the deferred multi-entry CFG. No test here
forces malloc or disables calloc to get an attractive result.

## Exact concrete anchors

The two actual deferred CI Core hashes are:

- linear: c7b8b9ef7619700fd9c5ec0dedb06fbf7ecc801563813b6cb7abaf7e08a467d3
- affine: 91f11c6cf67610dc0682640d0c24cbd2572a0fcbdea25fdf94ff7671cf1cc861

They come from #592 source 954ee966547a233c691c27bde7d0a3b44d38edf8 and its
compile-only run 41621254692, not from an initialization-elision experiment.
Both have allocation root dg_v_0 and requested extent originating at arg1.
The generic research checker derives, rather than trusts by name:

- guard_0 then→fast_1 and else→slow_1 as direct-body zero seed edges;
- fast_0 else→fast_2 and slow_0 else→slow_2 as normal fill-completion edges;
- shared_3 else→shared_4 as an empty-extent completion edge.

All these block names have the `dg_` prefix. An additional empty-edge certificate
at shared_5 else→shared_6 is redundant for the load-coverage cut. Certificate
consumers must not rely on these fixture names, the producer's prose invariant,
or a saved `status=checked` as evidence.

## Proposed certificate transport, not an authority format

A future untrusted connection proposal should contain hints sufficient to locate
and independently reconstruct the following facts. It must not embed a trusted
boolean saying the facts hold:

- Exact canonical Core hash, function identity, schema, producer source hash,
  checker/dependency identity, existing Lean model/toolchain/support identities,
  and a versioned, closed admitted opcode/profile inventory.
- Allocation operation location and ordinal, actual output and length operands,
  allocation kind, and an explicit dynamic-instance/non-repetition condition.
- For each loop: actual header/body operation inventories, typed index/extent
  parameter positions, ordered store and step operations, and ALL incoming edges.
- Each edge identity as (source block, branch arm or jump, target block), with
  exact ordered argument→parameter mapping. Source/target names alone are not
  enough when two arms have the same target.
- Per seed/backedge: root and extent provenance evidence, zero seed or verified
  successor expression, and the precise success/range precondition used.
- Per completion edge: its local certificate kind, corresponding allocation,
  bound expression, and an independently checkable path-coverage result for
  every actual load operation, including loads earlier in the same block.
- Explicit unresolved obligations and non-authority flags. A digest proves
  identity, not semantic correctness. Any unknown or unsupported fact refuses.

The present research report does not contain or prove this complete transport.
Its source/core hashes and structural findings are inputs to scrutiny, not
capabilities that a compiler can import.

## Falsifiable connection obligations

1. **Runtime projection and phi simultaneity.** Relate a verified Core environment
   to Lean Nat indices and to one existing Memory per dynamic owner. The runtime
   evaluates all edge arguments before simultaneously binding target parameters
   (`hia_program_runtime.py`, function execution loop). Reconstruct every ordered
   phi operand. Same-typed extent/index substitution, swapping two equal-looking
   parameter names, or changing one parallel edge must invalidate the connection.

2. **Static root is not a dynamic instance.** A static allocation SSA name can
   execute repeatedly. Either reject allocation-site cycles as the current
   closed profile does, or supply a separate epoch/instance proof. Owner move and
   borrow transports must preserve the actual live owner, not merely type/name.
   Wrong-owner and repeated-allocation controls must not inherit another fill.
   This needs a resource/environment correspondence beyond the Lean byte model.

3. **Requested extent versus successful owner length.** For a normal successful
   allocation, connect the exact requested usize N to the live owner's length.
   A failed buffer.try_new can instead return an empty owner and false; it must
   NOT be modelled as N arbitrary initialized bytes. Zero-length creation is a
   real owner but no allocator attempt/failure consumption. Object-size refusal,
   finite heap-budget stop and allocator failure are distinct cases in allocate().
   The successful object-size bound is 2^63−1, distinct from usize's 2^64−1.
   A certificate cannot turn a budget stop into a malloc failure or erase a
   refusal/drop event. Existing abstract coupled-allocation assumptions must be
   named; libc malloc and calloc are not promised identical host outcomes.

4. **usize to Nat with actual bounds.** Establish 0≤i≤N≤2^64−1 for the concrete
   operands, not merely a handwritten mathematical i and N. The true header edge
   supplies i<N. This discharges increment_within_limit for the exact +1 step,
   so checked/wrapping usize addition agrees with Nat successor on that path.
   Signed comparisons, narrowing casts, non-unit steps and changed extents must
   refuse unless separately proved. The existing Nat theorem alone does not
   prove the runtime's finite-integer implementation.

5. **Header and body seeds differ.** A header seed supplies i=0 and the same N.
   A direct-body seed supplies i=0 before any selected-header visit. Its normal
   store additionally needs 0<N: for the current rule this follows from the
   successful checked store on the same live owner. If N=0 it traps before a
   successor/completion is established. This is a conditional NORMAL-transition
   claim; do not move the store, assume it succeeds, or suppress its checks.
   start-one, wrong-extent and both-branch ingress counterexamples must reject.

6. **One actual store implements one Lean write.** Identify the mutable view,
   root, exact index, byte value and operation order. Establish that a successful
   buffer.store writes that byte and preserves other addresses, matching
   write_at_index/write_at_other. An increment before a trapping store cannot
   justify a completed prefix. Partial-width/unknown memory operations, stale
   loans, escape/call effects or wrong-index stores remain outside the profile.

7. **Prefix values must not smuggle initial bytes.** Existing Lean completion
   equality uses the SAME values : Nat→Byte for both initial memories. For each
   dynamic fill epoch, connect actual pure computations and scalar state to a
   common value schedule independent of arbitrary initial bytes. No body loads
   are admitted by the current loop pattern, but entry scalar values can have
   provenance from earlier reads. A whole-run argument must justify those reads
   from already established equal/initialized regions, not assume independence
   circularly. Coverage alone is weaker than output/program equivalence; #594's
   changed-byte-value control deliberately remains structurally checked.
   For the actual fixtures, candidate value DAGs represent (i+seed) mod 256
   and (i*seed+17) mod 256 respectively; a transport must derive these from
   actual typed operations, not accept this sentence as a premise.

8. **Normal loop completion, not mere exit reachability.** Apply
   write_extends_prefix only after a successful store and exact successor, then
   completed_exit_is_exact_bound and completed_exit_establishes_initialized on
   the header's exact false edge. Multiple seed edges need independent checks.
   Traps, refusal, nontermination or budget exhaustion before that edge establish
   no completed-fill fact. A previously checked body's static name is not an
   execution trace or a proof that its dynamic writes happened.

9. **Empty extent uses its own premise.** A false edge of actual unsigned 0<N
   with the exact allocation extent proves N=0. The initialized interval is then
   empty, so the existing FullyInitialized predicate is vacuous. Merely matching
   compare.lt's opcode is insufficient: the extent-phi-to-zero counterexample
   leaves the allocation nonempty while skipping its writes. That mutant keeps
   CFG/root/opcodes and must fail the operand/provenance connection.

10. **Completion-edge coverage must apply to actual traces.** The temporary
    graph-cut check says no entry→load CFG path avoids all certified completion
    EDGES for that root. Connect actual normal Core transitions to those exact
    labelled edges, including phi evaluation and branch polarity. Do not replace
    an edge fact with an exit-block fact or equate two same-target branch arms.
    No real Core edge is deleted. Shared-exit bypass and parallel-arm negatives
    must remain uncovered. Loads preceding a terminator are not protected by
    a completion edge that has not yet been traversed.

11. **Persistence between completion and read.** After completion, every admitted
    operation must preserve initialized/equal bytes or perform a corresponding
    deterministic byte write. Move/borrow/end do not manufacture a fresh root;
    drop ends its lifetime. A later allocation cannot reuse the fact without a
    new dynamic-instance correspondence. Reads beyond owner length trap before
    fetching a byte. This frame/trace argument is not supplied just by the
    existing one-fill theorem; it must be discharged for the closed Core subset.

12. **Composition, observation and costs remain separate.** Prove same-program
    memory-initialization independence under explicit coupled outcomes before
    considering a zero-elision transformation. That is separate from #592's
    reference→deferred transformation and from LLVM/backend refinement. Preserve
    first trap/refusal, owner/loan/drop events and declared observable results.
    Do not infer quota/time equivalence: the 20-versus-17-step counterexample is
    retained, and allocator family/timing remain separately constrained.

## Proposed next work and stopping conditions

First implement a read-only obligation ledger/extractor that binds the exact
actual operation/edge operands above, marks unsupported cases unresolved and
rejects stale/mutated transport. It must never call an emitter or authorize
elision. Reuse the actual Core counterexamples, including the extent phi that
preserves CFG shape, and add controls for failed-allocation owner length,
parallel edges, dropped/reallocated roots and initial-byte-dependent schedules.

Then review a narrow operational projection for the admitted Core fragment into
EXISTING HiaInitializationPrefix definitions. Reuse its proven schedule lemmas;
only missing transport/frame/trace obligations need new work. Do not build a
second unrelated prefix-memory model or label a model-only receipt a universal
bridge. Any proposed connection must state which parser, canonical verifier,
resource checker and runtime semantics are still trusted rather than proved.

Stop before production elision, native poison execution or performance timing
until the required distinct proof/review and execution permissions are satisfied.
A successful structural extraction, Lean model replay or finite VM search alone
does not cross that boundary. No production zero initialization changes here.

## Read-only ledger implementation

`tools/extract_initialization_obligations.py` now reconstructs a bounded ledger
from reverified Core, after the existing research structure checker accepts its
closed profile. It records the exact function, ordered operation/output and
block-parameter definitions, direct operand dependencies (including cyclic phi
bindings), every labelled incoming edge with ordered typed bindings, allocation
operations, and each load with graph reachability after candidate completion
edges are removed. Candidate cuts explicitly leave the load-to-root semantic
connection unproved. The ledger is an inspectable index, not a proof term.

All twelve semantic obligations are individually `unproved`. The result says
`extracted`, never verified/proved/eligible. Exact Core and checkout source hashes
bind the extractor, structure checker, Core/runtime Python modules, existing Lean
model, its qualifier/support and toolchain lock. This reads these files; it does
not execute Lean, a compiler, the target, or any model qualifier. Before/after
hash comparison is not an atomic snapshot against hostile concurrent replacement.

`check_obligation_transport` reconstructs the entire ledger, then compares strict
canonical JSON bytes. Mutation, stale source identity, added claims, omitted
edges and bool/integer substitutions do not match. This deliberately shares the
extractor and research checker; it is NOT a second independent verifier and
cannot convert a matching receipt into authority. Successful matching still
reports DENY_ALL and actual_core_bridge_proved=false. Unsupported profiles,
unknown extraction, malformed data or the 4 MiB transport bound cannot match.
The existing structure checker's graph/operation bounds also remain in force.

The existing Python-only lane includes the 17 ledger controls (62 total), with
exact inventory, zero skips and no artifact upload. No native or Lean execution
is added. Existing
negative Core fixtures are reused rather than introducing another mathematical
prefix model. A later narrow operational proof must actually discharge the
listed obligations; this implementation does not do that work implicitly.
