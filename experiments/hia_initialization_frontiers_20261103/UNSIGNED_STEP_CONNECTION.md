# Narrow next connection: a guarded actual usize unit step

Design only, selected from the finite_integer obligation. All twelve obligations
remain unproved; DENY_ALL and actual_core_bridge_proved=false remain unchanged.
Production zero initialization, qualifiers and gates are not modified. No Lean,
compiler or native target was run to prepare this design.

## Reuse and novelty

HiaInitializationPrefix.increment_within_limit already proves, for Nat index,
length and maximum, index<length and length<=maximum imply index+1<=maximum.
The existing tools/prove_initialization_prefix_conditions.py additionally checks
the analogous unsigned 64-bit unit-step condition with Z3. Repeating either
handwritten arithmetic statement would not address the missing connection.
HiaSelectedCore is a separate standalone u32 append-register model; it is not a
usize CFG/phi semantics and must not be relabelled to serve as this bridge.

The useful new target is instead one concrete compare/true-edge/phi/add slice
from actual canonical Core, with explicit transport of theorem premises. This
is smaller than a complete loop, load coverage, allocator relation or resource
proof. It can test exact operand binding without assuming a global loop theorem.

## Proposed claim and admission fragment

Let M=2^64-1, following hepta/hia_opcodes.py WIDTHS['usize']=64, not the host
pointer width. Start with a reverified Core function and a well-typed runtime
environment at one exact compare.lt operation on two usize operands i and N.
Require its result to be the exact following branch's condition, and consider
only the true edge. Independently bind every ordered source operand to the
corresponding target block parameter, using simultaneous environment lookup.
The unit-step operation in the target must consume the transported i, with
second operand an actual usize constant 1 (or a separately established exact
alias, initially unsupported). Its result must have type usize and its opcode
must be int.add.checked or int.add.wrap. Initially admit only a direct target
block, not arbitrary paths or synthetic producer-supplied correspondence.

The intended local conclusion is: IF this dynamic true edge is taken and this
exact add is reached normally, its result is mathematical i+1, lies at most N
and at most M, and that addition itself does not overflow/wrap. Intervening
operations may trap or budgets may stop before reaching it; the conclusion does
not assert reachability, termination, removal of traps, or cost equivalence.

This uses increment_within_limit twice, with maximum=N and maximum=M. It still
needs a connection from the actual addition to those Nat bounds:

1. Core/runtime operand typing entails actual Python integers (not bool),
   0<=i,N<=M; scalar_value_valid uses exact type(value) is int.
2. The selected actual compare.lt computes the intended unsigned-domain i<N.
   No signed reinterpretation, compare.le, swapped operands or different branch
   condition can supply the premise.
3. The chosen labelled true-edge arguments are read in the old environment and
   bound simultaneously, exactly as _Machine.invoke does. A same-named SSA slot
   or same CFG shape is insufficient. The add's operand is the SAME dynamic i,
   including after alpha renaming or parallel edges to the same target.
4. The exact constant and opcode implementation supply mathematical +1. Current
   _Machine.operation computes Python addition; _checked tests integer_range;
   _wrap masks by WIDTHS then performs signed adjustment only for signed types.
   A proof must connect these implementations or name them as trusted, not treat
   a source hash as a semantic theorem. Under the established bound, a usize
   mask is the identity and the checked range accepts the sum.
5. Type preservation from verified entry arguments through prior execution is
   still a separate obligation. A locally asserted well-typed state is a premise,
   not a whole-Core operational proof. The parser, canonical verifier, resource
   checker and Python interpreter remain explicit trust boundaries.

Direct-body zero seeds are deliberately outside this first fragment: they skip
the compare. Their successful store may imply i<actual_owner_length, but mapping
that to N needs allocation-success/actual-length and same-root/extent obligations.
Do not borrow that implication silently from the single-store observer.

## Falsifiers and required controls

Use tiny verified scalar-only Core programs; no enormous allocation is necessary
to test the 64-bit upper boundary. Their shape is entry compare/branch, body add
and return, with the false arm returning the unchanged index.

- Positive wrap AND checked cases: i=M-1,N=M produce M. Rejecting this valid usize
  case using Python signed-size or host pointer limits would be overrestriction.
- Change only lt to le: i=N=M takes the true edge; wrap +1 produces 0 and checked
  +1 traps. A non-strict guard cannot instantiate the strict theorem premise.
- Change only constant 1 to 2: i=M-1,N=M passes lt but wrap add yields 0. The
  same index/root/CFG and an add opcode are insufficient.
- Change only true-edge index operand to N: entry i=M-1,N=M still passes lt,
  but body receives M and wraps to 0. This directly falsifies omitted phi binding.
- Signed i64 i=-1,N=0 passes signed lt and adds to 0; treating -1 as its unsigned
  bit pattern M would assert a false Nat/unsigned premise. This is Core-valid
  signed code but outside the proposed slice.
- i=N=0 takes the false edge and executes no add. The packet must not report an
  observed step or a completed fill from merely finding an add in the CFG.
- A budget stop before the add or an intervening explicit trap supplies no normal
  add post-state. Same-target then/else edges and wrong-condition branches require
  distinct identities, not only a destination block name.
- Malformed bool/negative/2^64 usize arguments must fail at the existing typed
  boundary. A direct call to a private helper is not a valid-Core counterexample.

Seven tiny scalar Core cases were locally reverified and run in the ordinary VM:
wrap/checked upper-bound positives returned M; le, stride-two and changed-phi
variants returned 0; signed case returned 0; empty false edge returned 0 without
executing the add. These observations motivate the falsifiers, not universal
proofs. They performed zero allocations and did not alter any production code.

## Proposed deliverable and stopping line

First build a read-only, fail-closed slice extractor and fixture mutations which
bind the actual typed operations and labelled simultaneous-phi edges. Compare
its concrete bindings with the existing ledger rather than creating another
memory model. All unsupported/ambiguous/cyclic dependency cases remain rejected
or unresolved. A matching extracted packet still cannot prove the Python/Core
semantics. Do not mark finite_integer discharged just because the packet has
names of existing Lean theorems or a solver returns UNSAT under manual premises.

A later mechanized step would have to express and prove the narrowly scoped
operational interpretation, instantiate the EXISTING Nat theorem, and explain
which actual-Core decoding/type/trace facts remain outside that formal system.
That work needs separate review. This design does not claim an allocator bridge,
all-path induction, output/backend/resource equivalence, timing, native admission,
initialization elision, or any change to the twelve unproved statuses.

## Isolated dynamic checker implementation

`tools/check_dynamic_unsigned_step.py` implements the proposed restricted slice
extraction and finite ordinary-VM observation. It revalidates canonical Core,
requires a sole header compare.lt to supply the branch condition, binds exactly
the labelled then edge and all its ordered target parameters, and selects the
first eligible target usize unit addition whose constant-one definition appears
before it. Unknown/call operations before that step exclude the candidate.
Multiple independent supported slices can be extracted; this is not admission
of unsupported blocks or all other incoming edges to the same add.

The temporary VM operation wrapper captures the actual successful compare's
source environment and snapshots every incoming edge operand before entering
the target. The first actual target operation must have a new environment with
all scalar bindings equal in value AND exact type, and resource bindings identical
by object reference. At the selected add it rechecks the transported operands,
executes the unchanged actual VM operation, and checks the result equals i+1
and is bounded by the same N and usize maximum. False-arm execution, even when
both arms have the same destination, creates no true-edge event. First direct-body
fill steps remain unobserved. Ordinary VM outcomes/resources are compared in
tests, not claimed universally equivalent by an observer theorem.

The mechanism relies on the existing runtime's branch dispatch and synchronous
operation order; it is not a separately verified trace semantics. Source hashes
bind the relevant implementation, but do not turn that reliance into proof or
provide an atomic snapshot. The observer is isolated/nonconcurrent, like the
previous single-store observer, and neither emits nor runs native code or Lean.
A successful finite observation cannot mark any of the twelve obligations proved.

Bounds: 4 MiB canonical input, 128 blocks, 2,048 operations, 4,096 binders, and
at most 4,096 recorded events (default 1,024). Events reference their extracted
slice by index rather than duplicate its potentially large phi-binding list.
Only one pending phi environment is retained, bounded by the binder limit.
An observation event cap or changed sources makes the observation incomplete and
finite_step_matches=false while ordinary VM execution continues. Unsupported
slices and unknown extraction do not start a VM observation. A run recording no
normal step cannot report a finite step match; traps/budgets before an add do not
create its post-state. Earlier genuine local matches do not imply later or
whole-loop completion.

Twenty permanent tests cover the scalar maximum, rejected signed/non-strict/
non-unit/wrong-phi variants, same-target false arms, wrong conditions, exact
simultaneous extra/reordered phi bindings, alpha renaming, direct-body exclusion,
traps/budgets and source/event/size boundaries. Real deferred fixtures exercise
four extracted slices each. For n>0, only 2*n-1 steps are observed: n-1 header-
entered fill steps and n read-loop steps; the direct-body first fill is excluded.
The dedicated Python-only lane includes these tests in its exact 102-test,
zero-skip inventory, with no artifact upload or Lean/native execution.

Reports retain the function, copied scalar input arguments, VM limits and event
cap for reproducibility. The controls use generated fixture values only, not user
data. These reports are not automatically uploaded; the Python-only lane has
no artifact-upload step. Metadata does not authenticate a replay or prove a
transition.
