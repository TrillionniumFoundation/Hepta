# Checked resource-call expansion and guarded loop composition

`hepta/hia_call_expansion.py` extends the verified transformation surface from
fixed call skeletons to **resolved single-block leaf calls**. A caller may have
loops, branches, multiple owners and loans. A callee must be a complete checked
function with one entry block, a normal `ret`, and no nested `call` instruction.
No function pointer, foreign implementation, recursive body, unknown symbol or
producer-provided proof receipt grants admission.

This pass works on the canonical standalone Core after source capture and
nominal resource elaboration. It can therefore cross source-file boundaries
already resolved by the C/C++ project importer. It does not prove arbitrary
cross-module source equivalence, binary compatibility or dynamic linking.

## Independent checking rule

The proposer substitutes parameters and uses fresh **function-wide** SSA names.
The checker does not compare against the proposer's chosen names or regenerate
the proposal with the same algorithm. It independently constructs an ordered
SSA trace of the original selected calls, replacing each selected call with its
complete original callee body. It compares that trace with the actual candidate
instructions, including all argument identities, result types, attributes and
normalized CFG exit operands.

Both complete programs must pass the ordinary ownership/effect/CFG verifier.
Function inventory, public interface, block parameters, signatures and effect
declarations must agree. Each selected call site must exist exactly once in the
witness inventory. Every block is compared, including unselected functions.
The callee implementation cannot be silently changed while its call site is
expanded. The limit is 256 call sites and 16,384 total compared operations;
exhaustion rejects the request without publishing partial work.

For this rule, allocation, borrow, memory access, move, release and potentially
trapping scalar instructions retain their exact ordered trace. Resource release
reordering is refused even if ordinary linear-resource checking accepts both
programs. Source-level destructor order is not reducible to balanced counters.

An admitted leaf cannot loop or recurse internally. Replacing its call with the
same finite trace therefore preserves each caller block's value, ordered Core
effects, first semantic trap and exit. The unchanged caller CFG composes this
block relation through any number of completed loop iterations. The trusted
Python checker implements this rule; there is no machine-checked soundness
theorem for its implementation or the whole language.

### Explicit exclusions

Interpreter step counts, call-depth budgets, diagnostic source locations and
stack usage can change when a call is removed. They are explicitly excluded
from this transformation profile. A budget stop is not treated as a semantic
trap. In particular, an inlined call can run under `max_call_depth=1` when the
original program stops at that evaluator limit; a dedicated test records this
counterexample instead of claiming their budget outcomes are equal.

Native traps still abort rather than reporting the VM's precise trap code.
Native compiler/linker/loader behavior, system allocation and host isolation
remain trusted. No backend refinement theorem or universal performance gain
follows from this trace comparison.

## Exposing a loop optimization through a resource call

`propose_expanded_guarded` composes two independently checked stages:

1. Expand eligible leaf calls and bind the exact intermediate Core hash.
2. Apply the existing counted-byte reduction proposal to that intermediate,
   prove its entry condition, every inductive CFG edge and every removed
   overflow check, then construct the actual guarded fast path and checked
   fallback.

The regression fixture carries two owners through a loop and through a
multi-result leaf call. That call writes both buffers and returns a loaded byte.
Before expansion the guarded proposer cannot recognize the supported byte
producer. After expansion it can prove the checked `u64` accumulator addition
nontrapping under the explicit count guard. The complete checked fallback
remains available when the guard is false.

The chain checker verifies each stage afresh, requires the first stage's
candidate hash to equal the second stage's base hash, reconstructs the actual
guarded Core, and binds that final hash. A receipt alone cannot bridge two
unrelated programs. Forged entry invariants, unsafe guard enlargement, stale
intermediates, unlisted effect changes, solver timeout and solver `unknown`
remain refusals.

The composed resource claim follows the ordered original trace. It does not
allow moving allocations out of loops, suppressing allocation failures,
speculating a trapping load, changing callback order, or inventing cleanup
after abort. Those transformations would require additional explicit rules
and independent proof obligations.

## Binding proofs to executed artifacts

`build_expanded_native` and `build_expanded_guarded_native` verify the actual
proposal and freeze the checked candidate. They compile into a private staging
directory, compare native bytes with the backend receipt, recheck checker
identity, and publish only a new destination through the existing checked
publication mechanism. A changed checker causes publication withdrawal.

The receipt binds original Core, final Core, verification digest, actual
artifact bytes, compiler identity and target. Before publication, it also
checks that the backend receipt names the expected Core/input, freshly emitted
LLVM IR, implementation, export inventory, target, kind and staging output.
Actually compiling a different resource-valid Core is an explicit negative
control and cannot receive the original proof's artifact binding. The two-stage receipt also
retains both complete verification reports and the intermediate hash. A native
artifact hash is a binding, not a proof of the backend's correctness.

`tools/qualify_hia_call_expansion.py` loads a sealed Linux memfd made from the
receipt-bound bytes and checks the original path/inode/bytes again after use.
It executes the loop's fast and fallback cases, composite-owner cases, borrowed
loads and actual aborting children. VM allocation-failure injections compare
the complete resource ledgers. These are distinct observations: this tool does
not label VM resource counters as native allocation telemetry.

When `--component-core` names a Core produced by
`tools/qualify_cpp_callback_project.py`, it also expands real resolved calls in
that captured multi-file C++ component and compares original/expanded native
execution over 864 registered cases, including the callback's error return.
The separate component qualifier checks
original C++ against an independently implemented value/resource-event oracle;
this pass does not replace that source qualification with self-comparison.

## Reproduce

```bash
CLANG=/path/to/clang python -m unittest tests.test_hia_call_expansion -v

python tools/qualify_hia_call_expansion.py \
  --output /tmp/new-call-expansion-qualification \
  --clang /path/to/clang \
  --component-core /tmp/callback-qualification/three_weight/standalone.core.json
```

Use the pinned Z3 dependency for the guarded stage. Native tests must actually
run with Clang; skipped native or solver cases are not a complete qualification.
The output directory must be new. Source identity is checked before and after
qualification, so use a settled integration tree or a retained frozen snapshot.
The tool records finite behavior and actual build/verification costs without a
speed acceptance claim.
