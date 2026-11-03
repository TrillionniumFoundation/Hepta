# Isolated untrusted proposer and independent actual-Core checker

This work remains an experiment, separate from production native admission.
It does not modify `hepta/`, production CLI dispatch, the formal qualification
gates, or any performance threshold. No native candidate has been compiled or
timed. The design argument remains conditional, not a whole-language theorem.

## Separation of construction and checking

`tools/experimental_deferred_guard_proposer.py` constructs an untrusted Core
candidate from the current reduction pipeline. It uses the frontier model as a
construction aid and runs the standard Core verifier to catch malformed output.
This is not sufficient for acceptance.

`tools/check_deferred_guard_candidate.py` was implemented independently. It
imports neither the proposer nor the frontier planner. It freezes the bounded
wire input, independently derives all actual differences and cut edges, accounts
for every candidate block exactly once, reconstructs per-block alpha-renamings
from ordered definitions, and checks:

- exact function/module interfaces and unchanged unrelated functions;
- every original operation and attribute, including resource operations;
- ordered phi/edge operands and types, not just arity or target labels;
- immutable original-input snapshot propagation on every shared edge;
- exact pure unsigned guard, correct branch orientation and original arguments;
- closed selected-version successor namespaces, including loop backedges;
- actual candidate SSA/resource validity through the standard Core verifier;
- fresh scalar and inductive reduction proofs, reference/source hashes and
  before/after checker implementation identity.

A prior report grants no authority. `check_deferred_guard` returns an
experimental report, not a production capability or a native build receipt.
The checker does not regenerate the proposer's expected output and compare
itself to itself. Its design envelope still requires independent review.

## Deliberately narrow first profile

Exactly one guarded function, scalar public interface, a total original-input
usize upper-bound guard, at most 128 source blocks, no calls/recursion, identical
slow/fast block interfaces and terminators, common function entry and at least
one reachable divergent block. Incoming edges to the function ABI entry are
already rejected by the Core verifier. Unsupported shapes are refused, not
silently generalized. The standard verifier also enforces candidate size and
resource well-formedness.

The runtime guard is selected at first divergence; shared early-return and
allocation-refusal paths may never select a version. Original resource and
trapping operations remain in their original order. Neither n=0 recognition,
a constant answer, nor a thin wrapper is used by the proposer/checker.

## Preliminary actual-Core/VM evidence

Both linear and affine candidates contain 21 blocks and pass the actual Core
SSA/resource verifier. For testing both selected versions in a bounded range,
the existing independently checked reduction proposal uses maximum=4.
Sixty real VM cases cover n=0/1/4/5/17, three seeds including uint32 max, and
allocation success/failure for both workloads. Values and resource counters
match the entry-selected reference.

A test observer also records the **ordered** buffer/owner/borrow/loan operations,
attributes, scalar inputs, owner identities/data snapshots, outputs and resource
counters around each operation. These traces match in those cases. This is
finite real-VM evidence, not a universal resource theorem. Machine-range
allocation refusal and heap-budget cases are separately compared.

An additional real program inserts checked division by seed in the shared
prefix. With seed=0, both reference and candidate trap before allocation for
n=0/1/5. This ensures the experiment does not erase a prefix trap simply because
an eventual empty path would return zero.

## Actual quota counterexample: blocks production claims

For linear n=0, the reference VM consumes 20 counted steps while the candidate
consumes 17. With max_steps=17 the reference raises its step-budget error while
the candidate returns. This is an intentional permanent rejecting witness for
any claim of VM quota equivalence, **not** a native speedup observation.

Every report keeps `vm_steps_preserved=false`, `quota_equivalence=false`,
`native_admission=false`, `production_admission=false`,
`performance_qualified=false`, `authority=DENY_ALL`.

No existing receipt that promises guard-before-effects, VM costs, native ABI
refinement or production behavior authorizes this experiment. Before any future
native experiment, independently review the actual checker/candidate and its
scope. Any compiled layout change would still need correctness/refusal checks
and the complete original preregistered performance protocol. Do not silently
change a VM cost policy to accommodate the transformation.

## Local checks

Use the existing pinned Z3 4.15.4 environment, without installing new software:

```sh
python -B -m unittest tests.test_deferred_guard_model tests.test_deferred_guard_proposer tests.test_deferred_guard_checker -v
```

The pinned environment passes all 57 tests: 14 model, 5 proposer/VM, and
38 independent-checker tests. The checker tests include a real shared-prefix
loop, wrong backedge snapshots, alternate alpha names, shuffled block/layout
order, detached caller mutation, and missing/failing solver outcomes.

These tests include intentionally malformed and well-typed-but-wrong candidates.
No test success here grants permission for production integration or qualifies
Rust parity or any P0–P7 outcome.
