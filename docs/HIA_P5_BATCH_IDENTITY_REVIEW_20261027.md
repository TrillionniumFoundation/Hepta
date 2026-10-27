# P5 independent review: batch presentation identity

Review base: `0e0f07a48c1e66d608875800a8e51dc3eb7c29e0`.
The review read the v2 query traversal, batch preparation/application/rendering,
and the CFG/control-context tests. Reproduction and changes were isolated from
the integration and Rust worktrees.

## Reproduced defects

The existing batch renderer validated each nested presentation independently
but did not consistently validate relationships between them:

1. Two ordered response site IDs could name the same instruction. The later
   `edits` dictionary assignment erased the first `@site` marker.
2. A block first displayed as a downstream region and then as a selected block
   could carry conflicting parameters or a conflicting terminator. `setdefault`
   silently retained the earlier metadata. The opposite traversal order
   already rejected these block conflicts.
3. Nested queries from different real source snapshots could appear in the
   same rendered batch.
4. Overlapping function/callee summaries could disagree about their declared
   signatures or effects and be overwritten during deduplication.

These defects concern misleading or internally contradictory Agent context.
They did not bypass `apply_batch`: application reconstructs the full batch
against the captured verified program and then invokes the ordinary
whole-module patch verifier.

## Fix

Rendering now rejects repeated `(function, block, operation index)` selection
identities, requires every nested Core/source digest to match the batch, and
checks repeated function/callee summaries for exact wire equality. One block
retention path checks parameters and terminators regardless of which view
introduces a block first. SSA operation equality checks, unioned affected
parameters, and conservative control-reachability flags remain in use.

No Core semantics, patch permissions, source verification, or context schema
changed. Renderer consistency is not source authenticity or proof of behavior;
apply-time reconstruction remains required.

## Executed regression evidence

The dedicated module reproduces the prior failures using actual prepared
queries, including two independently verified source snapshots. Against the
review base its five tests produced seven failed assertions (including
subtests) and no execution errors. After the fix all five pass.

A positive resource test executes a branch-controlled, no-result call that
consumes an owner. Its callee summary remains visible, and the canonical VM
records one owner created and one dropped. A reversed selection-order test
retains both response markers and all control-region cleanup operations,
then applies the atomic edits and executes the resulting program.

```sh
/usr/bin/python3 -m unittest \
  tests.test_hia_edit_batch_identity tests.test_hia_edit_batch \
  tests.test_hia_edit_control_context tests.test_hia_edit_cfg_context \
  tests.test_hia_cfg_render_convergence tests.test_hia_context_render_input -v
```

Result on Python 3.12.3: **37 passed, zero skipped**. This is a scoped review
run, not another whole-repository qualification claim.

## Traversal assessment and remaining boundaries

Within the documented explicit-value/control-reachability scope, the reviewed
worklist unions affected block parameters, revisits newly affected states,
and propagates control reachability monotonically. A diamond reconvergence
does not discard later parameter contributions. A control-reachable block
retains all operations, including no-result calls, stores and cleanup.
Downstream loops reach a finite fixed point; an affected path returning to the
selected block explicitly refuses the compact view. Displayed terminator
inputs have their local producers closed.

The operation and block budgets are **per edit query**: 256 displayed
operations and 64 blocks. A batch can union several such views; its aggregate
limits are 16 sites and a 1 MiB serialized query, plus the existing bounded
JSON node/depth checks. The code does not claim a separate aggregate
256-operation/64-block batch cap.

The view remains a conservative editing aid. It does not infer memory alias
effects, include full callee bodies or all caller consequences, prove precise
control dependence, or establish behavioral equivalence. A scalar used by a
store can influence a later load through memory without explicit SSA flow;
that is outside this slice's promised closure. Full-module verification still
checks structural/resource validity after editing, but behavioral tests or a
stronger analysis are needed to establish the intended functional change.
