# Guarded capability borrowing and suspended-parent access

> Historical finite Core/native observations; removed harnesses are not
> delivered product entry points or current-source qualification.

`formal/HiaCapabilityBorrow.lean` extends the structural lifecycle work with
borrow-conflict exclusion and access suspension. Its new `Step` relation checks
the **before state**. It never assumes compatibility of the resulting state.
The existing 31 renaming/projection theorems and 22 structural lifecycle
theorems remain unchanged; the new namespace has 32 additional generic
theorems.

This closes a selected capability-graph obligation. It does not close complete
P1, and does not prove source semantics, heap execution, checker refinement,
LLVM lowering, FFI, concurrent access or whole-language type soundness.

## Rule correspondence

The model uses the existing capability record: name, root, optional parent,
kind, external flag and optional function-parameter origin. Buffer, chain,
shared-view and mutable-view kind tags remain 0, 1, 2 and 3.

| Production rule | Selected model rule | Preserved property |
| --- | --- | --- |
| `_BlockCheck.borrow`: exclude the source and its ancestors, then inspect every remaining same-root capability | `BorrowGuard`: every same-root capability relevant to a mutable conflict must be the source or its ancestor | Any pair involving a mutable capability on the same root remains comparable along the parent graph |
| Mutable borrowing rejects every capability outside that chain | `BorrowGuard ... 3` applies to every same-root capability | A second mutable sibling cannot be created |
| Shared borrowing rejects mutable capabilities outside that chain | `BorrowGuard ... 2` applies to same-root mutable capabilities | Shared siblings remain permitted; an incompatible mutable sibling does not |
| `_BlockCheck.access`: appropriate view kind and no direct children | `Access`: membership, read/write kind permission, and `Childless` | A parent view cannot be accessed until all its children end |
| `loan.end`: a local view with no child loans | The selected structural end rule plus `Unreferenced` | Existing root/parent closure and compatibility survive removal |
| CFG projection and injective alpha renaming | Existing `Transfer`, with initial `Unique` for the new compatibility theorem | Retained capabilities keep the relevant ancestor relationships |

`Compatible` deliberately permits a mutable view and its descendants to coexist
on an ancestor chain. The separate access rule suspends every ancestor that has
a live descendant: the last edge of a positive parent path supplies a direct
child. Therefore two distinct, simultaneously accessible same-root capabilities
cannot include a mutable capability. Two shared siblings may both be accessed.

`end_restores_access` requires the parent to survive, the requested view kind
to allow the access, and every prior direct child to have the ended name. It
proves access to the resulting erased graph. Ending only one of two shared
children does not satisfy this premise and does not restore parent access.
Scalar values, buffer bounds and actual memory contents are outside this
capability-level access judgment.

The inherited `Unreferenced` release premise is stronger than the production
`children(name)` test on arbitrary malformed internal graphs: it also excludes
other capabilities whose root is the ended name. Similarly, the selected owner
drop rule explicitly requires a self root and no parent. Actual witnesses prove
these premises for their observed states. A theorem deriving them from every
production state-construction rule and kind/environment invariant is still
missing. Consequently this model does not assert equivalence to the checker on
every arbitrary dictionary of capabilities.

The selected instruction relation covers `buffer.new`, `buffer.try_new`,
`chain.empty`, `borrow.read`, `borrow.mut`, `loan.end`, `owner.drop`,
`buffer.load` and `buffer.store`. The last two have identity transitions on
capability graphs and require `Access`; this does not model their heap effects.
The existing allocation abstraction represents the capability produced by the
successful static check, not allocation success or failure in a runtime heap.

## Composition without an after-state assumption

`compatible_loan` derives compatibility of the new graph from the old graph,
source membership and the before-state borrow guard. The guard is not expressed
as the desired compatibility conclusion. `compatible_owner` uses freshness and
root closure; release uses a closed subgraph argument.

For projection, `path_retained` proves that a closed subgraph containing a node
also retains the entire parent path above it. Unique names identify the retained
records with their original parents. This is necessary: deleting a middle
parent while retaining its grandchild is not an admissible projection. Path
renaming preserves the edges; injectivity reflects equality of roots.

The new `Trace` allows any finite interleaving of the selected guarded `Step`
and the existing admitted `Transfer`. Induction proves closure, uniqueness,
compatibility and, given initial parent ranks, absence of positive parent
cycles. `trace_accessible_exclusive` derives exclusion of simultaneously
accessible mutable aliases at the resulting state. There is no fixed trace
length in these generic theorems. Initial closure, unique names and
compatibility are required; acyclicity additionally requires initial ranks.

These are theorems about the new guarded relation. The older
`HiaCapabilityLifecycle.Trace` has a different structural scope and does not
acquire conflict exclusion merely by importing the new file.

## Finite observations from the actual checker

`retired harness verify-hia-capability-borrow` composes two observers in the current
Python thread. The original lifecycle observer captures every actual
`_verify_function -> _BlockCheck.instruction` occurrence. The new observer
captures actual `instruction -> borrow/access` calls and the actual
`access -> children` return. Neither observer replaces the production methods.
Both chain an existing callable profiler and restore it on exit or rejection.

Guard observations retain the actual before/after capability dictionaries,
source, requested permission, output name, ancestor exclusion and remaining
same-root capabilities, or the actual child-query result. An independently
inventoried selected instruction must have exactly its expected guard call.
Missing, duplicate, foreign or rebound calls reject qualification. Guard states
must equal the independently observed instruction states; the observer's
ancestor/conflict/child data are checked against those exact states.

The Lean exporter retains actual capability fields. It independently proves
the input graph's closure, rank, uniqueness and compatibility, literal ancestor
paths, the before-state guard, the exact observed transition, and the selected
step. Generic theorems then derive output preservation. For every observed loan
creation it also proves that its actual source is suspended in the output.
Access instructions must have unchanged capability graphs and an independently
proved input access judgment.

Each instruction has its own finite name mapping and independently checked
entry state. These observations are **not an exported whole-CFG execution
Trace**, and do not establish universal refinement of the Python checker or
exporter. The independently checked abstract trace theorem and finite
production observations are separate claims. Kind/environment agreement,
initial-state construction for arbitrary functions, calls and returned-loan
substitution still require their own refinement arguments.

The fixed cohort retains both existing production inputs and the 12-instruction
lifecycle fixture, then adds `capability_borrow_access.hia`:

| Input | Static instructions observed | Selected instructions | Actual borrow/access calls |
| --- | ---: | ---: | ---: |
| Stored loan record | 14 | 11 | 6 |
| Returned views | 32 | 23 | 13 |
| Explicit lifecycle | 12 | 12 | 4 |
| Shared siblings and mutable reborrow | 28 | 28 | 17 |
| Total | 86 | 74 | 40 |

The generated dependency inventory contains 1,100 theorem checks, including
the 85 generic theorems and concrete instruction/path witnesses. This is a
count of checked declarations, not a count of independent whole-language
safety properties. All 12 unmodelled static instructions remain visible in the
report. Existing instruction/capability limits remain 512, generated Lean and
kernel output remain capped at 1 MiB, and each Lean invocation retains its
60-second timeout. A new cumulative bound of 8,192 parent-path steps stops
path-proof materialization before it exceeds that budget.

## Independent refusal controls

The new qualifier preserves all seven prior observed-output corruption
categories and four generic lifecycle premise mutations. It adds:

- Removing the pre-state borrow conflict guard; Lean must reject
  `compatible_loan`.
- Removing the access child guard; Lean must reject `child_blocks_access`.
- Attempting a second mutable sibling in an observed nested-borrow state;
  Lean must reject the new borrow guard.
- Attempting parent access while its mutable child remains; Lean must reject
  the access judgment.
- Attempting parent access after one shared sibling ends while another
  remains; Lean must reject the access judgment.

Each of these 16 Lean controls must fail at its intended theorem, not merely
produce an unrelated compiler error. Actual-output controls check the affected
observed occurrence with its original index; the positive checks every selected
occurrence. The three invalid-admission countermodels are explicitly derived
controls, not falsely labelled production observations.

Four separate full-program controls must also receive `E_HIA_LOAN` from the
unchanged production checker: mutable siblings, premature parent access,
remaining shared sibling and shared-to-mutable escalation. The Python regression
suite additionally removes the actual production conflict guard, or forces its
child query to return empty. These altered checkers accept the bad program,
but the independent evidence validation must refuse it. Positive regression
cases execute shared siblings and nested mutable reborrows, check access
restoration, and exercise nontrivial alpha renaming plus closed external
projection. Projecting away an intermediate parent is rejected.

## Reproduce and inspect scope

> Removed source/mixed-campaign reproduction command; its harness is not
> delivered. No historical result is promoted to current qualification.

The runner checks the repository-pinned Lean 4.19.0 binary and support files,
retains generated Lean, all kernel output, source hashes, original inputs,
observed instruction and guard records, and all negative-control inputs.
`REPORT.json` has schema `hepta.hia.capability-borrow-proof.v1`.

`--program` can select a bounded primitive input instead of the fixed cohort.
Its inventory and exercised output/countermodel controls remain explicit;
missing opportunities in a custom cohort are not presented as the complete
fixed cohort. The generic premise controls and fixed production-refusal
programs still run. A custom program with no actual borrow/access call does
not claim a finite actual guard witness.

The report keeps `whole_cfg_execution_trace_exported`,
`source_semantics_refinement_proved`,
`python_checker_or_exporter_refinement_proved`, `heap_execution_proved`,
`calls_moves_chain_transfers_proved`, `complete_core_type_soundness_proved`,
`llvm_native_ffi_concurrency_proved` and `safety_certificate` false. Remaining
P1 work includes state construction and kind/environment agreement; owner moves,
chain and call/return frame rules; a capability-to-heap/provenance simulation;
outcome/effect composition; native lowering and explicit foreign trust rules.
