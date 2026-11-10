# Capability instruction lifecycle proofs

> Historical finite Core/native observations; removed harnesses are not
> delivered product entry points or current-source qualification.

`formal/HiaCapabilityLifecycle.lean` adds structural instruction semantics to
the existing capability projection/renaming model. It proves preservation for
allocation, local borrowing, ending a loan and dropping an owner. The previous
edge-only results and reports retain their original scope.

This is a capability-graph proof. It is not a proof of heap execution, all borrow
checker rules, the Python implementation, or complete Core type soundness.

## Instruction semantics

The model uses the existing capability fields: name, root, optional parent,
kind, external flag and optional formal-parameter origin. Names and ranks are
unbounded mathematical naturals. Its rules describe these exact changes:

| Production instructions | Model rule | Preconditions and exact change |
| --- | --- | --- |
| `buffer.new`, `buffer.try_new` | `Step.allocate`, buffer kind | A fresh name creates a local self-rooted owner without a parent or origin; every previous capability remains identical |
| `chain.empty` | `Step.allocate`, chain kind | The same owner rule creates an empty-chain capability |
| `borrow.read` | `Step.borrowRead` | A live buffer or byte view and a fresh result name create a local read loan with the source's root and origin, and the source as parent |
| `borrow.mut` | `Step.borrowMut` | A live buffer or mutable view and a fresh result name create a mutable loan with the same root/parent/origin rule; a shared view cannot be its source |
| `loan.end` | `Step.endLoan` | A local read/mutable loan may be removed only when no other capability refers to its name as root or parent |
| `owner.drop` | `Step.dropOwner` | A local self-rooted, parentless buffer/chain owner may be removed only when no other capability refers to it as root or parent |

Allocation failure handling is outside this graph semantics. `buffer.try_new`
still produces an owner capability when its runtime result is an empty owner
and a false success flag. The model asserts neither allocation success nor a
byte count or heap memory bound.

The borrowing rules are deliberately a structural slice. The production
checker additionally rejects conflicting live loans and suspends access to a
parent view while child loans exist. The new model does **not** prove those
alias/access rules, permission soundness, or Rust-equivalent memory safety.

## Generic results

There are 22 new generic theorems. For every finite capability list:

- Adding a fresh owner or a loan from an existing source preserves root and
  parent closure. A loan retains its source's root and formal origin.
- Adding a fresh name and removing an existing capability preserve unique
  names. Projection preserves uniqueness as a sublist. Injective renaming
  preserves name uniqueness, so an admitted CFG transfer preserves it too.
- New owners receive a fresh rank; new loans receive a rank above their
  source. Existing ranks remain valid because a closed graph cannot already
  refer to a fresh name. Removal retains the previous rank function.
- Removing an unreferenced capability preserves closure. This explicit
  premise prevents release from leaving a dangling root or parent.
- Induction over every finite `Trace` containing these instruction steps and
  existing admitted CFG transfers preserves closure, unique names and parent
  ranks. Strict descent excludes every positive parent cycle, with no fixed
  trace-length bound.

The mixed trace theorems assume the corresponding initial invariants and
admitted steps. A trace is an abstract sequence of model steps, not a generated
execution trace of an arbitrary Core program.

## Observations from the production checker

`retired harness verify-hia-capability-lifecycle` first verifies immutable canonical
Core, inventories **every** static instruction independently, then observes a
second verification of the same canonical bytes. A thread-local Python profile
callback captures the real `_BlockCheck.instruction` input/output capability
dictionaries. It requires the actual `_verify_function` caller and the identity
of the instruction object in that block. It neither replaces the checker nor
calls a substitute transition function. Callable existing profilers are chained
and restored, including on exceptions; an opaque profiler refuses.

Each occurrence is bound to its function, block, instruction index and complete
operation. Missing, duplicate, foreign or changed occurrences refuse the
witness. Unmodelled operations remain visible in the independent inventory and
report instead of being treated as identity steps.

For each supported occurrence the exporter writes the actual full before and
after graphs into Lean, including all fields of every retained capability.
Only list order is normalized to match the model's cons/filter operations.
Unexpected, missing or changed after-state entries remain in the kernel input.
The source capability is read from the observed input; output fields are never
rebuilt from the expected transition.

The kernel checks an exact result equality and the operation-specific `Step`,
then derives output closure, uniqueness and parent acyclicity from independently
checked input premises. Numeric name mappings are local to each occurrence.
These finite observations are **not** an exported whole-CFG trace or a theorem
that the Python checker refines the model for every program.

## Fixed cohort and negative controls

The default cohort contains the existing stored-loan record and returned-view
fixtures, plus `examples/hia_program/capability_lifecycle.hia`. The new primitive
fixture exercises nested mutable/read borrowing, sibling read loans,
`buffer.try_new`, and empty-chain allocation/release.

| Artifact | All static instructions observed | Supported instruction witnesses |
| --- | ---: | ---: |
| Stored-loan record, after existing elaboration | 14 | 8 |
| Returned views, after existing source lowering | 32 | 19 |
| Explicit lifecycle Core | 12 | 12 |
| Total | 58 | 39 |

The combined kernel run checks 404 theorem dependency inventories: 31 existing
renaming/projection theorems, 22 new generic lifecycle theorems and nine instance
theorems for each of 39 observed instructions. Positive proofs must contain
neither errors nor `sorryAx`; only the already permitted Lean standard axioms
are accepted.

Seven controls mutate actual output data while keeping inputs and operations
fixed: rebound root, discarded parent, changed kind, flipped external flag,
discarded formal origin, retained ended loan and retained dropped owner. Four
controls mutate the model: a loan rooted in itself, a self-parent loan, removed
freshness, and ignored release references. Every control must fail at its
specified theorem. A compiler error elsewhere is insufficient.

The Python regression module contains 16 tests, including real checker
rejections and profiler restoration. Existing edge-proof controls and tests
remain unchanged.

## Reproduce and inspect

Use an absolute path to the SHA-pinned Lean 4.19.0 and a fresh output directory:

> Removed source/mixed-campaign reproduction command; its harness is not
> delivered. No historical result is promoted to current qualification.

`--program /absolute/program.hia` selects explicit primitive Core v1–v8 using
the existing bounded regular-file reader. It still inventories all operations
but requires a nonempty supported subset. Output mutations that the custom
artifact cannot exercise are not invented; its report lists the controls
actually run. The default fixed cohort requires all seven output controls.
All four generic model controls remain mandatory in either mode.

The output retains canonical Core, original inputs, every observed instruction
state, positive and negative Lean files, complete kernel results, source
identities, executable identity, standard-library identities and `REPORT.json`.
The schema is `hepta.hia.capability-lifecycle-proof.v1`. `passed` is written only
after every required check succeeds and source/toolchain identities are
rechecked. An existing output directory refuses; a failed run leaves diagnostic
artifacts without a passed report.

## Remaining obligations

Calls, owner moves, chain transfer/head operations, program entry/return/trap
contracts, scalar instructions, heap execution and instruction lowering remain
outside this model. The original source/composite elaborators and Python-to-Lean
exporter remain trusted, hash-bound implementation boundaries. Alias conflict
exclusion, complete Core type soundness, backend refinement, FFI, concurrency
and hardware permissions are not proved here. The report explicitly sets
`safety_certificate` to false and grants no execution or release authority.
