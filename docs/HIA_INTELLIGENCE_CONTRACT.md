# HIA intelligence product contract

Status: **product decision and proposed extension contract; not new Core semantics**.

HIA is a typed virtual assembly language for AI Agent authoring and verified
optimization, with independent Core semantics, ownership/resource checks,
interpretation and direct LLVM compilation. This describes the language's
implemented role. It does not state that model inference, learning or model
state mutation is currently a primitive language capability.

## 1. Product direction and separate acceptance questions

The current product goal is to make an Agent deliver and maintain a correct
module at lower complete cost. Its unit of value is an accepted maintenance
task, including repair, review, integration, cancellation/recovery and upgrade
work. A compact generated file, a passing kernel or a favorable planner score
alone is insufficient. Use the same model/provider, task input, public tests,
private oracle, tool access, attempts and resource limits in both languages.

Two questions require separate registered experiments:

| Question | Required strong controls | What the result may establish |
| --- | --- | --- |
| HIA authoring increment | HIA and a conventional language at both full-file and structured patch interfaces | Language differences within the same interface and observed task population |
| NDU planning increment | NDU, ordinary MLE plus exact DP, same-information lightweight planner, strong fixed policy | The planner's incremental observed result after its actual invocation and full cost |

A HIA language win cannot be credited to NDU, and a NDU win cannot prove a
language advantage. Interface changes are a separate factor. Multiple versions
of one underlying task belong to the same independence unit. Task provenance,
possible model training exposure and observer authentication remain explicit
limitations. No current evidence establishes population productivity gains or
NDU-exclusive economic advantage.

The executable assessor, frozen history and no-native compute audit live in
[`experiments/hia_deliverable_controls_20261106`](../experiments/hia_deliverable_controls_20261106/PROTOCOL.md).
Tests live in [`test_hia_deliverable_controls.py`](../tests/test_hia_deliverable_controls.py).
The historical factorial runner remains
[`qualify_hia_agent_frontier_factorial.py`](../tools/qualify_hia_agent_frontier_factorial.py).

## 2. Current implementation boundary

The closed instruction contract is
[`hia_opcodes.py`](../hepta/hia_opcodes.py), with version selection in
[`hia_schema.py`](../hepta/hia_schema.py) and whole-program/ownership/effect
checking in [`hia_program.py`](../hepta/hia_program.py). Its current scalar and
byte-resource types and `alloc`, `read`, `write`, `trap` effects do not include
model/tensor state or external inference. The new test explicitly verifies that
`model.infer`, `model.train`, `model.update` and `model.replay` are rejected by
the current opcode catalog, and that proposed model types/effects are absent.

A planning snapshot accepted by [`hia_ndu_stateful.py`](../hepta/hia_ndu_stateful.py)
is a finite supplied cost model; it is not a neural-model object in Core.
Likewise, an Agent using a hosted model to generate HIA does not give the HIA
program that model's inference or learning semantics. Host adapters continue
to own external effects and execution authority. Advice and comparison reports
carry `DENY_ALL` and cannot authorize deployment or state mutation.

## 3. Proposed model-language extension

The following is a proposal for a future versioned extension. None of these
names, effects, manifest fields or guarantees are being added to Core by this
change. Any future implementation must publish schema/opcode/target/ABI
support and independent interpreter/native tests before changing that status.

### Identity and artifact manifest

An immutable model identity would bind the model format and schema version,
architecture or provider operation, exact weights/content digest when
available, tokenizer/preprocessor digest, inference configuration, runtime and
kernel versions, target/device class, quantization mode and public input/output
contract. A human-readable model alias is insufficient. A provider that does
not attest effective weights must report that identity as unavailable, with a
separate provider model/version identifier; it must not synthesize a digest
and claim attested identity. Credentials are references to host capabilities,
never language artifacts or replay-log contents.

Mutable state would have its own immutable snapshot digest and monotonically
versioned identity. A learning/update operation must identify the original
state, training data manifest and ordering, optimizer state/configuration,
seed/randomness provenance, resource limits and resulting snapshot. Publishing
a new model state must use a checked expected parent identity so concurrent
updates cannot silently overwrite each other.

### Types and effects

A future `Model<Identity, Input, Output, EffectSet>` type would distinguish an
immutable inference object from an exclusively owned mutable training state.
Tensor contracts would define dtype, rank, bounded dimensions, layout,
alignment, device, ownership/borrowing and output-size limits. Floating-point
NaNs, overflow, numerical tolerances and device-dependent behavior need
explicit semantics; an opaque byte buffer is not evidence that these have
already been defined.

Proposed effects must distinguish immutable model reads, local state updates,
randomness, external provider invocation, persistence and network access.
Borrowing immutable weights permits concurrent reads only within an explicit
runtime contract. Mutation requires exclusive state ownership or a declared
transaction. Lowering cannot silently add network access, mutate a model,
train a new model or expand effects. A host capability remains necessary for
all external operations; a type check alone never grants it.

### Resource and accounting semantics

Each invocation would declare separate limits for input/output tokens, owned
host bytes, device bytes, batch size, execution fuel where supported, provider
calls, external spend and elapsed deadline. The contract must distinguish
requested bounds from enforced bounds and measured observations. A wall-time
estimate is not a hard deadline. Warmup, model load, JIT, device transfer,
preparation, inference, failure, retries, human review, cleanup and state
publication remain in the full lifecycle ledger. Shared costs are charged in
full to each standalone alternative unless a measured deployment horizon was
registered in advance. Unknown measurements remain `null` with a reason.

Planner computation itself consumes resources. Current and future decision
costs must affect both the objective and the remaining budget wherever the
model says they do. The new independent audit checks these properties for the
existing deterministic preparation models, including the boundary at which a
one-nanosecond current invocation makes completion infeasible. It does not
claim an enforced real-time bound or patch the separate historical dynamic
policy model's deadline semantics.

### Failure, cancellation and publication

Proposed results must distinguish ordinary success, model rejection,
resource exhaustion, provider timeout, cancellation requested, cancellation
confirmed, partial output, uncertain external completion and state conflict.
Failed outputs cannot be relabeled as empty successful values. Cancellation
must not imply rollback of an already published state. An update has explicit
prepared, committed or uncertain status; uncertain completion requires a
status read by the original operation identity before another mutation.

State cleanup must report retained owners, pending provider operations and
unreleased device resources. A future implementation needs fault injection
around allocation, dispatch, response loss and publication, plus deterministic
readback tests. Existing HIA cancellation represented as ordinary program
values and evaluator budget stops must not be upgraded by documentation into
arbitrary external cancellation or process recovery guarantees.

### Replay and learning

Replay records would bind the Core/source digest, model/state identity,
input digest, runtime and target identity, exact options, RNG stream when
available, observations and outputs, and every external operation identity.
Recorded-output replay and fresh model execution must be distinguishable.
Deterministic byte replay is available only for an explicitly validated
runtime/model/target combination. A seed alone does not establish deterministic
GPU or hosted inference. Other backends require a declared tolerance or an
opaque recorded-output mode. Training replay additionally binds data order,
checkpoint ancestry and optimizer state; unknown source state blocks exact
replay claims.

Schema migrations must retain an exact readable old manifest and explicit
migration receipt. They must not silently reinterpret a prior model identity,
input ABI, cost estimate or result. Rollback restores an identified immutable
snapshot and cannot erase the failed attempt or its expense.

## 4. Evidence already available and next registered work

The frozen history index verifies byte length, SHA256 and Git blob identity for
seven source-owned reports/summaries from their original commits. It keeps the
prior 14/16 successful Agent main cells and the later 24/24 successful cells
separate. The later four arms cover only six underlying tasks, with missing
token/billing/review costs. Both 72-case NDU Round6 comparisons retain identical
rankings, positive aggregate native evaluation overhead, rejected/tied policy
generations and unknown review/maintenance costs. The separate 54-profile,
10,224-state policy closure remains finite-model evidence at its own source
revision. The raw-model and Linux followthrough negative reports are indexed
without reinterpreting historical failures as current candidate results.

Next execution should freeze genuine maintenance tasks from at least eight
independent projects/task families, preferably several real defect, API
migration, cancellation/recovery and upgrade tasks per family. Choose the
conventional language that the actual host module would use. Freeze the task
set, independent-unit grouping, ordinary baseline and minimum gain before
responses; retain all planned outcomes, including qualification failures and
missing cells. The new assessor requires at least eight units but does not
pretend to verify real independence or determine adequate statistical power.
A larger study and a registered precision/power target remain necessary for a
product claim.

For NDU, freeze the same training observations and MLE model for ordinary exact
DP and NDU, plus the same objective, candidate set, feasibility/budget rules,
hardware and final task oracle. Record actual NDU invocations separately from
skipped invocations. Keep computation-free, full computation-cost and budget
boundary controls distinguishable. A cheaper policy that skips every native
NDU call is evidence about avoiding NDU cost; it cannot establish positive
NDU invocation value. Neither adding a model proposal nor passing the offline
checks completes these future empirical studies.
