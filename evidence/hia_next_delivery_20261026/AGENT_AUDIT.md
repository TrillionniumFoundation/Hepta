# Independent reviewer audit of the completed GGUF agent pilot

## Conclusion and scope

This is an independent reviewer audit of the **same retained four-task experiment**.
It is not an independently sampled experiment, replication, new model run, or
post-hoc rescoring. No prompts, generation settings, compiler/runtime files,
candidate scores, or failed outputs were changed. The machine-readable companion
is [audit.json](audit.json); original measurements remain in [report.json](report.json).

The completed run provides actual model-generated candidates and native outcomes.
It does **not** establish a general HIA advantage over Rust, reduced maintenance
effort, or reduced total development cost. A narrower descriptive result is
supported: in this run, HIA semantic patches used fewer tokens and completed one
more task than complete HIA JSON rewrites. HIA patches tied Rust full functions on
task success while consuming substantially more tokens and observed time.

## Evidence integrity

- The canonical plan digest was independently recomputed as
  `35ba98c58d133ec5fb26575dc1957aea8888d2a9c06cbaf6e55bc12092460ba7`, matching
  both [plan.json](plan.json) and the report.
- All 90 beginning and ending source bindings match. The audit also rehashes
  available source/tool/model/runtime files and records those observations
  separately from the original before/after attestations.
- The model is the retained Qwen2.5-Coder-1.5B-Instruct Q8_0 GGUF,
  SHA-256 `507de59046601282ba768a9789900e6ccf60ed93ddf346730b7c68eb0715bc47`.
- All 16 retained positive/negative native controls pass their declared condition;
  rejected native behavior is required to have actually executed, not merely
  failed compilation. The audit records all 16 outcomes individually.
- All 29 response records have input/output token-ID counts matching their usage
  fields. Generation settings consistently use temperature 0 and seed 0.
- There were 2 passing eligibility probes and 27 task attempts. All 29 requests
  returned validated responses: 27 EOS stops and 2 generation-limit stops.
- All 16 task/arm cells completed under the frozen maximum-two-attempt rule.
  None of the 11 second attempts recovered a failed task.

These checks bind retained evidence and its reported execution; they do not
constitute hardware attestation or a proof that every possible input is correct.

## Outcomes and precise failure taxonomy

| Arm | Successful tasks | Attempts | Accepted but native-wrong | Rejected |
| --- | ---: | ---: | ---: | ---: |
| HIA full JSON | 1 / 4 | 7 | 4 | 2 |
| HIA semantic patch | 2 / 4 | 6 | 4 | 0 |
| Rust full function | 2 / 4 | 6 | 2 | 2 |
| Rust semantic expression | 0 / 4 | 8 | 0 | 8 |

| Task | HIA full | HIA patch | Rust full | Rust semantic |
| --- | --- | --- | --- | --- |
| boundary | Original `compare.le` retained twice | Success | Success | Wrong artifact format twice |
| constant | Original constant 6 retained twice | Original constant 6 retained twice | Success | Wrong artifact format twice |
| wrapping | Success | Success | Frozen single-site context rejection twice | Wrong artifact format twice |
| loop_state | JSON cut off at 512 tokens twice | Original add-one retained twice | Original add-one retained twice | Wrong artifact format twice |

### HIA full JSON

The four accepted failures are semantically wrong but well-typed no-op repairs:
boundary retains `compare.le`; constant retains 6. Their native outputs equal
the corresponding buggy behavior. For example, constant produces
`[6,7,43,0,5]` instead of `[7,8,44,1,6]`.

Both loop responses stop at the generation limit with incomplete JSON. The raw
responses report `stop_type="limit"` and 512 output tokens. Their separate
`truncated=false` field must not be interpreted as proof that generation did not
hit its output limit. Parsing correctly rejects the incomplete documents.

### HIA semantic patch

All six artifacts satisfy the protocol and static/context checks. Four remain
functionally wrong: the constant and loop patch both repeat the faulty operation
on both attempts. Static validity alone does not establish the requested behavior.

### Rust full function

Both loop candidates compile and execute but still add one per iteration,
producing `[0,1,2,3,7,19]` instead of `[0,0,1,3,21,171]`.

Both wrapping candidates use `(x + 1) % (1 << 32)` and are rejected by the frozen
single-site context gate. They were **not** compiled or natively evaluated in
these attempts. They must not be described as observed compiler failures.

### Rust semantic expression

All eight responses return complete fenced Rust functions rather than the
specified JSON expression-edit artifact, so JSON parsing rejects them. Static
inspection finds the expected repair expression in the first boundary response,
first constant response, and both wrapping responses. Nevertheless, all remain
failures under the frozen protocol, and their native correctness was not evaluated
by this arm. Extracting functions and retroactively awarding successes would
change the experiment; this audit does not do that.

Thus the 0 / 4 result primarily demonstrates a model/interface format-compliance
problem in this arm. It is not evidence that Rust could not express the repair.

## Complete observed costs, including failed attempts

The following totals exclude the two common eligibility probes. Time is the
recorded inference plus evaluation interval on this host, not isolated hardware
performance or monetary/total engineering cost.

| Arm | Input tokens | Output tokens | Total tokens | Inference seconds | Evaluation seconds | Sum seconds |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| HIA full JSON | 3,784 | 2,786 | 6,570 | 178.057945137 | 0.816390356 | 178.874335493 |
| HIA semantic patch | 3,314 | 1,092 | 4,406 | 85.332730056 | 1.031089431 | 86.363819487 |
| Rust full function | 1,001 | 284 | 1,285 | 22.107943992 | 0.323779501 | 22.431723493 |
| Rust semantic expression | 2,173 | 342 | 2,515 | 36.710261417 | 0.000332110 | 36.710593527 |

Under this fixed retry policy, HIA patch versus HIA full uses 60.80% fewer output
tokens, 32.94% fewer total tokens, and 51.72% less observed inference-plus-evaluation
time. This includes one fewer retry; it is not a pure encoding-length effect.

HIA patch versus Rust full has the same 2 / 4 successful tasks and six attempts,
but uses **3.43 times the total tokens** and **3.85 times the observed combined
time**. The successes differ: both solve boundary; Rust full solves constant;
HIA patch solves wrapping; neither solves loop.

### First attempts only: equal four-request comparison

| Arm | Input tokens | Output tokens | Total tokens | Inference plus evaluation seconds |
| --- | ---: | ---: | ---: | ---: |
| HIA full JSON | 1,366 | 1,540 | 2,906 | 88.094354263 |
| HIA semantic patch | 1,893 | 724 | 2,617 | 55.028621616 |
| Rust full function | 543 | 178 | 721 | 13.722019825 |
| Rust semantic expression | 935 | 171 | 1,106 | 17.195985640 |

On equal first-attempt counts, HIA patch has 52.99% fewer output tokens but
38.58% more input tokens than HIA full, for a **9.94% total-token reduction**.
Observed combined time is 37.53% lower. These measurements distinguish the
initial interface cost from costs introduced by failures and retries.

## Fairness and limits on inference

The same locked model, generation configuration, maximum 512-token output,
maximum-two-attempt policy, arithmetic goals and frozen native oracle are used
throughout. Arm order rotates across the four tasks. The longest compact correct
reference response is 342 tokens, so the common budget can represent every
reference answer. Fenced code cleanup is shared by all arms.

However:

- Compact-reference capacity does not remove interaction with generation style.
  Pretty-printed full HIA JSON exhausts the loop task's budget in both attempts.
- The language and artifact-interface effects are entangled. The Rust semantic
  failures cannot be used as a clean measurement of Rust programming ability.
- These are four disclosed, single-site scalar repairs, with frozen context and
  allowed changes. They do not exercise the new ADT/resource/task composition,
  migration, cross-file development, or subsequent maintenance workflows.
- One model and one four-task run do not establish population success rates,
  statistical superiority, or reproducibility across models and real projects.
- Model setup, compiler/tool implementation, task creation, human review,
  maintenance effort, prices and total engineering cost were not measured.

## Concrete design issue supported by this run

The current agent surface spends substantial budget repeating structure or
returning the wrong artifact, while generic failure feedback does not correct
no-op repairs. Evidence is the two truncated full-JSON responses, eight wrong-
artifact Rust responses, four accepted-but-wrong HIA patches and zero recovered
second attempts.

Future experiments could preregister a schema-constrained response channel for
both languages, compact semantic-field edits, explicit format/context/behavior
diagnostics, and equal minimal counterexample feedback. They should use new,
independent task families, including resource composition and maintenance. These
are design hypotheses, not improvements established by the current experiment.

The claims `effect_established`, `general_coding_advantage_established`,
`maintenance_cost_measured`, and `total_development_cost_measured` correctly remain
false. This reviewer audit does not close the independent agent-benefit requirement.
